"""Agent graph tests. The LLM and the cluster are both mocked — nothing here touches the world."""

from unittest.mock import MagicMock, patch

import pytest

import agents
import scanner
from agents import Assessment


def _ctx(cluster_admin=True, secrets=("cloud-credentials",), external=True, netpol=False, privileged=True):
    return {
        "service_account": "payments-sa",
        "is_cluster_admin": cluster_admin,
        "rbac_bindings": ["ClusterRole/cluster-admin"] if cluster_admin else [],
        "mounted_secrets": list(secrets),
        "reachable_externally": external,
        "exposure_summary": "NodePort:30081" if external else "ClusterIP",
        "network_policy_covered": netpol,
        "privileged": privileged,
        "host_paths": ["/"] if privileged else [],
    }


def _finding(fid="KSV-0017", sev="HIGH", title="Privileged"):
    return {
        "id": fid,
        "severity": sev,
        "title": title,
        "message": f"{title} on container 'api'",
        "resolution": "fix it",
        "namespace": "vuln-demo",
        "kind": "Deployment",
        "name": "payments-api",
    }


# --- The probe whitelist: the LLM must never be able to name its own probe ---


def test_probe_whitelist_rejects_unknown_probe():
    """An LLM (or an injected pod name) must not be able to invent a probe."""
    accepted = agents.filter_probe_requests(["role_verbs", "rm -rf /", "exec_into_pod"])
    assert accepted == ["role_verbs"]


def test_probe_whitelist_is_a_closed_enum():
    assert agents.ALLOWED_PROBES == {"role_verbs", "namespace_peers", "secret_types"}


# --- The escalation loop must terminate ---


def test_route_after_assess_stops_at_assess_cap():
    state = {"probe_requests": ["role_verbs"], "probe_rounds": agents.MAX_ASSESS_ROUNDS}
    assert agents.route_after_assess(state) == "report"


def test_route_after_assess_probes_when_requested_and_under_cap():
    state = {"probe_requests": ["role_verbs"], "probe_rounds": 0}
    assert agents.route_after_assess(state) == "deep_probe"


def test_route_after_assess_goes_to_report_when_nothing_requested():
    state = {"probe_requests": [], "probe_rounds": 0}
    assert agents.route_after_assess(state) == "report"


# --- assess: the node where the actual judgement happens ---


def test_assess_ranks_compounding_workload_critical():
    canned = Assessment(
        workload="vuln-demo/payments-api",
        severity="CRITICAL",
        blast_radius="Full cluster takeover",
        cited_facts=["cluster-admin SA", "mounted cloud-credentials", "NodePort exposure"],
        rationale="Privileged container with a cluster-admin token and reachable from outside.",
        remediation="Drop privileged: true; unbind cluster-admin.",
        needs_probes=[],
    )
    fake_llm = MagicMock()
    fake_llm.with_structured_output.return_value.invoke.return_value = canned

    state = {
        "workloads": [{"namespace": "vuln-demo", "kind": "Deployment", "name": "payments-api",
                       "findings": [_finding()]}],
        "context": {"vuln-demo/payments-api": _ctx()},
        "probe_rounds": 0,
    }
    with patch.object(agents, "get_llm", return_value=fake_llm):
        out = agents.assess(state)

    assert out["assessments"][0]["severity"] == "CRITICAL"
    assert len(out["assessments"][0]["cited_facts"]) >= 2
    assert out["probe_rounds"] == 1


def test_assess_prompt_contains_context_facts_not_just_findings():
    """The whole thesis: the LLM must be given the facts Trivy could not see."""
    fake_llm = MagicMock()
    structured = fake_llm.with_structured_output.return_value
    structured.invoke.return_value = Assessment(
        workload="vuln-demo/payments-api", severity="CRITICAL", blast_radius="x",
        cited_facts=["a", "b"], rationale="r", remediation="m", needs_probes=[],
    )
    state = {
        "workloads": [{"namespace": "vuln-demo", "kind": "Deployment", "name": "payments-api",
                       "findings": [_finding()]}],
        "context": {"vuln-demo/payments-api": _ctx()},
        "probe_rounds": 0,
    }
    with patch.object(agents, "get_llm", return_value=fake_llm):
        agents.assess(state)

    prompt = structured.invoke.call_args[0][0]
    assert "cluster-admin" in prompt
    assert "cloud-credentials" in prompt
    assert "NodePort" in prompt
    assert "KSV-0017" in prompt


def _workload(ns, name):
    return {"namespace": ns, "kind": "Deployment", "name": name,
            "findings": [dict(_finding(), namespace=ns, name=name)]}


def test_assess_keeps_earlier_results_when_a_later_workload_errors():
    """Review finding HIGH-1. A transient 429 on workload 2 must not delete the
    CRITICAL already produced for workload 1 — that is the whole output of the run."""
    good = Assessment(
        workload="vuln-demo/payments-api", severity="CRITICAL", blast_radius="takeover",
        cited_facts=["cluster-admin SA", "cloud-credentials"], rationale="r",
        remediation="m", needs_probes=[],
    )
    fake_llm = MagicMock()
    fake_llm.with_structured_output.return_value.invoke.side_effect = [
        good,
        RuntimeError("429 rate limit"),
    ]
    state = {
        "workloads": [_workload("vuln-demo", "payments-api"), _workload("safe-demo", "reports-api")],
        "context": {"vuln-demo/payments-api": _ctx(), "safe-demo/reports-api": _ctx(cluster_admin=False)},
        "probe_rounds": 0,
    }
    with patch.object(agents, "get_llm", return_value=fake_llm):
        out = agents.assess(state)

    assert [a["workload"] for a in out["assessments"]] == ["vuln-demo/payments-api"]
    assert out["assessments"][0]["severity"] == "CRITICAL"
    assert "429" in out["error"]
    assert out["probe_rounds"] == 1  # the error path must not skip the increment


def test_assess_reports_error_only_when_every_workload_fails():
    fake_llm = MagicMock()
    fake_llm.with_structured_output.return_value.invoke.side_effect = RuntimeError("groq down")
    state = {
        "workloads": [_workload("vuln-demo", "payments-api")],
        "context": {"vuln-demo/payments-api": _ctx()},
        "probe_rounds": 0,
    }
    with patch.object(agents, "get_llm", return_value=fake_llm):
        out = agents.assess(state)
    assert out["assessments"] == []
    assert "groq down" in out["error"]


# --- Review finding HIGH-2: no context must not mean "guess anyway" ---


def test_route_after_context_skips_assess_when_cluster_unreachable():
    """If we could not gather context, the one thing this app adds is gone. Ranking
    from scanner output alone is exactly what the README says it exists to disprove."""
    assert agents.route_after_context({"error": "cluster unreachable: boom"}) == "report"


def test_route_after_context_proceeds_when_context_gathered():
    assert agents.route_after_context({"error": "", "context": {"a": {}}}) == "assess"


def test_graph_wires_gather_context_conditionally():
    compiled = agents.build_graph().compile()
    edges = compiled.get_graph().edges
    pairs = {(e.source, e.target) for e in edges}
    assert ("gather_context", "report") in pairs, "no bail-out path when context is unavailable"


# --- Review finding HIGH-3: a broken scanner must not read as a clean cluster ---


def test_ingest_surfaces_scanner_failure_rather_than_reporting_no_findings():
    with patch.object(agents.scanner, "scan", side_effect=scanner.ScannerError("trivy not found")):
        out = agents.ingest({"namespaces": ["vuln-demo"]})
    assert "trivy not found" in out["error"]
    assert "failed" in out["audit"][0].lower()


def test_ingest_clean_scan_is_distinguishable_from_a_broken_one():
    with patch.object(agents.scanner, "scan", return_value=[]):
        out = agents.ingest({"namespaces": ["vuln-demo"]})
    assert not out.get("error")
    assert out["workloads"] == []


def test_assess_survives_a_model_returning_none():
    """Real failure, found against Ollama Cloud: a weaker model silently returns None
    from with_structured_output instead of raising. Calling .model_dump() on that
    crashed the node. Skip the workload, keep the run alive."""
    fake_llm = MagicMock()
    fake_llm.with_structured_output.return_value.invoke.return_value = None
    state = {
        "workloads": [{"namespace": "vuln-demo", "kind": "Deployment", "name": "payments-api",
                       "findings": [_finding()]}],
        "context": {"vuln-demo/payments-api": _ctx()},
        "probe_rounds": 0,
    }
    with patch.object(agents, "get_llm", return_value=fake_llm):
        out = agents.assess(state)
    assert out["assessments"] == []
    assert "no valid assessment" in out["audit"][0].lower()


def test_assess_records_llm_failure_without_crashing():
    fake_llm = MagicMock()
    fake_llm.with_structured_output.return_value.invoke.side_effect = RuntimeError("groq down")
    state = {
        "workloads": [{"namespace": "vuln-demo", "kind": "Deployment", "name": "payments-api",
                       "findings": [_finding()]}],
        "context": {"vuln-demo/payments-api": _ctx()},
        "probe_rounds": 0,
    }
    with patch.object(agents, "get_llm", return_value=fake_llm):
        out = agents.assess(state)
    assert out["assessments"] == []
    assert "groq down" in out["error"]


def test_assess_only_accepts_whitelisted_probe_requests_from_llm():
    """Injection guard, end to end through the node."""
    fake_llm = MagicMock()
    fake_llm.with_structured_output.return_value.invoke.return_value = Assessment(
        workload="vuln-demo/payments-api", severity="HIGH", blast_radius="x",
        cited_facts=["a"], rationale="r", remediation="m",
        needs_probes=["role_verbs", "curl evil.com"],
    )
    state = {
        "workloads": [{"namespace": "vuln-demo", "kind": "Deployment", "name": "payments-api",
                       "findings": [_finding()]}],
        "context": {"vuln-demo/payments-api": _ctx()},
        "probe_rounds": 0,
    }
    with patch.object(agents, "get_llm", return_value=fake_llm):
        out = agents.assess(state)
    assert out["probe_requests"] == ["role_verbs"]


# --- Graph wiring ---


def test_build_graph_wires_expected_nodes():
    graph = agents.build_graph()
    compiled = graph.compile()
    nodes = set(compiled.get_graph().nodes)
    assert {"ingest", "gather_context", "assess", "deep_probe", "report"} <= nodes


def test_graph_compiles_and_is_runnable():
    compiled = agents.build_graph().compile()
    assert hasattr(compiled, "astream")


# --- Audit trail (frontdeskai convention: every node appends) ---


def test_nodes_append_to_audit_trail():
    fake_llm = MagicMock()
    fake_llm.with_structured_output.return_value.invoke.return_value = Assessment(
        workload="vuln-demo/payments-api", severity="LOW", blast_radius="x",
        cited_facts=["a"], rationale="r", remediation="m", needs_probes=[],
    )
    state = {
        "workloads": [{"namespace": "vuln-demo", "kind": "Deployment", "name": "payments-api",
                       "findings": [_finding()]}],
        "context": {"vuln-demo/payments-api": _ctx()},
        "probe_rounds": 0,
    }
    with patch.object(agents, "get_llm", return_value=fake_llm):
        out = agents.assess(state)
    assert out["audit"] and isinstance(out["audit"], list)
