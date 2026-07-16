"""Agent graph tests. The LLM and the cluster are both mocked — nothing here touches the world."""

from unittest.mock import MagicMock, patch

import pytest

import agents
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


def test_route_after_assess_stops_at_probe_cap():
    state = {"probe_requests": ["role_verbs"], "probe_rounds": agents.MAX_PROBE_ROUNDS}
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
