"""Context probe tests. The k8s API is never called here — the API clients are the seam.

These probes are the whole differentiator: they gather the facts Trivy cannot see.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

import cluster


def _pod(sa="payments-sa", privileged=True, secrets=("cloud-credentials",), host_paths=("/",)):
    """A fake pod spec shaped like the k8s python client returns."""
    return SimpleNamespace(
        spec=SimpleNamespace(
            service_account_name=sa,
            containers=[
                SimpleNamespace(
                    name="api",
                    security_context=SimpleNamespace(privileged=privileged),
                    env_from=[
                        SimpleNamespace(secret_ref=SimpleNamespace(name=s)) for s in secrets
                    ],
                    env=None,
                    volume_mounts=[SimpleNamespace(name="host-root", mount_path="/host")],
                )
            ],
            volumes=[
                SimpleNamespace(
                    name="host-root",
                    host_path=SimpleNamespace(path=p),
                    secret=None,
                )
                for p in host_paths
            ],
        ),
        metadata=SimpleNamespace(labels={"app": "payments-api"}, name="payments-api-x"),
    )


# --- RBAC blast radius ---


def test_detects_cluster_admin_bound_service_account():
    rbac = MagicMock()
    rbac.list_cluster_role_binding.return_value = SimpleNamespace(
        items=[
            SimpleNamespace(
                metadata=SimpleNamespace(name="payments-sa-cluster-admin"),
                role_ref=SimpleNamespace(kind="ClusterRole", name="cluster-admin"),
                subjects=[
                    SimpleNamespace(kind="ServiceAccount", name="payments-sa", namespace="vuln-demo")
                ],
            )
        ]
    )
    rbac.list_namespaced_role_binding.return_value = SimpleNamespace(items=[])

    result = cluster.probe_rbac(rbac, "vuln-demo", "payments-sa")

    assert result.is_cluster_admin is True
    assert "ClusterRole/cluster-admin" in result.bindings


def test_service_account_with_no_bindings_is_not_cluster_admin():
    rbac = MagicMock()
    rbac.list_cluster_role_binding.return_value = SimpleNamespace(items=[])
    rbac.list_namespaced_role_binding.return_value = SimpleNamespace(items=[])

    result = cluster.probe_rbac(rbac, "safe-demo", "reports-sa")

    assert result.is_cluster_admin is False
    assert result.bindings == []


# --- Secrets: names only, never values ---


def test_reports_mounted_secret_names():
    assert cluster.probe_secrets(_pod()) == ["cloud-credentials"]


def test_never_returns_secret_values():
    """Security regression guard: secret material must never reach the LLM prompt.

    probe_secrets takes only the pod spec, which carries references, not data.
    If someone ever changes it to read Secret bodies, this test should be the tripwire.
    """
    names = cluster.probe_secrets(_pod())
    for n in names:
        assert isinstance(n, str)
    # The probe signature must not accept a CoreV1Api client at all - it cannot read data.
    import inspect

    params = inspect.signature(cluster.probe_secrets).parameters
    assert list(params) == ["pod"], "probe_secrets must only see the pod spec, never an API client"


# --- Exposure ---


def test_detects_nodeport_exposure():
    core = MagicMock()
    core.list_namespaced_service.return_value = SimpleNamespace(
        items=[
            SimpleNamespace(
                metadata=SimpleNamespace(name="payments-api"),
                spec=SimpleNamespace(
                    type="NodePort",
                    selector={"app": "payments-api"},
                    ports=[SimpleNamespace(node_port=30081, port=80)],
                ),
            )
        ]
    )
    exp = cluster.probe_exposure(core, "vuln-demo", {"app": "payments-api"})
    assert exp.reachable_externally is True
    assert "NodePort" in exp.summary
    assert "30081" in exp.summary


def test_clusterip_is_not_externally_reachable():
    core = MagicMock()
    core.list_namespaced_service.return_value = SimpleNamespace(
        items=[
            SimpleNamespace(
                metadata=SimpleNamespace(name="reports-api"),
                spec=SimpleNamespace(
                    type="ClusterIP",
                    selector={"app": "reports-api"},
                    ports=[SimpleNamespace(node_port=None, port=80)],
                ),
            )
        ]
    )
    exp = cluster.probe_exposure(core, "safe-demo", {"app": "reports-api"})
    assert exp.reachable_externally is False


# --- NetworkPolicy ---


def test_absent_network_policy_is_reported_as_uncovered():
    net = MagicMock()
    net.list_namespaced_network_policy.return_value = SimpleNamespace(items=[])
    assert cluster.probe_network_policy(net, "vuln-demo", {"app": "payments-api"}) is False


def test_default_deny_network_policy_covers_all_pods():
    net = MagicMock()
    net.list_namespaced_network_policy.return_value = SimpleNamespace(
        items=[
            SimpleNamespace(
                metadata=SimpleNamespace(name="default-deny-ingress"),
                spec=SimpleNamespace(pod_selector=SimpleNamespace(match_labels=None)),
            )
        ]
    )
    # An empty podSelector selects every pod in the namespace.
    assert cluster.probe_network_policy(net, "safe-demo", {"app": "reports-api"}) is True


# --- Workload facts from the pod spec ---


def test_detects_privileged_and_hostpath():
    facts = cluster.probe_workload_facts(_pod())
    assert facts.privileged is True
    assert facts.host_paths == ["/"]


def test_hardened_pod_reports_clean_facts():
    facts = cluster.probe_workload_facts(_pod(privileged=False, secrets=(), host_paths=()))
    assert facts.privileged is False
    assert facts.host_paths == []
