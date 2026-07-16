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


# --- Review finding HIGH-6: cluster-admin by RULES, not by role name ---


def _crb(binding_name, role_kind, role_name, sa_name, sa_ns):
    return SimpleNamespace(
        metadata=SimpleNamespace(name=binding_name),
        role_ref=SimpleNamespace(kind=role_kind, name=role_name),
        subjects=[SimpleNamespace(kind="ServiceAccount", name=sa_name, namespace=sa_ns)],
    )


def _rule(verbs, resources, api_groups):
    return SimpleNamespace(verbs=verbs, resources=resources, api_groups=api_groups)


def test_custom_role_granting_everything_is_detected_as_cluster_admin():
    """A ClusterRole granting */*/* under any name is cluster-admin in all but label.
    Matching on the string 'cluster-admin' misses every real-world custom role."""
    rbac = MagicMock()
    rbac.list_cluster_role_binding.return_value = SimpleNamespace(
        items=[_crb("b", "ClusterRole", "platform-operator", "payments-sa", "vuln-demo")]
    )
    rbac.list_namespaced_role_binding.return_value = SimpleNamespace(items=[])
    rbac.read_cluster_role.return_value = SimpleNamespace(
        rules=[_rule(["*"], ["*"], ["*"])]
    )

    result = cluster.probe_rbac(rbac, "vuln-demo", "payments-sa")
    assert result.is_cluster_admin is True


def test_rolebinding_to_edit_is_detected():
    """'admin' and 'edit' are normally bound via RoleBinding, not ClusterRoleBinding.
    The name check previously lived only in the ClusterRoleBinding loop."""
    rbac = MagicMock()
    rbac.list_cluster_role_binding.return_value = SimpleNamespace(items=[])
    rbac.list_namespaced_role_binding.return_value = SimpleNamespace(
        items=[_crb("b", "ClusterRole", "edit", "payments-sa", "vuln-demo")]
    )
    rbac.read_cluster_role.return_value = SimpleNamespace(rules=[])

    result = cluster.probe_rbac(rbac, "vuln-demo", "payments-sa")
    assert result.is_privileged_rbac is True


def test_narrow_readonly_role_is_not_flagged():
    """The regression guard: don't turn this into 'everything is cluster-admin'."""
    rbac = MagicMock()
    rbac.list_cluster_role_binding.return_value = SimpleNamespace(
        items=[_crb("b", "ClusterRole", "kubesentinel-readonly", "kubesentinel", "kubesentinel")]
    )
    rbac.list_namespaced_role_binding.return_value = SimpleNamespace(items=[])
    rbac.read_cluster_role.return_value = SimpleNamespace(
        rules=[_rule(["get", "list"], ["pods"], [""])]
    )

    result = cluster.probe_rbac(rbac, "kubesentinel", "kubesentinel")
    assert result.is_cluster_admin is False
    assert result.is_privileged_rbac is False


def test_unreadable_role_is_reported_not_silently_cleared():
    """If we cannot read the role we cannot claim it is safe."""
    rbac = MagicMock()
    rbac.list_cluster_role_binding.return_value = SimpleNamespace(
        items=[_crb("b", "ClusterRole", "mystery", "sa", "ns")]
    )
    rbac.list_namespaced_role_binding.return_value = SimpleNamespace(items=[])
    rbac.read_cluster_role.side_effect = RuntimeError("forbidden")

    result = cluster.probe_rbac(rbac, "ns", "sa")
    assert result.unresolved == ["ClusterRole/mystery"]


# --- Review finding HIGH-5: probe_secret_types must not carry values ---


def test_probe_secret_types_returns_only_types_never_data():
    core = MagicMock()
    core.read_namespaced_secret.return_value = SimpleNamespace(
        type="Opaque",
        data={"AWS_SECRET_ACCESS_KEY": "c3VwZXItc2VjcmV0"},  # the client DOES fetch this
    )
    out = cluster.probe_secret_types(core, "vuln-demo", ["cloud-credentials"])
    assert out == {"cloud-credentials": "Opaque"}
    assert "c3VwZXItc2VjcmV0" not in str(out)
    assert "AWS_SECRET_ACCESS_KEY" not in str(out)


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


# --- Review finding MEDIUM-8: initContainers and projected volumes ---


def _container(name, privileged=False, secret_env=(), ):
    return SimpleNamespace(
        name=name,
        security_context=SimpleNamespace(privileged=privileged),
        env_from=[SimpleNamespace(secret_ref=SimpleNamespace(name=s)) for s in secret_env],
        env=None,
        volume_mounts=[],
    )


def _pod_with_init(init_privileged=False, init_secret=(), main_privileged=False):
    return SimpleNamespace(
        spec=SimpleNamespace(
            service_account_name="sa",
            containers=[_container("api", privileged=main_privileged)],
            init_containers=[_container("setup", privileged=init_privileged, secret_env=init_secret)],
            volumes=[],
        ),
        metadata=SimpleNamespace(labels={}, name="p"),
    )


def test_privileged_init_container_is_detected():
    """A privileged initContainer is a textbook escape vector. Walking only
    spec.containers reported privileged=False and the LLM was told the pod was clean."""
    facts = cluster.probe_workload_facts(_pod_with_init(init_privileged=True))
    assert facts.privileged is True


def test_secret_mounted_only_into_an_init_container_is_detected():
    names = cluster.probe_secrets(_pod_with_init(init_secret=("bootstrap-creds",)))
    assert names == ["bootstrap-creds"]


def test_secret_in_a_projected_volume_is_detected():
    pod = SimpleNamespace(
        spec=SimpleNamespace(
            service_account_name="sa",
            containers=[_container("api")],
            init_containers=None,
            volumes=[
                SimpleNamespace(
                    name="creds",
                    host_path=None,
                    secret=None,
                    projected=SimpleNamespace(
                        sources=[SimpleNamespace(secret=SimpleNamespace(name="projected-creds"))]
                    ),
                )
            ],
        ),
        metadata=SimpleNamespace(labels={}, name="p"),
    )
    assert cluster.probe_secrets(pod) == ["projected-creds"]


# --- Review finding MEDIUM-7: NetworkPolicy coverage must not over-claim ---


def _netpol(name, match_labels, policy_types):
    return SimpleNamespace(
        metadata=SimpleNamespace(name=name),
        spec=SimpleNamespace(
            pod_selector=SimpleNamespace(match_labels=match_labels, match_expressions=None),
            policy_types=policy_types,
        ),
    )


def test_egress_only_policy_does_not_count_as_ingress_coverage():
    """An egress-only policy leaves ingress wide open, but was reported as 'covered',
    which pushes severity DOWN — a false negative in the unsafe direction."""
    net = MagicMock()
    net.list_namespaced_network_policy.return_value = SimpleNamespace(
        items=[_netpol("egress-only", None, ["Egress"])]
    )
    assert cluster.probe_network_policy(net, "ns", {"app": "x"}) is False


def test_matchexpressions_only_selector_is_not_assumed_to_select_everything():
    """match_labels is None both for {} (default-deny, selects all) and for a
    matchExpressions selector (may select nothing). Only the first means 'covered'."""
    net = MagicMock()
    pol = _netpol("expr", None, ["Ingress"])
    pol.spec.pod_selector.match_expressions = [
        SimpleNamespace(key="app", operator="In", values=["something-else"])
    ]
    net.list_namespaced_network_policy.return_value = SimpleNamespace(items=[pol])
    assert cluster.probe_network_policy(net, "ns", {"app": "x"}) is False


def test_true_default_deny_still_counts_as_covered():
    """Regression guard: safe-demo must keep ranking LOW."""
    net = MagicMock()
    net.list_namespaced_network_policy.return_value = SimpleNamespace(
        items=[_netpol("default-deny", None, ["Ingress"])]
    )
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
