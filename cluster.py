"""Read-only Kubernetes context probes.

This module is the differentiator. Trivy grades a Deployment on what the Deployment
says about itself. These probes answer the questions Trivy never asks, because the
answers live in *other objects*:

    Does this pod's ServiceAccount carry cluster-admin?   -> ClusterRoleBinding
    Does it hold real credentials?                        -> Secret refs
    Can anyone outside reach it?                          -> Service
    Is anything restricting its traffic?                  -> NetworkPolicy

Every call here is get/list. The ClusterRole in k8s/rbac.yaml grants nothing else,
so "read-only" is enforced by the cluster rather than by this comment.

SECRET VALUES ARE NEVER READ. probe_secrets sees only the pod spec, which carries
Secret *references*. Secret material must never reach an LLM prompt.
"""

import logging
from dataclasses import dataclass, field

from kubernetes import client, config

log = logging.getLogger("kubesentinel.cluster")


@dataclass
class RbacFacts:
    bindings: list[str] = field(default_factory=list)
    is_cluster_admin: bool = False


@dataclass
class ExposureFacts:
    summary: str = "none"
    reachable_externally: bool = False


@dataclass
class WorkloadFacts:
    privileged: bool = False
    host_paths: list[str] = field(default_factory=list)


# Roles that mean "game over" if the pod holding them is compromised.
ADMIN_ROLES = {"cluster-admin", "admin", "edit"}


def load_clients():
    """In-cluster config when deployed, kubeconfig when running on a laptop."""
    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()
    return client.CoreV1Api(), client.RbacAuthorizationV1Api(), client.NetworkingV1Api(), client.AppsV1Api()


# --- Probes ---


def probe_rbac(rbac_api, namespace: str, service_account: str) -> RbacFacts:
    """What can this ServiceAccount do cluster-wide?

    This is the fact that most often turns a MEDIUM into a CRITICAL, and it is
    invisible to a per-resource scanner: the binding is a separate object that does
    not mention the Deployment at all.
    """
    facts = RbacFacts()

    def _matches(subject) -> bool:
        return (
            getattr(subject, "kind", None) == "ServiceAccount"
            and getattr(subject, "name", None) == service_account
            and getattr(subject, "namespace", None) == namespace
        )

    for binding in rbac_api.list_cluster_role_binding().items:
        if any(_matches(s) for s in (binding.subjects or [])):
            ref = f"{binding.role_ref.kind}/{binding.role_ref.name}"
            facts.bindings.append(ref)
            if binding.role_ref.name in ADMIN_ROLES:
                facts.is_cluster_admin = True

    for binding in rbac_api.list_namespaced_role_binding(namespace).items:
        if any(_matches(s) for s in (binding.subjects or [])):
            facts.bindings.append(f"{binding.role_ref.kind}/{binding.role_ref.name} (ns:{namespace})")

    return facts


def probe_secrets(pod) -> list[str]:
    """Names of Secrets this pod can read. NAMES ONLY — never values.

    Takes the pod spec, not an API client, precisely so it *cannot* read Secret data.
    The blast-radius argument needs "a Secret is mounted", never its contents.
    """
    names: list[str] = []
    for container in pod.spec.containers or []:
        for src in getattr(container, "env_from", None) or []:
            ref = getattr(src, "secret_ref", None)
            if ref is not None:
                names.append(ref.name)
        for env in getattr(container, "env", None) or []:
            ref = getattr(getattr(env, "value_from", None), "secret_key_ref", None)
            if ref is not None:
                names.append(ref.name)
    for volume in pod.spec.volumes or []:
        secret = getattr(volume, "secret", None)
        if secret is not None:
            names.append(secret.secret_name)
    return sorted(set(names))


def probe_exposure(core_api, namespace: str, selector: dict) -> ExposureFacts:
    """Can anything outside the cluster reach this workload?"""
    facts = ExposureFacts()
    parts: list[str] = []
    for svc in core_api.list_namespaced_service(namespace).items:
        svc_selector = svc.spec.selector or {}
        if not svc_selector or not _selector_matches(svc_selector, selector):
            continue
        if svc.spec.type in ("NodePort", "LoadBalancer"):
            ports = [str(p.node_port) for p in (svc.spec.ports or []) if getattr(p, "node_port", None)]
            parts.append(f"{svc.spec.type}:{','.join(ports) or svc.metadata.name}")
            facts.reachable_externally = True
        else:
            parts.append(f"{svc.spec.type}:{svc.metadata.name}")
    facts.summary = "; ".join(parts) if parts else "none"
    return facts


def probe_network_policy(net_api, namespace: str, labels: dict) -> bool:
    """Is this pod covered by any NetworkPolicy?

    An empty podSelector ({}) selects every pod in the namespace — that is how a
    default-deny is written, and it is why safe-demo ranks low.
    """
    for policy in net_api.list_namespaced_network_policy(namespace).items:
        match_labels = getattr(policy.spec.pod_selector, "match_labels", None)
        if not match_labels:
            return True  # empty selector = all pods
        if _selector_matches(match_labels, labels):
            return True
    return False


def probe_workload_facts(pod) -> WorkloadFacts:
    """Privileged containers and host filesystem mounts — the escape surface."""
    facts = WorkloadFacts()
    for container in pod.spec.containers or []:
        sc = getattr(container, "security_context", None)
        if sc is not None and getattr(sc, "privileged", False):
            facts.privileged = True
    for volume in pod.spec.volumes or []:
        host_path = getattr(volume, "host_path", None)
        if host_path is not None:
            facts.host_paths.append(host_path.path)
    return facts


# --- Deep probes (the whitelist targets; see agents.ALLOWED_PROBES) ---


def probe_role_verbs(rbac_api, namespace: str, bindings: list[str]) -> dict:
    """What verbs do this SA's non-admin Roles actually grant?"""
    verbs: dict[str, list[str]] = {}
    for ref in bindings:
        if "/" not in ref:
            continue
        kind, name = ref.split("/", 1)
        name = name.split(" ")[0]
        try:
            role = (
                rbac_api.read_cluster_role(name)
                if kind == "ClusterRole"
                else rbac_api.read_namespaced_role(name, namespace)
            )
            verbs[ref] = sorted({v for rule in (role.rules or []) for v in (rule.verbs or [])})
        except Exception as e:
            log.warning("could not read %s: %s", ref, e)
    return verbs


def probe_namespace_peers(apps_api, namespace: str) -> list[str]:
    """What else lives in this namespace (i.e. what shares the blast radius)?"""
    return [d.metadata.name for d in apps_api.list_namespaced_deployment(namespace).items]


def probe_secret_types(core_api, namespace: str, secret_names: list[str]) -> dict:
    """Secret *types*, never data. A kubernetes.io/service-account-token differs from an opaque blob."""
    types: dict[str, str] = {}
    for name in secret_names:
        try:
            types[name] = core_api.read_namespaced_secret(name, namespace).type
        except Exception as e:
            log.warning("could not read type of secret %s: %s", name, e)
    return types


# --- Helpers ---


def _selector_matches(selector: dict, labels: dict) -> bool:
    return all(labels.get(k) == v for k, v in selector.items())


def get_workload_context(clients, namespace: str, name: str) -> dict:
    """Gather every context fact for one workload. Returns plain dicts for the graph state."""
    core, rbac, net, apps = clients
    deployment = apps.read_namespaced_deployment(name, namespace)
    pod_template = deployment.spec.template
    labels = pod_template.metadata.labels or {}
    service_account = pod_template.spec.service_account_name or "default"

    rbac_facts = probe_rbac(rbac, namespace, service_account)
    exposure = probe_exposure(core, namespace, labels)
    workload = probe_workload_facts(pod_template)

    return {
        "service_account": service_account,
        "rbac_bindings": rbac_facts.bindings,
        "is_cluster_admin": rbac_facts.is_cluster_admin,
        "mounted_secrets": probe_secrets(pod_template),
        "exposure_summary": exposure.summary,
        "reachable_externally": exposure.reachable_externally,
        "network_policy_covered": probe_network_policy(net, namespace, labels),
        "privileged": workload.privileged,
        "host_paths": workload.host_paths,
    }
