"""Read-only Kubernetes context probes.

This module is the differentiator. Trivy grades a Deployment on what the Deployment
says about itself. These probes answer the questions Trivy never asks, because the
answers live in *other objects*:

    Does this pod's ServiceAccount carry cluster-admin?   -> ClusterRoleBinding
    Does it hold real credentials?                        -> Secret refs
    Can anyone outside reach it?                          -> Service
    Is anything restricting its traffic?                  -> NetworkPolicy

Every call here is get/list. The ClusterRole in k8s/rbac.yaml grants nothing else,
so "cannot change the cluster" is enforced by the API server rather than by this
comment.

SECRETS — the honest version
----------------------------
`probe_secrets` takes a pod spec and no API client, so it cannot read Secret data
even if someone tried. That part is structural.

`probe_secret_types` is NOT. It holds a CoreV1Api and calls read_namespaced_secret,
which returns the whole Secret object — `.data` included — over the wire and into
this process's memory. We extract `.type` and drop the rest, so no secret value ever
reaches a prompt, but the guarantee there is *discipline, not architecture*. An
earlier version of this docstring claimed secret values were "never read", which was
false. If you add a field to that function, you are one attribute access away from
putting credentials in an LLM prompt.

Mitigation: rbac.yaml grants `get` on secrets, not `list`, so this app cannot
enumerate every Secret (and therefore every ServiceAccount token) in the cluster.
It can only fetch ones a scanned pod already references.
"""

import logging
from dataclasses import dataclass, field

from kubernetes import client, config

log = logging.getLogger("kubesentinel.cluster")


@dataclass
class RbacFacts:
    bindings: list[str] = field(default_factory=list)
    # Cluster-scoped and grants everything: compromise here is total.
    is_cluster_admin: bool = False
    # Broad write power short of full cluster-admin (admin/edit, wildcard verbs).
    is_privileged_rbac: bool = False
    # Roles we could not read. NOT the same as "safe" - say so rather than imply clean.
    unresolved: list[str] = field(default_factory=list)


@dataclass
class ExposureFacts:
    summary: str = "none"
    reachable_externally: bool = False


@dataclass
class WorkloadFacts:
    privileged: bool = False
    host_paths: list[str] = field(default_factory=list)


# Built-in roles that mean "game over" if the pod holding them is compromised.
# NOTE: this is a shortcut for the well-known names, NOT the test. The real test is
# _role_grants_everything(), which reads the role's rules — because a custom
# ClusterRole granting */*/* under a boring name like "platform-operator" is
# cluster-admin in all but label, and real clusters are full of those.
ADMIN_ROLES = {"cluster-admin", "admin", "edit"}


def load_clients():
    """In-cluster config when deployed, kubeconfig when running on a laptop."""
    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()
    return client.CoreV1Api(), client.RbacAuthorizationV1Api(), client.NetworkingV1Api(), client.AppsV1Api()


# --- Probes ---


def _role_grants_everything(role) -> bool:
    """Does this role's rule set amount to '*' on '*' in '*'?"""
    for rule in getattr(role, "rules", None) or []:
        verbs = set(getattr(rule, "verbs", None) or [])
        resources = set(getattr(rule, "resources", None) or [])
        groups = set(getattr(rule, "api_groups", None) or [])
        if "*" in verbs and "*" in resources and ("*" in groups or "" in groups):
            return True
    return False


def _read_role(rbac_api, kind: str, name: str, namespace: str):
    if kind == "ClusterRole":
        return rbac_api.read_cluster_role(name)
    return rbac_api.read_namespaced_role(name, namespace)


def probe_rbac(rbac_api, namespace: str, service_account: str) -> RbacFacts:
    """What can this ServiceAccount actually do?

    This is the fact that most often turns a MEDIUM into a CRITICAL, and it is
    invisible to a per-resource scanner: the binding is a separate object that does
    not mention the Deployment at all.

    We resolve each binding to its ROLE'S RULES rather than trusting the role's name.
    An earlier version only string-matched {cluster-admin, admin, edit}, which reported
    "Holds cluster-admin: False" for any custom ClusterRole granting */*/* — a false
    negative on this app's headline fact, on exactly the roles real clusters accumulate.
    """
    facts = RbacFacts()

    def _matches(subject) -> bool:
        return (
            getattr(subject, "kind", None) == "ServiceAccount"
            and getattr(subject, "name", None) == service_account
            and getattr(subject, "namespace", None) == namespace
        )

    def _classify(role_ref, ref_label: str, cluster_scoped: bool) -> None:
        by_name = role_ref.name in ADMIN_ROLES
        if by_name:
            facts.is_privileged_rbac = True
            if cluster_scoped and role_ref.name == "cluster-admin":
                facts.is_cluster_admin = True

        try:
            role = _read_role(rbac_api, role_ref.kind, role_ref.name, namespace)
        except Exception as e:
            # Could not read it -> we do not know. Never silently treat that as safe.
            log.warning("could not resolve %s: %s", ref_label, e)
            facts.unresolved.append(ref_label)
            return

        if _role_grants_everything(role):
            facts.is_privileged_rbac = True
            if cluster_scoped:
                facts.is_cluster_admin = True

    for binding in rbac_api.list_cluster_role_binding().items:
        if any(_matches(s) for s in (binding.subjects or [])):
            ref = f"{binding.role_ref.kind}/{binding.role_ref.name}"
            facts.bindings.append(ref)
            _classify(binding.role_ref, ref, cluster_scoped=True)

    for binding in rbac_api.list_namespaced_role_binding(namespace).items:
        if any(_matches(s) for s in (binding.subjects or [])):
            ref = f"{binding.role_ref.kind}/{binding.role_ref.name}"
            facts.bindings.append(f"{ref} (ns:{namespace})")
            # A RoleBinding grants power only inside this namespace, however broad the
            # ClusterRole it points at. That is why this is not cluster_scoped.
            _classify(binding.role_ref, ref, cluster_scoped=False)

    return facts


def _all_containers(pod) -> list:
    """Every container that runs in this pod — init and main.

    initContainers are not a footnote: they run FIRST, often as root to do setup, and
    a privileged one is a textbook escape vector. An earlier version walked only
    `spec.containers`, so a privileged initContainer was reported as privileged=False
    and the LLM was told the pod was clean. A false negative in the unsafe direction.
    """
    return list(
        (getattr(pod.spec, "init_containers", None) or [])
        + (getattr(pod.spec, "containers", None) or [])
        + (getattr(pod.spec, "ephemeral_containers", None) or [])
    )


def probe_secrets(pod) -> list[str]:
    """Names of Secrets this pod can read. NAMES ONLY — never values.

    Takes the pod spec, not an API client, precisely so it *cannot* read Secret data.
    The blast-radius argument needs "a Secret is mounted", never its contents.
    """
    names: list[str] = []
    for container in _all_containers(pod):
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
        # Projected volumes nest their sources - a common way to mount credentials,
        # and invisible if you only look at volume.secret.
        projected = getattr(volume, "projected", None)
        for source in (getattr(projected, "sources", None) or []) if projected else []:
            ref = getattr(source, "secret", None)
            if ref is not None:
                names.append(getattr(ref, "name", None) or getattr(ref, "secret_name", None))

    return sorted({n for n in names if n})


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
    """Is this pod's INGRESS restricted by a NetworkPolicy?

    Deliberately narrow, and the narrowness is the point. This answer feeds
    "Covered by a NetworkPolicy" straight into the prompt, where True pushes severity
    DOWN — so every over-claim here is a false negative on a security finding.

    Two ways an earlier version over-claimed:
      * An egress-only policy leaves ingress wide open. It was reported as covered.
      * `match_labels` is None BOTH for an empty selector `{}` (default-deny: selects
        every pod, correctly covered) AND for a matchExpressions selector (which may
        select nothing at all). Both were treated as "selects everything".

    We do not evaluate matchExpressions - we just refuse to assume it matches.
    Unknown is not covered.
    """
    for policy in net_api.list_namespaced_network_policy(namespace).items:
        policy_types = getattr(policy.spec, "policy_types", None) or ["Ingress"]
        if "Ingress" not in policy_types:
            continue  # egress-only: says nothing about who can reach this pod

        selector = policy.spec.pod_selector
        match_labels = getattr(selector, "match_labels", None)
        match_expressions = getattr(selector, "match_expressions", None)

        if not match_labels and not match_expressions:
            return True  # a genuinely empty selector: every pod in the namespace
        if match_labels and _selector_matches(match_labels, labels):
            return True
        # matchExpressions present: we cannot cheaply prove it selects this pod, so we
        # do not claim it does.
    return False


def probe_workload_facts(pod) -> WorkloadFacts:
    """Privileged containers and host filesystem mounts.

    NOT the whole escape surface — hostPID, hostNetwork and capabilities.add
    (SYS_ADMIN, SYS_PTRACE) are all still unexamined. Trivy flags those per-resource,
    so they reach the LLM via the findings; they just do not participate in the
    blast-radius composition here. Do not read a clean result from this as "no escape
    surface" — it means "not these two".
    """
    facts = WorkloadFacts()
    for container in _all_containers(pod):
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
    """Secret types. A kubernetes.io/service-account-token differs from an opaque blob.

    CAUTION: read_namespaced_secret returns the FULL Secret, `.data` included. We take
    `.type` and discard the rest, but the secret body does cross the wire and sit in
    memory. Do not widen what this returns. See the module docstring.
    """
    types: dict[str, str] = {}
    for name in secret_names:
        try:
            secret = core_api.read_namespaced_secret(name, namespace)
            types[name] = secret.type  # .type ONLY - never .data
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
        "has_privileged_rbac": rbac_facts.is_privileged_rbac,
        "unresolved_roles": rbac_facts.unresolved,
        "mounted_secrets": probe_secrets(pod_template),
        "exposure_summary": exposure.summary,
        "reachable_externally": exposure.reachable_externally,
        "network_policy_covered": probe_network_policy(net, namespace, labels),
        "privileged": workload.privileged,
        "host_paths": workload.host_paths,
    }
