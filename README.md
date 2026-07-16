# KubeSentinel — an agent that ranks Kubernetes findings by real blast radius

A scanner tells you what is wrong. KubeSentinel tells you **what to fix first**, by
gathering the live cluster context the scanner never had.

**Stack:** FastAPI + LangGraph 1.x + Groq / Ollama + Trivy + kind
**Docs:** [`todo/kubesentinel.md`](todo/kubesentinel.md) — plan, design decisions, and everything Phase 0 disproved.

---

## The problem, in one screen

Trivy on our demo cluster returns **19 findings on a single Deployment**:

```
[HIGH  ] KSV-0017  Privileged
[HIGH  ] KSV-0014  Root file system is not read-only     <- same grade as privileged
[MEDIUM] KSV-0023  hostPath volumes mounted              <- this is the escape path
[LOW   ] KSV-0011  CPU not limited
... 15 more
```

Every one is true. None is ranked against the others. And the thing that actually
matters is **not in the list at all**: that pod's ServiceAccount is bound to
`cluster-admin`, it has live cloud credentials in its environment, and it answers on
a public NodePort. Trivy cannot see any of that, because it grades each resource in
isolation and those facts live in a ClusterRoleBinding, a Secret, and a Service.

So the report gets a glance and a shrug, and nothing gets fixed.

KubeSentinel gathers those facts and reasons over them:

```
CRITICAL  vuln-demo/payments-api
  Blast radius: An attacker who compromises this pod can obtain the cluster-admin
  ServiceAccount token, use the mounted cloud-credentials secret, and leverage the
  privileged container with hostPath '/' to escape to the host node. Because the pod
  is exposed via NodePort and no NetworkPolicy isolates it, an attacker can reach it
  from outside — gaining full control of the cluster and any linked cloud resources.

LOW       safe-demo/reports-api
  Blast radius: Limited to the pod. Not privileged, no RBAC, no secrets, ClusterIP
  only, covered by a default-deny NetworkPolicy.
```

Same scanner. Same cluster. An ordering you can act on.

---

## Architecture

```
                  ┌──────────── LangGraph ────────────┐
  Trivy  ────────>│ ingest                            │
  (misconfig)     │   ↓                               │
                  │ gather_context   ← k8s API (RO)   │   RBAC bindings, mounted
                  │   ↓                               │   secrets, exposure, netpol
                  │ assess           ← LLM            │   ← the judgement call
                  │   ↓ ⇄ deep_probe (max 2, enum)    │
                  │ report                            │
                  └───────────────────────────────────┘
                              ↓
                    FastAPI + SSE  →  dashboard
```

**Where the intelligence is, and where it deliberately is not.**
`ingest` and `gather_context` are plain deterministic code — "which Secrets does this
pod mount" has exactly one right answer, so an LLM deciding to look it up would add
latency and flakiness and buy nothing. The LLM is used only for `assess`, where the
question is genuinely a judgement call: *how bad is this, given all of that?*
That is the honest boundary of the agentic claim.

| File | What it does |
|---|---|
| `agents.py` | The graph: state, nodes, `build_graph()` |
| `scanner.py` | Trivy invocation + finding parsing |
| `cluster.py` | Read-only k8s context probes — the differentiator |
| `llm.py` | Provider abstraction. **Read the docstring** before swapping models |
| `app.py` | FastAPI, SSE stream of node transitions |
| `demo/` | `vuln-demo` (deliberately broken) + `safe-demo` (hardened contrast) |
| `k8s/` | kind cluster, read-only RBAC, deploy scripts |

---

## Quick start

```bash
cp .env.example .env          # add your GROQ_API_KEY (https://console.groq.com)
bash k8s/setup-cluster.sh     # preflight + kind cluster + seed demo namespaces
bash k8s/build-and-load.sh    # build image, kind load (no registry)
bash k8s/deploy.sh            # secret from .env, read-only RBAC, deploy
```

Then open **http://localhost:8080** and scan `vuln-demo,safe-demo`.

In a **GitHub Codespace** the same four commands work — port 8080 is forwarded
automatically and kept **private** (the dashboard has no auth and reports exactly
where your cluster is weakest; do not make it public).

Run the tests: `pytest` (38 tests, no cluster or API key needed — everything is mocked).

### Running it locally instead (for iterating on the UI)

The deployed pod carries its own Trivy. Running on the host does not, so install it once:

```bash
curl -sSL https://github.com/aquasecurity/trivy/releases/download/v0.72.0/trivy_0.72.0_Linux-64bit.tar.gz \
  | sudo tar xz -C /usr/local/bin trivy
```

Then, against the same kind cluster (it reads your kubeconfig):

```bash
set -a; source .env; set +a
kubectl config use-context kind-kubesentinel
uvicorn app:app --reload --port 8001
```

`--reload` picks up edits to `templates/`, `static/` and the Python modules, so the
UI loop is: edit → save → refresh. **Use a port other than 8000 if you also run the
other workshop apps locally** — several of them default to 8000.

---

## Security posture

Point KubeSentinel at its own namespace. It rates itself **MEDIUM**, and it is right:

> Exposed publicly via a NodePort and lacks any NetworkPolicy, making it reachable
> from outside. While the ServiceAccount only has a read-only ClusterRole and the
> container is not privileged, the root filesystem is writable…

That is not a bug in the ranking — it is an accurate reading of a real weakness in
this MVP: **the dashboard has no authentication and is deliberately NodePort-exposed
so you can reach it.** Acceptable for a local kind cluster, not acceptable anywhere
else, which is exactly why the Codespace port is forced private.

Keep this in the demo. A security tool that quietly rates itself LOW is telling you
its ranking is decorative. This one had to be argued down from its own findings, and
it declined.

| Property | How it is enforced |
|---|---|
| Cannot change your cluster | `k8s/rbac.yaml` grants **get/list only**. No create/update/patch/delete/exec anywhere. Enforced by the API server, not by a prompt. |
| Secret values never reach the LLM | `cluster.probe_secrets()` takes a pod spec and has **no API client** — it structurally cannot read Secret data. Guarded by a test. |
| The LLM cannot run anything | Deep probes are a closed enum (`ALLOWED_PROBES`); the enum maps to hardcoded functions. No kubectl string is ever LLM-authored. |
| Prompt injection is inert | Pod names are attacker-controllable. Output is schema-constrained, the probe whitelist rejects anything off-enum, and templates escape everything. Guarded by a test. |
| The loop always terminates | `MAX_PROBE_ROUNDS = 2`. Guarded by a test. |

Verify the first one yourself:

```bash
kubectl auth can-i delete pods --as=system:serviceaccount:kubesentinel:kubesentinel -A   # no
kubectl auth can-i list secrets --as=system:serviceaccount:kubesentinel:kubesentinel -A  # yes
```

---

## LLM providers

```bash
LLM_PROVIDER=groq          # default. Fast, hosted. Works in a Codespace.
LLM_PROVIDER=ollama-cloud  # hosted Ollama. Works in a Codespace (no GPU).
LLM_PROVIDER=ollama-local  # your laptop. Nothing leaves the machine.
```

**Read `llm.py`'s docstring before changing a model.** The short version, measured
against the real schema on 2026-07-17:

| Provider / model | Structured output |
|---|---|
| `groq` / `openai/gpt-oss-120b` | works — the default |
| `ollama-cloud` / `gemma4:31b` | works — the default, free tier |
| `ollama-cloud` / `gpt-oss:120b` | **fails** — same weights as Groq's, but answers in prose |
| `ollama-cloud` / `nemotron-3-nano:30b` | **fails** — passes a toy schema, returns None on the real one |

That second row is the interesting one for a workshop: **"same model" is not "same
capability."** Structured output is a property of the serving stack, not the weights,
and an agent that depends on it is only as portable as its weakest host.

⚠️ Groq retires models fast — `llama-3.3-70b-versatile` and `llama-3.1-8b-instant`
are **shut down on 2026-08-16**. Model IDs are pinned in `llm.py` alone.

---

## Troubleshooting

**`kind create` fails with "Reached target Multi-User System":**
Your kind is too old for your Docker. Needs ≥ 0.32.
```bash
curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.32.0/kind-linux-amd64 && sudo install -m 0755 ./kind /usr/local/bin/kind
```

**`kubeadm` fails with "context deadline exceeded", API server never starts:**
inotify exhaustion — the default of 128 instances is not enough, especially if you
already run another kind cluster. `setup-cluster.sh` does this for you:
```bash
sudo sysctl -w fs.inotify.max_user_instances=512 fs.inotify.max_user_watches=524288
```

**`kind load` fails with "failed to detect containerd snapshotter":**
Same cause — a kind CLI older than the cluster it is talking to. Upgrade kind.

**Scan fails with `OUTPUT_PARSING_FAILURE` / a Pydantic enum error:**
Your model cannot do structured output. See the provider table above.

**Pod is `ImagePullBackOff`:**
The image comes from `kind load`, not a registry (`imagePullPolicy: Never`).
```bash
bash k8s/build-and-load.sh && kubectl rollout restart deployment/kubesentinel -n kubesentinel
```

**Scan returns no findings:** check the demo namespaces exist — `bash k8s/seed-demo.sh`

---

## Teardown

```bash
bash k8s/teardown.sh   # deletes ONLY the 'kubesentinel' kind cluster
```
