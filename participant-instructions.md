# KubeSentinel — Participant Lab Guide

You will build and deploy an agent that ranks Kubernetes security findings by real
blast radius, then break it in a way that teaches you why the ranking works.

## Prerequisites

- A GitHub Codespace on this repo (4 cores minimum), or a laptop with Docker + kind ≥ 0.32
- A Groq API key — free at https://console.groq.com
- ~20 minutes

---

## Part 1 — Deploy it (10 min)

```bash
cp .env.example .env
# edit .env, set GROQ_API_KEY

bash k8s/setup-cluster.sh     # preflight + kind cluster + demo namespaces
bash k8s/build-and-load.sh    # build image, load into kind
bash k8s/deploy.sh            # read-only RBAC, secret, deploy
```

Open http://localhost:8080 (Codespace: the **PORTS** tab, port 8080).
Scan `vuln-demo,safe-demo`.

Watch the step stream. Those are live LangGraph node transitions over SSE — you are
watching the graph think, not a progress bar.

**Expected:** `vuln-demo/payments-api` CRITICAL, `safe-demo/reports-api` LOW.

---

## Part 2 — See what the scanner alone gives you (5 min)

Run the raw scanner, with no agent:

```bash
trivy k8s --scanners misconfig --include-namespaces vuln-demo --report all
```

Count the findings. You get **19 on one Deployment**, four of them HIGH, in no
particular order. Now look for these three facts in that output:

1. `payments-sa` is bound to **cluster-admin**
2. the pod has live **cloud credentials** in its environment
3. it is reachable on a **NodePort** with **no NetworkPolicy**

None of them are there. They cannot be: Trivy grades each resource in isolation, and
those facts live in a ClusterRoleBinding, a Secret, and a Service. That gap is the
entire reason this app exists.

Now re-read KubeSentinel's CRITICAL rationale. Every one of those facts is cited.

---

## Part 3 — Prove the ranking is reasoning, not echoing (5 min)

The obvious objection: *maybe the LLM just says CRITICAL for whatever the scanner
scores highest.* Test it.

`safe-demo/reports-api` also has findings — it is not clean. It still ranks LOW,
because its context is benign. That is discrimination, not counting.

Now make it earn it. Give the safe workload one bad fact:

```bash
kubectl create clusterrolebinding reports-pwn \
  --clusterrole=cluster-admin \
  --serviceaccount=safe-demo:reports-sa
```

Re-scan. **The scanner output does not change at all** — you did not touch the
Deployment. But the ranking should move, because the blast radius did.

Clean up:
```bash
kubectl delete clusterrolebinding reports-pwn
```

---

## Part 4 — Swap the model host (5 min)

```bash
# in .env
LLM_PROVIDER=ollama-cloud
OLLAMA_API_KEY=...        # https://ollama.com
```

```bash
bash k8s/deploy.sh    # re-reads .env, recreates the secret
```

Same graph, same findings, different host. The ranking should hold.

**Now try to break it.** Set `OLLAMA_CLOUD_MODEL=gpt-oss:120b` and re-scan. It fails
with a parsing error — even though `gpt-oss-120b` is the model Groq runs perfectly.
Same weights, different serving stack, and structured output is a property of the
stack. An agent that depends on structured output is only as portable as its weakest
host. This is worth knowing before you promise a client "we can swap providers."

---

## Part 5 — Point it at itself (3 min)

Scan the `kubesentinel` namespace.

It rates itself **MEDIUM** — and it is right. It is NodePort-exposed with no
NetworkPolicy and no authentication, because that is how you are reaching the
dashboard right now. Its ServiceAccount genuinely cannot write anything:

```bash
kubectl auth can-i delete pods --as=system:serviceaccount:kubesentinel:kubesentinel -A
# no
```

...but read-only RBAC does not make an unauthenticated, internet-reachable dashboard
that reports your weakest points a good idea.

This is the most useful moment in the lab. The easy thing to build is a tool that
rates itself LOW and looks confident. If yours does that, ask whether the ranking is
reasoning or decoration. Then ask what it would take to get this one to LOW honestly
— auth, a NetworkPolicy, a read-only root filesystem — and notice that it is real
work, not a prompt change.

---

## Exercises

1. **Add a context probe.** Pod Security Admission labels on the namespace are a real
   blast-radius fact and we do not gather them. Add a probe in `cluster.py`, thread it
   into `_format_context`, and see whether the ranking changes.
2. **Break the injection guard.** Name a deployment something adversarial and try to
   get the agent to run a probe outside `ALLOWED_PROBES`. Then read
   `filter_probe_requests` and explain why it cannot work.
3. **Move the boundary.** `gather_context` is deterministic on purpose. Rewrite it as
   a ReAct tool-loop where the LLM chooses probes. Measure latency and consistency
   across five runs. Decide whether you would ship it.
4. **Make it write.** MVP is read-only by design. What would you need — approval gate,
   rollback, audit — before you would let it patch a live cluster? Sketch it before
   you code it.

---

## Troubleshooting

**Cluster will not create:**
```bash
kind --version    # needs >= 0.32; older breaks on Docker 27+
sudo sysctl -w fs.inotify.max_user_instances=512
```

**Pod stuck in ImagePullBackOff:**
```bash
bash k8s/build-and-load.sh && kubectl rollout restart deployment/kubesentinel -n kubesentinel
```
The image comes from `kind load`, not a registry.

**Scan fails with a Pydantic/enum/parsing error:** your model cannot do structured
output. See the provider table in [README.md](README.md).

**Logs:**
```bash
kubectl logs -n kubesentinel -l app=kubesentinel --tail=50
```
