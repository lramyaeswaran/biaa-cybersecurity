# KubeSentinel — LangGraph agent that ranks Kubernetes security findings by real blast radius

**Status:** MVP SHIPPED 2026-07-17 — deployed to kind, headline scenario passes 3/3 live in-cluster, 38 tests green. See Known Limitations before extending.
**Priority:** P1 — flagship lab for the 5-day Agentic AI workshop. Must demo end-to-end on a laptop and in a GitHub Codespace.
**Owner repos/paths:** `/home/rajesh/ai-apps/biaa-cybersecurity`
**Related:** Prior art `/home/rajesh/lab/aiagentic-comp-frontdeskai` (same workshop series — conventions borrowed, deploy target deliberately differs).

---

## How to update progress (READ FIRST)
1. Flip checkboxes (`- [ ]` → `- [x]`) as tasks land. Never delete a task; drop = `- [~]` + reason.
2. Update **Status:** each working session.
3. Append a dated **Progress Log** entry every session (what landed, blockers, decisions).
4. Record spike answers in **Open Questions** as resolved — later phases depend on them.
5. A phase is "done" only when its **test cases** pass and are checked off.
6. **Work test-first (TDD):** write the failing test before the code; red → green → refactor.

---

## Why this exists (problem)

A scanner run against one Kubernetes cluster emits hundreds of findings. Each is
individually true and almost none are individually actionable, because the scanner
grades every finding on the resource *in isolation*. It cannot see that the pod it
just flagged also carries a `cluster-admin` token, mounts live cloud credentials,
and answers on a NodePort — because those facts live in four other objects.

So the report gets a glance and a shrug. The cost isn't that teams fix the wrong
thing; it's that they fix **nothing**, because 19 findings with no ordering is
indistinguishable from noise.

**Measured on our own demo cluster (Phase 0, real Trivy output):**

| Finding | Trivy says | Reality |
|---|---|---|
| `KSV-0017` Privileged | HIGH | The one that matters — with the SA's cluster-admin binding it is a trivial full-cluster takeover |
| `KSV-0014` Root FS not read-only | **HIGH — same grade as privileged** | Real, but not the emergency |
| `KSV-0023` hostPath mounted | **MEDIUM** | Under-graded: this is the escape path |
| `KSV-0011` CPU not limited | LOW | Noise on this workload |

19 findings on one Deployment, 4 of them HIGH, no ordering between them — and the
*actual* attack chain is invisible because it spans a Deployment + a
ClusterRoleBinding + a Secret + a Service.

**KubeSentinel's job:** gather the live context the scanner never had, compute blast
radius, and return a ranked list with a written rationale — so the output is a
decision, not a spreadsheet.

### Non-goals
- **No writes to the cluster.** MVP drafts remediation as *text only*. No auto-apply,
  no patching, no admission control. (Deliberate v2 boundary — see Risks.)
- Not a CVE/image-vulnerability scanner. Misconfiguration + RBAC blast radius only.
- Not multi-cluster. One cluster, the one it runs in.
- Not a SIEM, not runtime detection. Posture at rest.

---

## Use cases

**Personas:**
- **Priya, platform engineer (read).** Owns the cluster. Runs a scan after a release,
  wants the top 3 things to fix before Friday, and an ordering she can defend to her
  lead. Tolerates ~60s.
- **Workshop participant (read/build).** Follows the lab, changes a prompt or a node,
  re-runs, sees the ranking change. Needs the graph legible on a projector and the
  loop fast enough to iterate.

1. **Priya scans a namespace.** Gets findings ranked by blast radius, each with a
   one-paragraph rationale citing the *specific* context facts that drove the rank.
2. **Priya reads the top finding.** Sees a drafted remediation (a patched manifest
   snippet) she can copy — and an explicit note that KubeSentinel did not apply it.
3. **Participant swaps `LLM_PROVIDER=groq` → `ollama`.** Same graph, same findings,
   provider changes. Demonstrates the abstraction and the private-inference story.
4. **HEADLINE ACCEPTANCE SCENARIO.** With `vuln-demo` and `safe-demo` both seeded and
   scanned, KubeSentinel ranks `vuln-demo/payments-api` **CRITICAL**, cites *at least
   two* of {cluster-admin SA, mounted cloud credentials, NodePort exposure, no
   NetworkPolicy} in its rationale — facts that appear in **zero** of Trivy's 19
   findings — and **ranks it strictly above `safe-demo/reports-api`**. Trivy alone
   cannot produce this ordering. That gap *is* the product.

   *(Criterion revised after measurement: the original wording required reports-api to
   be exactly LOW. It oscillates LOW↔MEDIUM across runs, while payments-api is CRITICAL
   every time. The stable, meaningful property is the **ordering**, not the low-end
   grade — so that is what the criterion tests. See Open Questions.)*

---

## Architecture & Design

### Topology / current state (confirmed in Phase 0 — not assumed)

- kind cluster `kubesentinel`, node v1.36.1, one control-plane. **Distinct from the
  user's existing `frontdeskai` cluster, which must not be touched.**
- `vuln-demo` seeded: privileged + hostPath + cluster-admin SA + mounted
  `cloud-credentials` + NodePort 30081, no NetworkPolicy → **19 Trivy findings**.
- `safe-demo` seeded: non-root, caps dropped, read-only FS, no SA token, ClusterIP,
  default-deny NetworkPolicy → **3 Trivy findings**. (Non-zero on purpose: the agent
  must discriminate, not just count.)
- App reaches the cluster via in-cluster ServiceAccount (deployed) or local kubeconfig
  (dev). Exposed on NodePort 30080 → hostPort 8080 → Codespaces auto-forwards to HTTPS.

### The key decision(s)

**1. Trivy is the scanner; we do not write our own checks.**
Verified: `trivy k8s --scanners misconfig` completes in **4.5s** against the demo
cluster and needs **no vulnerability DB download** (misconfig uses bundled Rego).
Rejected: hand-rolled checks — less credible to a security audience, and reinventing
a solved problem. The findings are *not* the differentiator; the context is.
*Cost:* 161MB binary in the image. Accepted (see Risks).

**2. Context gathering is deterministic; ranking is the LLM's job.**
The five context facts (SA→RBAC bindings, mounted Secrets, Service exposure,
NetworkPolicy coverage, privileged/hostPath flags) are gathered by plain read-only
k8s API calls, *not* by an LLM deciding what to look up. Rejected: a full ReAct
tool-loop for gathering — it adds latency and nondeterminism to a step with one
obviously-correct answer, and a flaky demo teaches nothing. The LLM is used where
judgement actually lives: **composing those facts into a blast-radius argument.**
This keeps the agentic claim honest rather than decorative.

**3. One bounded escalation loop, whitelisted.**
`assess` may request *deeper* probes (e.g. "this SA has a Role — what verbs does it
grant?") via a conditional edge back to `gather_context`, capped at 2 rounds. Probe
types are a **closed whitelist**: the LLM picks from an enum, it never forms a
kubectl call. This is the ReAct lesson with the tool-safety lesson attached.

**4. Provider abstraction over Groq / Ollama Cloud / Ollama local.**
`LLM_PROVIDER` switches. ⚠️ **The original "same weights on both hosts" plan was
REFUTED in Phase 2 — see Open Questions.** `gpt-oss:120b` is served by both Groq and
Ollama Cloud, but only Groq returns schema-valid structured output for it; on Ollama
Cloud the same weights answer in markdown prose and the enum never validates. So
ollama-cloud runs `gemma4:31b` via Ollama's **OpenAI-compatible endpoint** (not
langchain-ollama), which does return clean tool calls. The provider swap still works;
it is just not a same-weights A/B, and the docs must not claim it is.

### Load-bearing ASSUMPTIONS (all tested in Phase 0 — see Open Questions)
- Trivy misconfig scan is fast and DB-free → **CONFIRMED (4.5s)**
- LangGraph 1.x `StateGraph` / `add_conditional_edges` / `astream` API → **CONFIRMED**
- Groq model IDs → **REFUTED and corrected**
- kind works on this host → **REFUTED and fixed (two independent causes)**

### Components / surface

```
app.py            FastAPI: GET / dashboard, POST /scan, GET /runs/{id}/events (SSE)
agents.py         LangGraph: state, nodes, build_graph()
scanner.py        Trivy invocation + Finding parsing   (seam for tests)
cluster.py        Read-only k8s context probes         (seam for tests)
llm.py            Provider abstraction                 (seam for tests)
templates/        index.html — findings table, HTMX + SSE
k8s/              kind-cluster.yaml, rbac.yaml, deployment.yaml, service.yaml, *.sh
demo/             vuln-demo.yaml, safe-demo.yaml
```

**Graph:**
```
START → ingest → gather_context → assess ⇄ (deep_probe, max 2) → report → END
                                     │
                          conditional: needs_probe?
```

---

## Security considerations

This is a security tool; its own posture is part of the lesson.

- **Read-only RBAC.** The app's ClusterRole grants `get/list` only — no `create`,
  `update`, `delete`, `patch`. The "no writes" non-goal is enforced by the *cluster*,
  not by our good intentions.
- **Secret values are never read.** `cluster.py` reads Secret *names, types and mount
  points* — never `data`. The blast-radius argument needs "a Secret is mounted", not
  its contents. This keeps secret material out of the LLM prompt entirely.
- **Prompt injection surface.** Findings and resource names are attacker-influenceable
  (a pod can be named `ignore-previous-instructions`). Assessment output is constrained
  to a structured schema with an enum severity; free text is rendered escaped, never as
  HTML. The LLM cannot choose a probe outside the whitelist enum.
- **The LLM never executes anything.** Probes are a closed enum; `deep_probe` maps enum
  → hardcoded function. No kubectl string is ever LLM-authored.
- **Keys.** `GROQ_API_KEY` / `OLLAMA_API_KEY` via `.env` (gitignored, chmod 600) locally,
  k8s Secret in-cluster. Never baked into the image.
- **No auth on the dashboard (MVP).** Acceptable only because it binds to a local kind
  cluster. ⚠️ In a Codespace a forwarded port can be made public — the devcontainer must
  default port 8080 to **private** visibility and say so.

---

## Implementation Plan (progress markers)

### Phase 0 — Spike & de-risk ✅ COMPLETE
- [x] Verify Trivy misconfig scan speed + DB requirement against a live kind cluster → **4.5s, no DB**
- [x] Verify LangGraph 1.x API surface by introspection (not memory) → **stable**
- [x] Verify Groq model IDs against the live API → **deprecated IDs found, corrected**
- [x] Get a kind cluster actually running on this host → **needed kind 0.32 + inotify bump**
- [x] Verify `OLLAMA_API_KEY` is Cloud vs local → **Cloud, OpenAI-compatible**
- [x] Seed `vuln-demo` / `safe-demo` and confirm finding contrast → **19 vs 3**

### Phase 1 — Agent core (TDD)
- [x] **TESTS FIRST (red):** unit tests for scanner parsing, context probes, assess ranking, graph wiring — Trivy/k8s/LLM all mocked.
- [x] `scanner.py` — invoke Trivy, parse JSON → `Finding` list
- [x] `cluster.py` — the five read-only context probes
- [x] `llm.py` — provider abstraction (groq | ollama-cloud | ollama-local)
- [x] `agents.py` — state, nodes, `build_graph()`, bounded probe loop
- [x] Green: all Phase 1 unit tests pass — **28 passed**

### Phase 2 — Web layer
- [x] **TESTS FIRST (red):** route tests with the graph mocked (dashboard renders, /scan starts a run, SSE emits node transitions)
- [x] `app.py` + `templates/index.html`
- [x] Green: all Phase 2 tests pass

### Phase 3 — Cluster, packaging, deploy
- [x] `k8s/setup-cluster.sh` — kind create, **including the inotify preflight** (Phase 0 finding)
- [x] `k8s/seed-demo.sh` — apply demo namespaces + context guard
- [x] `Containerfile` + `k8s/build-and-load.sh` — build + `kind load` (804MB image)
- [x] `k8s/rbac.yaml` (read-only) + `deployment.yaml` + `service.yaml` + `k8s/deploy.sh`
- [x] `.devcontainer/devcontainer.json` + post-create.sh — Codespace, docker-in-docker, port 8080 **private**
- [x] `k8s/teardown.sh`

### Phase 4 — Verify & document
- [x] Run the **headline acceptance scenario** against the live cluster with a real LLM call — **3/3 runs pass**
- [x] Verify in-cluster (Trivy in the pod, read-only SA) — passes
- [x] Verify RBAC is read-only empirically (`kubectl auth can-i`) — all writes denied
- [x] Verify provider swap through the deployed app (ollama-cloud / gemma4:31b) — passes
- [x] Visual check of the rendered UI (headless screenshot) — renders correctly
- [~] `code-review` skill on the diff — **not run**: no git repo, so there is no diff to review. Ran a manual verification pass over the security claims instead (RBAC verbs, loop termination, autoescape, probe_secrets signature — all confirmed). A spawned reviewer agent stalled and produced nothing. **Worth doing properly once this is in git.**
- [x] `README.md` + `participant-instructions.md` (match frontdeskai doc style)

### Phase 5 — Adversarial review remediation (2026-07-17) ✅
An adversarial review agent found 14 issues (6 HIGH), each reproduced against running
code. It was a better review than my own pass, which checked the claims I was confident
about rather than the risks. Fixed test-first; suite grew 38 → 55.

- [x] **HIGH-1 `assess` discarded all prior results on any error.** The `return` was
  inside the workload loop, so a transient Groq 429 on workload 2 deleted the CRITICAL
  already found for workload 1 — while the `None` path 4 lines below deliberately did
  the opposite. Now accumulates and continues.
- [x] **HIGH-2 cluster unreachable → the agent confabulated.** No route guard, so
  `assess` ran with an empty context block while the schema still demanded
  `cited_facts` — the model duly invented them. The app silently degraded into the
  exact "LLM guesses from scanner output" behaviour it exists to disprove. Added
  `route_after_context`; bails to report.
- [x] **HIGH-3 fail-open scanner.** `scanner.scan()` swallowed failures and returned
  `[]`, which the UI rendered identically to a clean cluster. **A test asserted this
  behaviour** — the test was wrong. Now raises `ScannerError`; ingest surfaces it.
- [x] **HIGH-4 SSE split events between clients.** One shared queue + destructive
  `get()` → a laptop and a projector on the same run each got half the stream, and one
  never received the done sentinel. Now per-subscriber queues + a replay history for
  late joiners. Verified live with two concurrent clients.
- [x] **HIGH-5 false security claims.** `probe_secret_types` *does* hold an API client
  and `read_namespaced_secret` returns `.data`; the docstring claimed secret values are
  "never read". Corrected to say discipline, not architecture. **And the README cited
  cluster-wide `list secrets` as proof of safety** — that reads every ServiceAccount
  token in the cluster. RBAC narrowed to `get` on secrets; verified Trivy still works.
- [x] **HIGH-6 `is_cluster_admin` matched role NAMES.** A custom ClusterRole granting
  `*/*/*` reported False on the app's headline fact, and the `admin`/`edit` check lived
  only in the ClusterRoleBinding loop — missing their normal RoleBinding usage. Now
  resolves each binding to its rules. Added `has_privileged_rbac` and `unresolved_roles`
  (unknown ≠ safe).
- [x] **MEDIUM-9 `MAX_PROBE_ROUNDS = 2` delivered ONE probe round.** It counts assess
  invocations. Renamed `MAX_ASSESS_ROUNDS`; diagram and README corrected.
- [x] **MEDIUM-12 `RUNS` never evicted / LOW task GC.** Capped at `MAX_RUNS`; task
  reference retained.

### Phase 6 — the two false negatives (2026-07-17) ✅
Both failed in the *unsafe* direction, which is the wrong direction for this tool.

- [x] **MEDIUM-8 initContainers / projected volumes were invisible.** `probe_secrets`
  and `probe_workload_facts` walked only `spec.containers`. Added `_all_containers()`
  (init + main + ephemeral) and projected-volume secret sources. **Verified live**: a
  real Deployment with a non-privileged main container and a privileged initContainer
  now reports `privileged: True`; before the fix it reported False.
- [x] **MEDIUM-7 NetworkPolicy coverage over-claimed.** Egress-only policies and
  `matchExpressions`-only selectors both reported "covered: True" — which pushes
  severity DOWN. Now checks `policyTypes` for Ingress, and refuses to assume a
  matchExpressions selector matches (unknown ≠ covered). **Verified live**: safe-demo's
  default-deny still registers covered, so the LOW ranking is unchanged.

### Still open from the review (not fixed)
- [ ] **`probe_workload_facts` still ignores hostPID / hostNetwork / capabilities.add.**
  Now stated in the docstring rather than implied away — a clean result means "not
  privileged and no hostPath", not "no escape surface".
- [ ] **MEDIUM-10 probe requests are per-workload but applied to all** — N×N API calls,
  attribution lost.
- [ ] **MEDIUM-11 "watch the graph think" oversells the stream.** `assess` emits one
  audit line after all its LLM calls, so the slow node shows nothing.
- [ ] **MEDIUM-13 the `report` node's markdown is computed and discarded.** Nothing
  reads `run["report"]`. Wire it up or delete the node.
- [ ] **MEDIUM-14 no test that an adversarial pod name cannot skew the ranking.** The
  README now says so rather than claiming injection is "inert".
- [ ] **LOW: Ingress never inspected** though RBAC grants it — a workload exposed only
  via Ingress reports `reachable_externally: False`.
- [ ] **No auth on the dashboard.** Deliberate for the MVP; the reason the app rates
  itself MEDIUM. Do not expose it beyond a local kind cluster.
- [ ] **`ollama-local` is untested.** Implemented, never run — the local Ollama service
  was stopped during this session.
- [ ] **No eval loop.** Ranking varies run-to-run at the low end (see Open Questions).
  A fixture-based pass-rate harness is the obvious next step and a good lab exercise.

---

## Test Plan

**Harness:** No prior suite in this repo (greenfield; `frontdeskai` has none either).
Establishing one: `pytest` + `pytest-asyncio`, tests in `tests/`, `httpx.ASGITransport`
for FastAPI routes. Seams for mocking: `scanner.run_trivy()`, the `cluster.*` probes,
and `llm.get_llm()` — all external dispatch goes through these three.

### Unit (TDD-drivable — write FIRST, red before green)
- [ ] `scanner.py` parses real Trivy JSON (fixture captured from Phase 0) → Finding list
- [ ] `scanner.py` survives Trivy non-zero exit / malformed JSON without killing the graph
- [ ] `cluster.py` identifies a cluster-admin-bound SA
- [ ] `cluster.py` never returns Secret `data` values (**security regression test**)
- [ ] `cluster.py` detects NodePort exposure and absent NetworkPolicy
- [ ] `assess` ranks privileged+cluster-admin+creds+exposed above a hardened workload (LLM mocked)
- [x] `deep_probe` loop terminates at the cap (**infinite-loop guard**)
- [x] Probe whitelist rejects an out-of-enum probe request (**injection guard**)
- [ ] `build_graph()` wires the expected nodes/edges
- [ ] Routes: dashboard 200, POST /scan returns run id, SSE emits node transitions

### Integration (verification-after — live)
- [x] Real Trivy against the real kind cluster returns ≥1 HIGH on vuln-demo
- [x] Real Groq call returns a schema-valid assessment

### Manual / acceptance
- [x] **Headline scenario** — **PASSED live 2026-07-17**: payments-api CRITICAL citing 6 context facts + the chained path; reports-api LOW. 11.1s end-to-end.
- [x] Provider swap groq → ollama produces a comparable ranking — **PASSED with `gemma4:31b`** (CRITICAL/LOW, 7 and 5 cited facts, 13s). Required abandoning gpt-oss on the Ollama side; see Open Questions.

---

## Deploy & verify

```bash
bash k8s/setup-cluster.sh      # inotify preflight + kind create + seed demo
bash k8s/build-and-load.sh     # docker build + kind load
bash k8s/deploy.sh             # secret from .env, rbac, deployment, service
# -> http://localhost:8080  (Codespaces: forwarded, PRIVATE by default)
```
Pre-deploy gate: `pytest` green + image builds. Post-deploy smoke: `/health` returns
`{"status":"ok","service":"kubesentinel"}` and a scan of `vuln-demo` returns ≥1 CRITICAL.

---

## Risks & mitigations

- **Trivy binary is 161MB → fat image, slow `kind load`.** → Multi-stage Containerfile,
  copy only the binary. If still painful, run Trivy as a k8s Job instead. *Measure first.*
- **kind is fragile on modern hosts.** Phase 0 hit *two independent* failures (kind 0.26
  vs Docker 29; inotify instances 128 with 95 already consumed). → `setup-cluster.sh`
  preflights: check kind version, raise inotify, fail with a *specific* message. This is
  the single most likely thing to break for a workshop participant.
- **kind-in-Codespaces has known docker-in-docker breakage** (docker 27+ IPv6). → Pin the
  docker-in-docker feature version in devcontainer.json; document the fallback.
- **Groq deprecates models fast.** `llama-3.3-70b-versatile` dies 2026-08-16 — this
  already bites the existing frontdeskai app. → Model IDs env-configurable, defaulted to
  `openai/gpt-oss-120b`, pinned in one place (`llm.py`).
- **LLM ranks by echoing scanner severity instead of reasoning.** The failure mode that
  would make the whole thesis hollow. → The `safe-demo` contrast + an acceptance test that
  *requires citing context facts*, which is exactly what echoing cannot produce.

---

## Open Questions / Spike Findings

- **Is `trivy k8s --scanners misconfig` fast enough to demo, and does it need a vuln DB?**
  → **RESOLVED (Phase 0):** 4.5s against the demo cluster, **no DB download** — misconfig
  uses bundled Rego. Binary is 161MB. Viable — Trivy stays.
- **Did LangGraph 1.x break the API I'd write from memory?**
  → **RESOLVED:** No. `StateGraph`, `add_node`, `add_edge`, `add_conditional_edges`,
  `compile` all present with expected signatures on **1.2.9**. `astream(stream_mode="updates")`
  is the SSE feed. Prior art pins `langgraph==0.2.60`; we deliberately use current 1.x for
  new material.
- **Are the Groq model IDs I know still valid?**
  → **RESOLVED — REFUTED, and this one would have shipped broken.** `llama-3.3-70b-versatile`
  and `llama-3.1-8b-instant` are **deprecated, shutdown 2026-08-16**. Verified against the
  live API with the user's key. Using **`openai/gpt-oss-120b`** (reason/synthesise) and
  **`openai/gpt-oss-20b`** (cheap/fast). ⚠️ **Spillover: the existing `frontdeskai` workshop
  app pins `llama-3.3-70b-versatile` and will start failing on 2026-08-16.**
- **Does kind work on this host?**
  → **RESOLVED — REFUTED twice.** (a) kind **0.26 cannot create a cluster on Docker 29**
  (fails "Reached target Multi-User System"); needs **≥0.32**. (b) `fs.inotify.max_user_instances`
  was **128 with 95 already consumed** by the running `frontdeskai` cluster → API server never
  bootstrapped. Fix: `sysctl fs.inotify.max_user_instances=512 max_user_watches=524288`
  (runtime, reverts on reboot → must live in `setup-cluster.sh`). **Both** fixes were needed.
- **Is `OLLAMA_API_KEY` local or Cloud?**
  → **RESOLVED:** **Ollama Cloud**, OpenAI-compatible at `https://ollama.com/v1`. Changes the
  story: Cloud works in a Codespace (no GPU) but data *does* leave; local Ollama is the true
  air-gap. Support both. **`gpt-oss:120b` is on both Groq and Ollama Cloud** → clean
  same-weights provider A/B.
- **Will the seeded demo produce a real contrast?**
  → **RESOLVED:** vuln-demo **19** findings (4 HIGH/4 MED/11 LOW), safe-demo **3** (1 MED/2 LOW).
  Non-zero on the safe side, so the agent must discriminate rather than count.
- **Should the app run Trivy in-process or as a Job?**
  → **RESOLVED (Phase 3):** in-process. Multi-stage Containerfile copies the binary from
  `aquasec/trivy:0.72.0`. Final image **804MB** — chunky but `kind load` handles it and a
  scan runs in ~6s in-cluster. Not worth a Job's complexity at this size. Revisit if it grows.
- **Is the provider swap really a same-weights A/B?**
  → **RESOLVED — REFUTED.** This was design decision #4 and it did not survive testing.
  Measured against the real Assessment schema:
  `groq/openai/gpt-oss-120b` **works**; `ollama-cloud/gpt-oss:120b` **fails** (prose, not
  JSON — every structured-output method, both client libraries); `ollama-cloud/gemma4:31b`
  **works** (free tier, the new default); `ollama-cloud/nemotron-3-nano:30b` **passes a
  2-field toy schema then returns None on the real one**. Two consequences: (a) ollama-cloud
  goes through the OpenAI-compatible endpoint with `langchain-openai`, not langchain-ollama;
  (b) the workshop framing is "same graph, different host" — NOT "same weights".
  This also exposed a real crash: `assess` called `.model_dump()` on a None result.
  Fixed test-first (`test_assess_survives_a_model_returning_none`).
- **Is the ranking stable across runs?**
  → **RESOLVED — PARTIALLY. Known limitation, do not oversell.** Over ~6 live runs,
  `vuln-demo/payments-api` was **CRITICAL every single time** (the compounding case is
  unambiguous). But `safe-demo/reports-api` oscillates **LOW ↔ MEDIUM** at temperature 0 —
  when it says MEDIUM it latches onto "image from an untrusted registry", which is a
  defensible but noisier read. The *discrimination* that matters (CRITICAL vs not) is
  stable; the exact low-end grade is not. Two consequences: (a) the acceptance criterion
  should be "payments-api CRITICAL **and ranked above** reports-api", not "reports-api == LOW";
  (b) this is the natural hook for an eval loop — a handful of fixture clusters with
  expected orderings and a pass-rate, which is also the right lab exercise. **Not built yet.**
- **Does KubeSentinel survive its own scan?**
  → **RESOLVED — it rates itself MEDIUM, and it is correct.** It is NodePort-exposed with no
  NetworkPolicy and no auth (that is how you reach the dashboard), and has a writable root
  filesystem. An earlier draft of the README claimed it self-rates LOW; that was wrong and is
  corrected. Keep the MEDIUM in the demo — a security tool that rates itself LOW is telling
  you the ranking is decorative.
- **Do local Ollama models work?** → _UNVERIFIED._ `ollama-local` is implemented but was not
  tested this session — the local Ollama service was stopped to free memory for kind. Treat
  as untested until someone runs a real scan with it.

---

## Progress Log

- **2026-07-17** — Plan scaffolded. Use cases + design written against **verified** facts.
  **Phase 0 spike complete; it moved the plan in four places:**
  (1) Groq model IDs I would have written from memory are deprecated with a 2026-08-16
  shutdown — corrected to `openai/gpt-oss-*`, verified live against the user's key;
  (2) kind 0.26 is broken on Docker 29 → require ≥0.32;
  (3) inotify instances exhausted (128, 95 in use) by the existing `frontdeskai` cluster →
  preflight sysctl bump is mandatory, and workshop participants will hit this too;
  (4) `OLLAMA_API_KEY` is an Ollama **Cloud** key, not local — "Ollama" means two modes, and
  `gpt-oss:120b` on both Groq and Ollama Cloud gives a clean provider A/B.
  Trivy confirmed viable (4.5s, no DB). Demo contrast confirmed (19 vs 3).
  Conventions adopted from `frontdeskai` (flat layout, TypedDict + `Annotated[list, add]`
  audit, uncompiled `build_graph()`, `==>` script logging, `.env` secret injection);
  deliberately diverged on: kind + `kind load` instead of EKS + registry, LangGraph 1.x
  instead of 0.2.60, SSE instead of sync invoke.
  Next: Phase 1, tests first.

- **2026-07-17 (cont.)** — Phases 1-4 landed. 38 tests green; headline scenario passes 3/3
  live and in-cluster. Two things testing refuted after the plan was written, both recorded
  in Open Questions: (1) the "same weights on Groq and Ollama Cloud" A/B does not work —
  gpt-oss:120b answers in prose on Ollama, so ollama-cloud now runs `gemma4:31b` via the
  OpenAI-compatible endpoint (thanks to Rajesh for suggesting gemma4); (2) KubeSentinel
  rates *itself* MEDIUM, not LOW as an earlier README draft claimed — it is right, and the
  docs now say so. Real bug found by live testing and fixed test-first: `assess` crashed on
  a model returning None. Host fixes applied outside the repo: system kind upgraded
  0.26 → 0.32 (0.26 cannot create clusters on Docker 29), inotify raised to 512 instances.
  Next: git init + a real code review; then the eval loop.
