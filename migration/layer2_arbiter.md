# arbiter — L2 Control Plane (intent integration, engine-agnostic)

> **Layer name:** arbiter.
> **Plane:** Control (L2).
> **Repo:** `tidereach/arbiter`.
> **Status:** Migration spec; greenfield build planned.

arbiter is the control-plane integration spec. It defines (a) a hook-side adapter library that asks an external rule engine "deny / ask / allow?" before a tool call, (b) the IPC contract for engine communication, (c) the hook-ordering rule (arbiter-first → sieve-second → OR-to-block), and (d) interlock's `check-engine` preflight assertion. **The rule engine itself is operator-pluggable** — Falco/Prempti, OPA, custom Python rules, anything that can accept a verdict request over the defined IPC. arbiter does not pick one.

arbiter is the smallest layer: an engine-agnostic spec + a thin adapter + one CLI extension to interlock. No engine source code.

Read [`MAIN.md`](MAIN.md) first; it sets the architecture, the decisions, and the execution order. This file is arbiter's slice.

---

## Mission

arbiter owns the contract that lets a hook-side adapter talk to whichever control engine the operator chose. Concretely:

- **Engine-agnostic IPC contract** (schema in interlock `contracts/engine-ipc/v1`): HTTP-over-UDS — `POST /verdict {tool, args, session_id, context_id}` → `{verdict: deny|ask|allow, reason, evidence?}`.
- **Adapter library**: a small Python package (`arbiter_adapter`) the integration hooks import to make verdict requests.
- **Hook-ordering rule**: arbiter-first (cheap; engine-side decision) → sieve-second (content scan) → OR-to-block (any layer denies → block).
- **interlock `check-engine` extension**: asserts the configured engine socket exists, S_ISSOCK with the right owner/mode, and a probe `POST /verdict` returns within timeout.
- **Reference adapter shipping for one engine** — operator choice in deployment; arbiter does not pick. The reference adapter is documented as an example, not as canonical.

arbiter does **not** own: rule authoring (engine-side; operator), engine deployment (operator), picking a default engine (deliberately none), audit-event emission (forwarded via interlock `AuditChain`).

---

## Scope decision history

References [`MAIN.md § 7 Decisions locked`](MAIN.md#7-decisions-locked):

- **Row 3 (4 sibling layer repos)**: arbiter is its own repo even though it ships very little code, because it's a stable, citable contract surface. Both Tidereach and engine implementors can cite the contract by URL.
- **Row 7 (arbiter engine-agnostic)**: no Falco-specific text. The IPC contract supports any engine that accepts a verdict request and returns deny/ask/allow. Falco/Prempti, OPA, and custom Python rules are all valid backends.
- **Row 8 (per-layer-file review)**: this file is reviewable standalone.

arbiter is **Stage 5** in MAIN.md's execution order — parallelisable with Stage 4 airlock; no dependency between them.

---

## Doc audit

| Doc | Disposition for arbiter | Notes |
|---|---|---|
| `docs/ENDPOINT_STACK.md` § Hook ordering | **Rewrite** | Rewrite engine-agnostic; drop the Falco-specific framing in favour of "the configured engine." The hook-ordering rule (arbiter first → sieve second → OR-to-block) is the canonical contract and carries forward unchanged in meaning. |
| `docs/ENDPOINT_STACK.md` § Posture | **Rewrite** | Fail-closed posture applies to arbiter exactly as to other layers. |
| `docs/SANDBOX_ALTERNATIVES.md` § The overlap seam — cplt vs Prempti | **Rewrite** | Rewrite engine-agnostic; the operator-choice framing (redundant engines, OR-to-block) is the right shape and guides the rewrite. Specifics about cplt vs Prempti become "the configured engine." |
| `docs/RATIONALE.md` | **No arbiter rationale exists** | The layer is new in narrative; arbiter's RATIONALE.md authors a fresh section. |
| `AGENTS.md` | **No arbiter-specific gotchas yet** | Stable IPC contract; v1 should be small enough to have no gotchas; document any that emerge in v1 development. |

**Doc reconciliation tasks**:

1. `docs/ENDPOINT_STACK.md` § "Hook ordering" prose is rewritten engine-agnostic in Stage 1 (meta); arbiter's docs reference the rewritten version.
2. Any Prempti-specific framing in `docs/SANDBOX_ALTERNATIVES.md` § "The overlap seam" likewise becomes engine-agnostic.

---

## Lessons learned

- **The current repo bakes no engine choice into L1** (no Prempti adapter in `src/`, only references in docs). *Lesson:* preserve this discipline; engine choice belongs to the operator. *v1:* arbiter's IPC contract is engine-agnostic from the first line of the spec. No `from falco import ...` anywhere.

- **`docs/ENDPOINT_STACK.md` leaves the IPC socket path unstated.** *Lesson:* a contract that leaves the socket path implicit is brittle. *v1:* the contract publishes a concrete default (`/run/arbiter-engine/hook.sock`), root-owned, **mode 0660 with gid matching the engine's service group**. A 0666 UDS accepts connections from any process on the host, which defeats the layered defense whether or not the engine validates callers internally; the engine's internal auth is a defense in depth, not the access boundary. Operator overrides socket path via `ANALYZER_ENGINE_SOCKET`, mode via `ANALYZER_ENGINE_SOCKET_MODE`, and per-request timeout via `ANALYZER_ENGINE_TIMEOUT_MS` (default 200ms).

- **`tidereach check-sandbox` exists but no equivalent for the control engine** today. The ENDPOINT_STACK.md roadmap calls this out as "still roadmap." *Lesson:* preflight must cover every external dependency the stack assumes. *v1:* interlock's `check-engine` subcommand is part of arbiter v1's deliverables (arbiter writes the spec; interlock implements the CLI).

- **Falco was the implicit-default engine** because of the Prempti reference. *Lesson:* operator pluggability is a v1 invariant, not a v2 aspiration. *v1:* the spec is engine-agnostic from the start; the reference adapter ships for one engine in deployment but the layer file does not name a default.

- **Per-hook latency budgets are documented for sieve** but not for arbiter's adapter or for the engine call. *Lesson:* the cross-layer latency budget must include the engine round trip. *v1:* arbiter documents an engine-call budget of ≤100ms p95 (since sieve's PreToolUse budget is 300ms and sieve's classifier-side latency is the bulk). Engines that cannot resolve deterministically within the latency budget **must respond with `ask`**; the user provides the gate. LLM-backed engines follow this consultative pattern in v1 — inference may run, but the verdict is `ask`, never a synchronous block. Async / deferred verdicts are an explicit v2 open question (see Out of scope).

---

## Reuse table

| Source (current) | Disposition | Notes |
|---|---|---|
| No `src/spektralia/` code for arbiter | n/a | No current code. |
| `docs/ENDPOINT_STACK.md § Hook ordering` prose | **Rewrite** | Rewrite engine-agnostic; the pre-migration hook-ordering rule carries forward in meaning while engine-specific language is replaced. |
| `docs/SANDBOX_ALTERNATIVES.md § The overlap seam` prose | **Rewrite** | Rewrite engine-agnostic; the pre-migration operator-choice framing carries forward in meaning while Prempti-specific framing is replaced. |
| No tests for arbiter in the current repo | n/a | Greenfield. |

---

## v1 spec

### Deliverables

A small Python package + a one-document spec + a interlock CLI extension. Total surface area is intentionally tiny.

1. **Engine-agnostic spec** (`SPEC.md` inside arbiter repo) — the contract every adapter and engine implementation honours.
2. **`arbiter_adapter` Python package** — a thin adapter library the integration hooks (in hull meta-repo) import. Single public function: `request_verdict(tool, args, session_id, context_id) -> Verdict`. **No console script** per Decision 16: `tidereach-arbiter` registers no `[project.scripts]` entry; the package exposes the importable library only. Operator-facing preflight (`check-engine`) lives under `tidereach interlock` (umbrella; owned by `tidereach-interlock`); see deliverable 3 below.
3. **interlock `check-engine` CLI extension** — specified here, implemented in interlock. Asserts the socket exists, S_ISSOCK, owner/mode invariants, and a probe `POST /verdict` returns within timeout.
4. **Hook-ordering example** — a Claude Code / Copilot `settings.json` snippet showing arbiter-first → sieve-second wiring; lives in the hull meta-repo's `integrations/` and follows the **composition contract owned by layer0 (interlock)**. Arbiter cross-references the contract; it does not define ordering.

### IPC contract

Lives in interlock `contracts/engine-ipc/v1/`. The contract defines two layered surfaces, kept deliberately separable:

- **Envelope** — the JSON request and response schemas (below). The stable surface engine authors pin against.
- **Transport profile** — v1 ships **HTTP-over-UDS** as the sole transport. v2 may add a gRPC profile as an alternate. Because the envelope is profile-agnostic, sync engines authored against the v1 transport are unaffected by gRPC's arrival.

**Request**:
```http
POST /verdict HTTP/1.1
Host: localhost
Content-Type: application/json
X-arbiter-Adapter-Version: 1.0.0

{
  "tool": "Bash",
  "args": {"command": "git push --force"},
  "session_id": "abc123",
  "context_id": "tool-call-42"
}
```

**Response**:
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "verdict": "deny",
  "reason": "policy.git.no_force_push",
  "evidence": {"matched_rule": "git-force-push-block", "rule_version": "2026-04-01"}
}
```

`verdict` is one of `"deny" | "ask" | "allow"`. `reason` is a stable identifier (rule name or category); never a free-form string the model could exfiltrate. **The adapter validates `reason` against `^[a-z][a-z0-9._-]{0,63}$` and treats a violation as a malformed response (fail-closed deny).** The stable-identifier property is load-bearing for the exfiltration defense and must be enforced at the trust boundary, not just documented. `evidence` is optional; engines may include richer audit detail. `context_id` is the **v1 correlation ID** — adapters propagate it into audit events so SIEM-side joins across arbiter / sieve / airlock work without a v2 retrofit.

**Fail-closed semantics**: if the socket is absent, the response is malformed, the connection times out (configurable, default 200ms), or the verdict string is not one of the three enum values, the adapter returns `Verdict(verdict="deny", reason="arbiter_engine_unavailable")`. No engine outage allows a tool call through.

### Hook ordering

The arbiter adapter returns a `Verdict`. Ordering and OR-to-block semantics are **governed by the layer0 (interlock) composition contract**, with the wiring example living in the hull meta-repo's `integrations/`. Per that contract, any layer's `deny` terminates the chain before the tool proceeds.

Arbiter participates by:

- Returning a verdict synchronously per the IPC envelope above (no streaming, no callbacks in v1).
- Reserving user-interactive `ask` for arbiter's engine. Sieve stays strict at PreToolUse (deny, no user prompt), so the two layers do not compete for the prompt.

The composition rule (arbiter-first → sieve-second → OR-to-block) is **not duplicated here**. See layer0's composition contract for the canonical statement; arbiter asserting it would mean two homes for one rule.

### interlock `check-engine` (specified here, implemented in interlock)

```bash
tidereach interlock check-engine
# socket configured but absent       -> "FAIL: socket not found at <path>"       (exit 1)
# socket exists, wrong owner/mode    -> "FAIL: socket invariants violated"        (exit 1)
# socket exists, probe times out     -> "FAIL: engine probe timed out (200ms)"    (exit 1)
# socket exists, probe returns deny  -> "OK: engine responding"                   (exit 0)
# no engine configured               -> "OK: no engine configured (arbiter off)" (exit 0)
```

Wired into the SessionStart preflight per `docs/ENDPOINT_STACK.md § Posture`.

### Audit events owned

None directly. Verdicts are surfaced two ways:

1. **Engine logs** — the engine's own audit trail (Falco logs, OPA decision logs, custom rule output). arbiter does not duplicate.
2. **hull meta-repo integration hook's interlock audit event** — when the hook forwards a arbiter verdict to the user, it emits a `tool_call_verdict` event into interlock's `AuditChain` with fields `{tool, verdict, reason, latency_ms, context_id}`. The `context_id` is the v1 correlation ID, propagated from the IPC request; this is what lets a SIEM join arbiter / sieve / airlock events without a v2 retrofit. The interlock `audit-envelope/v1` contract permits this event type with reason-string only (never the args themselves).

### Cross-layer contracts honoured

- interlock's `engine-ipc/v1` contract — arbiter writes; engines honour.
- interlock's `audit-envelope/v1` contract — used for the `tool_call_verdict` event emission from the integration hook.
- No sieve integration directly; the integration hook (in hull meta-repo) is the integration point.

### Verification

- **Adapter unit tests** against a respx-mocked engine: deny / ask / allow each propagate; malformed response → deny; timeout → deny; socket absent → deny; **`reason` violating the stable-identifier pattern → deny** (exfiltration defense at the boundary).
- **interlock `check-engine`** returns 0 against a running mock engine; 1 against an absent socket; 1 against a probe-timeout mock.
- **Contract conformance harness** — a portable test set in interlock `contracts/engine-ipc/v1/conformance/` that any engine implementation can run against itself: known inputs, expected response shapes, boundary cases (malformed JSON, unknown verdict enum value, missing `reason`, oversize `reason`, malformed `context_id`). Third-party engines are not considered v1-conformant without passing.
- **Integration e2e — deny path** — Claude Code with a mock engine running denies a `git push` despite no sieve content hit; sieve still blocks an email in the same session (proves OR-to-block).
- **Integration e2e — `ask` path** — Claude Code with a mock engine returning `ask` on a tool call surfaces a user prompt rendering the engine's `reason`; user accept proceeds, user reject denies. **Stage 5 gate criterion** — adapter unit tests alone are insufficient for sign-off because the consultative `ask` pattern is the v1 path for any engine that can't rule deterministically (including LLM-backed engines).
- **Spec review** — arbiter's `SPEC.md` is reviewed and cross-references interlock's `engine-ipc` contract.

---

## v2 spec

- **Per-hook latency budget instrumentation** — adapter records `latency_ms` per verdict; surfaces in `tool_call_verdict` event; CI gate on regression.
- **Async / deferred verdicts** — engine returns `{verdict: "pending", token: ...}` immediately; adapter resolves via callback / polling / SSE (transport TBD). Envelope shape *extends* v1 (new verdict value, new response fields) so v1 sync engines keep working unchanged. **This is the v2 work that unblocks LLM-as-blocker and multi-engine routing.**
- **Multi-engine routing** — operator wants Falco for system rules + OPA for app rules consulted in sequence. Requires async to fit in the latency budget; ships with the async work.
- **gRPC transport profile** — for high-throughput deployments where HTTP-over-UDS becomes a bottleneck. interlock's `engine-ipc/v2` contract adds gRPC as an alternate **transport profile**; the envelope is unchanged so v1 engines are unaffected.
- **Reference adapter for additional engines** — community-contributed adapters for OPA, custom Python rule sets, etc. Hosted under the arbiter org but not part of the v1 release.

---

## Out of scope

- **Rule authoring** — engine-side; operator concern.
- **Engine deployment** — operator concern (compose snippets, helm charts, systemd units are all out of scope).
- **Picking a default engine** — deliberately none. The reference adapter ships for whatever engine the development team uses; the spec is engine-agnostic.
- **LLM-backed engines as primary blocking agents** — the 200ms hard cap on the sync IPC is incompatible with LLM inference latency. LLM engines participate in v1 as **consultative backends only**: inference may run, but the verdict is `ask` and the user gates. Authoritative LLM-gated blocking requires the async-verdict shape in v2.
- **Multi-engine routing** — v1 supports one configured engine. Sequential or parallel consultation of multiple engines requires async (combined budget would be 200ms total under sync); see v2 spec.
- **Hook composition order and OR-to-block** — owned by layer0 (interlock) per the composition contract. Arbiter participates; it does not define the chain.
- **Content scanning** — sieve.
- **Sandbox / proxy / FS isolation** — airlock.
- **Session-stream ingest / behavioural rules** — jettison.
- **Audit chain management, freeze, integrity hashing** — interlock.

---

## Open questions for v2

- **HTTP-over-UDS vs gRPC at scale** — performance testing in v2 with real engine workloads. The envelope/transport split in v1 keeps this a transport-profile addition, not a contract break.
- **Async response shape** — callback URL vs polling endpoint vs SSE-on-the-request-socket. The v1 spec commits to sync; v2 picks one and specifies it. Driven by LLM-as-blocker demand and multi-engine routing.
- **Correlation-ID format standardisation** — v1 uses whatever the integration hook stamps into `context_id` (opaque string, propagated end-to-end). v2 may standardise on UUIDv7 / ULID across interlock's `audit-envelope` schema.
- **Should arbiter ship a default engine itself** as an "arbiter embedded" mode for operators who don't want to deploy a separate engine? Trade-off: pulls arbiter out of pure-spec land and into an opinionated default.
- **Interactive `ask` rendering** — v1 pins that the integration hook renders `reason` as a confirmation prompt, but does not formalise the prompt template, "remember this verdict" affordances, or per-engine customisation. v2 may standardise.
