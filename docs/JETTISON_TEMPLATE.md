# JETTISON template

> **Status: scaffold, not the doc.**
> Per `migration/MAIN.md § 11 Stage 1` line 274, `docs/JETTISON.md` was
> originally scheduled as a Stage 1 deliverable so it would be ready
> when Stage 2 cuts the policy-module release. As of 2026-06-30 the
> policy module's implementation has not yet shipped in interlock; the
> rule-engine surface, the `SessionEvent` shape, and the baseline-rule
> set described in `migration/layer4_jettison.md` are spec-level only.
> Writing the rule-authoring prose now would produce examples that go
> stale the moment Stage 2 lands.
>
> Same pattern as `docs/BLUEPAPER_TEMPLATE.md`: capture audience,
> voice, outline, and per-section intent now; fill prose when the
> implementation it documents is concrete.
>
> **When to graduate this template to `docs/JETTISON.md`:** when
> `tidereach/interlock` Stage 2 has shipped the policy module —
> specifically when the YAML rule schema, `SessionEvent` shape,
> `LogAction` implementation, and `tidereach interlock
> {session-audit,session-watch,rules-lint}` subcommands exist as
> code that operators can run against fixture transcripts. The
> baseline-policy rules are the load-bearing artifact this doc
> documents; they must exist as files in interlock's source tree
> before the doc can be authored honestly.

---

## Audience, length, voice

**Audience** (one primary, unlike BLUEPAPER's three):

- **Operators writing rules for jettison.** They have a session stream
  they want to detect behaviour in, they know YAML, they want
  concrete examples and a way to test rules locally before deploying.

**Length:** No spec-mandated budget. Target 4–8 pages. The DSL
reference + baseline rules + worked examples set the floor; anything
above 8 pages is over-explained and should link to
`migration/layer4_jettison.md` (the canonical spec) instead.

**Voice:** Operational, imperative. Closer to a `man` page than to
BLUEPAPER's RFC voice. *"To detect X, write this rule."* Concrete
examples beat prose. Show YAML, then explain. No marketing register;
no narrative arc; no "in this guide we'll explore."

**Distinct from `migration/layer4_jettison.md`:** the migration spec
is the *what and why*; JETTISON.md is the *how to write a rule
against it*. The two are paired — the spec defines vocabulary, the
guide teaches use.

---

## Compression rules

- **Implementation rationale:** zero lines. The "why this DSL shape"
  story lives in `migration/layer4_jettison.md § Lessons learned`.
- **Cross-layer coupling:** zero lines. The L4-in-L0 collapse, the
  AuditChain integration, the SquidAccessReader feed — none of these
  matter to a rule author. Link if asked, don't elaborate.
- **Soft/Hard action mechanics:** ½ page max. Operators need to know
  what an action *does* (`LogAction` records, `BlockAction`
  cooperates, Hard kills/severs/freezes) and that emit-before-execute
  is a property. They don't need the `podman` invocation details —
  that's interlock-internal.
- **CLI internals:** zero lines. `tidereach interlock session-audit`
  is documented by `--help`; the doc only needs to name it as the
  testing entry point.
- **LLM detection:** explicit one-line "not supported" with a link to
  Decision 18(a) / sieve. Don't justify.

---

## Outline — 9 sections

Section order is operator-task-shaped: orient → input model → DSL →
actions → baseline → workflow → operate → audit events → next reads.
A rule author should be able to skim § 1–§ 3, paste a baseline rule
from § 5, lint it via § 6, and ship it.

### § 1. What jettison is (and what it isn't)

<!-- TODO: fill -->
One paragraph: jettison is the deterministic rule engine over agent
session streams. It reads JSONL events from the substrate `airlock`
mounts, evaluates YAML rules, dispatches actions. **No model calls.
No embedding lookups. No LLM-based detection** (that's sieve, per
Decision 18(a)).

One paragraph on what jettison does NOT own: session-stream writing
(no writer in any layer — agent CLI writes directly), content
scanning (sieve), intent rules (arbiter), audit-chain management
(interlock).

One line on deployment: layer-4 code ships *inside interlock's
process* per the 2026-06-29 collapse — the operator never installs
`jettison` as a separate package or runs a separate binary. The
subcommands live under `tidereach interlock`.

Approximate: ½ page.

### § 2. The SessionEvent shape

<!-- TODO: fill -->
The input model. Adapter-normalized event shape that rules see
regardless of which agent CLI produced the transcript (Claude Code
adapter in v1, Copilot adapter in v1). Document:

- The field set (`event_type`, `args`, `text`, timestamps,
  `context_id` for arbiter cross-references, the metadata envelope)
- Event-type taxonomy (`tool_call`, `tool_result`, `user_message`,
  `assistant_message`, `stop`, …)
- Per-CLI adapter notes — Claude transcripts in `$SESSION_DIR` per
  hook env; Copilot in `COPILOT_SESSION_DIR`; the two are
  independent (no cross-CLI delegation)

Cite `interlock-contracts/session-stream-jsonl/v1.0.0/schema.json`
as the canonical source. Quote the field skeleton inline so a rule
author doesn't have to leave the doc to write a rule.

Approximate: 1 page.

### § 3. Rule DSL

<!-- TODO: fill -->
The heart of the doc. YAML rule structure with one worked example
above the reference:

- Predicates over event fields (boolean composition with `AND` / `OR`
  / `NOT`; comparison operators; `MATCHES` for regex)
- Regex flavour + flags (re2; case sensitivity defaults; the
  `--regex-engine` note)
- Threshold counters (count events matching a predicate within a
  window; emit when the count crosses a configured floor)
- Cooldowns (per-rule throttle so a single anomalous session can't
  emit 1000 audit events)
- Allowlists (the `<!-- legacy-name-allowed -->` equivalent at the
  rule level — surface the documented exclusion mechanism)

End the section with one **complete** rule example: predicate +
threshold + action + audit-event name, ready to paste. The example
becomes the load-bearing teaching artifact; pick it carefully when
authoring.

Approximate: 1½ pages.

### § 4. Actions

<!-- TODO: fill -->
The action surface, in the v1/v2-Soft/v2-Hard order:

- **v1 `LogAction`** — observer; emits `action_logged` audit event;
  no cooperation needed; safe default for any new rule.
- **v2 Soft `BlockAction`** — writes a per-session flag file at
  `${SESSION_DIR}/<session_id>.blocked` (mode 0600). The dedicated
  Stop-hook in the meta-repo's `integrations/{claude,copilot}/hooks/`
  lstats the file on Stop fire and refuses the Stop. **Cooperative
  with the agent CLI** — won't work if the CLI doesn't honor the
  hook. Ships as `NotImplementedError` stub in v1.
- **v2 Hard** (three independent primitives, each opt-in,
  `*_enabled=False` default):
  - `KillAgentContainerAction` → `podman kill <agent>`
  - `SeverEgressAction` → `podman network disconnect <net> <ctr>`
  - `FreezeWorkspaceAction` → `podman exec <airlock-supervisor>
    mount -o remount,ro /work`

**Emit-before-execute is a property, not a footnote.** Every action
that actually does anything (`BlockAction` and the three Hard
primitives) emits its audit envelope *before* the destructive call.
This is a load-bearing contract; document it as one.

Approximate: ½ page.

### § 5. Baseline policy

<!-- TODO: fill -->
The rules jettison ships with. This section depends entirely on what
interlock's Stage 2 policy module actually ships. **Until then, this
section is a stub.** When authoring:

- For each baseline rule: name, what it detects, the YAML, the audit
  event it emits, when an operator might want to disable it
- Common-sense candidates: prolonged silent tool-call loops,
  outsized `Bash` argv (e.g., the `rm -rf /` shape), egress to
  unknown domains (correlate with `SquidAccessReader` envelopes),
  prompt-injection canary tokens appearing in `user_message` after
  `tool_result` (the [classic indirect-prompt-injection pattern])
- The author should sanity-check baseline candidates against
  `migration/layer4_jettison.md § Mission` for scope (jettison is
  behavioural; sieve is content)

Approximate: 1 page (longest section; rule examples are dense).

### § 6. Authoring workflow

<!-- TODO: fill -->
How an operator iterates from "I want to detect X" to "this rule is
deployed." Step-by-step:

1. Find or construct a fixture transcript. Live recordings work; so
   do hand-crafted JSONL files matching the schema. **Deterministic
   tests are the only kind.**
2. Write the YAML rule.
3. Lint: `tidereach interlock rules-lint <path>` checks structure,
   regex compilability (re2-incompatible patterns fail here), and
   predicate field references (typos in field names fail here).
4. Replay against the fixture: `tidereach interlock session-audit
   <fixture-path> --rules <new-rule>`. Inspect the emitted audit
   envelopes.
5. Add the rule to the operator's rules directory; commit signed.

One paragraph on the **deterministic-only constraint**: no `httpx`,
`requests`, or `ollama` imports in any rule module. CI asserts this
on every PR. If you need content classification, that's sieve, not
jettison.

Approximate: 1 page.

### § 7. Operating jettison

<!-- TODO: fill -->
The two operator modes:

- **Offline audit**: `tidereach interlock session-audit <path>` —
  summarises a stored transcript end-to-end; useful for incident
  review or replaying a captured session against a new rule set
- **Live tail**: `tidereach interlock session-watch <volume>` —
  tails the substrate volume `airlock` mounts; emits as events
  arrive

Per-CLI adapter notes — Claude transcripts arrive in
`$SESSION_DIR`; Copilot in `COPILOT_SESSION_DIR`. The two are
parsed independently; no cross-CLI fall-back delegation.

Approximate: ½ page.

### § 8. Audit events

<!-- TODO: fill -->
What jettison writes to interlock's AuditChain:

- **v1:** `session_event_seen` (per ingested event), `rule_hit`
  (per matched rule), `action_logged` (per `LogAction` execution)
- **v2:** `block_flag_written` (Soft), `kill_agent_container_initiated`,
  `sever_egress_initiated`, `freeze_workspace_initiated` (Hard) —
  emitted *before* the corresponding action runs

Quote the envelope skeleton (`record_hash` / `prev_hash` / `seq` +
event-specific fields) inline so an auditor reading this doc can
recognise a `rule_hit` envelope without leaving for the AuditChain
spec.

The audit-event ownership is two-tiered (per
`interlock-contracts/governance/audit-event-ownership.md`):
layer-exclusive (interlock-only) vs cross-layer (defined by
interlock, emitted by named layer). jettison's events are all
defined by interlock and emitted by the policy module *inside
interlock's process* — so this isn't really "cross-layer," it's an
in-process producer. Document the distinction in one sentence.

Approximate: ½ page.

### § 9. Reading paths

<!-- TODO: fill -->
One-line pointers:

- **Need the canonical spec?** → `migration/layer4_jettison.md`
- **Need the SessionEvent schema?** →
  `interlock-contracts/session-stream-jsonl/v1.0.0/schema.json`
- **Need the AuditChain envelope shape?** →
  `interlock-contracts/audit-envelope/v1.0.0/`
- **Need to know how the substrate gets written?** →
  `migration/layer3_airlock.md § Session-stream substrate`
- **Need to know why no LLM detection in jettison?** →
  `migration/MAIN.md § 7 Decision 18(a)`
- **Need the architecture gestalt?** → `docs/BLUEPAPER.md`
  (forthcoming — see `docs/BLUEPAPER_TEMPLATE.md`)

Approximate: ⅓ page.

---

## Source material the future author should consult

These are the inputs to the framing decisions captured here. When
authoring, re-read these so the operational voice stays grounded:

- `migration/layer4_jettison.md` — the canonical spec; do not
  duplicate, do link
- `migration/MAIN.md § 7 Decisions 14, 18(a), 19` (locked decisions —
  no LLM detection, single-operator governance, layer naming)
- `migration/MAIN.md § 11 Stage 1` line 274 (the spec's framing of
  what JETTISON.md is for)
- `interlock-contracts/session-stream-jsonl/v1.0.0/` (the input
  schema; load-bearing for § 2 + § 3)
- `interlock-contracts/audit-envelope/v1.0.0/` (the output envelope
  shape; load-bearing for § 8)
- `interlock-contracts/governance/audit-event-ownership.md` (the
  two-tier ownership model; one sentence in § 8)
- Whatever baseline rules ship in interlock's `policy/baseline/`
  directory at the time of authoring — this section CANNOT be
  written until those exist as files

---

## Verification criteria (for the eventual full doc)

When `docs/JETTISON.md` gets authored from this template, the
acceptance checks are:

1. **Length** — `wc -w docs/JETTISON.md` between 1500 and 3000 words
   (4–8 pages). Below 1500 = under-served; above 3000 = duplicating
   the spec.
2. **Operator scan** — read top-to-bottom imagining a rule author:
   can they get from § 1 to a copy-pasteable rule from § 5 within
   the first 5 minutes of reading?
3. **Worked-example density** — every section that explains a
   mechanism (§ 3, § 5, § 6) has at least one complete, runnable
   YAML or shell example. Prose-only explanations of YAML are a
   failure mode.
4. **Legacy-name-guard sim** — 0 hits across `docs/JETTISON.md`.
5. **Hygiene** — trailing whitespace = 0, EOF newline present.
6. **Cross-reference integrity** — every `[link](path)` resolves or
   is suffixed `(forthcoming)`.
7. **Determinism check** — search the doc for any rule example that
   could be read as "consult a model" / "score the embedding" /
   "ask the LLM." If found, rewrite. The constraint is structural;
   the doc must reflect it.

---

## What this template explicitly does NOT prescribe

The eventual author retains discretion on:

- **The specific baseline rules** in § 5 — depends on what interlock's
  Stage 2 policy module ships
- **Word-level phrasing** anywhere
- **The worked example in § 3** — pick one that's pedagogically
  useful when you know what the real rule shapes look like
- **Whether to inline the full SessionEvent JSON schema or just the
  field skeleton** in § 2 (skeleton is safer for length budget)
- **Section sub-headings** within each numbered section
