# jettison — L4 Visibility Plane (deterministic rules + actions)

> **Layer name:** jettison (the conceptual visibility plane; layer name is decoupled from code identifiers per `AGENTS.md § Project code standards`).
> **Plane:** Visibility (L4).
> **Repo:** None — layer-4 code is hosted in `tidereach/interlock` as a `policy/` module (2026-06-29 merge); this spec doc lives in the meta-repo (`tidereach/hull`). See [Deployment](#deployment).
> **Status:** Migration spec; greenfield build planned.

jettison is the visibility plane. It ingests agent session streams from the substrate airlock mounts, applies **deterministic** rules to the events, and dispatches actions. **No LLM-based detection** — that lives in sieve. v1 ships `LogAction` only (observer; no cooperation needed). v2 adds one Soft action — `BlockAction` (cooperative; the agent CLI is asked to finish on the next Stop boundary, delivered via a flag file and a dedicated Stop-hook script) — and three Hard actions that exercise container-runtime primitives directly: `KillAgentContainerAction` (kill the agent container), `SeverEgressAction` (disconnect the agent container's egress network), `FreezeWorkspaceAction` (remount the workspace bind-mount read-only). The three Hard primitives collapse the previous under-specified `VentAction` into named actions whose verb-noun shape makes the operational target explicit.

There is **no writer** in any layer. The agent CLI writes JSONL session events directly into the volume airlock mounts; jettison reads from that volume.

Read [`MAIN.md`](MAIN.md) first; it sets the architecture, the decisions, and the execution order. This file is jettison's slice.

---

## Mission

jettison owns behavioural detection over agent session streams. Concretely:

- **Session-stream ingest**: tail-safe JSONL reader over the volume airlock mounts at `$SESSION_DIR`.
- **Agent-CLI adapters**: per-CLI parser that converts native transcript JSONL into a normalised `SessionEvent` stream. Claude Code adapter ships in v1; Copilot adapter ships in v1.
- **Deterministic rule engine**: YAML-defined rules with boolean predicates over event fields (`event_type == "tool_call" AND args.tool == "Bash" AND args.command MATCHES "rm -rf /"`), regex over event text, threshold counters. **No model calls.** **No embedding lookups.**
- **Action interface**: `Action` protocol. v1: `LogAction` (observer; emit audit event + metric; no cooperation needed). v2 Soft: `BlockAction` (cooperative; writes a per-session flag file that a dedicated Stop-hook script in the meta-repo lstats on Stop fire). v2 Hard (each destructive; per-action opt-in): `KillAgentContainerAction` (kill the agent container), `SeverEgressAction` (disconnect the egress network), `FreezeWorkspaceAction` (remount the workspace bind-mount read-only).
- **Offline + live CLI**: `tidereach interlock session-audit <path>` summarises a stored transcript; `tidereach interlock session-watch <volume>` tails live. Subcommands live under `tidereach interlock` per Decision 16; the policy module does not own its own binary.
- **`docs/JETTISON.md`** — the baseline policy + rule authoring guide that pre-split issue #117 promised. Lives in the meta-repo (`tidereach/hull/docs/`); not a per-repo file. Authored in Stage 1 alongside BLUEPAPER.md / GOVERNANCE.md (per the 2026-06-29 layer-4 collapse) so the rule-authoring guide is ready when Stage 2 cuts the policy-module v1.0 release.

jettison does **not** own: the session-stream substrate (airlock — mounts the volume), Python session writing (deleted in migration), content scanning (sieve), LLM-based detection (deliberately excluded), intent rules (arbiter), audit chain management (interlock).

---

## Deployment

**Layer 4 is a conceptual layer; layer-4 code ships inside interlock's process.** Following the 2026-06-29 architecture review (see [`REVIEW_NOTES.md § Downstream follow-ups from layer4 review`](REVIEW_NOTES.md)), jettison no longer ships as a sibling repo. Its code merges into interlock as a policy module — `policy/` under interlock's source tree — co-located with the AuditChain, FreezeManager, and SquidAccessReader it already calls into.

This file remains jettison's specification surface: rule DSL, action vocabulary, the `SessionEvent` shape, audit events emitted, settings group, tuning. It lives in the meta-repo (this directory) because there is no `tidereach/jettison` repo to host it. interlock's spec (`layer0_interlock.md § Policy module`) cross-references this file for the rule-engine surface; it does not re-document the DSL.

What "layer 4" still names: the conceptual visibility plane. What it does **not** name: a separate process, repo, deploy artefact, or CLI. interlock's CLI absorbs whatever subcommands the policy module needs (`session-audit`, `session-watch`, `rules-lint`); these collapse into `interlock` rather than a separate `jettison` binary.

The merge is justified by data locality: every action interlock-the-process emits (audit-chain append, freeze write, anomaly bump, container-runtime call) is already in-process for L0 work; the rule engine adds another producer alongside SquidAccessReader. Splitting it across two processes would require an IPC contract for what is fundamentally local state.

---

## Scope decision history

References [`MAIN.md § 7 Decisions locked`](MAIN.md#7-decisions-locked):

- **Row 2 (L4 scope + name)**: ingest + rules + actions form one policy module. v1: `LogAction` only. v2 Soft: `BlockAction` (cooperative, flag-file + dedicated Stop-hook script). v2 Hard: `KillAgentContainerAction`, `SeverEgressAction`, `FreezeWorkspaceAction` (non-cooperative container-runtime primitives that replace the earlier under-specified `VentAction`). **No LLM detection** — the LLM stays in sieve. The rule engine is YAML predicates + regex + threshold counters; no model calls. As of 2026-06-29: layer-4 code is hosted in interlock's process; see [Deployment](#deployment).
- **Row 3 (4 sibling layer repos + 1 meta-repo)**: jettison is not a sibling repo. Layer-4 code lives in the interlock repo as a `policy/` module; this spec doc lives in the meta-repo.
- **Row 6 (airlock owns substrate)**: `sessions/writer.py` is deleted. The agent CLI writes JSONL directly into the volume airlock mounts; the policy module's `SessionStreamReader` reads it. **No writer in any layer.**
- **Row 8 (per-layer-file review)**: this file is reviewable standalone.

Layer-4 work is **Stage 2** in MAIN.md's execution order, alongside interlock — the 2026-06-29 layer-4 collapse merged what had previously been a separate Stage 6 into interlock's Stage 2 because the policy module's v1 surface (`LogAction` only) has no runtime dependency on airlock at all; it depends only on the `session-stream-jsonl/v1.0.0` contract that is already Stage-2-release-blocking per Pivot 3. Hard actions are v2 anyway and ship as `NotImplementedError`-raising stubs. The collapse eliminated the prior Stage 6 entirely and the docs-publish Stage 8 renumbered to Stage 7; live-airlock verification of the policy module happens at the Stage 6 cross-repo soak (was Stage 7 pre-collapse).

---

## Doc audit

| Doc | Disposition for jettison | Notes |
|---|---|---|
| `docs/PLAN.md § 8 jettison` | **Rewrite** | Rewrite per spec; PLAN.md retires under #133, so this section's scope statement (#110 epic + #114-120 sub-issues) is captured in jettison's v1 spec before retirement. No prose is copied; the canonical scope reappears in the new spec text. |
| `docs/SANDBOX_ALTERNATIVES.md § Session stream` | **Rewrite** | Establishes the airlock↔jettison contract (substrate as named volume); the pre-migration section guides the rewritten contract text. |
| `integrations/claude/hooks/stop.py` `_extract_last_assistant_text` | **Rewrite (optional)** | The pre-migration function is correct but its writer-feed role disappears in the migration (airlock's substrate replaces the writer). If the Stop hook is retained for other reasons (e.g. emitting a session-end audit event into interlock), the function is re-authored greenfield in the meta-repo Stop hook; otherwise drop. |
| No `docs/JETTISON.md` yet | **Create** | #117 promises it; jettison v1 ships it in the meta-repo (`tidereach/hull/docs/JETTISON.md`) — there is no jettison repo. |

**Doc reconciliation tasks**:

1. `docs/PLAN.md § 8 jettison` content has been absorbed into this spec's Lessons-learned section; rule-engine rationale + tuning guide is authored greenfield in `tidereach/hull/docs/JETTISON.md` during Stage 1 (per the 2026-06-29 layer-4 collapse — `docs/JETTISON.md` moves from a Stage-2 code deliverable to a Stage-1 operator-facing doc so it is ready when Stage 2 cuts the policy-module release). The pre-migration `PLAN.md` is not lifted forward and not archived as a separate reference (per `MAIN.md § 8` Constraint 1; greenfield rebuild). There is no jettison-repo `RATIONALE.md`.
2. `docs/SANDBOX_ALTERNATIVES.md § Session stream` is referenced (not lifted) from airlock; jettison cites airlock for the substrate contract.

---

## Lessons learned

- **`sessions/writer.py` was bolted onto L1** (`src/spektralia/sessions/writer.py`). The writer had no internal callers — it was integration-adapter code masquerading as library internals. *Lesson:* session-stream production is a substrate concern, not a layer concern. *v1:* airlock's volume mount obsoletes the writer; jettison reads directly from the volume; **no writer in any layer**.

- **#114-119 critical path** was `#114 → #115 → #116 → #117` (ingester core → Claude adapter → CLI → baseline doc). #118 (rules + actions) parallelised; #119 (Copilot adapter) parallelised. *Lesson:* honour the dependency order even when parallel work is possible. *v1:* the meta-repo `docs/JETTISON.md` records the dependency order; the build proceeds Reader → Adapter (Claude) → CLI → Rules + LogAction → Adapter (Copilot) → publish JETTISON.md.

- **#118 v1 was Log-only** (the rule engine and action interface ship in v1; only `LogAction` is implemented); **#120 v2 adds the Soft + Hard family**. *Lesson:* the rule engine must define the action surface even when v1 ships one action. *v1:* `Action` is a protocol; `LogAction` is the only implementation; `BlockAction` (Soft) and `KillAgentContainerAction` / `SeverEgressAction` / `FreezeWorkspaceAction` (Hard) are `NotImplementedError`-stubbed (with the v2 contract documented in their docstrings).

- **Stop hook read `transcript_path`** (Claude Code) — fragile if the transcript layout changes. The current Copilot integration delegates to the Claude hook via `load_claude_hook`, which couples the two adapters in the monorepo. *Lesson:* per-CLI adapter is the integration boundary; if a CLI changes its transcript format, only its adapter changes. *v1:* per-CLI `SessionAdapter` with its own integration tests; no cross-CLI delegation.

- **Copilot adapter delegated to the Claude hook** via `load_claude_hook` in `integrations/copilot/hooks/_common.py`. *Lesson:* delegation made sense in the monorepo (sharing transcript-extraction utilities); breaks post-split where L1 ships from `tidereach/sieve` while the L4 adapters live in `tidereach/interlock`'s `policy/` module. *v1:* independent Copilot adapter from day one inside the policy module; no transcript-extraction code shared across adapters except via the published `SessionEvent` contract.

- **Hard actions (formerly the single under-specified `VentAction`) are destructive** in different ways and at different blast radii. The current monorepo has not implemented any of them; #120 plans the Vent verb. *Lesson:* one action name papered over three different decisions (kill the container vs. cut its network vs. take away its write access). Each deserves its own opt-in and its own pre-action audit event so the chain captures the decision even if the container dies mid-flush. A second lesson, from the 2026-06-29 naming pass: action names use **verb-noun** ordering, and the noun names the explicit operational target from airlock's vocabulary (`agent_container`, `egress`, `workspace`) — never a category like "process" that could mean container, agent CLI, or subprocess. *v2:* three named primitives — `KillAgentContainerAction`, `SeverEgressAction`, `FreezeWorkspaceAction` — each gated on its own `*_enabled=False` default; each emits a `*_initiated` audit event before executing; per-session override (`--no-hard` for a known-benign session) suppresses all three; documented rollback per action (operator restarts the agent container / reconnects egress / remounts workspace rw).

- **Deterministic-only** (per user's L4 scope direction in the migration). The current monorepo's jettison plan does not assume LLM-based detection; the migration codifies this. *Lesson:* the visibility plane is a complement to sieve's data plane; reusing the LLM here doubles cost and adds attack surface. *v1:* rule DSL is pure expression — boolean predicates over event fields, regex over event text, threshold counters. No model calls; no embedding lookups; CI asserts no `httpx` / `requests` / `ollama` imports in `src/interlock/policy/` (the policy module's source tree).

- **#117's "jettison baseline audit + policy doc"** is the layer's user-facing onboarding artifact. *Lesson:* the rule DSL is only useful if operators know how to write rules. *v1:* `docs/JETTISON.md` ships at v1 with: rule grammar, three example rules per category (filesystem read, network call, dangerous shell command), a tuning guide, and a baseline rule set every operator should start from.

---

## Reuse table

| Source (current) | Disposition | Notes |
|---|---|---|
| `src/spektralia/sessions/writer.py` | **Drop** | airlock substrate obsoletes it. |
| `src/spektralia/sessions/__init__.py` | **Drop** | Empty. |
| `integrations/claude/hooks/stop.py` `_extract_last_assistant_text` function | **Keep in hull (meta-repo, optional)** | The Stop hook stays in meta; its writer-feed role disappears. If the hook is retained for session-end audit emission, the function is re-authored greenfield against the pre-migration logic; otherwise drop. |
| Nothing else in `src/spektralia/` for jettison | n/a | Reader, rules, actions all greenfield. |
| Issue threads #114-120 | **Quote into Lessons learned**, then close | Per [`MAIN.md § 7 Decisions locked`](MAIN.md#7-decisions-locked) row 4 (freeze main). |
| `tests/test_sessions_writer.py` | **Drop** | The writer is deleted; the test is no longer applicable. |

---

## v1 spec

### Module API

interlock's `policy/` module exposes (internally; this is the in-process surface, not a separately-installable package):

- `@dataclass(frozen=True) class SessionEvent` — `ts: float`, `session_id: str`, `source: Literal["claude","copilot"]`, `event_type: str`, `transcript_path: Path | None`, `assistant_text: str | None`, `correlation_id: str | None`. The normalised event format every adapter produces; fields match the `session-stream-jsonl/v1.0.0` contract one-to-one. `assistant_text` is the per-CLI adapter's extraction of the assistant turn (None for non-assistant records); `correlation_id` is the arbiter `context_id` propagated through the in-process verdict map (None when there is no preceding verdict to join on; see `layer3_airlock.md § Adapter mapping — correlation_id`). **No `raw_payload` / `extra` catch-all** — the v1.0.0 contract is exhaustive; any field the policy module needs must be named in the schema. Adapter-internal scratch data does not survive into `SessionEvent`.
- `class SessionAdapter(Protocol)` — `def parse(line: str) -> SessionEvent | None`; per-CLI implementation.
- `class Reader(volume: Path)` — tail-safe JSONL reader over the volume airlock mounts; supports both offline (read-and-close) and live (tail-with-poll) modes.
- `class RuleEngine(rules: list[Rule])` — evaluates events against the rule set; returns `RuleHit(rule_name, action, evidence)` or `None`.
- `class Rule` — YAML-loadable; fields `name`, `when` (predicate over `SessionEvent`), `action` (`Action` instance), `cooldown_seconds` (anti-flap).
- `class Action(Protocol)` — `def run(hit: RuleHit, event: SessionEvent) -> None`.
- `class LogAction` (YAML key: `log`) — implements `Action`; emits a `rule_hit` audit event via interlock and a metric.
- `class BlockAction` (YAML key: `block`) — stubbed (v2 Soft; `NotImplementedError("BlockAction is v2")`); contract documented in docstring. See [v2 spec](#v2-spec) for the flag-file + Stop-hook mechanism.
- `class KillAgentContainerAction` (YAML key: `kill_agent_container`) — stubbed (v2 Hard; `NotImplementedError("KillAgentContainerAction is v2")`); kills the agent container via the container runtime. Replaces a slice of the earlier `VentAction`.
- `class SeverEgressAction` (YAML key: `sever_egress`) — stubbed (v2 Hard; `NotImplementedError("SeverEgressAction is v2")`); disconnects the agent container from its egress network. Replaces a slice of the earlier `VentAction`.
- `class FreezeWorkspaceAction` (YAML key: `freeze_workspace`) — stubbed (v2 Hard; `NotImplementedError("FreezeWorkspaceAction is v2")`); remounts the agent workspace bind-mount read-only without killing the container. Replaces a slice of the earlier `VentAction`.

The YAML `action:` key is the class name with the `Action` suffix dropped and the remainder snake-cased (matching the case style of the rest of the YAML — `event_type`, `cooldown_seconds`, etc.). The shape is **verb-noun**: the verb names the operator-level intent (`kill`, `sever`, `freeze`); the noun names the explicit operational target using airlock's existing vocabulary (`agent_container`, `egress`, `workspace`) — never a category like "process" that could mean container, agent CLI, or subprocess. `action: kill` would be ambiguous to a rule author (kill what?); `action: kill_agent_container` is not. The class-name and YAML-key vocabularies are therefore the same verbs and nouns in the same order, only the case differs.

### Rule DSL

YAML rules consumed by `RuleEngine.load(rules_file)`. Example:

```yaml
- name: bash_rm_rf_root
  when:
    event_type: tool_call
    args.tool: Bash
    args.command:
      matches: '\brm\s+-rf\s+/'
  action: log
  cooldown_seconds: 60

- name: read_aws_credentials
  when:
    event_type: tool_call
    args.tool: [Read, Bash, Grep]
    args.file_path:
      contains: '/.aws/credentials'
  action: log

- name: classifier_unavailable_burst
  when:
    event_type: audit
    audit_event: classifier_unavailable
  threshold:
    count: 10
    window_seconds: 300
  action: log
```

DSL primitives:

- **Predicates over event fields**: equality, set membership (`[A, B, C]`), `contains`, `matches` (regex), `gt` / `lt` for numeric.
- **AND-of-predicates by default**; `any: [...]` for OR.
- **Threshold counters**: `threshold: {count, window_seconds}` for burst detection.
- **Cooldowns**: `cooldown_seconds` prevents the same rule from firing repeatedly within a window.
- **Action keys**: snake_case tokens that resolve to `Action` implementations. v1 ships `log`. v2 adds `block` (Soft) and the three Hard tokens `kill_agent_container`, `sever_egress`, `freeze_workspace`. See [Module API](#module-api) for the class-to-key mapping.

**No model calls. No embedding lookups.** The DSL is intentionally tiny and inspectable.

### Module map

Lives inside interlock's source tree at `src/interlock/policy/`:

```
src/interlock/policy/
├── __init__.py
├── config.py                   # jettisonSettings
├── events.py                   # SessionEvent dataclass
├── adapters/
│   ├── __init__.py             # SessionAdapter protocol
│   ├── claude.py               # Claude Code transcript parser
│   └── copilot.py              # Copilot session JSON parser
├── reader.py                   # Tail-safe JSONL reader
├── rules.py                    # Rule, RuleEngine, predicates, thresholds, cooldowns
├── actions.py                  # Action protocol, LogAction; BlockAction (Soft) + Kill/Sever/Freeze (Hard) stubs
└── cli.py                      # session-audit, session-watch, rules-lint — wired into `tidereach interlock` per Decision 16
```

Adjacent in interlock's tree: `src/interlock/audit/` (AuditChain), `src/interlock/freeze/` (FreezeManager), `src/interlock/squid/` (SquidAccessReader). The policy module imports from these directly — same process, no IPC. See `layer0_interlock.md § Policy module` for interlock's perspective on the merge.

### CLI

`tidereach interlock` umbrella subcommand surface (the policy module's subcommands live under `tidereach interlock` per the 2026-06-29 merge into interlock — see § Deployment below and `layer0_interlock.md § Policy module`). Versioned via `tidereach interlock --api-version`.

| Subcommand | Function |
|---|---|
| `session-audit <path>` | Offline: read a JSONL transcript file or directory; print rule hits + summary. |
| `session-watch <volume>` | Live: tail `$SESSION_DIR` (or the supplied path); emit rule hits as they fire. |
| `rules-lint <rules.yaml>` | Validate a rules file against the schema; report unreachable rules / cooldown conflicts. |

### Settings (`jettisonSettings`)

| Field | Type | Default | Policy |
|---|---|---|---|
| `session_streams_dir` | `Path` | `/work/session-streams` | yes |
| `rules_file` | `Path` | `~/.tidereach/jettison-rules.yaml` | yes |
| `actions` | `list[str]` | `["log"]` | yes |
| `block_enabled` | `bool` | `False` | yes (v2 Soft) |
| `kill_agent_container_enabled` | `bool` | `False` | yes (v2 Hard) |
| `sever_egress_enabled` | `bool` | `False` | yes (v2 Hard) |
| `freeze_workspace_enabled` | `bool` | `False` | yes (v2 Hard) |
| `block_flag_dir` | `Path` | `${SESSION_DIR}` | yes (v2 Soft) |
| `tail_poll_interval_seconds` | `float` | `1.0` | no |
| `rule_eval_timeout_ms` | `int` | `100` | yes |

Precedence: kwargs > env (`INTERLOCK_*`) > TOML (`[interlock]`) > defaults. The policy module's fields share interlock's `INTERLOCK_*` env namespace and `[interlock]` TOML section per the 2026-06-29 merge — one process, one prefix family. Field names are designed not to collide with interlock's own settings (e.g., `INTERLOCK_RULES_FILE` is unambiguously the policy rules file; interlock owns no other `rules_file`). The `jettisonSettings` dataclass remains a separate group within the codebase for cohesion, but reads from the same TOML section / env prefix as `interlockSettings`.

### Audit events owned

- `session_event_seen` — diagnostic; emitted at `--debug` level only (per-event is too noisy for routine production).
- `rule_hit` — primary event; carries `rule_name`, `action`, `event_summary` (event_type + tool name + session_id — never raw args), and `correlation_id` (the arbiter `context_id` the originating event was joined to; `None` when the joining missed). Including `correlation_id` lets downstream consumers correlate a `rule_hit` back to the arbiter verdict that authorised the tool call.
- `action_logged` — emitted by `LogAction.run()` confirming the action fired.
- `jettison_baseline_drift` — v2 hook; emitted when the rule engine's metrics differ significantly from a recorded baseline (#117 baseline policy doc defines).
- `block_flag_written` — v2 Soft; emitted by `BlockAction.run()` after the per-session flag file is written.
- `kill_agent_container_initiated` — v2 Hard; emitted by `KillAgentContainerAction.run()` *before* the container kill is issued (the chain captures the decision even if the container dies mid-flush).
- `sever_egress_initiated` — v2 Hard; emitted by `SeverEgressAction.run()` *before* the network disconnect is issued.
- `freeze_workspace_initiated` — v2 Hard; emitted by `FreezeWorkspaceAction.run()` *before* the workspace remount is issued.

### Cross-layer contracts honoured

- **Reads** the session-stream substrate airlock mounts at `$SESSION_DIR`. Honours the `session-stream-jsonl/v1` contract in interlock.
- **Writes** events through interlock's `AuditChain.append` directly — the policy module is in-process with `AuditChain`, so no IPC envelope is required. Honours the `audit-envelope/v1` contract; never writes raw event args into the audit envelope (labels and rule names only).
- **No Settings overlap with sieve** — `jettisonSettings` and `sieveSettings` share zero fields. Both are loaded by interlock's startup; `jettisonSettings` is the policy module's settings group within the interlock process.
- **Hard actions invoke container-runtime primitives directly from interlock's process** — the policy module does not exec into the agent container; instead it calls `podman network disconnect` / `podman kill` / `podman exec <airlock-supervisor> remount` from the host. The container-runtime invocation contract (which binary, which arguments per action) is co-owned with airlock and documented under airlock's runtime-API surface; jettison v2 is the consumer.
- **Soft `BlockAction`** writes a flag file at `${block_flag_dir}/<session_id>.blocked` (default `${SESSION_DIR}/<session_id>.blocked` — co-located with the session stream, so it lives on the same volume the agent CLI already sees). The dedicated Stop-hook script (`integrations/.../tidereach-block-hook`, in the meta-repo) lstats the path on Stop fire (same family of construct as the FREEZE file: lstat-only check, mode 0600, owner == EUID). **Assumption**: the Stop hook script runs inside the agent container (the substrate volume is mounted at the same path the policy module sees). For agent CLIs where the Stop hook runs outside the container, a host-side flag-file mirror is required — open question in v2.

### Verification

- **Unit**: every adapter parses its fixture transcripts correctly; the rule engine evaluates the canonical rule set against fixture events; `LogAction.run()` emits the documented audit event.
- **No-model-call assertion**: CI grep-asserts no `httpx` / `requests` / `httpcore` / `ollama` imports in `src/interlock/policy/` — deterministic-only invariant.
- **Integration**: a fixture Claude Code session writing into a fixture `$SESSION_DIR` directory; `tidereach interlock session-audit` against the directory produces the expected rule hits.
- **Live**: `tidereach interlock session-watch` tails a live agent run inside airlock; rule hits emit log lines within `tail_poll_interval_seconds` of the event landing.
- **Rules lint**: `tidereach interlock rules-lint` against the v1 baseline rule set passes; against a deliberately broken rule (unknown predicate, missing action) fails with a clear error.
- **`docs/JETTISON.md` ships** in the v1 release (closes #117).

---

## v2 spec

v1 ships `LogAction` only. v2 adds one Soft action and three Hard actions; each is independently opt-in.

### Soft action (cooperative)

- **`BlockAction`** — cooperative: the agent CLI is asked to finish what it's doing on the next Stop boundary. Mechanism: the policy module writes a flag file at `${block_flag_dir}/<session_id>.blocked` (default `${SESSION_DIR}/<session_id>.blocked`); a dedicated thin Stop-hook script delivered from the **meta-repo** (proposed path `integrations/<cli>/hooks/tidereach-block-hook` or analogous; bin-name TBD) lstats the flag on Stop fire and returns the documented JSON shape the agent CLI interprets as "refuse this Stop." Mode-0600, owner==EUID lstat invariants mirror the FREEZE file. Operator opt-in (`block_enabled=True`); emits `block_flag_written` audit event after the file is fsynced. **The Stop-hook script is NOT hosted in sieve** — sieve owns UserPromptSubmit / PreToolUse / PostToolUse; not Stop. It is also not hosted in interlock — interlock writes the flag but the integration surface (a Stop hook installed into the agent CLI's settings) is meta-repo glue.

### Hard actions (non-cooperative)

Each Hard action exercises a container-runtime primitive directly from interlock's process. All emit a pre-action audit event before invoking the runtime so the chain captures the decision even if the action takes the container down.

- **`KillAgentContainerAction`** — kills the agent container. Operator opt-in (`kill_agent_container_enabled=True`); mechanism: `podman kill <container>` against the `agent` compose service. Emits `kill_agent_container_initiated` before. Documented rollback: operator restarts with `podman compose up agent`.

- **`SeverEgressAction`** — disconnects the agent container from its egress network (the route to the Squid proxy). Operator opt-in (`sever_egress_enabled=True`); mechanism: `podman network disconnect <network> <container>` (preferred) or iptables rule injection on the proxy host (fallback). The proxy container itself is left running so its access log keeps producing audit envelopes via interlock's `SquidAccessReader`. Emits `sever_egress_initiated` before. Documented rollback: `podman network connect` once the operator clears the session.

- **`FreezeWorkspaceAction`** — remounts the agent workspace bind-mount read-only without killing the container. Operator opt-in (`freeze_workspace_enabled=True`); mechanism: `podman exec <airlock-supervisor> mount -o remount,ro /work` (or equivalent helper supplied by airlock; co-owned contract). Distinct from interlock's session-level `FreezeManager` — this freezes the workspace mount, not the session. Emits `freeze_workspace_initiated` before. Documented rollback: operator remounts rw and restarts the agent.

Per-session escape hatch (`--no-hard` flag on the session, recorded in audit) suppresses all three Hard actions for a known-benign session.

### Other v2 items

- **Live `session-watch` daemon supervision** — systemd unit / launchd plist ships in the v2 release; documented operator install path. As of the 2026-06-29 merge, `session-watch` is an `interlock` subcommand, not its own binary.
- **jettison baseline audit + drift detector** (#117 v2) — records the rule-engine's metric baseline; raises `jettison_baseline_drift` when current metrics diverge by configurable thresholds.
- **Richer DSL primitives** — sequence rules (event A then event B within window), session-level aggregations (events per session_id), regex capture groups feeding subsequent predicates.

---

## Verification

(Stage 2 gate alongside interlock's L0 surface per the 2026-06-29 layer-4 collapse; mirrors `MAIN.md § 12 Per-stage product specs`. Live-airlock verification of the policy module happens at the Stage 6 cross-repo soak — was Stage 7 pre-collapse.)

- [ ] Adapter unit tests for Claude Code + Copilot transcripts green.
- [ ] Rule engine evaluates the canonical rule set deterministically; predicates only (no model calls).
- [ ] CI grep-assertion: no LLM / HTTP-client imports in `src/interlock/policy/`.
- [ ] `tidereach interlock session-audit <fixture-transcript>` produces expected rule hits per fixture.
- [ ] `tidereach interlock session-watch` tails a live agent run and emits log lines within the documented latency window.
- [ ] `tidereach interlock rules-lint` passes on the v1 baseline ruleset.
- [ ] `docs/JETTISON.md` exists in the meta-repo (`tidereach/hull/docs/JETTISON.md`); closes the pre-split #117 promise.
- [ ] interlock `AuditChain` integration: `rule_hit` events appear in the chain; `audit-verify` reports no breaks.
- [ ] Cross-layer e2e (Stage 6 soak; was Stage 7 pre-collapse): a airlock-confined agent run writes JSONL into `$SESSION_DIR`; the policy module detects the seeded suspicious turn; interlock's audit chain captures the `rule_hit` event.

---

## Out of scope

- **Real-time per-token interception** — Stop / per-event boundary is the contract; no inline streaming interception.
- **Sensitive-content scanning** — sieve does this at PostToolUse.
- **LLM-based detection** — deliberately excluded; sieve owns the LLM. jettison's value proposition is determinism.
- **Session-stream substrate provisioning** — airlock mounts the volume; jettison reads from it.
- **Audit chain management** — interlock.
- **Intent rules / control engine** — arbiter.
- **Running outside a airlock substrate** — jettison requires the mounted volume or an operator-equivalent (e.g., a bind-mount with the same path contract).
- **Rule-set distribution / federation** — operator concern in v1; community rule sets may emerge but are not part of the jettison release.

---

## Open questions for v2

- **Hard-action escalation defaults** — block-then-Hard (first the cooperative `BlockAction`, then a Hard action on a retry) vs Hard-only (skip the cooperative attempt for high-severity rules). Operator preferences will guide the default.
- **Rule DSL evolution** — YAML + Python predicates (current shape) vs CEL (the Common Expression Language) vs OPA-Rego. CEL has stronger sandboxing for operator-written rules but adds a runtime dependency.
- **Per-session-ID volume scoping** — for parallel agent runs, should the substrate use per-session subdirectories? airlock v2 question; jettison follows.
- **BlockAction interaction with arbiter** — if arbiter's engine has already issued an `ask` verdict for a tool call, and jettison subsequently fires `BlockAction` for the corresponding Stop, does the user see two prompts? Coordinate with arbiter v2.
- **Block-flag path** — current spec: `${SESSION_DIR}/<session_id>.blocked`. This works **only if** the Stop-hook script runs inside the agent container (substrate volume visible at the same path). For agent CLIs where Stop hooks run on the host, a host-side mirror path is required and must be reconciled with airlock's volume conventions. Confirm per CLI before v2 ships.
- **Stop-hook script bin-name and install path** — proposed `bin/tidereach-block-hook` in the meta-repo; or `integrations/<cli>/hooks/<n>` matching the existing per-CLI integration layout. Choose at v2 design time.
- **Airlock runtime-API contract for Hard actions** — co-owned contract between interlock's policy module and airlock for the exact runtime commands invoked (`podman network disconnect ...`, `podman kill ...`, `podman exec ... remount ...`). Owner: airlock's runtime-API surface, with a schema in interlock's `contracts/` directory. Must land before any Hard action ships.
- **Should jettison ship sample rule sets** for common scenarios (data-exfil patterns, prompt-injection telltales, anomalous tool combinations), and if so, who curates them?
