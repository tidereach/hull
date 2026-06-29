# interlock — L0 Attestation / Glue

> **Layer name:** interlock.
> **Plane:** Attestation / glue (L0).
> **Repo:** `tidereach/interlock`.
> **Status:** Migration spec; greenfield rebuild planned.

interlock is the layer that ties the four endpoint-stack planes together. It owns hash-pinning, supply-chain verification, the hash-chained audit log, the freeze switch, the canary corpus harness, anomaly counters, heartbeat, and the cross-layer contracts directory. Every other layer's CI calls into interlock to answer "is this endpoint configured to run the stack safely?"

Read [`MAIN.md`](MAIN.md) first; it sets the architecture, the decisions, and the execution order. This file is interlock's slice.

---

## Mission

interlock owns the cross-cutting integrity surface that every other plane targets. Concretely:

- **Hash-pinning** for every component whose change would alter stack verdicts: pattern table, model digest, prompt template, sandbox config files, hook manifests, dependency lockfile.
- **Supply-chain verification**: `verify-installed [--strict]` compares `pip freeze --all` (and optionally re-runs `pip install --require-hashes --dry-run`) against `requirements.lock`.
- **Hash-chained audit log** with `seq`, `prev_hash`, `record_hash`, wall + monotonic time, persisted across process restarts via `~/.tidereach/audit.state` (fsync + atomic rename).
- **Audit sinks** with detection-based default (journald > syslog > append-only file > stdout).
- **Freeze switch**: the file at `~/.tidereach/FREEZE` whose presence forces every guarded call to block immediately. Lstat-only checks; anomalous-mode handling.
- **Canary corpus harness**: runs a layer's scan / verify routine against known-bad / known-safe / random-nonced payloads; drift auto-freezes the stack.
- **Anomaly counters**: rolling-window counts of `classifier_unavailable`, `framing_disagreement`, `canary_drift`, etc.; threshold-driven auto-freeze.
- **Heartbeat emission**: periodic audit events that confirm the stack is alive and the pinned hashes unchanged.
- **Hook integrity manifest**: SHA-256 digest of every installed hook script + per-call Ed25519 identity proofs.
- **Cross-layer contracts directory**: `contracts/` holds JSON schemas + Markdown explainers for every protocol other layers exchange.

interlock does **not** own: content scanning (sieve), container runtime / proxy / Landlock policy (airlock), intent rules (arbiter). interlock **does** host layer-4 (visibility plane) code in-process as of the 2026-06-29 merge — session-stream ingest, deterministic rule evaluation, and action dispatch live in `src/interlock/policy/`; see [Policy module](#policy-module) and `layer4_jettison.md § Deployment`. interlock is the glue *and* the visibility-plane host; the other three planes (data, control, execution) are sibling repos.

v1 ships runtime preflight. v2 adds opt-in cryptographic attestation (Ed25519-signed manifests, sigstore/cosign verifier, key rotation).

---

## Scope decision history

References [`MAIN.md § 7 Decisions locked`](MAIN.md#7-decisions-locked):

- **Row 1 (L0 scope = preflight + opt-in attestation)**: v1 = preflight (`verify-*`, `check-*`, audit, freeze, canary, anomaly, heartbeat). v2 = attestation (Ed25519, sigstore, key rotation). One product, two phases. Ships sooner than a full attestation framework; the attestation hook surface lands in v1 so v2 builds on it without re-architecting.
- **Row 3 (interlock owns `contracts/`)**: contracts are attestation surface — they describe what each layer must conform to in order for the others to trust its output. interlock already owns hashing and signing; adding the contract directory is the smallest extension.
- **Row 4 (open issues roll into specs)**: issues #55-59 (hook known issues), #117 (jettison baseline policy doc) inform interlock's `hook-check` and `verify-hooks` design; not lifted, but their lessons drive the spec.
- **Row 8 (per-layer-file review)**: this file is reviewable standalone; MAIN.md sets architecture, interlock documents its own slice.

interlock is **Stage 2** in MAIN.md's execution order — first layer to ship after the meta restructure (Stage 1) because every other layer's CI references interlock contracts.

---

## Pre-parallel-work sequencing

The five layer specs can be drafted in parallel, but several artifacts must be locked first. Without them, independent teams make locally-reasonable decisions that conflict at integration.

1. **`contracts/integrity-inputs/v1.0.0/`** — canonical `HashInput` names plus a one-line serialization spec for each. This is the coordination point: sieve, airlock, arbiter, and jettison each implement `HashInput` against this contract. Without it, two teams produce different bytes for the same logical input and `model_swap_detected` fires spuriously.

2. **`governance/audit-event-ownership.md`** — which layer owns which audit events. interlock's list (see [Audit events owned](#audit-events-owned)) uses a two-tier model: **layer-exclusive events** (e.g., `gate_frozen_auto`, `heartbeat`, `chain_*`, `canary_drift`) where no other layer may emit them, and **cross-layer shared-namespace events** (e.g., the four `ollama_*` trust events) which are defined by interlock but emitted by sieve. Other layers must not emit layer-exclusive events; cross-layer events must match the interlock-defined schema. This constraint belongs in the contracts package, not only in interlock's lessons section.

3. **`governance/freeze-manager-constraint.md`** — the `FreezeManager` sole-emitter constraint, written once and cited by all four other specs. No layer except interlock emits `gate_frozen_auto`. Layers call `anomaly_counter.bump()` only; interlock decides whether to freeze.

4. **`governance/composition.md`** — the hook-chain composition contract: layer ordering at PreToolUse / PostToolUse, the OR-to-block invariant, `ask` ownership (arbiter's engine only; sieve stays deny-or-allow at PreToolUse), layer-absence policy, and which layers participate in which hook types. **Stage 5-blocking specifically**: arbiter's `SPEC.md` cites this contract by name and does not duplicate its rules. Without it, arbiter's "per the layer0 composition contract" reference has no target and the rule has no canonical home.

5. **`governance/layer-constraints.md`** — the import isolation contract: no layer's production code imports another layer's code directly; interlock's `contracts/` directory is the only valid cross-layer dependency path; any new cross-layer protocol must create a schema file in `contracts/` before the consuming layer pins to it. **Stage 3-blocking**: without this, independent teams make locally-reasonable import decisions (e.g., the `integrity.py:14-15` leak that the migration is explicitly designed to prevent — see `MAIN.md § 6` table).

6. **`contracts/session-stream-jsonl/v1.0.0/`** — the v1.0.0 record schema as committed in [`Contracts directory § session-stream-jsonl/v1.0.0 schema commitment`](#session-stream-jsonlv100-schema-commitment) above. **Stage 2-release-blocking specifically**: the policy module's `SessionEvent` shape, the layer3 Per-CLI adapter-mapping table, and the layer4 `rule_hit` payload (which carries `correlation_id`) all depend on the schema as written. Without the schema file pinned at v1.0.0 before Stage 2 cuts its release, Stage 3+ layer development desyncs on the policy-module surface (per the 2026-06-29 layer4 ember review, Pivot 3). interlock must ship this contract file in Stage 2 alongside the others.

Items 1, 2, 3, 5, and 6 must exist before any layer can begin Stage 3 (items 1–3, 5 gate Stage 3 generally; item 6 gates the policy module's contract surface and therefore must also be locked at Stage 2 release). Item 4 (`composition.md`) must exist before arbiter's `SPEC.md` is finalised in Stage 5; it is listed here because the composition contract is interlock-owned and its absence creates the same coordination failure as the Stage-3 blockers.

---

## Doc audit

| Doc | Disposition for interlock | Notes |
|---|---|---|
| `docs/SPEC.md` §§12, 13.1, 13.2, 13.4 | **Rewrite** | Rewrite per spec; the pre-migration invariants on hash construction, audit sink detection, anomaly thresholds, and freeze file lstat are interlock's contract surface and carry forward unchanged in meaning. |
| `docs/SPEC.md` §13.3 | **Rewrite** | Rewrite per spec; the pre-migration canary corpus structure (known-bad / known-safe / random-nonced) guides the design. Interlock owns the runner; layers provide the scan callable. |
| `docs/SPEC.md` §17 | **Rewrite** | Rewrite per spec; apply the interlock/sieve CLI split as part of the rewrite (interlock owns `verify-*`, `check-*`, `hook-*`, `audit-*`, `freeze`, `unfreeze`, `stats`). |
| `docs/ENDPOINT_STACK.md` § Cross-layer integrity + Wiring into Spektralia's preflight | **Rewrite** | Rewrite per spec; the pre-migration section is the canonical statement of interlock's role in the stack and shapes the rewrite. Apply the `Spektralia` → `Tidereach` rename in the new section heading (the pre-migration doc predates Decision 15). |
| `docs/ENDPOINT_STACK.md` § Visibility plane | **Rewrite** | Audit envelope as the cross-plane visibility surface; cite from interlock. |
| `docs/COMPLIANCE.md` §21 OWASP table | **Drop duplicate** | Currently copies `docs/SPEC.md §21`. interlock's spec references SPEC.md; no copy. |
| `docs/COMPLIANCE.md § Audit log as personal data` | **Rewrite** | GDPR obligations on the audit log; interlock owns retention (`audit-rotate`) and erasure (`audit-purge`) under data minimisation. |
| `docs/THREATS.md § Tampering with the gate itself` | **Rewrite** | Load-bearing motivation; interlock's pattern_hash + model_digest + prompt_hash + hash-chained audit + canary directly answer this section. |
| `docs/RATIONALE.md` v3 § Supply-chain integrity / Anomaly / Audit chain | **Rewrite** | Rewrite per spec; the pre-migration v3 narrative is the rationale source and is re-summarised in interlock's `RATIONALE.md`. |
| `docs/RATIONALE.md` v4 § Ollama trust + § Filesystem state + § Operational proof | **Rewrite** | Rewrite per spec; the UDS + lstat + heartbeat rationale carries forward. Ollama trust lives in sieve, but interlock's `check-ollama` references the rewritten rationale. |
| `AGENTS.md` Gotchas — `hook-check checks both global and project settings` | **Rewrite** | Invariant; both `~/.claude/settings.json` and project `.claude/settings.json` scanned. |
| `AGENTS.md` Gotchas — `SBOM is generated from requirements.lock` | **Rewrite** | Critical invariant; never run `cyclonedx-py environment` for committed SBOMs. |
| `AGENTS.md` Gotchas — `recheck is not on PyPI` | **Rewrite** | interlock CI uses pure-Python timeout assertion. |
| `docs/SANDBOX_ALTERNATIVES.md § Wiring it into Spektralia's preflight` | **Rewrite** | Rewrite per spec; the pre-migration section defines `check-sandbox` behaviour and the operator-facing bypass. Apply two renames as part of the rewrite: `SPEKTRALIA_SANDBOX_OFFLINE` → `AGENT_SANDBOX_OFFLINE` (parallels `AGENT_CLI` / `AGENT_PIDS_LIMIT` operator-facing env vocabulary; mental model is "the agent's sandbox is offline" rather than "the project is offline"); and section heading "Spektralia" → "Tidereach" per Decision 15. |
| `docs/PLAN.md § Phase 1 carry-overs` (#1, #4) | **Rewrite** | Rewrite per spec; carry-overs #1 (NFKC offset map) and #4 (`PR_SET_DUMPABLE` at import) belong to sieve. Interlock docs reference the rewritten sieve carry-over text for completeness. |
| `docs/PLAN.md § Hook known issues #55-59` | **Rewrite** | Rewrite per spec; each pre-migration issue informs a specific `hook-check` / `verify-hooks` invariant in interlock v1, and the issues close on Stage 2 cut. |

**Doc reconciliation tasks**:

1. `docs/COMPLIANCE.md §21` deduplication is a Stage 1 (meta) task; interlock's Doc audit references SPEC.md directly.
2. `docs/ENDPOINT_STACK.md` Fence-vs-cplt-sndbx prose is a Stage 1 / Stage 4 task; interlock's `check-sandbox` does not need to know which backend won — it asserts the configured backend.

---

## Lessons learned

Each: *what we learned — how it shapes v1*.

- **`integrity.py:14-15` reaches into L1** by importing `.classifier.PROMPT_HASH` and `.patterns.PATTERNS` directly. *Lesson:* interlock must not depend on the specific scanner runtime to compute hashes. *v1:* define a `HashInput` protocol (`name: str`, `bytes_for_hash() -> bytes`); sieve / airlock / arbiter each provide a `HashInput` impl; interlock hashes bytes. Closes the L0→L1 leak the current monolith carries.

- **`gate_frozen{_auto}` audit events emit from L1's `gate.py`** but represent interlock-owned freeze state. *Lesson:* freeze is a interlock concern; emission of freeze-related events must live with the manager that decides the freeze. *v1:* `FreezeManager` lives in interlock and is the sole emitter of `gate_frozen`, `gate_frozen_auto`, `freeze_file_anomalous`. sieve calls `FreezeManager.check()` first thing in `gate()`.

- **`audit.state` fsync + atomic rename is correct but undocumented in failure modes**. The current implementation handles the happy path; what happens after a `kill -9` during the fsync window is implicit. *Lesson:* state-file corruption is a real risk and the operator needs a documented recovery path. *v1:* `tidereach interlock audit-repair --confirm` re-anchors the chain from the last verifiable record with an explicit `chain_anchor_after_repair` event; documented in interlock's README under "Disaster recovery."

- **`recheck` was added to CI without verifying it exists on PyPI** (it doesn't). The current `redos-fuzz.yml` workaround is a pure-Python timeout assertion. *Lesson:* CI tooling must be validated against a fresh venv install before landing in workflow YAML. *v1:* interlock's nightly ReDoS fuzz job uses the same pure-Python timeout assertion (`AssertionError` if any pattern exceeds 500ms wall-clock); no `recheck` dependency.

- **`canary_interval_seconds` declared in `Settings` but never read** in production code. The intent (periodic canary scheduling) was never wired into `gate.py._run_canary`. *Lesson:* dead Settings fields rot, silently. *v1:* every `interlockSettings` field has a test that grep-asserts at least one production read; CI fails on a stale field.

- **`verify-installed` at SessionStart catches lockfile drift but not non-`--require-hashes` installs**. An operator who does `pip install -e .` rather than `pip install --require-hashes -r requirements.lock` ships a verifiably-OK lockfile while running a hash-unverified environment. *Lesson:* assert install posture, not just file contents. *v1:* `verify-installed --strict` re-runs `pip install --require-hashes --dry-run -r requirements.lock` and asserts zero diff against the active env; documented as the default for CI / SessionStart.

- **Issues #55-59 (hook known issues)** all reduced to "the SessionStart preflight didn't catch a real misconfiguration": self-scan FP, empty-categories block, UnboundLocalError without venv, wrong JSON output shape, `Task` vs `Agent` tool name. *Lesson:* `hook-check` must assert matcher count and tool-name accuracy, not just file existence. *v1:* each integration hook ships with a canonical fixture (matcher set + tool-name set); interlock's `hook-check` compares to the fixture; drift fails the check.

- **`hook_manifest.py` introduced post-v1** as a layered Ed25519 identity proof. The hash-only check is mode `warn` by default; Ed25519 is opt-in. *Lesson:* identity proof must degrade gracefully on missing keyring / missing `crypto` extra. *v1:* interlock `verify-hooks` honours the same three modes (`off` / `warn` / `block`); the manifest format documented in `contracts/hook-manifest/`.

- **The audit chain currently re-anchors silently on first-ever start.** No `GENESIS` event is emitted; the first record's `prev_hash` is just the empty/analyzer value. *Lesson:* every chain transition deserves an explicit event so `audit-verify` can interpret it. *v1:* `chain_genesis`, `chain_anchor_after_rotate`, `chain_anchor_after_purge`, `chain_anchor_after_repair` are all real audit events with their own enum value.

- **Heartbeat currently emits via `gate.py:347` only.** A scanner-only import path (e.g. the legacy `spektralia scan-config` binary, which becomes `tidereach sieve scan-config` post-migration) never starts a heartbeat. *Lesson:* heartbeat is a per-process concern that should be owned by interlock, started by whoever needs it. *v1:* `interlock.Heartbeat(interval_seconds, every_n_calls)` is a context manager; any layer that wants liveness signal starts one explicitly.

---

## Reuse table

100% ready filter applied per file. All implementation work is greenfield: `Rewrite` dispositions are authored against this layer's spec text (informed by the pre-migration source, but never copied from it). Tests, package shells, configs, CI helpers, and fixture payloads are likewise authored greenfield. See `MAIN.md § 8 Constraint 2`.

| Source (current) | Disposition | Notes |
|---|---|---|
| `src/spektralia/audit.py` | **Rewrite** | Clean leaf, pure stdlib; the pre-migration hash-chain + sink abstraction + persistence semantics inform the rewritten contract. |
| `src/spektralia/anomaly.py` | **Rewrite** | Clean leaf, pure stdlib; rewrite drops the `canary_interval_seconds` field-read (there is none). |
| `src/spektralia/hook_manifest.py` | **Rewrite** | Pure stdlib; the pre-migration SHA-256 manifest + Ed25519 identity proof contracts are correct and guide the rewrite. |
| `src/spektralia/sandbox.py` | **Rewrite** | Pure stdlib; rewrite retargets the cplt-sndbx hash check at airlock's release tag in the config. |
| `src/spektralia/canary/__init__.py` | **Rewrite** | Rewrite per spec; the pre-migration runner function's shape guides the design (runner accepts a `scan` callable; interlock owns the runner, layers provide `scan`). The current `gate.py:_run_canary` call site becomes the contract. |
| `src/spektralia/heartbeat.py` | **Rewrite** | Sole caller is `gate.py` (L1); reshape as a interlock-owned context manager any layer can start. The current TYPE_CHECKING-only intra-pkg deps reduce on rewrite. |
| `src/spektralia/integrity.py` | **Rewrite** | Breaks the L1 leak; takes hash-source via the `HashInput` protocol; rewrites the byte-hashing arithmetic per spec, preserving the bit-for-bit construction. |
| `src/spektralia/cli.py` (interlock subset) | **Rewrite** | New `cli.py` for the 17 interlock subcommands; the pre-migration argparse skeleton informs the structure, but subcommand bodies are authored greenfield against interlock's service objects. |
| `src/spektralia/config.py` (interlock fields) | **Rewrite** | New `interlockSettings` dataclass; rewrite the `from_env` / `from_toml` / `config_hash` pattern per spec; the 13 interlock fields move; the `_non_policy` set is a per-layer concern. |
| `scripts/check_lock_sbom_fresh.py` | **Rewrite** | CI helper; stdlib + minimal subprocess. Pre-migration script's structure guides the rewrite. |
| `scripts/audit_hook_invariants.py` | **Rewrite** | CI helper; stdlib. Pre-migration script's structure guides the rewrite. |
| `scripts/redos_fuzz.py` | **Drop from interlock** | Belongs in sieve (ReDoS is a regex/pattern concern). interlock's nightly job uses the pure-Python timeout assertion in its own CI. |
| Tests (`tests/test_audit_chain.py`, `test_audit_no_values.py`, `test_audit_extra.py`, `test_anomaly.py`, `test_canary.py`, `test_integrity.py`, `test_hook_manifest.py`, `test_sandbox.py`, `test_sandbox_cplt_sndbx.py`, `test_heartbeat.py`) | **Rewrite** | Tests reference the unified `Settings`; greenfield rewrite against `interlockSettings`. Corpus payloads and audit-record fixtures are likewise re-authored greenfield against the new fixture format. |
| Test fixtures in `tests/corpus/` | **Rewrite** | Re-authored greenfield. The canary positive/negative/injection payloads (currently empty in the pre-migration repo) are pure data; interlock's canary harness consumes them. Coordinated with sieve (which seeds them as part of Stage 3). |

---

## v1 spec

### Public API

A Python library exposing the following classes / functions. No global state; every object is explicit-construct.

- `FreezeManager(settings: interlockSettings, anomaly_counter: AnomalyCounter)` — `.check()` polls anomaly rates and triggers auto-freeze if thresholds are exceeded, then checks the freeze file; `.freeze()` / `.unfreeze()` / `.is_frozen() -> bool`. Layers call `anomaly_counter.bump()` only; `FreezeManager` is the sole emitter of `gate_frozen_auto`.
- `AuditChain(sink: AuditSink, settings: interlockSettings)` — `.append(record: AuditRecord) -> None`; `.verify(path: Path) -> VerifyResult`; persists last `record_hash` to `audit.state`.
- `AuditSink` (protocol) with `JournaldSink`, `SyslogSink`, `AppendOnlyFileSink`, `StdoutSink` impls. Default chosen by `_choose_sink()` detection.
- `IntegrityHasher` — `.compute(*inputs: HashInput) -> dict[str, str]` mapping name → hex digest. Zero inputs returns empty dict (defined behavior, not implicit).
- `HashInput` (protocol) — `name: str`, `bytes_for_hash() -> bytes`.
- `FileHashInput(name: str, path: Path)` — concrete `HashInput` impl shipping with interlock v1; reads raw file bytes. The standalone default for `verify-integrity`; other layers provide richer impls.
- `AnomalyCounter(window_seconds: int)` — rolling counters; `.bump(event_name)`; `.rate(event_name) -> float`.
- `Heartbeat(interval_seconds, every_n_calls)` — context manager; emits `heartbeat` audit events.
- `Canary(scan: Callable[[str], list[Detection]], corpus_dir: Path)` — `.run() -> CanaryResult`; `.drift_detected -> bool`.
- `HookManifest(manifest_path: Path, mode: Literal["off","warn","block"])` — `.verify() -> ManifestVerifyResult`.
- `SandboxCheck(backend: str, config_paths: list[Path], config_hash: str | None)` — `.run() -> CheckResult`.
- `OllamaCheck(url: str)` — `.run() -> CheckResult`; thin HTTP ping (no full classifier client).
- `EngineCheck(socket_path: Path)` — `.run() -> CheckResult`; probes arbiter's IPC.
- `SessionStreamReader(session_dir: Path)` — tail-safe JSONL reader over the substrate volume; supports offline (read-and-close) and live (tail-with-poll) modes. Consumed by the Policy module (see below). Honours the `session-stream-jsonl/v1` contract.
- `PolicyEngine(rules: list[Rule], audit_chain: AuditChain, anomaly_counter: AnomalyCounter)` — evaluates `SessionEvent`s against the loaded rules; dispatches `Action`s; emits `rule_hit` envelopes directly through the in-process `AuditChain`. Replaces what a separate jettison Reader+RuleEngine would have done. Surface spec'd in `layer4_jettison.md`.
- `BlockFlagWriter(flag_dir: Path)` — writes per-session block flags on behalf of v2 `BlockAction`. Mode-0600, owner==EUID lstat invariants mirror the FREEZE file. v1 has no callers; ships in v2 alongside `BlockAction`.

### Dispatcher

**Stage 2 deliverable** (alongside the policy module, per the 2026-06-29 collapse). interlock owns the `tidereach` umbrella binary; the dispatcher routes `tidereach <layer> <subcommand>` invocations to the installed layer package.

- **Module:** `src/interlock/dispatch.py`.
- **Entry point:** declared in `tidereach-interlock`'s `pyproject.toml` as `[project.scripts] tidereach = "tidereach.interlock.dispatch:main"`. This is the only `tidereach` console script in the ecosystem; sieve / arbiter / airlock register none (per Decision 16, Umbrella ownership clause).
- **Routing table:** `argv[1]` is parsed as the layer name (`interlock`, `sieve`, `arbiter`, `airlock`). The dispatcher attempts `importlib.import_module(f"tidereach.{layer}.cli")` and calls that module's `main(argv[2:])`.
- **Graceful-error pattern (optional-import):** on `ImportError`, the dispatcher prints `'<layer> not installed. Run: pip install tidereach-<layer>'` to stderr and exits 1. Layers are independently installable; missing layers are an expected operator state, not a crash.
- **Reserved subcommands:** the bare `tidereach` invocation (no `<layer>`) and `tidereach --version` print the umbrella version and the list of installed layers; they do not require any layer to be installed.
- **Pattern reference:** matches `kubectl plugin` / `git <subcommand>` / `cargo <subcommand>` — the umbrella binary is a router, not a re-implementation of every layer's surface.

### CLI

`tidereach interlock` umbrella subcommand (per Decision 16; the in-repo `interlock = "tidereach.interlock.cli:main"` entry point exists for test invocation but is not installed on PATH). Versioned: `tidereach interlock --api-version` prints integer ≥ 1.

| Subcommand | Function |
|---|---|
| `verify-integrity [--input name:path …]` | Compute and print all pinned hashes. `--input` accepts `name:path` pairs using `FileHashInput` for standalone use; full-stack mode assembles real layer impls via the meta-repo's preflight. |
| `verify-installed [--strict]` | Compare `pip freeze --all` vs `requirements.lock`; `--strict` re-runs `pip install --require-hashes --dry-run` and asserts zero diff. |
| `check-sandbox` | Assert the configured execution-plane sandbox is present and matches the pinned config hash. |
| `check-ollama` | HTTP ping the configured Ollama endpoint; do not invoke the classifier. |
| `check-engine` | Probe arbiter's IPC socket; assert the configured control engine answers within timeout. |
| `hook-check` | Read `~/.claude/settings.json` + project `.claude/settings.json`; assert every expected hook is wired and matcher set matches the fixture. |
| `verify-hooks` | Re-hash installed hook scripts; compare to `hook_manifest.json`; verify per-call Ed25519 signatures. |
| `install-hooks` | Write hooks to `.claude/settings.json` (with `--dry-run`); record the manifest. |
| `hook-pubkey` | Print the Ed25519 hook-identity public key for external pinning. |
| `audit-verify <path>` | Walk a JSONL audit log; report the first index where the chain breaks. |
| `audit-rotate --keep-days N` | Prune old records; re-anchor chain with `chain_anchor_after_rotate` event. |
| `audit-purge --before YYYY-MM-DD` | GDPR Right to Erasure; re-anchor chain with `chain_anchor_after_purge` event. |
| `audit-repair --confirm` | Re-anchor the chain from the last verifiable record after corruption; emits `chain_anchor_after_repair`. |
| `self-test` | Run the canary corpus on demand; print per-payload pass/fail. With no scan callable registered, exits 0 with: "no scan implementations registered; install a layer that provides a scan callable to run corpus checks." |
| `freeze` / `unfreeze` | Manipulate the freeze file. |
| `stats` | Print current anomaly counter state + freeze file state. |

### Settings (`interlockSettings`)

15 fields. Each policy-marked or non-policy-marked; `config_hash()` excludes non-policy fields. Every field has at least one production read (CI-asserted) — this is a hard v1 invariant enforced by CI, not a nice-to-have; CI fails on any stale or unread field.

| Field | Type | Default | Policy | Read at |
|---|---|---|---|---|
| `state_dir` | `Path` | `~/.tidereach/` | yes | startup; all state files anchored here |
| `freeze_path` | `Path` | `<state_dir>/FREEZE` | yes | every `FreezeManager.check()` |
| `audit_state_path` | `Path` | `<state_dir>/audit.state` | yes | every `AuditChain.append()` |
| `audit_sink_preference` | `list[str]` | `["journald","syslog","file","stdout"]` | yes | `_choose_sink()` |
| `audit_file_path` | `Path` | `<state_dir>/audit.jsonl` | yes | `AppendOnlyFileSink` |
| `anomaly_window_seconds` | `int` | `300` | yes | `AnomalyCounter.__init__` |
| `classifier_unavailable_rate_threshold` | `float` | `0.5` | yes | every anomaly check |
| `rule_classifier_disagreement_rate_threshold` | `float` | `0.5` | yes | every anomaly check |
| `heartbeat_seconds` | `int` | `300` | no | `Heartbeat.__init__` |
| `heartbeat_every_n_calls` | `int` | `100` | no | `Heartbeat.__init__` |
| `hook_integrity_mode` | `Literal["off","warn","block"]` | `"warn"` | yes | `HookManifest.__init__` |
| `hook_manifest_path` | `Path` | `<state_dir>/hook_manifest.json` | yes | `HookManifest.verify()` |
| `sandbox_backend` | `str` | `"none"` | yes | `SandboxCheck.run()` (validated there; closed Literal removed so new backends don't require an interlock release) |
| `sandbox_config_paths` | `list[Path]` | (from `sandbox_backend`) | yes | `SandboxCheck.run()` |
| `sandbox_config_hash` | `str \| None` | `None` (detect-only) | yes | `SandboxCheck.run()` |

Precedence: kwargs > env (`interlock_*`) > TOML (`[interlock]` section) > defaults.

### Contracts directory

`contracts/` and `governance/` are top-level directories in the `interlock-contracts` repo. **`interlock-contracts` ships as a separate GitHub repository (`tidereach/interlock-contracts`) in v1 — public OSS for visibility, consumed by sibling repos as a git submodule under `vendor/interlock-contracts/`.** PyPI publication is a v2 candidate (see `ROADMAP.md`); the re-open triggers are: contracts stabilize at v1.0.0, OR a non-Python consumer appears, OR submodule UX friction outweighs the publish friction we avoided. Every consumer pulls the submodule to access schemas; they also get governance rules in the same checkout.

```
interlock-contracts/
├── contracts/                        ← data exchange formats; semver-versioned
│   ├── audit-envelope/
│   │   └── v1.0.0/
│   │       ├── schema.json
│   │       ├── README.md
│   │       └── CHANGELOG.md
│   ├── integrity-inputs/
│   │   └── v1.0.0/
│   │       ├── schema.json           ← canonical input names + one-line serialization spec per entry
│   │       ├── README.md
│   │       └── CHANGELOG.md
│   ├── session-stream-jsonl/v1.0.0/
│   ├── hook-manifest/v1.0.0/
│   ├── sandbox-config/v1.0.0/
│   ├── freeze-file/v1.0.0/
│   └── engine-ipc/v1.0.0/
└── governance/                       ← ownership and constraint rules; no version subdirs
    ├── audit-event-ownership.md      ← which layer owns which events; since: annotations; changes strike-through old entries with date
    ├── freeze-manager-constraint.md  ← FreezeManager is sole emitter of gate_frozen_auto; paste into all four other specs
    ├── layer-constraints.md          ← cross-layer invariants that every spec must honour
    └── composition.md                ← hook-chain composition: ordering, OR-to-block, ask ownership, layer-absence; Stage 5-blocking (arbiter SPEC.md cites this)
```

Each `contracts/` directory has the same three files: `schema.json` (JSON Schema), `README.md` (explainer + rationale + example payloads), `CHANGELOG.md` (semver bump entries with issue / PR references). Governance docs don't need version subdirectories — a `since:` annotation on each entry plus struck-through old entries with dates is the changelog.

`contracts/integrity-inputs/v1.0.0/README.md` lists every canonical `HashInput` name with a one-line serialization spec (e.g., `pattern_table` — sorted-keys JSON, UTF-8, no trailing newline; `model_digest` — raw bytes of the model manifest file; `prompt_template` — UTF-8, NFC-normalized). Entries that depend on a layer's internal representation are marked TBD pending that layer's spec. This is the coordination point for parallel layer development — all four layers implement `HashInput` against this contract without needing to cross-reference each other.

#### `session-stream-jsonl/v1.0.0` schema commitment

The contract directory will ship a `schema.json` enumerating the v1.0.0 record shape; until Stage 2 produces the file, this spec doc is the canonical home for the field list. The v1.0.0 schema commits interlock to **exactly these fields** (no `extra` / `raw_payload` catch-all):

| Field | Type | Required | Source / meaning |
|---|---|---|---|
| `ts` | float (epoch seconds, UTC) | yes | Wall-clock timestamp at which the agent CLI emitted the record. |
| `session_id` | string | yes | The agent CLI's session identifier; opaque to interlock. |
| `source` | string (enum: `claude`, `copilot`) | yes | Which agent CLI emitted the record; selects the adapter. |
| `event_type` | string | yes | Normalised event type the adapter assigns (`user`, `assistant`, `tool_call`, `tool_result`, `system`, …). |
| `transcript_path` | string (path) \| null | no | Source transcript file when the adapter parsed an on-disk record; null for synthesised entries. |
| `assistant_text` | string \| null | no | The assistant turn text the adapter extracted; null on non-assistant records. |
| `correlation_id` | string \| null | no | The arbiter `context_id` propagated through interlock's in-process verdict map; null when no verdict precedes the record. See `layer3_airlock.md § Adapter mapping — correlation_id`. |

The schema is **exhaustive**: any field the policy module needs to act on must be named here. Adapters that need scratch state during parsing keep it adapter-local; it does not survive into a v1 record. Adding a field is a v1.1 minor bump; removing or retyping is a v2 major bump.

Consumers (sieve, airlock, arbiter) pin a contract version range in their own `pyproject.toml`. interlock's policy module (which implements layer-4 behaviour in-process; see below) consumes the same contracts internally, but does not pin via `pyproject.toml` since it ships in this repo.

### Policy module

interlock's source tree includes a `policy/` module that implements the layer-4 visibility surface: session-stream ingest, deterministic rule evaluation, action dispatch. The 2026-06-29 architecture review merged what had previously been planned as a sibling `jettison` repo into interlock's process so the rule engine, `AuditChain.append`, freeze/anomaly state, and container-runtime invocations all run in one process. **The policy module ships in Stage 2 alongside interlock's L0 surface as a single coherent v1.0 release** — the second 2026-06-29 collapse decision eliminated the prior Stage 6 because the policy module's v1 surface (`LogAction` only) has no runtime dependency on airlock; it depends only on the `session-stream-jsonl/v1.0.0` contract that is already Stage-2-release-blocking per Pivot 3. Live-airlock verification of the policy module happens at the Stage 6 cross-repo soak (was Stage 7 pre-collapse). The merge is described in [`layer4_jettison.md § Deployment`](layer4_jettison.md#deployment); the full surface (DSL grammar, action vocabulary, rule examples, audit events, tuning) is specified in that file. **interlock's spec does not re-document it.**

What lives where, locally:

```
src/interlock/
├── …                              (existing modules — audit, anomaly, integrity, freeze, …)
└── policy/
    ├── __init__.py
    ├── events.py                  # SessionEvent dataclass
    ├── adapters/                  # per-CLI transcript parsers (Claude Code, Copilot)
    ├── reader.py                  # SessionStreamReader (tail-safe JSONL)
    ├── rules.py                   # Rule, PolicyEngine, predicates, thresholds, cooldowns
    ├── actions.py                 # Action protocol; LogAction (v1); BlockAction + Hard primitives (v2 stubs)
    └── flags.py                   # BlockFlagWriter (v2)
```

Settings: the policy module's configuration ships as `jettisonSettings` — a separate dataclass loaded alongside `interlockSettings` at startup. The fields are spec'd in `layer4_jettison.md § Settings`; interlock's spec does not duplicate them.

CLI: `tidereach interlock session-audit <path>`, `tidereach interlock session-watch [<volume>]`, `tidereach interlock rules-lint <rules.yaml>`. These are subcommands of the `tidereach interlock` umbrella namespace rather than a separate `tidereach jettison` namespace — the merge collapses what would have been a `tidereach jettison` CLI surface into `tidereach interlock`.

Audit events: emitted by the policy module via the in-process `AuditChain`. The full list (v1: `session_event_seen`, `rule_hit`, `action_logged`; v2: `block_flag_written`, `kill_agent_container_initiated`, `sever_egress_initiated`, `freeze_workspace_initiated`, `jettison_baseline_drift`) is owned by `layer4_jettison.md § Audit events owned`. Cross-reference: these are interlock-emitted events (interlock-the-process is the only emitter); they do not appear in the layer-exclusive list below because the canonical home for their semantics is the layer-4 spec.

**Block flag.** v2 Soft `BlockAction` uses a per-session flag file in the substrate volume — same family of construct as the FREEZE file but per-session rather than global. `BlockFlagWriter` (Public API above) writes it; a dedicated Stop-hook script in the meta-repo lstats it on Stop fire. Default path `${SESSION_DIR}/<session_id>.blocked`; lstat invariants (S_ISREG, mode 0600, owner == EUID) mirror the FREEZE-file protocol in `contracts/freeze-file/`. The flag-file path assumes the Stop hook runs inside the agent container so it sees the substrate volume at the same mount point; for CLIs where Stop hooks run on the host, a host-side mirror is required (open question in `layer4_jettison.md § Open questions for v2`).

### Audit events owned

Event ownership follows a two-tier model (see `governance/audit-event-ownership.md`):

**Layer-exclusive events** — interlock is the only emitter. Other layers calling `AuditChain.append()` with these names is a contract violation:
- `heartbeat` — periodic liveness.
- `gate_frozen` — freeze file detected at call time.
- `gate_frozen_auto` — anomaly-triggered auto-freeze.
- `freeze_file_anomalous` — freeze file present but lstat invariants violated.
- `canary_drift` — canary corpus result differs from baseline.
- `chain_genesis` — first chain event ever (no prior `audit.state`).
- `chain_anchor_after_rotate` — `audit-rotate` re-anchor.
- `chain_anchor_after_purge` — `audit-purge` re-anchor.
- `chain_anchor_after_repair` — `audit-repair` re-anchor.
- `hook_integrity_check` — `verify-hooks` result.
- `hook_identity` — per-call Ed25519 signature emission (recorded inline with each audit record from a hook context).
- `hook_missing` — `hook-check` found an expected hook absent.
- `model_swap_detected` — model digest mismatch.

**Cross-layer events with defined namespace** — defined and versioned by interlock, but emitted by the named layer:
- `ollama_socket_untrusted` — UDS owner/mode invariant failed. Defined by interlock; **emitted by sieve** via `ollama_trust.py`.
- `ollama_identity_changed` — TCP fallback PID/exe-hash drift. Defined by interlock; emitted by sieve.
- `ollama_telemetry_status_unknown` — Ollama telemetry status not confirmable. Defined by interlock; emitted by sieve.
- `ollama_shared_socket_warning` — heuristic detection of bind-mounted shared socket. Defined by interlock; emitted by sieve.

**Indirect ingestion** — interlock-owned readers convert third-party log artefacts into audit envelopes; the source layer originates no events directly:
- `egress_decision` — one envelope per line of airlock's Squid access log. Labels `{domain, action: allow|deny, client, http_status}`. Emitted by interlock's `SquidAccessReader` tailing the host-bound `${PROXY_LOG_DIR}/access.log` produced by airlock's proxy container. v1 has Squid `logfile_rotate` disabled (append-only per session; rotation is v2). Failure mode: if `AuditChain.append()` raises, the reader logs to stderr and continues; the access line is preserved in the file but the chain envelope is lost. See `layer3_airlock.md § Cross-layer contracts`.

### Verification

- `pytest -q` green; coverage on every public class.
- **Field-read invariant (hard CI requirement):** every `interlockSettings` field has a test that grep-asserts at least one production read. CI fails on any stale or unread field. This must not be treated as a nice-to-have check — it is a load-bearing guard against silent field rot (lesson from `canary_interval_seconds`).
- Integration: a fixture project boots; every `check-*` and `verify-*` subcommand returns 0 against a healthy fixture and ≠ 0 against deliberately-broken inputs (forged freeze file, mismatched lockfile, canary corpus drift, missing hook).
- Contract tests: every contract in `contracts/` is consumed by at least one external test that exercises produce / consume against the schema.
- E2E: a Tidereach stack with the four other layers in place runs `tidereach interlock self-test` and reports all canary corpus payloads pass; `tidereach interlock audit-verify` over the session's slice reports zero chain breaks.

---

## v2 spec

Opt-in cryptographic attestation. Backwards-compatible: v1 binaries continue to work without attestation; v2 adds gates that fail-closed when configured.

- **Ed25519-signed manifests** for every hashed component. Private key in OS keyring (managed via `tidereach interlock keys rotate`). Each manifest is `{hashes: {...}, signature: <hex>, pubkey: <hex>, signed_at: <ts>}`.
- **`attest verify --pubkey <hex|file>`** verifies a signed manifest against a pinned trust root without keyring access.
- **Sigstore / cosign verifier** behind a `[attest]` extra (`pip install tidereach-interlock[attest]`). Operator-org publishes expected digests via sigstore; interlock verifies on receipt.
- **Key rotation**: `tidereach interlock keys rotate` generates a new keypair, signs a rotation event into the audit chain, and re-signs the active manifest.
- **Federated trust roots**: optional `attest_trust_roots: list[Path]` config for multi-org deployments.

v2 issues to track in the new repo (not the current monorepo): trust-root distribution model; key rotation cadence default; sigstore vs cosign default verifier.

---

## Out of scope

- **Scanning content** — sieve owns the gate.
- **Container runtime, proxy ACLs, Landlock policy** — airlock.
- **Intent rule authoring, control engine selection** — arbiter (and the operator).
- **Session-stream rule *authoring*** — operator concern; the policy module evaluates rules but does not curate them. (Note: the policy module itself — ingest, evaluation, action dispatch — lives in this repo as of the 2026-06-29 merge; see [Policy module](#policy-module). What was a separate-layer responsibility is now an in-process module.)
- **`gate()` orchestration / classifier prompt design** — sieve.
- **Hook script bodies** — hull (meta-repo). Includes the v2 dedicated Stop-hook script that delivers `BlockAction` by lstat'ing interlock-written flag files.

---

## Open questions for v2

- **Trust-root distribution**: organisation-published expected digests vs. sigstore as the default. (Decision deferred to v2 design; the contract surface allows both.)
- **Ed25519 / sigstore trust model gap**: the v2 spec lists Ed25519-signed manifests and sigstore/cosign verification as parallel options, but they are different trust models. Sigstore uses X.509/Fulcio, not raw Ed25519 keys. If sigstore is intended as the *verification* layer for manifests that interlock *signs* with Ed25519, a bridge is required. Before v2 design begins this must be resolved: are they parallel (sign with Ed25519, verify with Ed25519; *or* sign via sigstore, verify via sigstore), or does one feed the other (requiring an explicit bridging step)? Decision deferred to v2 design, but the gap is named here so it is not discovered mid-implementation.
- **Key rotation cadence default**: 90 days? 365 days? Configurable but with a sensible default warning if unset.
- **Contracts directory governance**: how do layer-repo maintainers propose a contract bump? PR review by interlock maintainers? A `contracts-rfcs/` directory? Defer to first real contract evolution.
- **Should `verify-installed --strict` block on any drift, or warn-and-continue with a configurable threshold?** v1 ships block-only; v2 may add tolerance for known-safe drift (e.g. patch-version bumps in transitive deps).
