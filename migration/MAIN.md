# Tidereach Migration — Macro Plan

This document is the macro plan for splitting Tidereach from one monolithic project into a meta-repository plus four sibling layer repositories — data (sieve), control (arbiter), execution (airlock), and attestation/glue (interlock) — along the four-plane endpoint-stack model. The visibility plane (jettison) is hosted in-process by interlock per Decision 2 rather than as a separate repo. It is the single source of truth for the migration's architecture, execution order, cross-layer contracts, and gate criteria.

> **Naming note.** The project was renamed Spektralia → Tidereach on 2026-06-29 (see [§ 7 Decision 15](#7-decisions-locked)). Historical references in this document and the per-layer specs (e.g. `src/spektralia/*.py`, `[spektralia]` TOML sections, `spektralia check-sandbox`, `SPEKTRALIA_*` env vars, `~/.spektralia/`) describe the pre-migration state being migrated away from. **They appear in migration docs only and MUST NEVER propagate into the new repositories** (`tidereach/hull`, `tidereach/interlock`, `tidereach/sieve`, `tidereach/arbiter`, `tidereach/airlock`, `tidereach/drydock`) — see [Constraint 6 in § 8](#8-constraints) for the CI grep gate that enforces this. Forward-looking references use **Tidereach**; the `~/.tidereach/` state directory, the `tidereach/<repo>` GitHub org URLs, and the new `tidereach` CLI binary are the post-migration identity.

Read it once before touching any layer file. Reread it before each stage's go/no-go gate.

Per-layer specifications live in:

- [`layer0_interlock.md`](layer0_interlock.md) — L0 attestation/glue
- [`layer1_sieve.md`](layer1_sieve.md) — L1 data plane (sensitivity gate)
- [`layer2_arbiter.md`](layer2_arbiter.md) — L2 control plane (intent integration, engine-agnostic)
- [`layer3_airlock.md`](layer3_airlock.md) — L3 execution plane (sandbox + session-stream substrate)
- [`layer4_jettison.md`](layer4_jettison.md) — L4 visibility plane (deterministic rules + actions)

Deferred items and v2 candidates live in [`ROADMAP.md`](../ROADMAP.md), each entry carrying a concrete re-open trigger. New deferrals are appended there at the moment they surface, not at the end of a stage.

---

## 1. Why this migration is happening

Tidereach started as a "local pre-cloud sensitivity gate" (regex + entropy + classifier + sanitizer) under the name Spektralia. Over four spec drafts the scope grew far past that mission:

- **Supply-chain integrity** (`integrity.py`, `verify-installed`, SBOM, `requirements.lock`).
- **Hook integrity manifest** + Ed25519 identity signatures (`hook_manifest.py`).
- **Execution-plane sandbox** (`infra/sandbox/` = cplt-sndbx: Containerfile, compose, Squid proxy, Landlock policy, seccomp profile).
- **Sandbox preflight** (`sandbox.py`, `spektralia check-sandbox`).
- **Session-stream writer** (`sessions/writer.py`) as jettison substrate (#110/#114-120).
- **Output gating** (`output_gate.py`).
- **Opt-in NER** (`ner.py`).
- **Canary corpus, anomaly counters, heartbeat, freeze switch, hash-chained audit**.

The repo now houses **three architectural planes plus an emerging behavioural-detection layer** under one `pyproject.toml`. The scope-bloat symptoms are visible in the docs and tracker:

- `docs/PLAN.md` is openly retiring under issue #133 because a single phased plan cannot serve five planes' independent work.
- `docs/COMPLIANCE.md §21` literally duplicates `docs/SPEC.md §21` with a "canonical version lives in SPEC.md" note.
- `docs/ENDPOINT_STACK.md` cites Fence as the canonical sandbox backend in legacy prose while `infra/sandbox/` and `docs/SANDBOX_ALTERNATIVES.md` treat cplt-sndbx as v1.
- 14+ CLI subcommands live on one binary; a user wanting only sandbox preflight pulls in the entire sensitivity scanner.
- `integrations/claude_code_hooks/__pycache__/` exists with no `.py` siblings — orphan rot.
- `infra/sandbox/workspace/name-alchemist.{md,eval.md}` was checked in from an unrelated eval run.
- `src/spektralia/sessions/writer.py` has no internal callers; it is integration-adapter code masquerading as library internals.

**The migration's intent.** Split the monolith into a meta-repository (which keeps macro docs and operator-facing hook scripts) plus four sibling layer repos (sieve, arbiter, airlock, interlock; the visibility plane lives in-process within interlock per Decision 2). Each layer becomes its own self-contained product with its own pyproject, lockfile, SBOM, CI, and release cadence. Cross-layer contracts live in one named home (L0 interlock) so the explosion of repos does not bring an explosion of coordination overhead.

**Explicit non-goals.**

- This is **not** a refactor of the existing repo. It is a greenfield rebuild per layer.
- This is **not** a feature pause. `main` is frozen for new feature merges during migration design; the post-split layer repos resume cadence independently.
- This is **not** a rewrite-while-shipping plan. The existing Tidereach code keeps running for any user who pins to it; the migration produces sibling products, not in-place replacements.

---

## 2. The five-plane architecture

The architecture follows the four-plane model already documented in `docs/ENDPOINT_STACK.md` — **data / control / execution / visibility** — with one additional layer that ties the planes together via attestation. Each plane becomes its own self-contained product; L0 is the cross-cutting attestation and integrity surface that proves the whole stack is configured correctly.

| Plane | Layer-id | Proposed name | Mission | Repo name (proposed) | Currently lives in |
|---|---|---|---|---|---|
| Attestation/glue | L0 | **interlock** | Hash-pinning, supply-chain verification, hash-chained audit, freeze switch, canary harness, anomaly counters, heartbeat, cross-layer contracts. Runtime preflight v1; opt-in cryptographic attestation v2. | `tidereach/interlock` | `src/spektralia/{audit,anomaly,integrity,hook_manifest,sandbox,canary,heartbeat}.py` + L0-shaped CLI subcommands |
| Data | L1 | **sieve** | Content scan — what information leaves the endpoint. Regex + Luhn/MOD-11 + entropy + decoded payloads + local classifier + sanitiser + opt-in NER + opt-in output gating. | `tidereach/sieve` | `src/spektralia/{patterns,normalize,scanner,entropy,decode,memory_safety,sanitizer,classifier,ollama_trust,cache,gate,output_gate,ner,errors,config}.py` |
| Control | L2 | **arbiter** | Intent policy — what the agent is asking to do. Engine-agnostic integration spec + thin adapter library that hooks a control engine into the agent-CLI hook surface. The engine itself is pluggable (Falco/Prempti, OPA, custom Python rules); arbiter does not pick one. | `tidereach/arbiter` | Nothing currently in `src/`; `docs/ENDPOINT_STACK.md § Hook ordering` is the seed |
| Execution | L3 | **airlock** | Sandbox — what actually runs against the OS. Hardened container + Squid egress proxy + Landlock/bwrap + seccomp. **Also owns the session-stream substrate**: mounts a writable volume at the agent CLI's session-output path so the visibility plane can read it directly. **Audit-event posture:** no direct emission; Squid access log is host-bound and indirectly ingested into the AuditChain via interlock's `SquidAccessReader` (`egress_decision` envelopes). | `tidereach/airlock` | `infra/sandbox/` (Containerfile, compose, proxy, landlock, seccomp, scripts) |
| Visibility | L4 | **jettison** | Ingests session streams from the substrate airlock mounts. Applies **deterministic** rules to the events. Triggers actions. v1: `LogAction` only. v2 Soft: `BlockAction` (refuse Stop via flag-file + Stop-hook). v2 Hard: `KillAgentContainerAction` + `SeverEgressAction` + `FreezeWorkspaceAction` (three named container-runtime primitives replacing the earlier under-specified `VentAction`). **No LLM-based detection**. | **Hosted in interlock as a `policy/` module** (2026-06-29 merge); not a sibling repo. Spec lives in `layer4_jettison.md` in the meta-repo. | `src/spektralia/sessions/` (going away — see [§ 13](#13-hygiene-findings-folded-into-the-migration)), `integrations/claude/hooks/stop.py` (current producer), #110/#114-120 (epics) |

The names follow the user's "sci-fi / space" theme: lighthouse signals identity (interlock), sieve separates content (sieve), arbiter watches intent (arbiter), airlock contains the agent (airlock), jettison vents on detection (jettison). The layer + repo names were finalized 2026-06-29 (see [§ 7 Decision 14](#7-decisions-locked)) and the project identity locked the same day under the name **Tidereach** (see [§ 7 Decision 15](#7-decisions-locked)). Repo URLs follow `tidereach/<repo-name>` — `tidereach/hull` (meta), `tidereach/interlock`, `tidereach/sieve`, `tidereach/arbiter`, `tidereach/airlock`, `tidereach/drydock`.

---

## 3. Meta-repository role (hull)

hull (this current repo) is **not deprecated**. It is **demoted to a meta-repository** holding what spans all five layers. The repo is named `hull` (full URL `tidereach/hull`); the project as a whole is named **Tidereach** (formerly Spektralia; see [§ 7 Decision 15](#7-decisions-locked)):

| Stays in hull (meta) | Reason |
|---|---|
| Macro spec (`docs/SPEC.md` — restructured as a stack-level spec; per-layer detail moves to layer repos) | Single canonical spec for the layered stack; survives layer churn |
| Threat model (`docs/THREATS.md`) | Threats span planes; stack-level concern |
| Compliance framing (`docs/COMPLIANCE.md`) | Compliance applies to the deployment as a whole, not per layer |
| Stack architecture (`docs/ENDPOINT_STACK.md`, possibly renamed `STACK.md`) | The plane-composition document — the reason Tidereach exists as an umbrella |
| Design rationale history (`docs/RATIONALE.md`) | v2/v3/v4 narrative belongs to the umbrella, not any one layer |
| Integration hook scripts for Claude Code and Copilot (`integrations/{claude,copilot}/hooks/`) | Operator-facing glue between layers and the agent CLI; not a layer in its own right; **authored greenfield against the post-migration CLI surface** |
| This `migration/` directory | Migration audit trail; kept indefinitely as historical reference |

hull **houses no Python source** post-migration. The `src/spektralia/` directory was removed from `main` in commit `65d99b2` (the codebase-replacement commit that replaced the monolithic implementation with the migration planning specs); no archival tag is created and no future-state reference to the pre-migration codebase is maintained in the planning docs. The migration proceeds as a greenfield rebuild per Constraint 1.

**Why hook scripts stay in the meta-repo, not in any layer.** The hook scripts sit at the boundary between L1 sieve (which they invoke for content scanning) and the agent CLI surface (which they integrate with). They are operator-facing glue — the surface a Tidereach user copies into `~/.claude/settings.json` to wire the stack together. Placing them in sieve would entangle the data-plane release with the agent-CLI integration surface; placing them in interlock would couple attestation to a specific agent CLI. The meta-repo is the right home: cross-cutting integration glue, plus a stable URL to point operators at, plus the freedom for the hook scripts to be revised independently of any layer's release cadence.

---

## 4. Cross-integration documentation rule

With one exception, integration / cross-layer documentation lives only in hull (meta). The exception is **L0 interlock**, which holds cross-repo contracts (audit event envelope, session-stream JSONL schema, IPC contracts) under its `contracts/` directory.

interlock owns these because contracts are **attestation surface** — they describe what each layer must conform to in order for the others to trust its output. Attestation cuts across every layer, so the contracts naturally belong with the layer that owns hashing and signing.

Each other layer repo (sieve, arbiter, airlock) holds **only** documentation specific to its own product. Layer repos do not document cross-layer interactions; they reference interlock contracts by name and version, and point at hull (meta) for stack-level framing.

Layer 4 (jettison) is a special case: its code merges into interlock's process as a policy module (see [§ 7](#7-decisions-locked) row 2). The layer-4 spec (`layer4_jettison.md`) therefore lives in the meta-repo alongside this `MAIN.md`, not in a sibling layer repo. interlock's own spec (`layer0_interlock.md`) cross-references it for the policy-module surface.

**Decision rule for new docs:** ask "does this describe the stack, a contract between layers, or one layer's product?"

- *Stack-level* → hull (meta).
- *Cross-layer contract* → interlock `contracts/`.
- *One layer* → that layer's repo.

If a single doc would need to live in two places, it is in the wrong shape; split it.

---

## 5. Viability, effort, gain

The user asked for an honest evaluation of viability, required effort, and gain. The per-layer table below is the answer; the layer files restate it in their own context.

| Layer | Effort (calendar) | Gain | Viability risk |
|---|---|---|---|
| **hull (meta)** | ~3 days | Citable canonical home for stack-level spec; survives layer churn; clear operator landing page | Low — docs already exist; this is reduction work, not creation |
| **L0 interlock + L4 jettison policy module** | ~8 weeks (includes vacation buffer) | External products can attest a Tidereach endpoint; preflight ships without a sensitivity dep; clean home for cross-layer contracts; behavioural detection ships in the same v1.0 release rather than waiting for a later stage; deterministic-only keeps the surface tight; opens the audit-correlated visibility plane | Low for interlock core (every dep is stdlib; attestation v2 is opt-in); Medium for the policy module — agent-CLI transcript format drift breaks adapters; v2 Hard actions (`KillAgentContainerAction`, `SeverEgressAction`, `FreezeWorkspaceAction`) are destructive and each is individually opt-in. The estimate history: an initial 2-week interlock-only estimate was already optimistic; the 2026-06-29 layer4 ember review added 1–2 weeks for the policy module (LogAction-only v1 plus per-CLI adapters, rule engine, `session-audit` / `session-watch` / `rules-lint` CLI). The locked v1 estimate is **~8 weeks calendar**, inclusive of a vacation buffer; this is the realistic ship date, not an aspirational build budget. |
| **L1 sieve** | ~3–4 person-weeks | Smaller surface ships faster; per-pattern releases without sandbox/jettison churn; clearer threat-model boundary; the canonical product the project (then named Spektralia) originally referred to | Medium — `gate.py` is the hub; the L0 contracts it calls into must land first; `ollama_trust` placement (sieve vs interlock) is an open v2 question |
| **L2 arbiter** | ~3 days | Stable, citable contract for hook↔control-engine; engine-pluggable; no Falco knowledge in sieve | Medium-high — viability depends on the operator's chosen engine being stable; if the engine's IPC shifts, arbiter follows |
| **L3 airlock** | ~1 week | Ops adopt the sandbox without pulling a Python package; per-image release cadence; owns the session-stream substrate so the Python writer goes away | Low — already infra-only; substrate ownership simplifies the policy module |
| **Cross-repo soak** | ~1 week | Validates the full layered stack in a fixture endpoint; baseline for SIEM-style visibility plane | Low — fixtures and live e2e well-understood from `docs/PLAN.md § 3.19` |

**Total v1 effort:** ~10–12 person-weeks calendar with cross-stage parallelism (Stages 2+3 parallel; Stages 4+5 chain on 3; cross-repo soak chains on all of 2–5). Without parallelism: ~14–16. The 2026-06-29 collapse of layer-4 into interlock's Stage 2 eliminates the previously separate Stage 6 — the policy module ships in the same v1.0 release as interlock's core, against fixture transcripts (no live airlock dependency for the v1 surface; live airlock e2e is verified in the cross-repo soak).

**Cost of *not* splitting.** Every commit currently re-tests 250+ tests across unrelated planes. `docs/PLAN.md` is retiring under #133 because the single plan stopped serving five planes' work. Each new feature in any one plane adds CI weight and cognitive load to all four others. The monorepo's coordination cost grows superlinearly with each plane added.

**Cost of splitting.** Front-loaded (~10–12 person-weeks). Recovers from Stage 4 onwards as per-layer cadence dominates.

---

## 6. Friction — current vs post-split

A two-column comparison. Honest about the counter-friction the split introduces.

| Today (single project) | After split (meta + 4 layer repos + drydock) |
|---|---|
| Every gate change retests sandbox infra + jettison substrate + Prempti integration | Per-layer CI runs independently; integration runs on contract-bumping releases only |
| `docs/PLAN.md` retiring under #133 because one plan can't serve five planes | Per-layer roadmaps; macro plan in hull (meta) |
| `spektralia check-sandbox` lives in the data-plane package — sensitivity gate ships with sandbox knowledge | interlock owns `check-*` CLI; sieve ships pure sensitivity |
| `sessions/writer.py` orphaned in `src/spektralia/` with no internal callers | airlock owns the substrate (volume mount); jettison reads from it; **no Python writer in any layer** |
| `integrity.py:14-15` imports `.classifier.PROMPT_HASH` and `.patterns.PATTERNS` — L0-belonging code reaches into L1 | interlock takes a `HashInput` protocol; sieve implements it; no reverse imports |
| `gate_frozen{_auto}` audit events emit from L1's `gate.py` but represent L0 freeze state | sieve calls `interlock.FreezeManager.check()`; interlock owns the event |
| One `Settings` dataclass tries to serve 5 planes; field overlap zero in fact but cognitive load high | Per-layer `*Settings`; each has its own `from_env` |
| 14+ CLI subcommands on one binary; users learn the full surface to use any subset | Per-layer CLI; users adopt only the layers they need |
| Hygiene rot tolerated — orphan `__pycache__`, `name-alchemist.*` checked in | Per-repo `.gitignore` covers each layer's surface; rot doesn't spread |
| Integration docs scattered across `docs/`, `infra/sandbox/`, AGENTS files | hull (meta) + interlock `contracts/` are the only two homes |
| **Counter-friction:** 4 release cadences to coordinate (interlock — including layer-4 policy module — sieve, arbiter, airlock) + meta-repo doc cadence | Versioned contracts in interlock absorb coordination cost; releases that touch a contract bump it explicitly |
| **Counter-friction:** cross-repo PRs for cross-layer features | Honest cost; mitigated by narrow contracts that rarely change in v1 |
| **Counter-friction:** contributors learn which repo a change belongs in | The "which file owns event X / Settings Y / CLI Z" check in [§ 16](#16-how-this-plan-is-verified) is the litmus test |
| **Counter-friction:** ~10–12 person-weeks initial migration cost | Front-loaded; recovers from Stage 4 onwards |

**Net argument.** The friction the split introduces is bounded and visible (4 layer-repo cadences + meta-repo doc cadence + cross-repo coordination + initial cost). The friction the monorepo introduces is unbounded and growing (PLAN.md retirement is the canary). The split flips O(N²) plane coupling into O(N) with explicit contracts.

---

## 7. Decisions locked

All nineteen decisions are user-confirmed and govern the rest of the migration. Reopening them requires explicit re-entry to plan mode.

| # | Decision | Choice | Provenance |
|---|----------|--------|------------|
| 1 | L0 scope | **Preflight + opt-in attestation.** v1 ships runtime preflight (`verify-*`, `check-*`, canary, audit, freeze, anomaly). v2 adds Ed25519-signed manifests + sigstore-style verifier. One product, two phases. | AskUserQuestion 2026-06-28 |
| 2 | L4 scope + name | **jettison** as a single module covering ingest + deterministic rules + actions. v1: `LogAction`. v2 Soft: `BlockAction` (cooperative; flag-file + dedicated Stop-hook script). v2 Hard: `KillAgentContainerAction`, `SeverEgressAction`, `FreezeWorkspaceAction` (non-cooperative container-runtime primitives that replace the earlier under-specified `VentAction`; verb-noun naming with airlock's target vocabulary — `agent_container`, `egress`, `workspace`). **No LLM-based detection** in jettison; the LLM lives in L1 sieve only. **Implemented as a module within interlock's process; layer 4 remains a conceptual layer with its own spec doc (`layer4_jettison.md`) in the meta-repo.** | AskUserQuestion + 2026-06-28 correction + 2026-06-29 layer4 review |
| 3 | Repo topology | **4 sibling layer repos (sieve, arbiter, airlock, interlock) + 1 meta-repo (hull).** hull keeps macro docs + hook scripts (including the dedicated Stop-hook script that delivers the v2 Soft `BlockAction`). Each layer repo has its own pyproject, lockfile, SBOM, CI. interlock hosts both layer-0 (attestation/glue) and layer-4 (policy / behavioural detection) code in one process. Cross-repo contracts live in interlock's `contracts/`. | AskUserQuestion + 2026-06-28 correction + 2026-06-29 layer4 review |
| 4 | In-flight work | **Freeze main; all open issues roll into module specs.** #114-120 (jettison substrate/rules), #138-142 (airlock hardening), and other open issues re-scoped into the appropriate layer's spec rather than carried as half-implementations. | AskUserQuestion |
| 5 | Layer naming | **Sci-fi/space-themed names per layer.** interlock, sieve, arbiter, airlock, jettison. Finalized in Decision 14 (2026-06-29); not subject to per-layer-review revision. | 2026-06-28 correction; finalized 2026-06-29 |
| 6 | Session-stream substrate | **L3 airlock owns the substrate** by mounting a writable volume at the agent CLI's session-output path. `src/spektralia/sessions/writer.py` is **deleted, not migrated** — the agent CLI writes JSONL directly to the bind-mounted directory; jettison reads it from the volume. | 2026-06-28 correction |
| 7 | L2 abstractness | **arbiter is engine-agnostic.** No Falco-specific text. The IPC contract supports any rule engine that accepts a verdict request and returns deny/ask/allow. Falco/Prempti, OPA, and custom Python rules are all valid backends. | 2026-06-28 correction |
| 8 | Deliverable workflow | **Write each migration/<name>.md file individually for separate review.** Avoid one mega-document; each layer plan is reviewable standalone. | 2026-06-28 correction |
| 9 | License & visibility | **Apache-2.0 across all five repos; OSS.** Explicit patent grant + retaliation clause chosen over MIT's brevity because Tidereach touches cryptographic primitives, container runtime APIs, and proxy enforcement — surfaces where enterprise legal review prefers explicit patent terms. Single license across all repos avoids SBOM and contributor-attribution friction. `LICENSE` file ships in every repo root; `SPDX-License-Identifier: Apache-2.0` header in source files. | 2026-06-29 user decision |
| 10 | Commit signing | **`gitsign` (sigstore) required on `main` across all five repos.** Keyless via OIDC (GitHub login) → ephemeral Fulcio cert → Rekor transparency log. Chosen over GPG to eliminate per-developer key custody, tighten identity binding to the OIDC chain operators already trust, and stay coherent with Tidereach's own transparency-log-shaped audit chain. Branch protection enforces "require signed commits" on `main`. Trigger to re-open: an enterprise consumer mandates GPG, or an air-gapped dev workflow becomes a requirement. Note: commit-signing is separate from interlock's Ed25519 (hook-manifest, audit-chain identity) — those remain operator-signed per Decision 1. | 2026-06-29 user decision |
| 11 | Merge strategy | **Squash-and-merge across all five repos.** One commit per PR on `main`. Cleanest history, easiest revert, simplest bisect — each merge is a single reviewed unit. Cross-repo submodule-pinned-at-SHA coordination cares about merge points on `main`, not intermediate WIP commits. Branch protection enforces squash; rebase-and-merge and merge-commit disabled. Operational expectation: PRs are reasonably scoped (one feature, one fix). | 2026-06-29 user decision |
| 12 | Bluepaper | **Separate `docs/BLUEPAPER.md` in the meta-repo, authored once architecture stabilizes, tracked as a Stage 1 deliverable.** 5–10 page distillation aimed at security teams evaluating adoption, auditors, and contributors wanting the gestalt before per-layer reading. Distinct from MAIN.md (migration plan, not architecture doc) and not a one-page exec summary. Not authored at decision time; commit to the deliverable now, write when the spec docs settle. | 2026-06-29 user decision |
| 13 | Ed25519 key custody | **Operator-only signing.** CI never holds the Ed25519 key. CI verifies signatures; it does not produce them. Hook-manifest signatures, audit-chain bootstrap events, and any other Ed25519-signed artifact are signed from an operator's machine — hardware token (YubiKey) recommended. Trade: slower release cadence in exchange for a stronger key-custody guarantee — a CI exploit is not equivalent to key compromise. Consistent with Decision 10's two-trust-domain split: gitsign signs every commit via OIDC (cheap, continuous); Ed25519 signs release events (rare, deliberate). Key-custody operational guide lives in `interlock/docs/KEY_CUSTODY.md` when authored. | 2026-06-29 user decision |
| 14 | Layer + repo names finalized | The set: `hull` (meta), `interlock` (L0), `sieve` (L1, renamed from `spectograph`), `arbiter` (L2, renamed from `analyzer`), `airlock` (L3), `drydock` (cross-repo soak). Code-identifier-decoupling rule from `REVIEW_NOTES.md` still applies — these are documentation/repo names, not Python package/class names. Project-name decision moved to Decision 15. | 2026-06-29 user decision |
| 15 | Project name + GitHub org | **Tidereach** (formerly Spektralia). GitHub org `tidereach` (registered 2026-06-29). All repo URLs follow `tidereach/<repo-name>` — `tidereach/hull` (meta), `tidereach/interlock`, `tidereach/sieve`, `tidereach/arbiter`, `tidereach/airlock`, `tidereach/drydock`. CLI binary `tidereach`. Path prefix `~/.tidereach/`. Python package `tidereach`. Env var prefix `TIDEREACH_` for any remaining project-scoped env vars. Pre-migration code paths (`src/spektralia/*.py`) and the current monolith's binary name (`spektralia check-sandbox`) retain "spektralia" as historical-state references; everything forward-looking uses "tidereach". | 2026-06-29 user decision |
| 16 | CLI binary topology | **`tidereach` umbrella binary with namespaced subcommands.** The public installed binary is `tidereach` only — operators invoke `tidereach interlock verify-host`, `tidereach airlock check-sandbox`, etc. No bare per-layer binaries (`interlock`, `sieve`, …) on PATH. Each layer's `pyproject.toml` still exposes its CLI as a `tidereach.<layer>.cli:main`-style entry point for in-repo testing, but the released-and-installed surface is the umbrella only. Constraint 6's CI grep gate covers legacy `spektralia` binary names; this Decision governs the new shape. **Umbrella ownership:** the `tidereach` console script is registered in `tidereach-interlock`'s `pyproject.toml`. Layer packages (`tidereach-sieve`, `tidereach-arbiter`, `tidereach-airlock`) register NO console scripts; they expose `tidereach.<layer>.cli:main` as importable callables only. The dispatcher (`src/interlock/dispatch.py`) parses `argv[1]` as the layer name, attempts to import `tidereach.<layer>.cli`, and dispatches; on `ImportError` prints `'<layer> not installed. Run: pip install tidereach-<layer>'` and exits 1. Pattern matches `kubectl plugin` / `git <subcommand>` / `cargo` subcommands. | 2026-06-29 user decision |
| 17 | Container distribution + image signing + arch | **Container registry: GHCR (`ghcr.io/tidereach/<image>`).** **Signing: cosign keyless via GitHub OIDC** → ephemeral short-lived code-signing cert from Fulcio CA → `cosign sign` writes a signature payload referencing the image digest; the signature, cert, and inclusion proof are recorded as a Rekor `hashedrekord` entry. Build provenance and SBOMs are produced as **in-toto DSSE attestation envelopes** (`predicateType: https://slsa.dev/provenance/v1` and `predicateType: https://cyclonedx.org/bom`); `cosign attest` uploads each envelope, which Rekor records as an `intoto` entry referencing the image digest. Same trust root as Decision 10's gitsign — operators verify image and commit provenance against one Fulcio chain. **Arch: multi-arch manifest lists for amd64 + arm64 from v1.** Driven by Apple Silicon developer machines as a first-class operator platform; servers stay amd64. Signatures, provenance attestations, and SBOMs are produced *per architecture*, keyed by per-arch image digests; the manifest list itself is also signed. Reproducible-build verification baselines computed per arch (see Stage 4 gate in § 12). Verification: `cosign verify --certificate-identity-regexp` against the expected GitHub Actions workflow identity + `cosign verify-attestation` for SBOM/provenance, both per-arch and on the manifest-list digest. | 2026-06-29 user decision |
| 18 | CI hygiene tooling baseline | Shared baseline replicated across all five repos: **(a) `betterleaks`** as the pre-commit + CI secrets scanner (originally chose `gitleaks` over `trufflehog` for lower false-positive rate and single-binary distribution; **amended 2026-06-30 to `betterleaks`** — the original `gitleaks` author's successor at Aikido, drop-in compatible with gitleaks rules / config / CLI, MIT-licensed, no org-license signup; the switch was driven by the `gitleaks-action` v2.0.0 requiring a free-but-required org-license that contradicted the spec's claim of optional licensing; see `tidereach/hull/ROADMAP.md` item 7 for the abandonment-risk tracker). **(b) `CHANGELOG.md` follows keep-a-changelog format**, hand-authored at release time; auto-generation rejected. **(c) PR-title-lint workflow** enforces Conventional Commit prefixes (`feat:` / `fix:` / `chore:` / `breaking:` / etc.) — required because Decision 11's squash-and-merge makes the PR title the merge commit's title. **Reusable-workflow implementations live in `tidereach/hull/.github/workflows/`** — `betterleaks.yml` (a), `pr-title-lint.yml` (c) — and are consumed by layer repos via `uses: tidereach/hull/.github/workflows/<name>.yml@main`. The canonical pre-commit baseline lives at `tidereach/hull/.pre-commit-config.yaml`. Operator overview at `tidereach/hull/docs/CI.md`. | 2026-06-29 user decision; (a) amended 2026-06-30 |
| 19 | Subagent roadmap | **(a) Contract-bump reviewer subagent: build at Stage 2** when `contracts/` lands in interlock; not before (no schemas exist to review pre-Stage-2). **(b) Cross-repo release-coordinator: never built as a subagent**; replaced with a workflow. On interlock tag push, `release-coordination.yml` opens tracking PRs in each consumer via `gh pr create` with the pin bump pre-applied — yes/no work that doesn't need an LLM in the loop and is audit-friendlier as a workflow. | 2026-06-29 user decision |

---

## 8. Constraints

The five user-stated constraints, phrased as verifiable gates rather than aspirations.

1. **"Implementation must be from the ground up."**
   *Gate:* Every layer file's Reuse table has explicit `Rewrite | Drop | Superseded` per source. No "we'll see at execution time" rows.

2. **"Only reuse existing code if 100% ready for migration without modifications."**
   *Gate:* All implementation work is greenfield. `Rewrite` dispositions are authored against the migration spec text in this repo (MAIN.md + the per-layer specs); pre-migration code patterns inform the spec but no source file from any prior implementation is copied forward. Tests, package shells (`__init__.py`), configs, and CI files are likewise authored greenfield against the spec. There is no `Lift verbatim` category.

3. **"Each component must have a lessons learned and what to improve."**
   *Gate:* Every layer file has a `Lessons learned` section drawn from at least three sources: (a) `AGENTS.md` Gotchas, (b) `docs/RATIONALE.md` v2/v3/v4 narratives, (c) closed issues / open issues rolled into the migration. Each lesson is phrased as *what we learned — how it shapes v1*.

4. **"Read existing code, but especially documentation — making sure it is current and up to date."**
   *Gate:* Every layer file has a `Doc audit` section calling out which current docs apply, which contain stale prose, and which contradict another doc. Doc reconciliation tasks are listed in [§ 13](#13-hygiene-findings-folded-into-the-migration).

5. **"Spare no expense token wise. We're laying the ground work for huge changes later, this is step 0."**
   *Gate:* Layer files are detailed enough for a fresh contributor to start work on Stage 2/3/4 from the file alone. No "see the old SPEC.md §X" hand-offs that depend on the soon-archived `src/`.

6. **Historical names and paths MUST NEVER propagate into the new repositories.**
   *Gate:* Migration docs (this file and the per-layer specs in the meta-repo) reference legacy `Spektralia`, `spektralia`, `src/spektralia/*`, `SPEKTRALIA_*` env vars, `[spektralia]` TOML sections, and `~/.spektralia/` paths **only** to describe the pre-migration state being migrated away from. When greenfield implementation in `tidereach/hull`, `tidereach/interlock`, `tidereach/sieve`, `tidereach/arbiter`, `tidereach/airlock`, or `tidereach/drydock` draws on pre-migration documentation or design patterns, **every legacy reference is renamed before commit**. Each new repo's CI runs a grep gate asserting zero matches for `[Ss]pektralia|SPEKTRALIA_|~/\.spektralia/|src/spektralia/|spektralia-` outside an explicitly-flagged `migration/` or `CHANGELOG.md` historical-narrative block (mark exempt blocks with an `<!-- legacy-name-allowed -->` HTML comment). The grep check is a required status check on `main` per Decision 11. No exceptions; the rebrand is part of the greenfield rewrite, not a follow-up.

---

## 9. Per-layer file template

The mandatory section skeleton each `migration/<name>.md` follows. Layer files are comparable side-by-side so the gate criteria stay mechanical to apply.

1. **`Mission`** — one paragraph: what the layer owns, what it does not own.
2. **`Scope decision history`** — references back to [§ 7 Decisions locked](#7-decisions-locked); explains *why* this layer has this shape.
3. **`Doc audit`** — current docs that touch this layer:
   - which are still authoritative;
   - which are stale (e.g., predate cplt-sndbx);
   - which contradict another doc;
   - which must be retired before the greenfield rewrite begins.
4. **`Lessons learned`** — per-source bullets from `AGENTS.md` Gotchas, `docs/RATIONALE.md` narratives, open / closed issues. Each: *what we learned — how it shapes v1*.
5. **`Reuse table`** — 100% ready filter applied per file/asset: *Rewrite | Drop | Superseded*. Strict reading of constraint #2 above.
6. **`v1 spec`** — mission + module map + public API + Settings + CLI + audit events owned + verification. Greenfield. Cross-references inward only — no "see the old SPEC.md §X."
7. **`v2 spec`** (where applicable) — explicit roadmap items tied to open-issue titles. Each item names the v1→v2 contract change.
8. **`Verification`** — concrete commands, expected outputs, integration test surfaces.
9. **`Out of scope`** — what this layer deliberately does not own. Cross-references the layer that does.
10. **`Open questions for v2`** — anything not yet decided; deferred to a follow-up gate.

---

## 10. Cross-repo contracts

All cross-layer contracts live in **L0 interlock**'s `contracts/` directory, semver-versioned, one schema-file + one Markdown explainer per contract. Consumers pin the contracts repo as a git submodule at a SHA (see v1 distribution paragraph below); semver bumps on individual schema directories signal compat surface; breaking changes bump the major version.

Rationale for interlock ownership: contracts are attestation surface. interlock already owns hashes, signing, verification; adding contract files is the smallest extension. Alternative (a sixth "contracts" repo) is overhead at our scale.

| Contract | Schema | Reference impl | Owners / consumers |
|---|---|---|---|
| **Audit event envelope** | JSON Schema: `record_hash`, `prev_hash`, `seq`, wall + monotonic time, `event`, `labels`, `categories`, `confidence`, `pattern_hash`, `model_digest`, `prompt_hash` | interlock `AuditChain` | Owned by interlock; produced by sieve / interlock itself (interlock's policy module emits `rule_hit` in-process — not a cross-repo producer); consumed by interlock `audit-verify` |
| **Session-stream JSONL** | `{ts, session_id, source, event_type, transcript_path, assistant_text, correlation_id}` (v1.0.0). `assistant_text` is the last assistant turn extracted by the per-CLI adapter; `correlation_id` is the arbiter `context_id` propagated through the substrate so `rule_hit` events can be joined to the originating tool-call verdict. | None in any layer — **the agent CLI writes directly** into the volume airlock mounts; per-CLI adapter (in interlock's policy module) maps native transcript records into this schema | Schema owned by interlock; consumed by interlock's policy module (formerly jettison Reader; see `layer4_jettison.md`) |
| **Hook integration manifest** | `settings.example.json` shape; per-hook strict/fast mode; matcher regexes; matcher count + tool-name fixtures | hull (meta) `integrations/{claude,copilot}/` | Schema owned by interlock; reference impl in meta-repo; consumed by interlock `hook-check` / `verify-hooks` |
| **Sandbox config-hash protocol** | What file set is hashed (compose + Containerfile + proxy lists + landlock policy + seccomp), how rotation works | airlock release artefacts | Schema owned by interlock; reference impl in airlock; consumed by interlock `check-sandbox` |
| **Freeze file protocol** | `~/.tidereach/FREEZE` lstat invariants (S_ISREG, mode 0600, owner == EUID), anomalous-mode handling | interlock `FreezeManager` | Owned by interlock; obeyed by sieve at gate-call time |
| **Control engine IPC** | UDS path default `/run/arbiter-engine/hook.sock`; HTTP-over-UDS: `POST /verdict {tool,args,session_id,context_id} → {verdict: deny|ask|allow, reason, evidence?}`; fail-closed timeout | arbiter reference adapter | Schema owned by interlock; reference adapter in arbiter; engine-agnostic; consumed by integration hooks in meta-repo |
| **Integrity inputs** | Canonical `HashInput` names + one-line serialization spec per entry (e.g., `pattern_table` — sorted-keys JSON, UTF-8; `model_digest` — raw model manifest bytes; `prompt_template` — UTF-8, NFC-normalized). Entries that depend on a layer's internal representation are marked TBD until that layer's spec locks. | sieve / airlock / arbiter each implement `HashInput` against this contract (interlock's policy module contributes its own inputs in-process, not via cross-repo) | Schema owned by interlock; implemented by every layer that contributes to the integrity hash; consumed by interlock `IntegrityHasher` |

Each contract file has a `CHANGELOG.md` alongside the schema and explainer; semver bumps require a changelog entry citing the issue / PR that triggered the bump.

**v1 distribution:** each consumer (sieve, arbiter, airlock, meta-repo) consumes `interlock-contracts` as a git submodule pinned at a SHA. Trades publish friction for SHA-pin precision during pre-1.0 churn. A proper distribution mechanism (PyPI package, tarball, or other) is deferred to v2; the trigger to re-open is contract stabilization at v1.0.0 or the appearance of a non-Python consumer.

**Tag convention:** bare semver tags (`v1.0.0`, `v0.4.0`, …) on every repo. Cross-repo references use `repo@tag` form (`interlock-contracts@v0.4.0`). The contracts repo carries two independent version namespaces that must not be conflated: (a) the *repo tag* identifies the contracts package as a whole and bumps whenever any contract or governance file changes; (b) the *inner schema directory version* (`contracts/<name>/vX.Y.Z/`) identifies a specific schema's compat surface and bumps only when that schema breaks compat. A single `interlock-contracts@v0.4.0` might contain `session-stream-jsonl/v1.0.0` + `audit-envelope/v1.2.0` + `hook-integration/v0.3.0`. The canonical home for this note moves to `interlock-contracts/README.md` once the repo exists; recorded here in the meantime so the convention survives the repo bootstrap.

`interlock-contracts` also ships a `governance/` directory alongside `contracts/`. Governance files carry ownership and constraint rules with no version subdirectories — a `since:` annotation on each entry is the changelog. See `layer0_interlock.md § Pre-parallel-work sequencing` for the canonical list of pre-parallel-work artifacts (one contract plus four governance docs); most gate Stage 3, and `governance/composition.md` gates Stage 5. The enumeration lives there to avoid two homes for one fact (cf. § 4).

---

## 11. Execution order

Strict sequence with binary go/no-go gates per stage. Stages 2 + 3 parallelise after Stage 1; Stage 4 starts after Stage 3 cuts a release candidate; Stage 5 parallelises with 4; Stage 6 (cross-repo soak) requires all of Stages 2–5. The 2026-06-29 layer-4 collapse merged the prior Stage 6 (jettison policy module) into Stage 2 — interlock and the policy module ship as a single v1.0 release; live-airlock verification of the policy module happens at Stage 6 soak rather than as a standalone stage.

### Stage 0 — Freeze `main` (already complete)

The freeze was effected by commit `65d99b2` ("chore(migration): replace codebase with migration planning docs") which removed the monolithic implementation from `main` and replaced it with these migration planning specs. Subsequent commits on `main` have been doc / planning / hygiene only. No further Stage 0 action is required.

*Gate (already satisfied):* `main` contains no Python source; no `src/spektralia/` directory; subsequent commits since `65d99b2` are doc / scaffolding / hygiene only.

### Stage 1 — `main` → hull (meta) restructure

Restructure this repo (rename to `hull`). All Stage 1 work is greenfield authoring on the current `main` — no copying from earlier history; the pre-migration codebase is not a source of truth for any Stage 1 artifact.

- Restructure macro docs into the meta-shape per [§ 3](#3-meta-repository-role-hull). The current migration planning specs (this file + layer specs + ROADMAP.md + AGENTS.md) are the seed; the meta-shape evolves from them in place.
- Author hook scripts (`integrations/{claude,copilot}/hooks/`) from scratch against the current spec; no lift from prior implementations.
- Rewrite README.md as a meta-overview pointing at the four sibling layer repos + drydock.
- Confirm no `pyproject.toml` exists at the meta-repo root (meta has no Python source).
- Author `docs/BLUEPAPER.md` (5–10 page architectural distillation per Decision 12) once the spec docs settle. Audience: security teams evaluating adoption, auditors, contributors wanting the gestalt before per-layer reading. Distinct from MAIN.md (migration plan).
- Author `docs/JETTISON.md` — the policy-module rule-authoring + baseline-policy guide (closes the pre-split #117 promise). Audience: operators writing rules. Per the 2026-06-29 layer-4 collapse, the doc lives in the meta-repo (`tidereach/hull/docs/JETTISON.md`) alongside BLUEPAPER.md / GOVERNANCE.md; the policy module's implementation ships in Stage 2 alongside interlock, but the rule-authoring guide is an operator-facing doc rather than a code deliverable and is authored in Stage 1 so it is ready when Stage 2 cuts the policy-module release.
- Author `docs/GOVERNANCE.md` capturing: (a) single-operator governance posture until further notice — `main` accepts commits only from the operator; no team-permissions model is designed for v1; (b) `CODEOWNERS` wildcard `* @dotknewt` per repo for v1, present in every new repo's scaffold; (c) the trigger conditions for re-opening team-permissions design — first non-operator commit on `main` of any new repo, OR first external PR merged to any of the new repos.
- Author the canonical CI workflow templates in hull that every layer repo inherits — `.github/workflows/legacy-name-guard.yml` (Constraint 6), `.github/workflows/gitleaks.yml` (Decision 18(a)), `.github/workflows/pr-title-lint.yml` (Decision 18(b)), `.github/workflows/signature-verify.yml` (Decision 10 per-PR pass/fail signal), `.github/workflows/image-sign.yml` (Decision 17 — airlock-only, reusable), `.github/workflows/ci-template.yml` (the example layer-repo CI file consumers copy at bootstrap), and `.github/workflows/release-template.yml` (the consumer-side `push: tags: ['v*']` caller for `image-sign.yml`; copied by image-publishing layers only). All third-party actions pinned to commit SHAs per Constraint 6's strict-pinning posture.
- Author the canonical pre-commit baseline `.pre-commit-config.yaml` covering gitleaks (Decision 18(a)), the standard hygiene set (trailing-whitespace, end-of-file-fixer, check-yaml, check-toml, check-added-large-files, …), `astral-sh/uv-pre-commit` for lockfile-freshness, and a commented-in-baseline `mirrors-mypy` block that each layer uncomments once its `src/` tree lands.
- Author `docs/REPO_SETTINGS.md` — the operator cookbook for the GitHub repo-side rules that complement the CI workflows: branch protection per Decisions 10 + 11 (require signed commits, require status checks `legacy-name-guard / grep-gate`, `gitleaks / scan`, `pr-title-lint / lint`, `signature-verify / verify`, and the airlock-only `image-sign / build-sign-attest`, plus require linear history, require conversation resolution, restrict pushes per Decision 19); merge strategy = squash-only with PR title as commit title per Decisions 11 + 18(b); a `gh api`-based apply script; drift-detection commands.
- Author `docs/CI.md` — operator-facing overview of the CI infrastructure: the inheritance model (hull is the canonical home; layer repos consume via `uses: tidereach/hull/.github/workflows/<name>.yml@main`), the six assertions mapped to their workflow files, pre-commit baseline copy procedure, troubleshooting common failures (signature missing, gitleaks false positive, legacy-name hit needing exemption), maintenance cadence for SHA pin bumps.
- **Transfer the GitHub repository** from `dormant-warlock/spektralia` to `tidereach/hull` per Decision 15. GitHub's automatic redirect from the old URL persists for the redirect's lifetime, but every internal doc reference and every operator-facing URL is updated to `tidereach/hull` at this stage. Contributors with local clones run `git remote set-url origin git@github.com:tidereach/hull.git`.

**Template-first acceptance (amended 2026-06-30).** For Stage 1 docs whose prose materially depends on Stage-2-or-later implementation (`docs/BLUEPAPER.md` requires the architecture to have stabilized; `docs/JETTISON.md` requires the policy module to ship with baseline rules), a `*_TEMPLATE.md` scaffold in the same directory satisfies the gate. The scaffold MUST capture: audience priority, length budget, voice and compression rules, per-section intent, source-material list, and verification criteria for the eventual full doc. The scaffold MUST also name the graduation condition — the concrete observable event that makes authoring the prose appropriate (e.g., "when interlock Stage 2 ships the policy module + baseline rules as files in `interlock/policy/baseline/`"). The full doc is authored at that point and replaces the template; until then, the template carries the spec. The same rule applies to any future doc whose prose depends on yet-to-ship implementation (e.g., `docs/THREATS.md`, `docs/COMPLIANCE.md`).

*Gate:* `README.md` lists the four sibling layer repos + drydock; `migration/` planning docs preserved; **BLUEPAPER scaffold** (`docs/BLUEPAPER.md` or `docs/BLUEPAPER_TEMPLATE.md`) exists on `main`; `docs/GOVERNANCE.md` exists on `main`; **JETTISON scaffold** (`docs/JETTISON.md` or `docs/JETTISON_TEMPLATE.md`) exists on `main` (policy-module rule-authoring + baseline guide, per the 2026-06-29 layer-4 collapse); `docs/REPO_SETTINGS.md` exists on `main`; `docs/CI.md` exists on `main`; `.github/workflows/` contains the seven canonical workflows (`legacy-name-guard.yml`, `gitleaks.yml`, `pr-title-lint.yml`, `signature-verify.yml`, `image-sign.yml`, `ci-template.yml`, `release-template.yml`); `.pre-commit-config.yaml` exists on `main`; `CODEOWNERS` file is present with the wildcard rule (`* @dotknewt`) in each new repo's scaffold; canonical URL is `github.com/tidereach/hull`; legacy `dormant-warlock/spektralia` either 404s or redirects to the new URL.

### Stage 2 — interlock (L0) v1 + policy module (L4)

Standalone CLI + library + `contracts/` + **the policy module** (`src/interlock/policy/`). Greenfield rewrite throughout; `integrity.py` is reshaped to break the L1 leak; `heartbeat.py` and the freeze-manager surface are rewritten against the per-layer settings. Publishes the cross-repo contracts. Ships `SquidAccessReader` (tails airlock's host-bound Squid access log; appends one `egress_decision` envelope per line to the AuditChain — see `layer3_airlock.md § Cross-layer contracts`).

**Policy-module deliverables fold in per the 2026-06-29 layer-4 collapse** — the policy module's v1 surface (`LogAction` only) has no runtime dependency on airlock at all; it depends only on the `session-stream-jsonl/v1.0.0` contract that is already Stage-2-release-blocking per Pivot 3. Hard actions (`KillAgentContainerAction`, `SeverEgressAction`, `FreezeWorkspaceAction`) are v2 and ship as `NotImplementedError`-raising stubs in Stage 2. Folding the policy module into Stage 2 eliminates the awkward "interlock without its policy submodule" window between the prior Stages 2 and 6, removes consumer-pin and import-graph stub questions, and lets the policy module's v1.0 surface ride the same release that publishes `session-stream-jsonl/v1.0.0`. Live-airlock verification happens at the Stage 6 cross-repo soak.

Policy-module Stage 2 deliverables:

- Reader (tail-safe JSONL over the substrate volume; offline read-and-close and live tail-with-poll modes).
- Adapters: Claude Code + Copilot per-CLI transcript parsers.
- Rule engine: YAML rules, predicates, regex, threshold counters, cooldowns.
- Actions: `LogAction` (v1 implementation); `BlockAction` (Soft) + `KillAgentContainerAction` + `SeverEgressAction` + `FreezeWorkspaceAction` (Hard) v2 stubs raising `NotImplementedError` with the v2 contract documented in their docstrings.
- CLI subcommands under `tidereach interlock`: `session-audit`, `session-watch`, `rules-lint`.
- Policy-module audit events: `session_event_seen`, `rule_hit`, `action_logged` (v1 wired); `block_flag_written`, `kill_agent_container_initiated`, `sever_egress_initiated`, `freeze_workspace_initiated`, `jettison_baseline_drift` (v2 hooks documented).
- Tests against fixture JSONL transcripts — no live airlock dependency at Stage 2 (the volume mount + live-tail e2e is verified at Stage 6 soak).

*Gate:*

- `pytest -q` green on the new interlock repo.
- `tidereach interlock {verify-integrity, verify-installed, check-sandbox, check-ollama, check-engine, hook-check, verify-hooks, install-hooks, audit-verify, audit-rotate, audit-purge, audit-repair, self-test, freeze, unfreeze, stats}` all green on a fixture project (each subcommand invoked as `tidereach interlock <subcommand>` per Decision 16).
- `tidereach interlock {session-audit, session-watch, rules-lint}` all green on fixture transcripts (policy module).
- `contracts/{audit-envelope,session-stream-jsonl,hook-manifest,sandbox-config,freeze-file,engine-ipc,integrity-inputs}.{schema.json,md}` all present with semver `1.0.0` tags.
- `governance/{audit-event-ownership,freeze-manager-constraint,layer-constraints}.md` all present (pre-parallel-work artifacts; without them Stages 3–5 cannot begin safely in parallel).
- CI grep-assertion: no LLM / HTTP-client imports in `src/interlock/policy/` (deterministic-only invariant).
- Audit events `session_event_seen`, `rule_hit`, `action_logged` appear in the chain when the policy module is exercised against fixture transcripts.

*Why first after meta:* every other layer's CI calls into interlock for attestation; interlock's contracts are the schemas the others target; the policy module rides the same release because it consumes those contracts in-process.

### Stage 3 — sieve (L1) v1

Greenfield rewrite throughout, including the leaf detectors, `gate.py`, `config.py`, `cli.py`, and `ner.py`. Calls into interlock for freeze / audit / integrity. Corpus seeded.

*Gate:*

- `pytest -q` green (~215+ tests).
- `tidereach sieve scan` / `tidereach sieve scan --explain` / `tidereach sieve scan-config` / `tidereach sieve self-test` green; respx-mocked classifier; injection corpus does not flip verdict.
- SPEC §20 verification list (rewritten for sieve) passes.
- Latency budgets preserved: UserPromptSubmit ≤500ms p95, PreToolUse ≤300ms p95, PostToolUse ≤200ms p95 on 10KB.
- Live e2e against `llama3.1:8b`: credential block at UserPromptSubmit; Task block; Bash block; self-test green. (Reproduces `docs/PLAN.md § 3.19`.)

Stage 2 ↔ Stage 3 parallelism: sieve can be developed against interlock's published contracts even before interlock cuts its release; Stage 3 acceptance requires a interlock release-candidate to be pinned.

### Stage 4 — airlock (L3) v1

Greenfield Containerfile + compose; rewrite `infra/sandbox/proxy/*` and `landlock/*` per the airlock Reuse table (pending the strict bar check). Add the session-stream named volume mount at the agent CLI's expected session-output path. Add the host-bound Squid access log mount that interlock's `SquidAccessReader` (Stage 2) tails. Pin sieve to a released tag in the Containerfile. Stage 4 also commits the v1 concurrency model: one active agent per compose stack; parallel runs require separate stacks with distinct `SESSION_STREAMS_VOLUME` values.

*Gate:*

- `sandbox-quickstart.sh` boots a clean container in <60s on the reference host (2-vCPU, 4GB, Ubuntu 24.04 amd64 + arm64 (multi-arch baseline; both required for reproducible-build verification), Podman rootless); timing recorded in `bench/stage4-baseline.txt` (one row per arch).
- Egress: an allowlisted domain (Anthropic API) reachable; a denied domain (paste site) blocked with TCP-RST; the denied domain appears as an `egress_decision{action=deny}` envelope in the AuditChain within ≤ 2s, and `audit-verify` reports no chain breaks.
- bwrap fallback works on hosts without bwrap.
- Seccomp profile blocks the documented dangerous syscalls.
- `tidereach interlock check-sandbox` returns 0 against this image.
- **A test agent run produces JSONL files in `$SESSION_DIR`** — the substrate works; the per-CLI session-output mechanism is documented and confirmed by the test run (Claude Code: `CLAUDE_TRANSCRIPT_DIR` as primary; Stop hook secondary).

Stage 4 requires Stage 3 release candidate (for the sieve pin in the Containerfile). Stage 4 final release pin is a Stage 7 sweep.

### Stage 5 — arbiter (L2) v1 integration spec

Smallest layer. Produces an engine-agnostic spec + a thin adapter library + interlock's `check-engine` CLI extension. Reference adapter ships for one engine (operator choice in deployment; not arbiter's call to make).

*Gate:*

- Spec reviewed against the engine-IPC contract in interlock.
- Adapter passes contract tests against a respx-mocked engine.
- interlock `check-engine` returns 0 against a running mock engine; returns 1 against an absent socket.

Stage 5 parallelises with Stage 4 (no dependency between them).

### Stage 6 — Cross-repo soak

All five layers wired into a fixture endpoint (Claude Code + Copilot, both running inside airlock, both gated by sieve, both observed by jettison, all attested by interlock, optionally fronted by a arbiter engine). The soak fixtures, harness scripts, and baseline results are hosted in `tidereach/drydock` (a sixth repo dedicated to cross-layer integration — see [§ 7 Decision 14](#7-decisions-locked)); each layer's CI pins drydock at a tag for its own integration run.

*Gate:*

- Full integration suite passes (mirrors `tests/test_hooks.py` of the current monorepo, rewritten for the split).
- Latency budgets from Stage 3 preserved.
- Audit chain traversal across all five layers (interlock `audit-verify`) reports zero breaks.
- A known-bad input (credential in prompt, suspicious tool call, sensitive file read) triggers the correct layer's block / log / audit event.

### Stage 7 — Stack-level documentation publish

hull (meta-repo) README points to the four sibling layer repos + drydock with stable URLs. The pre-migration codebase is not maintained as a reference — the migration is greenfield per Constraint 1 and there is no archival tag to cite.

*Gate:* meta-repo README is updated and lists all four sibling layer repos plus drydock (`tidereach/interlock`, `tidereach/sieve`, `tidereach/arbiter`, `tidereach/airlock`, `tidereach/drydock`) with their canonical URLs.

---

## 12. Per-stage product specs (gate criteria)

Each stage's gate restated as a CI-runnable checklist. Mirrors `docs/SPEC.md §20 Verification` style.

### Stage 2 interlock + policy module
- [ ] `pytest -q` green
- [ ] `tidereach interlock --api-version` prints integer ≥ 1
- [ ] Each CLI subcommand has a positive and a negative test
- [ ] `contracts/` has 7 schema files + 7 explainers + 7 `CHANGELOG.md` (the seventh is `integrity-inputs`)
- [ ] `contracts/session-stream-jsonl/v1.0.0/schema.json` matches the field list committed in `layer0_interlock.md § session-stream-jsonl/v1.0.0 schema commitment` exactly (`ts`, `session_id`, `source`, `event_type`, `transcript_path`, `assistant_text`, `correlation_id`; no `extra` / `raw_payload` catch-all). **Stage-2-release-blocking** per the 2026-06-29 layer4 ember review Pivot 3 — without the v1.0.0 schema pinned at release, Stage 3+ layer development desyncs on the policy-module surface.
- [ ] `governance/` has `audit-event-ownership.md`, `freeze-manager-constraint.md`, `layer-constraints.md`, `composition.md` (the last gates Stage 5; the other three plus `contracts/integrity-inputs/` and `contracts/session-stream-jsonl/` gate Stage 3)
- [ ] `verify-installed --strict` fails on a venv without `--require-hashes`
- [ ] `freeze` followed by any other check returns block; `unfreeze` restores
- [ ] `SquidAccessReader` unit tests green (parses representative allow/deny lines into `egress_decision` envelopes with `{domain, action, client, http_status}` labels; raise inside `AuditChain.append()` → stderr-log-and-continue, file line preserved)
- [ ] Policy-module: `tidereach interlock session-audit <fixture-transcript>` produces expected rule hits against the canonical fixture set (Claude Code + Copilot)
- [ ] Policy-module: `tidereach interlock session-watch` tails a fixture-volume run; rule hits emit log lines within `tail_poll_interval_seconds`
- [ ] Policy-module: `tidereach interlock rules-lint` against the v1 baseline ruleset passes; against a deliberately broken rule (unknown predicate, missing action) fails with a clear error
- [ ] Policy-module: adapter unit tests for Claude Code + Copilot transcripts green
- [ ] Policy-module: CI grep-assertion — no LLM / HTTP-client imports in `src/interlock/policy/` (no `httpx`, `requests`, `httpcore`, `ollama`); deterministic-only invariant
- [ ] Policy-module: audit events `session_event_seen`, `rule_hit`, `action_logged` appear in the AuditChain when fixture transcripts are processed (`audit-verify` reports no chain breaks)

### Stage 3 sieve
- [ ] `pytest -q` green (≥ 215 tests)
- [ ] `tests/corpus/{positive,negative,injection}/` populated and consumed
- [ ] NFKC-expanding sanitization round-trip test passes
- [ ] Cache invalidation matrix (two mechanisms): (a) hash-drift triggers — pattern_hash, model_digest, prompt_hash, normalization_map_version, policy config_hash — each produce a key-miss naturally with no explicit call; (b) state-event triggers — freeze, unfreeze, canary_drift, self-test fail — each wire to `Cache.invalidate_all()` explicitly; both mechanisms tested per-trigger
- [ ] `scripts/latency_bench.py` passes (p95 within budget, 100-request run per hook type, respx-stubbed classifier with 80ms simulated model latency); baseline result committed to `bench/stage3-baseline.json`
- [ ] Live `llama3.1:8b` bench result recorded in Stage 3 sign-off comment (not a CI gate; documents the hardware baseline for regression detection)
- [ ] ReDoS fuzz passes (all patterns return within 100ms timeout)
- [ ] Live e2e against `llama3.1:8b` reproduces the four Phase-3 block scenarios

### Stage 4 airlock
- [ ] `sandbox-quickstart.sh` boots < 60s on the reference host (amd64 + arm64 multi-arch baseline per Decision 17); `bench/stage4-baseline.txt` committed with one row per arch
- [ ] Squid ACL lint passes (no domain in both bare and leading-dot form)
- [ ] `setup.sh` refuses to proceed if workspace bind-mount is not pre-created (exits 1 with the chown instruction)
- [ ] Containerfile pin to sieve release tag is referenced explicitly
- [ ] Session-stream volume `SESSION_STREAMS_VOLUME=session-streams` is mounted at `SESSION_DIR=/work/session-streams`
- [ ] A test agent run writes JSONL files into the substrate volume; per-CLI session-output mechanism documented (Claude Code → `CLAUDE_TRANSCRIPT_DIR`)
- [ ] Squid access log is host-bound at `${PROXY_LOG_DIR}/access.log` (file-bind, not directory-bind); proxy container has no other writable host mounts
- [ ] Egress deny test asserts the blocked domain appears as an `egress_decision{action=deny}` envelope in the AuditChain within ≤ 2s; `audit-verify` reports no chain breaks
- [ ] v1 concurrency policy committed: one active agent per compose stack
- [ ] Container images built and signed for amd64 + arm64 per Decision 17; both manifest entries verified via `cosign verify-blob` against the keyless Fulcio chain and Rekor transparency log

### Stage 5 arbiter
- [ ] Spec reviewed; cross-references interlock's `engine-ipc` contract
- [ ] Adapter unit tests against respx-mocked engine green
- [ ] interlock `check-engine` returns 0 against a running mock; 1 against an absent socket
- [ ] Hook-ordering example documented; cites interlock `governance/composition.md` (arbiter participates in the chain; ordering and OR-to-block are defined there, not in arbiter's `SPEC.md`)

### Stage 6 Cross-repo soak
- [ ] Integration suite green
- [ ] Latency budgets preserved
- [ ] Audit chain traversal across all layers reports zero breaks
- [ ] Known-bad fixtures fire the correct layer's response

---

## 13. Hygiene findings folded into the migration

Repo cleanup carried forward as explicit Stage tasks.

| Finding | Resolution | Stage |
|---|---|---|
| `integrations/claude_code_hooks/__pycache__/` (5 orphan .pyc, no `.py` siblings) | Delete during Stage 1 meta restructure | Stage 1 |
| `integrations/copilot/__pycache__/` (wrong level — source moved to `hooks/`) | Delete during Stage 1 | Stage 1 |
| `infra/sandbox/workspace/name-alchemist.{md,eval.md}` (stale eval workspace content) | Not carried forward; the greenfield airlock `.gitignore` covers `workspace/**` from the start | Stage 4 |
| `infra/sandbox/_podman` (empty placeholder) | Drop during Stage 4 | Stage 4 |
| `canary_interval_seconds` declared in `Settings` but never read | Drop during Stage 2 interlock `interlockSettings` rewrite | Stage 2 |
| `src/spektralia/sessions/writer.py` (no internal callers; obsoleted by airlock's volume mount) | **Delete** during Stage 1; **not migrated** to jettison | Stage 1 |
| `src/spektralia/sessions/__init__.py` (empty) | Delete during Stage 1 | Stage 1 |
| `docs/PLAN.md` retiring under #133 | Pre-migration plan; no longer maintained. Layer specs in `migration/` are the canonical replacements. Not copied forward. | (n/a — pre-migration document) |
| `docs/ENDPOINT_STACK.md` references Fence in legacy prose while reality is cplt-sndbx | Reconcile during Stage 4 airlock doc audit; ENDPOINT_STACK.md becomes a hull (meta) doc, rewritten cplt-sndbx-canonical | Stage 4 |
| `docs/COMPLIANCE.md §21` table duplicates `docs/SPEC.md §21` | Deduplicate during Stage 1 meta restructure; COMPLIANCE.md references SPEC.md instead | Stage 1 |
| `integrity.py:14-15` imports `.classifier.PROMPT_HASH` and `.patterns.PATTERNS` (L0 leak into L1) | Resolved by Stage 2 interlock rewrite; `HashInput` protocol replaces direct import | Stage 2 |
| `gate_frozen{_auto}` audit events emit from `gate.py` (L1) but represent interlock (L0) state | Resolved by Stage 2 interlock `FreezeManager`; sieve calls interlock at gate-call time | Stage 2 + Stage 3 |
| `output_gate.py` masquerades as library internal but has no intra-`src/` callers | Marked as sieve public output-gating API during Stage 3 | Stage 3 |
| `recheck` referenced in CI workflows but does not exist on PyPI | Stage 2 interlock CI uses pure-Python timeout assertion | Stage 2 |
| 14+ CLI subcommands on one binary | Resolved by per-layer CLI (interlock owns `verify-* / check-* / hook-* / audit-* / freeze / unfreeze / stats / self-test` plus the policy-module subcommands `session-audit / session-watch / rules-lint`; sieve owns `scan / scan --explain / scan-config / self-test`) | Stages 2–5 |

---

## 14. What the migration deliberately does NOT do

- Does **not** pause feature development on `infra/sandbox/` mid-Stage 4 — the main freeze (Stage 0) covers feature scope; Stage 4 greenfield rewrite work continues during the freeze.
- Does **not** introduce attestation (sigstore-style signing) in v1 — interlock v1 is preflight only; attestation is interlock v2.
- Does **not** implement `BlockAction` (Soft) or the Hard primitives (`KillAgentContainerAction`, `SeverEgressAction`, `FreezeWorkspaceAction`) in v1 — jettison v1 is `LogAction` only; the Soft + Hard family is v2 and each Hard action is individually opt-in.
- Does **not** pick a control engine for arbiter — the engine is operator choice. arbiter ships an engine-agnostic spec + adapter; Falco, OPA, custom Python rules are all valid backends.
- Does **not** redesign the Ollama classifier prompts — the pre-migration two-framing prompt text guides sieve's greenfield rewrite of `classifier.py`. Classifier prompt evolution is a sieve v2 concern.
- Does **not** ship a Python session writer in any layer — airlock's volume mount handles the substrate; the agent CLI writes JSONL directly.
- Does **not** preserve the unified `Settings` dataclass — per-layer `interlockSettings`, `sieveSettings`, `jettisonSettings` replace it.
- Does **not** ship NER or output gating disabled — both are opt-in defaults in sieve v1, matching current behaviour.
- Does **not** introduce LLM-based detection in jettison — jettison is deterministic-rules-only.
- Does **not** ship a v1 binary called `spektralia` — the meta-repo has no binary; per Decision 16 the public installed surface is a single `tidereach` umbrella binary with namespaced per-layer subcommands (`tidereach interlock …`, `tidereach sieve …`, `tidereach airlock …`), not bare per-layer binaries.

---

## 15. Risks and mitigations

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Four sibling layer repos triple coordination cost | Medium | High | interlock `contracts/` is the single home for cross-cutting protocols; narrow in v1, evolves via semver |
| sieve rewrite of clean leaves preserves intent but tests still assume a unified Settings | High | Low | All production and test code is rewritten greenfield per layer against per-layer settings (`sieveSettings`, `interlockSettings`, `jettisonSettings`) — no source carries forward from the pre-migration repo |
| airlock Containerfile pin to sieve release means Stage 4 cannot finish before Stage 3 release | High | Medium | Stage 4 acceptance allows pinning to a release-candidate tag; final pin is a Stage 7 sweep |
| Session-stream volume contract is fragile if agent CLI's expected path varies between Claude Code / Copilot | Medium | High | airlock exposes the mount via `SESSION_DIR` env var; per-CLI configuration documented in airlock |
| Open-issue post-mortems get lost when issues close | Medium | Medium | Each layer's `Lessons learned` copies the relevant issue's surviving narrative before closing |
| Sci-fi names contested post-lock-in | Low | Low | Names finalized 2026-06-29 ([§ 7 Decision 14](#7-decisions-locked)); re-opening requires plan-mode re-entry, not a per-layer-review edit |
| Stage 6 cross-repo soak finds a contract gap | Medium | High | Plan for one contract-bump cycle in the Stage 6 budget; interlock contracts are semver so a fix is a minor bump |
| The control engine the operator picks turns out incompatible with arbiter's IPC | Low | High | arbiter's IPC is HTTP-over-UDS with a documented envelope; engines that can't speak this need a per-engine shim, which is operator scope |
| `infra/sandbox/proxy/allowed-domains.txt` curation drifts during migration | Medium | Medium | airlock ships an ACL lint that asserts no domain appears in both bare and leading-dot form |
| Claude Code or Copilot transcript format changes mid-migration | Low | High | Adapter is the integration boundary; transcript-format drift requires only an adapter PR, not a jettison-core change |

---

## 16. How this plan is verified

The plan is satisfied — and the migration is ready to begin Stage 0 — when all of the following hold:

1. **All six files exist.** `migration/` contains `MAIN.md` (this file), `layer0_interlock.md`, `layer1_sieve.md`, `layer2_arbiter.md`, `layer3_airlock.md`, `layer4_jettison.md`.
2. **Every layer file has the section skeleton from [§ 9](#9-per-layer-file-template).** Mission, scope, doc audit, lessons learned, reuse table, v1 spec, v2 spec (where applicable), verification, out of scope, open questions.
3. **Every cross-repo contract in [§ 10](#10-cross-repo-contracts) is referenced by name in at least one layer file**, and interlock's file references all six.
4. **A fresh reader can answer "which file owns event X / Settings Y / CLI command Z" by reading `MAIN.md` alone.** No "see the old `src/`" punts.
5. **The meta-repo / layer-repo / contract-home assignments in [§ 3](#3-meta-repository-role-hull) + [§ 4](#4-cross-integration-documentation-rule) + [§ 10](#10-cross-repo-contracts) are mutually consistent.** No doc claims two homes; no contract claims two owners.
6. **Every clean-leaf `src/spektralia/*.py` module surfaces with an explicit `Rewrite` row in exactly one layer's Reuse table** (or `Drop` for `sessions/writer.py` + `sessions/__init__.py`).
7. **Every cross-layer leak (`integrity.py:14-15`, `gate_frozen{_auto}` emission site, `output_gate.py` orphan, `sessions/writer.py` deletion) has a v1 fix specified.**
8. **Every open issue in [§ 13](#13-hygiene-findings-folded-into-the-migration) is rolled into a layer's spec.** No issue carries forward as "we'll figure out later."
9. **Every doc currently in `docs/` is named in exactly one layer's `Doc audit`** (no orphan docs) or in [§ 3](#3-meta-repository-role-hull)'s meta-repo retention table.
10. **The sci-fi names (interlock / sieve / arbiter / airlock / jettison) are finalized** per [§ 7 Decision 14](#7-decisions-locked) and the project identity (Tidereach, GitHub org `tidereach`) is locked per Decision 15. Renaming any of these is not a one-Edit operation; it requires re-entering plan mode.

If any check fails at execution time, the relevant layer file is amended (or re-entered into plan mode if the failure is architectural) — never powered through.
