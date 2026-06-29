# Tidereach — Migration Planning Repo

Main branch contains only migration planning specs. Full codebase is archived on `archive/pre-migration`.

## Files

- `MAIN.md` — architecture, decisions, execution order. **Read this first.**
- `ROADMAP.md` — v2 candidates and other deferred items, each with a concrete re-open trigger. Append new candidates here as they surface; don't wait to be asked.
- `layer0_interlock.md` — L0 Attestation/Glue (Stage 2; ships before other layers)
- `layer1_sieve.md` — L1 Data Plane / sensitivity gate (Stage 3)
- `layer2_arbiter.md` — L2 Control Plane / intent integration (Stage 5)
- `layer3_airlock.md` — L3 Execution Plane / sandbox + session-stream substrate (Stage 4)
- `layer4_jettison.md` — L4 Visibility Plane / deterministic rules + actions (Stage 6)

## Project code standards

Layer names (`interlock`, `sieve`, `arbiter`, `airlock`, `jettison`, `hull`, `drydock`) may be rejected by stakeholders. Keep code resilient to a layer rename — the doc-level name is one search-and-replace away, but a Python identifier or env var carrying a layer name is a breaking change for consumers.

- Use layer names in **documentation** as memorable handles for the layers.
- Avoid using layer names in **code**. Instead use descriptive, best-practice naming conventions for files, classes, functions, and variables.
- See also `MAIN.md § 8 Constraint 6`: legacy `spektralia` names MUST NEVER propagate into the new repositories; CI grep gate enforces.

## Working with specs

- Ember agent (`ember:Ember`) works well for planning revision sessions — spawn once, relay follow-ups via `SendMessage` with the returned agentId
- Before any layer spec work begins in parallel, three pre-parallel artifacts must be locked in `interlock-contracts`: `contracts/integrity-inputs/v1.0.0/`, `governance/audit-event-ownership.md`, `governance/freeze-manager-constraint.md`
- Settings tables: always verify the stated field count matches the actual row count (layer0 said 13/had 15; layer1 said 15/had 20)
- Audit event ownership uses a two-tier model: layer-exclusive events (interlock only) vs. cross-layer shared-namespace events (defined by interlock, emitted by named layer)

## Git

- `archive/pre-migration` — full monorepo snapshot before restructure (2026-06-28)
- Working tree may have untracked residue (infra/, src/, tests/) after branch switches; clear with `git clean -fd`
