# Migration Layer Specs

Planning specs under `migration/` are the canonical record for the Tidereach rebuild. Read `migration/MAIN.md` before editing any layer spec.

## Files

- `migration/MAIN.md` — architecture, decisions, execution order. `§ 7` = Decisions table; `§ 8` = Constraints; `§ 9` = per-spec Reuse + Doc-audit template; `§ 11` = Stage gate definitions.
- `migration/layer0_interlock.md` — L0 Attestation/Glue (Stage 2; ships before other layers)
- `migration/layer1_sieve.md` — L1 Data Plane / sensitivity gate (Stage 3)
- `migration/layer2_arbiter.md` — L2 Control Plane / intent integration (Stage 5)
- `migration/layer3_airlock.md` — L3 Execution Plane / sandbox + session-stream substrate (Stage 4)
- `migration/layer4_jettison.md` — L4 Visibility Plane / deterministic rules + actions (Stage 2; policy module ships alongside interlock per the 2026-06-29 layer-4 collapse)

## Working with specs

- Ember agent (`ember:Ember`) works well for planning revision sessions — spawn once, relay follow-ups via `SendMessage` with the returned agentId.
- If Ember fails to spawn with a model-access error, check that the Ember agent definition at `~/.claude/plugins/cache/agency/ember/1.0.2/agents/ember.md` uses hyphen notation for the model ID (e.g. `claude-opus-4-7`, not `claude-opus-4.7`). Fix the file and start a new session.
- Before any layer spec work begins in parallel, three pre-parallel artifacts must be locked in `interlock-contracts`: `contracts/integrity-inputs/v1.0.0/`, `governance/audit-event-ownership.md`, `governance/freeze-manager-constraint.md`.
- Settings tables: always verify the stated field count matches the actual row count (layer0 said 13/had 15; layer1 said 15/had 20).
- Audit event ownership uses a two-tier model: layer-exclusive events (interlock only) vs. cross-layer shared-namespace events (defined by interlock, emitted by named layer).
