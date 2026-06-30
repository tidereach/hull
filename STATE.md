# STATE — Tidereach Hull

> Maintained by `state-keeper` (`instruction-management` plugin). Update after each stage gate, branch-protection change, or significant repo event. See `AGENTS.md` for stable project context; this file tracks point-in-time state only.

## Current status (2026-06-30)

Stage 1 complete. Repo lives at `tidereach/hull` (public). Branch protection applied per `docs/REPO_SETTINGS.md § 1` (amended — see ROADMAP items 5 + 6). BLUEPAPER and JETTISON ship as templates per the template-first acceptance rule (`migration/MAIN.md § 11 Stage 1`); each scaffold names its graduation condition (interlock Stage 2 minimum for JETTISON; Stage 2+ architecture stabilization for BLUEPAPER).

## Stage tracker

| Stage | Status |
|---|---|
| Stage 1 — hull restructure | Complete (2026-06-30) |
| Stage 2 — interlock + jettison (parallel) | Bootstrap complete; substance in progress |
| Stage 3 — sieve | Not started |
| Stage 4 — airlock | Not started |
| Stage 5 — arbiter | Not started |

## Completed — Stage 2 bootstrap (2026-06-30)

- **B1**: Create `tidereach/interlock` GitHub repo; branch protection applied per `docs/REPO_SETTINGS.md`
- **B2**: Scaffold interlock package skeleton (`pyproject.toml`, `src/tidereach/interlock/`, `.github/workflows/`, tests/, governance/, contracts/)
- **B3**: Author pre-parallel-work contracts: `contracts/integrity-inputs/v1.0.0/` + `contracts/session-stream-jsonl/v1.0.0/` (gate Stage 3; release-blocking per Pivot 3)
- **B4**: Author pre-parallel-work governance: `governance/audit-event-ownership.md`, `governance/freeze-manager-constraint.md`, `governance/layer-constraints.md`, `governance/composition.md`
- **B5**: Validate hull reusable-workflow inheritance via smoke test (PR #1, squash-merged `8eed140` on 2026-06-30; all five status checks pass)

## WIP — Stage 2 substance

Contracts — 3 of 7 complete (`integrity-inputs/v1.0.0`, `session-stream-jsonl/v1.0.0`, `audit-envelope/v1.0.0`); 4 remain:
- `hook-manifest/v1.0.0`
- `sandbox-config/v1.0.0`
- `freeze-file/v1.0.0`
- `engine-ipc/v1.0.0`

Dispatcher, CLI & policy module:
- All 18 CLI subcommands (stubs → real implementations)
- Policy-module v1 surface (Reader, Claude Code + Copilot adapters, rule engine, `LogAction`)

Tests & auxiliary:
- Test fixtures (Claude Code + Copilot JSONL transcripts)
- `SquidAccessReader` (depends on airlock Squid access log format spec)

## Recent events

- 2026-06-30: `audit-envelope/v1.0.0` authored on feature branch in `tidereach/interlock` (contract 3 of 7 in Stage 2 substance)
- 2026-06-30: B5 smoke test PR #1 included follow-up fix `0b4fc0d` (`pull-requests: read` permission for reusable-workflow callers) — key CI inheritance lesson for cascading workflows
- 2026-06-30: B5 PR #1 (`chore(ci): B5 smoke test — validate hull reusable-workflow inheritance`) squash-merged `8eed140`; all five status checks pass
- 2026-06-30: betterleaks switch from `gitleaks-action` (PR #149); ROADMAP item 7 opened for abandonment risk
- 2026-06-30: `signature-verify.yml` skips merge commits via `--no-merges` (PR #150); "Update branch" UI button safe again
- 2026-06-30: branch protection amended — `required_approving_review_count: 0`, `required_signatures: false` (ROADMAP items 5+6)
- 2026-06-30: `BLUEPAPER_TEMPLATE.md` and `JETTISON_TEMPLATE.md` added (PR #151, #152); template-first acceptance added to `MAIN.md § 11`
- 2026-06-30: `betterleaks.yml` renamed from `gitleaks.yml`; `signature-verify.yml` docs refreshed (PR #154)
- 2026-06-30: Stage 1 close-out PR (AGENTS.md restructure + MAIN.md betterleaks/hook-scripts drift fix) — in flight
