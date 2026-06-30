# STATE — Tidereach Hull

> Maintained by `state-keeper` (`instruction-management` plugin). Update after each stage gate, branch-protection change, or significant repo event. See `AGENTS.md` for stable project context; this file tracks point-in-time state only.

## Current status (2026-06-30)

Stage 1 complete. Repo lives at `tidereach/hull` (public). Branch protection applied per `docs/REPO_SETTINGS.md § 1` (amended — see ROADMAP items 5 + 6). BLUEPAPER and JETTISON ship as templates per the template-first acceptance rule (`migration/MAIN.md § 11 Stage 1`); each scaffold names its graduation condition (interlock Stage 2 minimum for JETTISON; Stage 2+ architecture stabilization for BLUEPAPER).

## Stage tracker

| Stage | Status |
|---|---|
| Stage 1 — hull restructure | Complete (2026-06-30) |
| Stage 2 — interlock + jettison (parallel) | Not started |
| Stage 3 — sieve | Not started |
| Stage 4 — airlock | Not started |
| Stage 5 — arbiter | Not started |

## WIP — Stage 2 bootstrap (next session)

Stage 2 bootstrap begins after the Stage 1 close-out PR merges. Priority items for next session:

- **B1**: Create `tidereach/interlock` GitHub repo (private → public after CI green); apply branch protection per `docs/REPO_SETTINGS.md`
- **B2**: Scaffold interlock package skeleton (`pyproject.toml`, `src/tidereach/interlock/`, `.github/workflows/`, tests/, governance/, contracts/)
- **B3**: Author pre-parallel-work contracts: `contracts/integrity-inputs/v1.0.0/` + `contracts/session-stream-jsonl/v1.0.0/` (gate Stage 3; release-blocking per Pivot 3)
- **B4**: Author pre-parallel-work governance: `governance/audit-event-ownership.md`, `governance/freeze-manager-constraint.md`, `governance/layer-constraints.md`, `governance/composition.md`
- **B5**: Push a no-op PR to `tidereach/interlock`; verify all five required status checks pass green (validates hull reusable-workflow inheritance)

Remaining Stage 2 substance (deferred to subsequent sessions after bootstrap):
- Remaining 5 contracts: `audit-envelope`, `hook-manifest`, `sandbox-config`, `freeze-file`, `engine-ipc`
- All 18 CLI subcommands (stubs → real implementations)
- Policy-module v1 surface (Reader, Claude Code + Copilot adapters, rule engine, `LogAction`)
- Test fixtures (Claude Code + Copilot JSONL transcripts)
- `SquidAccessReader` (depends on airlock Squid access log format spec)

## Recent events

- 2026-06-30: betterleaks switch from `gitleaks-action` (PR #149); ROADMAP item 7 opened for abandonment risk
- 2026-06-30: `signature-verify.yml` skips merge commits via `--no-merges` (PR #150); "Update branch" UI button safe again
- 2026-06-30: branch protection amended — `required_approving_review_count: 0`, `required_signatures: false` (ROADMAP items 5+6)
- 2026-06-30: `BLUEPAPER_TEMPLATE.md` and `JETTISON_TEMPLATE.md` added (PR #151, #152); template-first acceptance added to `MAIN.md § 11`
- 2026-06-30: `betterleaks.yml` renamed from `gitleaks.yml`; `signature-verify.yml` docs refreshed (PR #154)
- 2026-06-30: Stage 1 close-out PR (AGENTS.md restructure + MAIN.md betterleaks/hook-scripts drift fix) — in flight
