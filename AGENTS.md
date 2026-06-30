# Tidereach — Migration Planning Repo

Main branch contains only migration planning specs. The migration is a greenfield rebuild per `migration/MAIN.md § 8` Constraint 1 — no source is copied forward from any prior implementation.

See `STATE.md` for current stage progress and point-in-time status.

## Files

<!-- legacy-name-allowed -->
- `migration/` — historical planning specs preserved as the canonical migration record. Exempted from `legacy-name-guard` so layer specs may reference pre-migration `spektralia` names where required for narrative accuracy. See `migration/AGENTS.md` for layer-file details.
<!-- /legacy-name-allowed -->
- `migration/MAIN.md` — architecture, decisions, execution order. **Read this first.**
- `ROADMAP.md` — v2 candidates and other deferred items, each with a concrete re-open trigger. Append new candidates here as they surface; don't wait to be asked.
- `README.md` — meta-overview pointing at the four sibling layer repos + drydock.
- `.pre-commit-config.yaml` — canonical pre-commit baseline (betterleaks, hygiene set, uv-lock; mypy ships commented out, uncommented per layer once `src/` lands).
- `.github/CODEOWNERS` — `* @dotknewt` wildcard per `docs/GOVERNANCE.md § 2`.
- `docs/` — operator documentation. See `docs/AGENTS.md`.
- `.github/workflows/` — CI workflows. See `.github/workflows/AGENTS.md`.

## Commands

| Command | Purpose |
|---|---|
| `.venv/bin/pre-commit run --files <paths>` | Hygiene + betterleaks + (when uncommented) mypy. Install per `docs/CI.md § 3`. |
| `gh api -X PUT repos/tidereach/hull/branches/main/protection ...` | Apply branch protection per `docs/REPO_SETTINGS.md § 4` (amended apply script — count=0, code-owner-reviews=false, required_signatures=false; the `signature-verify / verify` required-status-check was removed 2026-06-30 per ROADMAP item 8). |

**Signing setup** — commit signing is **deferred to v2** per `ROADMAP.md` item 8 (2026-06-30). Day-to-day commits don't require gitsign; `git commit` works without `-S`. The `signature-verify.yml` workflow is retired. **Tag signing for release artifacts (Decision 17 image-sign chain) is not affected** — see `docs/CI.md § 4b "Prerequisite: gitsign configured locally"` for the tag-only gitsign config when cutting a release. When ROADMAP item 8 re-opens, the original commit-signing setup is restored via the steps listed in that item's "Re-enable touches" line.

## Project code standards

Layer names (`interlock`, `sieve`, `arbiter`, `airlock`, `jettison`, `hull`, `drydock`) may be rejected by stakeholders. Keep code resilient to a layer rename — the doc-level name is one search-and-replace away, but a Python identifier or env var carrying a layer name is a breaking change for consumers.

- Use layer names in **documentation** as memorable handles for the layers.
- Avoid using layer names in **code**. Instead use descriptive, best-practice naming conventions for files, classes, functions, and variables.
<!-- legacy-name-allowed -->
- See also `migration/MAIN.md § 8 Constraint 6`: legacy `spektralia` names MUST NEVER propagate into the new repositories; CI grep gate enforces.
<!-- /legacy-name-allowed -->

## Live operator gotchas (post-Stage-1)

- **Branch protection's `required_status_checks` lists three contexts** (`legacy-name-guard / grep-gate`, `betterleaks / scan`, `pr-title-lint / lint`). `ci.yml` produces all three on every PR; the gates are in steady state. The `signature-verify / verify` context was removed 2026-06-30 per `ROADMAP.md` item 8 (commit signing deferred to v2). Don't bump `required_approving_review_count` back to 1 without amending governance (re-introduces the single-operator deadlock); don't flip `required_signatures` back to `true` without resolving ROADMAP items 6 and 8 (GitHub UI doesn't accept Fulcio certs; commit signing is parked anyway).
- **PR-only CI gates go at the job level inside the reusable workflow**, not on the consumer's `jobs.<name>:` block. Use `if: github.event_name == 'pull_request'` on the job in the reusable `.yml`; consumers in `ci.yml` / `ci-template.yml` wire it unconditionally. Established by `pr-title-lint.yml`. (The same pattern was used by `signature-verify.yml` before its retirement.)
- **Secrets scanner is `betterleaks`, not `gitleaks`.** PR #149 switched after `gitleaks-action` v2 required a free-but-required org-license signup. Drop-in compatible at the rule + config level (`.gitleaks.toml` still accepted as fallback). Abandonment risk tracked in `ROADMAP.md` item 7; fallback path is the `gitleaks` binary directly.
- **Commit signing is deferred to v2 per `ROADMAP.md` item 8 (2026-06-30).** `git commit` does not require `-S`; the `signature-verify.yml` workflow was retired and its caller removed from each layer's `ci.yml`. Item 6 (Fulcio cert / GitHub UI mismatch) is consequently dormant — relevant only when item 8 re-opens. Release-tag signing for Decision 17's image-sign chain is **not** affected; tag-only gitsign config is documented in `docs/CI.md § 4b`.
- **Single operator + 1-approval is structurally deadlocked.** Resolved as path (a) in `ROADMAP.md` item 5 — `required_approving_review_count: 0`. Don't bump that knob back to 1 without amending governance.

## New layer-repo bootstrap — defaults inherited from hull

When standing up a new `tidereach/*` layer repo (sieve, arbiter, airlock, drydock, or future additions), inherit the following hull-canonical defaults verbatim. **Do not re-introduce commit signing for the new repo**; the v1 posture is documented below as the load-bearing don't-front-load.

| Surface | Source | What the new repo inherits |
|---|---|---|
| Branch protection | `docs/REPO_SETTINGS.md § 4` apply script | Three required status checks (`legacy-name-guard / grep-gate`, `betterleaks / scan`, `pr-title-lint / lint`); `required_signatures: false`; `required_approving_review_count: 0`; linear history; restricted pushes |
| CI workflows | Copy `.github/workflows/ci-template.yml` → new repo's `.github/workflows/ci.yml` | Three reusable-workflow jobs (`legacy-name-guard`, `betterleaks`, `pr-title-lint`). **Do not add a `signature-verify:` job.** |
| Pre-commit baseline | Copy `.pre-commit-config.yaml` verbatim | betterleaks + hygiene set + uv-lock; mypy commented out until `src/` lands |
| CODEOWNERS | Author `.github/CODEOWNERS` with `* @dotknewt` | Wildcard until team-permissions design lands (ROADMAP item 2) |
| Local git signing config | **Do not set** `commit.gpgsign=true` or `tag.gpgsign=true` repo-locally | Commit signing is deferred per `ROADMAP.md` item 8 |

**Commit signing is deferred to v2** per `ROADMAP.md` item 8 (2026-06-30). Do NOT re-introduce any of the following when scaffolding a new repo: `commit.gpgsign=true` in repo-local config; the `signature-verify / verify` required status check in branch protection; a `signature-verify:` job in the consumer-side `ci.yml`; the `signature-verify.yml` reusable workflow in hull. When ROADMAP item 8's re-enable trigger fires (first non-operator contributor lands on `main`, or a SLSA L2+ target is committed to, or an enterprise consumer mandates signing, or air-gapped dev becomes a requirement), restore all four surfaces together — the re-enable touchpoints are enumerated in ROADMAP item 8.

**Release-artifact signing (Decision 17 cosign / image-sign chain) is NOT deferred.** Image-publishing repos (currently airlock) still consume `image-sign.yml` from their `release.yml` on `v*` tag push, and the `image-sign / build-sign-attest` required status check is added to airlock's branch protection per `docs/REPO_SETTINGS.md § 1` row "Required status checks (airlock only, release.yml)". Tag-signing setup (the gitsign config) for the operator's local machine remains documented at `docs/CI.md § 4b "Prerequisite: gitsign configured locally"` — but the tag-only variant (only `tag.gpgsign=true`, NOT `commit.gpgsign=true`).

## Git

- Greenfield rebuild — no pre-migration codebase is treated as a source of truth in this repo. Any artifact authored under Stages 1–7 is written against the migration specs, not lifted from earlier history.

## Memory vs State

`AGENTS.md` is the north star for stable project decisions: architecture, code standards, file roles, operator gotchas. It changes infrequently and is checked into git.

`STATE.md` is a session bookmark for point-in-time tracking: current stage, recent PR outcomes, in-flight work. The `state-keeper` subagent (`instruction-management` plugin) maintains it. Read `STATE.md` at the start of any session touching stage progress or branch-protection state.

## STATE.md update mechanics (the standing rule)

**`STATE.md` updates ship in dedicated chore-PRs, never bundled with feature work.** Established 2026-06-30 after two adjacent-line merge conflicts in one session (hull #157 vs #158 and the same shape on interlock #3 vs #4). The root cause is the same as the contracts/README.md status-table problem: shared aggregate files that every PR edits hit git's line-based merge limit when two PRs edit nearby content, even when the edits are semantically independent.

What this means in practice:

| Scenario | Do |
|---|---|
| Feature PR (new contract, doc rewrite, CI change, etc.) | Touch ONLY the feature-relevant files. Do NOT update STATE.md in the same PR, even if state-keeper offers to. |
| STATE.md is out of date because feature work landed | Open a dedicated `chore(state): roll <range>` PR. Single file change (STATE.md only). Squash-merges cleanly because nothing else touches the file. |
| state-keeper agent run | Direct it to write to STATE.md as the only file. If the session has uncommitted feature work, finish that PR first, then run state-keeper. |
| Several PRs landed in a batch | One state-roll PR covers the batch. State-keeper aggregates the Recent events rather than each feature PR adding its own line. |

This rule is durable for the same reason the per-PR-dir contract discipline (`interlock/contracts/AGENTS.md`) is durable: it eliminates the shared mutable surface that line-based merge can't reconcile. No infra needed — the discipline IS the fix.

**Implication for state-keeper**: invoke the agent with explicit instructions to touch ONLY `STATE.md`, never AGENTS.md or feature files, even when it surfaces "candidate" learnings. Surface those candidates back as a separate recommendation, not as in-line edits.

## Merge queue (the backstop)

Merge queue is enabled on `tidereach/hull` and `tidereach/interlock` (2026-06-30) as the second-line defense for the "main moved out from under my PR" race. It does NOT auto-resolve adjacent-line conflicts (the per-PR-dir + chore-PR discipline above is the primary fix for those), but it does catch the "PR-was-mergeable-when-CI-passed-but-main-moved-since" gap by re-rebasing each PR onto the latest main at queue time and re-running required checks.

Operator path to merge a PR under merge queue:
1. Click **Merge when ready** (the merge queue's button — replaces "Squash and merge")
2. GitHub adds the PR to the queue, rebases it onto current main, re-runs `legacy-name-guard / grep-gate`, `betterleaks / scan`, `pr-title-lint / lint` against the rebased commit
3. If green, the queue performs the squash-merge automatically
4. If the rebase produces a conflict OR a check fails, the PR is kicked out of the queue with a notification; rebase manually and re-add

See `docs/REPO_SETTINGS.md § 6` for the enablement steps and current configuration parameters.
