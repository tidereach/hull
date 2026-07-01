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

**Release-artifact signing (Decision 17 cosign / image-sign chain) is NOT deferred.** Image-publishing repos (currently airlock) still consume `image-sign.yml` from their `release.yml` on `v*` tag push, and the `image-sign / build-sign-attest` required status check is added to airlock's branch protection per `docs/REPO_SETTINGS.md § 1` row "Required status checks (airlock only, release.yml)". Tag-signing setup (the gitsign config) for the operator's local machine remains documented at `docs/CI.md § 4b "Prerequisite: gitsign configured locally"` — but the tag-only variant (only `tag.gpgsign=true`, NOT `commit.gpgsign=true`).

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
- **Commit signing is deferred to v2 per `ROADMAP.md` item 8 (2026-06-30).** See the "Signing setup" note under `## Commands` for the full posture and tag-signing carve-out.
- **Single operator + 1-approval is structurally deadlocked.** Resolved as path (a) in `ROADMAP.md` item 5 — `required_approving_review_count: 0`. Don't bump that knob back to 1 without amending governance.

## New layer-repo bootstrap

To stand up a new `tidereach/*` layer repo (sieve, arbiter, airlock, drydock, or future additions), see **`docs/BOOTSTRAP.md`** — the hull-canonical defaults table (branch protection, CI, pre-commit, CODEOWNERS, signing posture) with the do-not-front-load rationale.

## Git

- Greenfield rebuild — no pre-migration codebase is treated as a source of truth in this repo. Any artifact authored under Stages 1–7 is written against the migration specs, not lifted from earlier history.

## Memory vs State

`AGENTS.md` is the north star for stable project decisions: architecture, code standards, file roles, operator gotchas. It changes infrequently and is checked into git.

`STATE.md` is a session bookmark for point-in-time tracking: current stage, recent PR outcomes, in-flight work. The `state-keeper` subagent (`instruction-management` plugin) maintains it. Read `STATE.md` at the start of any session touching stage progress or branch-protection state.
