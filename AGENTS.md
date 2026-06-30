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
| `gitsign verify HEAD` | Verify the most recent commit's sigstore signature against Rekor. The CI workflow `signature-verify.yml` runs this on every PR. |
| `gh api -X PUT repos/tidereach/hull/branches/main/protection ...` | Apply branch protection per `docs/REPO_SETTINGS.md § 4` (amended apply script — count=0, code-owner-reviews=false, required_signatures=false). |

**Signing setup** (one-time per machine, per `docs/CI.md § 4b → "Prerequisite: gitsign configured locally"`): install `gitsign` (Arch: `pacman -S gitsign`; or download to `~/.local/bin/` from sigstore/gitsign releases), then configure per that section. **GitHub UI will show "Unverified" — that's ROADMAP item 6, not a real failure; `gitsign verify` and the signature-verify workflow are the truth.** For DNS resolver timeouts on systemd-resolved, see `docs/CI.md § 5 → "signature-verify reports a commit without a valid signature"`.

## Project code standards

Layer names (`interlock`, `sieve`, `arbiter`, `airlock`, `jettison`, `hull`, `drydock`) may be rejected by stakeholders. Keep code resilient to a layer rename — the doc-level name is one search-and-replace away, but a Python identifier or env var carrying a layer name is a breaking change for consumers.

- Use layer names in **documentation** as memorable handles for the layers.
- Avoid using layer names in **code**. Instead use descriptive, best-practice naming conventions for files, classes, functions, and variables.
<!-- legacy-name-allowed -->
- See also `migration/MAIN.md § 8 Constraint 6`: legacy `spektralia` names MUST NEVER propagate into the new repositories; CI grep gate enforces.
<!-- /legacy-name-allowed -->

## Live operator gotchas (post-Stage-1)

- **Branch protection's `required_status_checks` lists four contexts** (`legacy-name-guard / grep-gate`, `betterleaks / scan`, `pr-title-lint / lint`, `signature-verify / verify`). `ci.yml` produces all four on every PR; the gates are in steady state. Don't bump `required_approving_review_count` back to 1 without amending governance (re-introduces the single-operator deadlock); don't flip `required_signatures` back to `true` without resolving ROADMAP item 6 (GitHub UI doesn't accept Fulcio certs). `signature-verify.yml` skips merge commits via `git rev-list --no-merges` (PR #150) — using GitHub's "Update branch" UI button on a stale PR is safe again. `signature-verify` is also gated at the job level with `if: github.event_name == 'pull_request'` — push-to-main HEAD is GitHub's X.509-signed squash commit, which gitsign would always reject; on push the check reports "skipped" by design.
- **PR-only CI gates go at the job level inside the reusable workflow**, not on the consumer's `jobs.<name>:` block. Use `if: github.event_name == 'pull_request'` on the job in the reusable `.yml`; consumers in `ci.yml` / `ci-template.yml` wire it unconditionally. Established by `pr-title-lint.yml`; `signature-verify.yml` follows the same pattern.
- **Secrets scanner is `betterleaks`, not `gitleaks`.** PR #149 switched after `gitleaks-action` v2 required a free-but-required org-license signup. Drop-in compatible at the rule + config level (`.gitleaks.toml` still accepted as fallback). Abandonment risk tracked in `ROADMAP.md` item 7; fallback path is the `gitleaks` binary directly.
- **gitsign signatures show "Unverified" in GitHub UI.** GitHub's verifier doesn't accept Fulcio short-lived certs; `signature-verify.yml` is the canonical Decision 10 gate. `ROADMAP.md` item 6.
- **Single operator + 1-approval is structurally deadlocked.** Resolved as path (a) in `ROADMAP.md` item 5 — `required_approving_review_count: 0`. Don't bump that knob back to 1 without amending governance.

## Git

- Greenfield rebuild — no pre-migration codebase is treated as a source of truth in this repo. Any artifact authored under Stages 1–7 is written against the migration specs, not lifted from earlier history.

## Memory vs State

`AGENTS.md` is the north star for stable project decisions: architecture, code standards, file roles, operator gotchas. It changes infrequently and is checked into git.

`STATE.md` is a session bookmark for point-in-time tracking: current stage, recent PR outcomes, in-flight work. The `state-keeper` subagent (`instruction-management` plugin) maintains it. Read `STATE.md` at the start of any session touching stage progress or branch-protection state.
