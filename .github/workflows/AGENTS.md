# CI Workflows

Reusable GitHub Actions workflows under `.github/workflows/`. See `docs/CI.md` for the operator overview.

## Files

- `ci.yml` — hull's own CI; calls the three reusable workflows via local-path notation (`uses: ./.github/workflows/<file>`). Distinct from `ci-template.yml` (the layer-repo template). Produces the three required status check contexts on every PR. (Was four contexts pre-2026-06-30; `signature-verify` was retired per `ROADMAP.md` item 8.)
- `ci-template.yml` — example layer-repo CI; copied to each layer at bootstrap. Consumers call hull's workflows via remote-path notation (`uses: tidereach/hull/.github/workflows/...@main`).
- `legacy-name-guard.yml` — reusable; enforces `migration/MAIN.md § 8` Constraint 6 (legacy-name grep gate). Job id: `grep-gate`.
- `betterleaks.yml` — reusable; secrets scanner per Decision 18(a). Switched from `gitleaks-action` (PR #149; see ROADMAP item 7). Job id: `scan`.
- `pr-title-lint.yml` — reusable; Conventional Commit PR title validation per Decision 18(b). Job id: `lint`.
- ~~`signature-verify.yml` — reusable; per-PR gitsign signature check per Decision 10. Skips merge commits via `git rev-list --no-merges` (PR #150). Job id: `verify`.~~ **Retired 2026-06-30 per `ROADMAP.md` item 8.** Recover from git history (`git log -- .github/workflows/signature-verify.yml`) when item 8 re-opens.
- `image-sign.yml` — reusable; airlock-only cosign keyless + multi-arch + SBOM/provenance attestations per Decision 17. (Release-artifact signing; not affected by item 8 deferral.)
- `release-template.yml` — example layer-repo release workflow (image-publishing layers only, currently airlock); wires the consumer-side `push: tags: ['v*']` trigger that calls hull's `image-sign.yml`.

## Required status check contexts

These three job ids must match what `docs/REPO_SETTINGS.md § 4`'s apply script registers in `required_status_checks.contexts`:

| Workflow file | Job id |
|---|---|
| `legacy-name-guard.yml` | `grep-gate` |
| `betterleaks.yml` | `scan` |
| `pr-title-lint.yml` | `lint` |
| ~~`signature-verify.yml`~~ | ~~`verify`~~ (retired 2026-06-30 per `ROADMAP.md` item 8) |

If you rename a job id in a workflow, update `REPO_SETTINGS.md § 4` and re-run the apply script; GitHub's branch protection won't auto-update.

## Authoring patterns

- **PR-only gates go at the job level inside the reusable workflow**, not on the consumer's `jobs.<name>:` block. Use `if: github.event_name == 'pull_request'` on the job in the reusable `.yml`; consumers (`ci.yml` / `ci-template.yml`) wire it unconditionally. Established by `pr-title-lint.yml`.
- **Secrets scanner is `betterleaks`, not `gitleaks`.** PR #149 switched after `gitleaks-action` v2 required a free-but-required org-license signup. Drop-in compatible at the rule + config level (`.gitleaks.toml` still accepted as fallback). Abandonment risk: `ROADMAP.md` item 7; fallback path is the `gitleaks` binary directly.
