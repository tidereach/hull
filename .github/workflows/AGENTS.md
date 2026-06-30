# CI Workflows

Reusable GitHub Actions workflows under `.github/workflows/`. See `docs/CI.md` for the operator overview.

## Files

- `ci.yml` — hull's own CI; calls the four reusable workflows via local-path notation (`uses: ./.github/workflows/<file>`). Distinct from `ci-template.yml` (the layer-repo template). Produces all four required status check contexts on every PR.
- `ci-template.yml` — example layer-repo CI; copied to each layer at bootstrap. Consumers call hull's workflows via remote-path notation (`uses: tidereach/hull/.github/workflows/...@main`).
- `legacy-name-guard.yml` — reusable; enforces `migration/MAIN.md § 8` Constraint 6 (legacy-name grep gate). Job id: `grep-gate`.
- `betterleaks.yml` — reusable; secrets scanner per Decision 18(a). Switched from `gitleaks-action` (PR #149; see ROADMAP item 7). Job id: `scan`.
- `pr-title-lint.yml` — reusable; Conventional Commit PR title validation per Decision 18(b). Job id: `lint`.
- `signature-verify.yml` — reusable; per-PR gitsign signature check per Decision 10. Skips merge commits via `git rev-list --no-merges` (PR #150). Job id: `verify`.
- `image-sign.yml` — reusable; airlock-only cosign keyless + multi-arch + SBOM/provenance attestations per Decision 17.
- `release-template.yml` — example layer-repo release workflow (image-publishing layers only, currently airlock); wires the consumer-side `push: tags: ['v*']` trigger that calls hull's `image-sign.yml`.

## Required status check contexts

These four job ids must match what `docs/REPO_SETTINGS.md § 4`'s apply script registers in `required_status_checks.contexts`:

| Workflow file | Job id |
|---|---|
| `legacy-name-guard.yml` | `grep-gate` |
| `betterleaks.yml` | `scan` |
| `pr-title-lint.yml` | `lint` |
| `signature-verify.yml` | `verify` |

If you rename a job id in a workflow, update `REPO_SETTINGS.md § 4` and re-run the apply script; GitHub's branch protection won't auto-update.
