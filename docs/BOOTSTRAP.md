# New Layer-Repo Bootstrap — Defaults Inherited from Hull

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
