# Repo settings cookbook (Stage 1 operator guide)

This document is the canonical reference for the **GitHub repo settings** that
implement [migration/MAIN.md § 7](../migration/MAIN.md) Decisions 10 and 11 across all six tidereach
repositories (`hull`, `interlock`, `sieve`, `arbiter`, `airlock`, `drydock`).

These settings are **not workflows** — they are properties of the GitHub repo
itself. Apply them at repo bootstrap. The CI workflows in
[`../.github/workflows/`](../.github/workflows) enforce the per-PR / per-commit
side of the same decisions; this doc is the org-side complement.

> **Authoritative provenance.** Every rule below cites the migration/MAIN.md decision it
> implements. Reopening a rule requires plan-mode re-entry per § 7's preamble.

---

## 1. Per-repo branch protection (`main`)

Apply to every repo at bootstrap. The required status checks must match the
exact `job-id` strings under [`../.github/workflows/ci-template.yml`](../.github/workflows/ci-template.yml).

> **2026-06-30 amendment — commit signing deferred to v2.** The `signature-verify / verify` required check has been retired and Decision 10 is deferred per `ROADMAP.md` item 8. Rationale in `migration/MAIN.md § 7 Decision 10` (amended). The rows below already reflect the deferred state; the strike-through cells preserve the pre-amendment text for audit-trail purposes.

| Rule | Setting | Source |
|---|---|---|
| Require pull request before merging | **On** | Decision 11 (squash-only merge requires a PR) |
| Required approvals | **0** for v1 (single-operator governance — GitHub forbids self-approval and no second reviewer exists; linear history + required status checks are the authenticity gates per `docs/GOVERNANCE.md § 1`) | `docs/GOVERNANCE.md`; bumps when team-permissions are designed (see `ROADMAP.md` items 2 and 5) |
| Dismiss stale approvals on new commits | **On** (inert under count=0; left enabled so the v2 unlatch to ≥1 doesn't need to flip this knob too) | Standard hygiene |
| Require signed commits | **Off** — deferred to v2 per `ROADMAP.md` item 8 (2026-06-30). ~~GitHub's native verifier rejects sigstore Fulcio certs; the `signature-verify / verify` check was the canonical Decision 10 gate, running `gitsign verify` against Rekor.~~ | **Decision 10** (deferred 2026-06-30) |
| Require status checks to pass before merging | **On** | Decision 11 |
| Require branches to be up to date before merging | **On** | Avoids merge-state divergence under squash-only |
| Required status checks (every repo) | `legacy-name-guard / grep-gate`, `betterleaks / scan`, `pr-title-lint / lint` (the `signature-verify / verify` context was retired 2026-06-30 per `ROADMAP.md` item 8) | Decisions 18(a), 18(b), and Constraint 6 |
| Required status checks (airlock only, release.yml) | `image-sign / build-sign-attest` | Decision 17 (release-artifact signing is separate from commit signing; not deferred) |
| Required status checks (layer pytest, when present) | `ci / pytest`, `ci / type-check`, `ci / sbom` | Layer-specific |
| Require linear history | **On** | Decision 11 (squash-only ⇒ history is linear) |
| Require conversation resolution before merging | **On** | Standard hygiene |
| Restrict who can push to matching branches | **On** — `dotknewt` is the sole authorized pusher on `tidereach/hull` and on every sibling `tidereach/*` repo, via the `tidereach` org | Decision 19 (single-operator governance) |
| Allow force pushes | **Off** | Linear-history protection (formerly cited Decision 10's "signed history must be stable"; signing deferred 2026-06-30 but the off-state still holds for hygiene) |
| Allow deletions | **Off** | Hygiene; was Decision 10 |

---

## 2. Per-repo general settings

| Setting | Value | Source |
|---|---|---|
| Default branch | `main` | Stage 0 / Stage 1 |
| Allow merge commits | **Off** | Decision 11 |
| Allow squash merging | **On** | Decision 11 |
| Allow rebase merging | **Off** | Decision 11 |
| Squash merge commit title | **Pull request title** | Decision 11 + Decision 18(b) — the linted PR title becomes the merge commit title |
| Squash merge commit message | **Pull request title and description** | Standard |
| Automatically delete head branches | **On** | Hygiene |
| Wikis | **Off** for v1 | Single-operator scope (Decision 19); revisit when team permissions are designed |
| Issues | **On** | Used for roadmap tracking + per-layer specs |
| Projects | **On** | Optional; per-operator preference |
| Discussions | **Off** for v1 | Single-operator scope |

---

## 3. Trusted Publisher / OIDC

| Surface | Trust root | Used for |
|---|---|---|
| ~~`gitsign` commit signing~~ | ~~GitHub OIDC → Fulcio CA → Rekor~~ | ~~Decision 10 — every commit on `main`~~ **Deferred 2026-06-30 per `ROADMAP.md` item 8.** |
| `cosign` image signing (airlock only) | GitHub Actions OIDC → Fulcio CA → Rekor | Decision 17 — every image on `ghcr.io/tidereach/airlock` (release-artifact signing; not affected by the commit-signing deferral) |
| `cosign attest` SBOM/provenance | Same OIDC chain | Decision 17 |
| Future: PyPI `interlock-contracts` (v2) | PyPI Trusted Publisher via the same GitHub OIDC chain | v2 contracts distribution; currently submodule-pinned per migration/MAIN.md § 10 |

Release-artifact signing (cosign, Decision 17) keeps its OIDC chain. Commit
signing (Decision 10) is parked until ROADMAP item 8's re-enable trigger
fires; when it does, the gitsign row above is restored and the
`signature-verify / verify` check is re-wired.

---

## 4. Apply script (`gh` CLI)

Run once per repo at bootstrap. Replace `<repo>` with each of
`hull`, `interlock`, `sieve`, `arbiter`, `airlock`, `drydock`.

> **v1 inheritance note (2026-06-30).** This script is the canonical source for new layer-repo branch protection. It deliberately does NOT include `signature-verify / verify` in `required_status_checks.contexts`, and `required_signatures: false`. Commit signing is deferred to v2 per `ROADMAP.md` item 8. Do not add the signature-verify context when standing up a new repo; the re-add touchpoints are enumerated in ROADMAP item 8 and fire only when its re-enable trigger is met.

```bash
#!/usr/bin/env bash
set -euo pipefail

ORG="tidereach"
REPO="$1"  # e.g. interlock

# --- General settings ----------------------------------------------------
gh api -X PATCH "repos/${ORG}/${REPO}" \
  -F default_branch=main \
  -F allow_merge_commit=false \
  -F allow_squash_merge=true \
  -F allow_rebase_merge=false \
  -F squash_merge_commit_title=PR_TITLE \
  -F squash_merge_commit_message=PR_BODY \
  -F delete_branch_on_merge=true \
  -F has_wiki=false \
  -F has_issues=true \
  -F has_discussions=false

# --- Branch protection on main ------------------------------------------
# Required status checks must match the job-ids in .github/workflows/ci.yml.
# v1 contexts: legacy-name-guard, betterleaks, pr-title-lint.
# signature-verify is intentionally absent (Decision 10 deferred; ROADMAP item 8).
gh api -X PUT "repos/${ORG}/${REPO}/branches/main/protection" \
  --input - <<'JSON'
{
  "required_status_checks": {
    "strict": true,
    "contexts": [
      "legacy-name-guard / grep-gate",
      "betterleaks / scan",
      "pr-title-lint / lint"
    ]
  },
  "enforce_admins": true,
  "required_pull_request_reviews": {
    "required_approving_review_count": 0,
    "dismiss_stale_reviews": true,
    "require_code_owner_reviews": false
  },
  "required_signatures": false,
  "required_linear_history": true,
  "required_conversation_resolution": true,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "restrictions": null
}
JSON

echo "Applied settings to ${ORG}/${REPO}."
```

For **airlock**, append `"image-sign / build-sign-attest"` to the `contexts`
array (the image-sign workflow only runs on `airlock`).

For layer repos with `pytest`/`mypy`/`sbom` jobs, append those job-ids to the
`contexts` array as the source tree lands.

---

## 5. Drift detection

The settings above are not enforced by CI; they are repo-side rules. To detect
drift (e.g., an operator accidentally toggled "allow merge commits"):

```bash
gh api "repos/tidereach/${REPO}" | jq '{allow_merge_commit, allow_squash_merge, allow_rebase_merge, squash_merge_commit_title, delete_branch_on_merge}'
gh api "repos/tidereach/${REPO}/branches/main/protection" | jq '{required_status_checks, required_signatures, required_linear_history}'
```

Diff the output against this doc when changing operator handoff.

---

## 6. Cross-references

- [`../migration/MAIN.md` § 7 Decision 10](../migration/MAIN.md) — commit signing (deferred to v2 per `ROADMAP.md` item 8, 2026-06-30)
- [`../migration/MAIN.md` § 7 Decision 11](../migration/MAIN.md) — squash-and-merge
- [`../migration/MAIN.md` § 7 Decision 17](../migration/MAIN.md) — cosign image signing
- [`../migration/MAIN.md` § 7 Decision 18](../migration/MAIN.md) — gitleaks + PR-title-lint
- [`../migration/MAIN.md` § 7 Decision 19](../migration/MAIN.md) — single-operator governance
- [`./CI.md`](./CI.md) — operator overview of the CI workflows themselves
- [`../.github/workflows/`](../.github/workflows) — the canonical reusable workflows
