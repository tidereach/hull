#!/usr/bin/env bash
# Canonical branch-protection + general-settings applier for tidereach/* repos.
# Source of truth for docs/REPO_SETTINGS.md § 1, § 2, § 4, and for the
# `cross-repo-consistency-auditor` subagent's drift check (via --dry-run).
set -euo pipefail

usage() {
  echo "Usage: $0 <repo> [--dry-run] [--sign-repo]" >&2
  echo "  <repo>       short repo name, e.g. hull, interlock" >&2
  echo "  --dry-run    print the branch-protection JSON instead of applying it" >&2
  echo "  --sign-repo  append the image-sign required check (airlock and future image-publishing layers)" >&2
  exit 64
}

REPO=""
DRY_RUN=0
SIGN_REPO=0

for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    --sign-repo) SIGN_REPO=1 ;;
    -*) usage ;;
    *) REPO="$arg" ;;
  esac
done

[ -n "$REPO" ] || usage

ORG="tidereach"

CONTEXTS='"legacy-name-guard / grep-gate", "betterleaks / scan", "pr-title-lint / lint"'
if [ "$SIGN_REPO" -eq 1 ]; then
  CONTEXTS="${CONTEXTS}, \"image-sign / build-sign-attest\""
fi

PROTECTION_JSON=$(cat <<JSON
{
  "required_status_checks": {
    "strict": true,
    "contexts": [${CONTEXTS}]
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
)

if [ "$DRY_RUN" -eq 1 ]; then
  echo "${PROTECTION_JSON}"
  exit 0
fi

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
echo "${PROTECTION_JSON}" | gh api -X PUT "repos/${ORG}/${REPO}/branches/main/protection" --input -

echo "Applied settings to ${ORG}/${REPO}."
