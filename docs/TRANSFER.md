# Org transfer runbook (Stage 1)

<!-- legacy-name-allowed -->
This entire runbook is *about* the legacy `dormant-warlock/spektralia`
URL and its transfer; the legacy-name-guard pattern necessarily
appears throughout. The exemption block opens here and closes at the
end of the document.

The Stage 1 GitHub repository transfer from
`dormant-warlock/spektralia` → `tidereach/hull` per
[`../migration/MAIN.md § 11 Stage 1`](../migration/MAIN.md) line 280 and
[`../migration/MAIN.md § 7 Decision 15`](../migration/MAIN.md).

This document is the operator's runbook: prerequisites, pre-transfer
state, the transfer steps, and post-transfer verification. Audit
outputs captured on **2026-06-30** are inlined under § 2.

---

## 1. Prerequisites

- All other Stage 1 deliverables on `main`. Gate criteria are in
  [`../migration/MAIN.md § 11`](../migration/MAIN.md) line 282; as of
  this runbook, the remaining gaps are `docs/BLUEPAPER.md`,
  `docs/JETTISON.md`, and the redirect-or-404 confirmation after the
  transfer itself. Everything else is in place.
- Operator has the `tidereach` GitHub org **admin** role. The transfer
  acceptance side requires it.
- Operator has resolved the **plan-tier gap** in § 2.2 below before
  expecting branch protection to apply automatically.
- Local working tree is clean and pushed to
  `dormant-warlock/spektralia` (the source side cannot be transferred
  mid-PR).

---

## 2. Pre-transfer state (audited 2026-06-30)

### 2.1 Source repo settings — drift from `docs/REPO_SETTINGS.md`

`gh api repos/dormant-warlock/spektralia` (full export in
scratchpad `transfer/settings.json`) reports the following drift from
the [`./REPO_SETTINGS.md § 2`](./REPO_SETTINGS.md) spec. These should
be re-applied **after** the transfer, on `tidereach/hull`, via the
apply script in [`./REPO_SETTINGS.md § 4`](./REPO_SETTINGS.md):

| Setting | Current (`dormant-warlock/spektralia`) | Target (`REPO_SETTINGS.md`) |
|---|---|---|
| `allow_merge_commit` | `true` | `false` |
| `allow_rebase_merge` | `true` | `false` |
| `squash_merge_commit_title` | `COMMIT_OR_PR_TITLE` | `PR_TITLE` |
| `delete_branch_on_merge` | `false` | `true` |
| `allow_squash_merge` | `true` | `true` ✓ |
| `default_branch` | `main` | `main` ✓ |
| `has_wiki` | `false` | `false` ✓ |
| `has_issues` | `true` | `true` ✓ |
| `has_discussions` | `false` | `false` ✓ |

These knobs travel with the repo during transfer; settings will need a
post-transfer apply pass to align with spec.

### 2.2 Plan-tier gap: branch protection requires Team or public

`gh api repos/dormant-warlock/spektralia/branches/main/protection`
returns **HTTP 403**:

> Upgrade to GitHub Pro or make this repository public to enable this
> feature.

The `tidereach` org is on the **free** plan (`gh api orgs/tidereach`
confirms `plan.name = "free"`). [`./REPO_SETTINGS.md § 1`](./REPO_SETTINGS.md)
requires branch protection on `main` in every tidereach repo.

**Decision (locked 2026-06-30): make `tidereach/hull` public** post-
transfer. Branch protection becomes available on the free plan once
the repo is public; an open-source posture is also consistent with the
attestation-bounded, externally-verifiable identity goal of the
project. The legacy `dormant-warlock/spektralia` redirect (§ 4.2)
becomes publicly verifiable as a side effect.

The sibling layer repos inherit this decision unless they surface a
reason to differ (none anticipated for v1).

Concrete command, run after § 4.1 verifies the transfer landed:

```bash
gh api -X PATCH repos/tidereach/hull -F private=false
```

### 2.3 Secrets and variables

- `gh secret list --repo dormant-warlock/spektralia` → **empty**.
- `gh variable list --repo dormant-warlock/spektralia` → **empty**.

No secrets to migrate. No variables to migrate. If either changes
before transfer, re-audit before proceeding (transferred secrets
follow the repo per GitHub's transfer semantics, but a fresh audit is
cheap insurance).

### 2.4 URL references in the working tree

`git grep -nE 'dormant-warlock/spektralia'` returns matches in only
two files, both intentional:

- `docs/REPO_SETTINGS.md` line 35 — pre/post-transfer language in the
  "authorized pusher" row; will need updating post-transfer.
- `migration/MAIN.md` — multiple lines of intentional historical
  narrative (the legacy URL is the migration's source).

`git grep -nE 'tidereach/hull'` shows forward references already in
place across **all seven workflow files**, `docs/CI.md`,
`docs/REPO_SETTINGS.md`, `migration/MAIN.md`, and
`migration/layer4_jettison.md`. The reusable-workflow `uses:` lines
already reference `tidereach/hull/.github/workflows/<name>.yml@main`.

**Consequence:** no workflow URL rewrite is needed at transfer time.
The single forward-reference fix is the post-transfer language in
`docs/REPO_SETTINGS.md` line 35.

### 2.5 History scan (gitleaks)

`gitleaks detect --source . --log-opts="--all"` (via
`zricethezav/gitleaks:v8.30.1`, the version pinned in
`.pre-commit-config.yaml`) reports **21 findings across the full
history of 247 commits**. Breakdown by rule:

| Count | Rule |
|---|---|
| 7 | `stripe-access-token` |
| 4 | `generic-api-key` |
| 4 | `jwt` |
| 2 | `gcp-api-key` |
| 2 | `slack-bot-token` |
| 1 | `curl-auth-header` |
| 1 | `private-key` |

**All 21 findings are in `tests/corpus/*` fixtures and test files from
the pre-Stage-0 Spektralia implementation.** They are deliberately
well-formed *fake* secret shapes used as **positive** test inputs for
the original sieve's detection rules (hence the directory name
`tests/corpus/positive/`) — a secrets-detection tool's test suite
needs example secrets to detect. They are not connected to any real
accounts.

Files involved:

- `tests/corpus/positive/{google_api_key,jwt,private_key_block,slack_token,stripe_key}.txt`
- `tests/corpus/eval/positive/jwt/1.txt`
- `tests/test_{audit_no_values,entropy,hooks,memory_safety,no_secret_in_exceptions}.py`
- `TEST.md`, `endpoint/TESTING.md`

**Important:** none of these files exist on `main` today. They were
removed by commit `65d99b2` ("chore(migration): replace codebase with
migration planning docs") on **2026-06-28** as part of the Stage 0
freeze. They remain only in commits older than `65d99b2`.

**Decision (locked 2026-06-30): rewrite history before transfer** to
drop the implementation-era directories that carry the fixtures.
Driven by § 2.2's decision to make the destination public: under a
public posture, even non-real test fixtures get crawled and indexed,
and "honest about history" loses to "minimal public surface" since the
freeze commit (`65d99b2`) is itself the audit record of the rebuild.

Concrete invocation — run on a fresh clone (filter-repo refuses to
operate on a clone with a remote unless `--force`-d; the canonical
workflow is to clone, filter, then push):

```bash
# 1. Fresh clone (filter-repo defaults are safest on a fresh tree).
mkdir -p /tmp/hull-filter && cd /tmp/hull-filter
git clone --no-local git@github.com:dormant-warlock/spektralia.git .

# 2. Inventory pre-freeze paths to drop. The gitleaks findings cluster
#    under these four roots; verify against the table above before
#    running.
git log --all --name-only --format= --follow -- tests src TEST.md endpoint \
  | sort -u | head

# 3. Drop the implementation-era directories from every commit.
#    filter-repo prunes commits that become empty.
git filter-repo --invert-paths \
  --path tests \
  --path src \
  --path TEST.md \
  --path endpoint

# 4. Re-run gitleaks on the rewritten history. Expect: 0 findings.
podman run --rm -v "$PWD:/repo:Z" -w /repo \
  docker.io/zricethezav/gitleaks:v8.30.1 \
  detect --source . --redact --no-banner --log-opts="--all"

# 5. Force-push the rewritten history. THIS IS THE DESTRUCTIVE STEP —
#    every collaborator's clone is invalidated, every commit SHA after
#    the deletion point is new. There are no other collaborators today
#    (single-operator governance), so the blast radius is the local
#    clone at /home/dotme/Code/llm/spektralia/ which must be re-cloned
#    or reset against the new origin.
git push --force origin main
```

After step 5 succeeds, return to the original clone and either re-
clone or `git fetch && git reset --hard origin/main` to align with the
rewritten history.

The full pre-filter gitleaks log
(`scratchpad/transfer/gitleaks.log`) and JSON report
(`scratchpad/transfer/gitleaks-report.json`) capture the original 21
findings for the audit record (filter-repo's own
`.git/filter-repo/commit-map` will additionally record the SHA
remapping).

---

## 3. Transfer execution

After § 2.5's filter-repo + force-push has completed (history is
clean) and the operator has confirmed via the post-filter gitleaks
re-scan:

```bash
# Confirm working tree is clean and pushed.
cd <repo-root>
git status --short                       # MUST be empty
git fetch origin && git log @{u}..HEAD   # MUST be empty (no unpushed commits)

# Transfer via gh CLI. The destination org must already exist
# (`tidereach` was registered 2026-06-29 per MAIN.md § 7 Decision 15).
gh api -X POST \
  repos/dormant-warlock/spektralia/transfer \
  -f new_owner=tidereach \
  -f new_name=hull

# Equivalent web flow:
#   Settings → Transfer ownership → "tidereach" → confirm by typing
#   "dormant-warlock/spektralia"
```

GitHub will:

- Move the repo to `tidereach/hull`.
- Install a redirect from `github.com/dormant-warlock/spektralia` to
  the new URL. The redirect persists for the redirect's lifetime
  (subject to GitHub's redirect-eviction policy; see § 4 note).
- Keep all branches, tags, issues, and PRs intact.
- **Drop branch protection rules** — they have to be re-applied on
  the new repo (this is GitHub's documented behavior).

---

## 4. Post-transfer verification

Run in order; each check has a hard pass criterion.

### 4.1 New URL serves the repo

```bash
gh api repos/tidereach/hull --jq '{full_name, default_branch}'
# Expect: {"full_name": "tidereach/hull", "default_branch": "main"}
```

### 4.2 Legacy URL either 404s or redirects

```bash
# 404 case (org-renamed-with-clobber):
curl -sI https://github.com/dormant-warlock/spektralia | head -1
# Redirect case (the normal outcome — 301 to the new URL):
curl -sIL https://github.com/dormant-warlock/spektralia | grep -E '^(HTTP|location:)'
```

Per [`../migration/MAIN.md § 11 Stage 1`](../migration/MAIN.md) line
282, **either** a 404 or a redirect satisfies the gate.

**Redirect lifetime caveat** (per MAIN.md § 11): GitHub's automatic
redirect "persists for the redirect's lifetime" — meaning every
internal doc reference and every operator-facing URL is updated to
`tidereach/hull` at this stage regardless. Don't rely on the redirect
as the permanent reference.

### 4.3 Flip `tidereach/hull` to public (per § 2.2)

```bash
gh api -X PATCH repos/tidereach/hull -F private=false
gh api repos/tidereach/hull --jq '.private'   # Expect: false
```

Branch protection becomes available the moment this returns. The
legacy URL redirect check (§ 4.2) also becomes publicly verifiable.

### 4.4 Apply settings + branch protection

Run the apply script from
[`./REPO_SETTINGS.md § 4`](./REPO_SETTINGS.md) against
`tidereach/hull`. This re-aligns the settings drift surfaced in § 2.1
and installs branch protection (now allowed because the repo is
public per § 4.3).

```bash
bash <(curl -fsSL <path-to-script>) hull
# Or copy the script body from REPO_SETTINGS.md § 4 into a local file.
```

Cross-check via the drift-detection commands in
[`./REPO_SETTINGS.md § 5`](./REPO_SETTINGS.md). The expected diff
after this step: every drift row in § 2.1 reads as spec-aligned.

### 4.5 Reusable-workflow refs already correct

No action required. § 2.4 confirmed every `uses: tidereach/hull/...`
line already points at the new URL. The first push to `main` post-
transfer should resolve those refs without rewriting.

### 4.6 Fix the one forward-reference

Edit `docs/REPO_SETTINGS.md` line 35: drop the pre-transfer language,
keep the `dotknewt` operator identity on `tidereach`. The change is a
single PR titled `docs(repo-settings): post-transfer authorized-pusher
language`.

### 4.7 Update local clone

```bash
git remote set-url origin git@github.com:tidereach/hull.git
git remote -v                                # confirm new URL
git fetch && git log --oneline -1            # confirm refs travel
```

---

## 5. Contributor migration

For any other clone in the wild:

```bash
git remote set-url origin git@github.com:tidereach/hull.git
```

There is no notification mechanism from GitHub; communicate the
new URL in the README and (if applicable) in a one-line announcement
on the new repo's first post-transfer issue.

---

## 6. Cross-references

- [`../migration/MAIN.md § 11 Stage 1`](../migration/MAIN.md) — the
  transfer is line 280; the gate criteria are line 282
- [`../migration/MAIN.md § 7 Decision 15`](../migration/MAIN.md) —
  the rename to Tidereach + the `tidereach` org choice
- [`./REPO_SETTINGS.md`](./REPO_SETTINGS.md) — branch-protection and
  general-settings spec; the apply script lives in § 4
- [`./GOVERNANCE.md`](./GOVERNANCE.md) — why single-operator
  governance is what this transfer is moving toward
- [`./CI.md`](./CI.md) — the reusable workflows whose `tidereach/hull`
  refs already work
- Scratchpad audits (this session): `transfer/settings.json`,
  `transfer/gitleaks.log`, `transfer/gitleaks-report.json`
<!-- /legacy-name-allowed -->
