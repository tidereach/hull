# CI infrastructure overview

This document is the operator-facing overview of the CI workflows that live in
[`../.github/workflows/`](../.github/workflows). hull is the **canonical home**
for these workflows; every other tidereach/* repo consumes them via the
GitHub Actions reusable-workflow pattern.

Pair this with [`./REPO_SETTINGS.md`](./REPO_SETTINGS.md), which covers the
repo-side rules (branch protection, merge strategy, OIDC) that complement the
per-PR CI assertions documented here.

---

## 1. Inheritance model

```
tidereach/hull/.github/workflows/
├── legacy-name-guard.yml   ─┐
├── gitleaks.yml             │   reusable; called from every layer repo
├── pr-title-lint.yml        │
├── signature-verify.yml    ─┘
├── image-sign.yml           ←  airlock-only (consumed from release.yml)
├── ci-template.yml          ←  copied verbatim to each layer (becomes ci.yml)
└── release-template.yml     ←  copied verbatim to image-publishing layers (becomes release.yml)
```

A layer repo references the reusable workflows via:

```yaml
jobs:
  legacy-name-guard:
    uses: tidereach/hull/.github/workflows/legacy-name-guard.yml@main
```

For v1, every consumer pins to `@main`. Once hull cuts tagged releases
(`v1.0.0` and onward per migration/MAIN.md § 10), consumers SHOULD bump the pin to a
release tag so a hull refactor cannot break every layer repo's CI at once.

`image-sign.yml` is **not generic**. It is consumed only by airlock (and any
future image-publishing layer) from its own `release.yml`, not from `ci.yml`.

---

## 2. The six CI assertions mapped to files

| Assertion | migration/MAIN.md provenance | Implemented in |
|---|---|---|
| **(1)** Legacy-name grep gate (zero hits for `[Ss]pektralia\|SPEKTRALIA_\|~/\.spektralia/\|src/spektralia/\|spektralia-` outside exemptions) | § 8 Constraint 6 | [`legacy-name-guard.yml`](../.github/workflows/legacy-name-guard.yml) |
| **(2)** gitsign signed-commit verification (per-PR pass/fail signal complementing branch protection's "require signed commits") | § 7 Decision 10 | [`signature-verify.yml`](../.github/workflows/signature-verify.yml) + REPO_SETTINGS.md § 1 |
| **(3)** Squash-and-merge enforcement | § 7 Decision 11 | **Not a workflow** — [REPO_SETTINGS.md § 2](./REPO_SETTINGS.md) |
| **(4)** cosign keyless image signing + multi-arch + SBOM/provenance attestations (airlock) | § 7 Decision 17 | [`image-sign.yml`](../.github/workflows/image-sign.yml) |
| **(5)** gitleaks pre-commit + CI secrets scanner | § 7 Decision 18(a) | [`gitleaks.yml`](../.github/workflows/gitleaks.yml) + [`../.pre-commit-config.yaml`](../.pre-commit-config.yaml) |
| **(6)** PR-title-lint enforcing Conventional Commits (required because Decision 11 squash-merges the PR title onto `main`) | § 7 Decision 18(b) | [`pr-title-lint.yml`](../.github/workflows/pr-title-lint.yml) |

---

## 3. Pre-commit baseline

Every layer repo copies [`../.pre-commit-config.yaml`](../.pre-commit-config.yaml)
to its root at bootstrap, then a contributor runs:

```bash
pip install pre-commit
pre-commit install
```

The baseline hooks include:

- `gitleaks` — same scanner as the CI job, runs locally before commit
- `pre-commit-hooks` hygiene set — trailing whitespace, EOF newline, YAML/TOML/JSON validity, large-file check, merge-conflict marker, line-ending normalization
- `astral-sh/uv-pre-commit` — `uv-lock` checks that `uv.lock` is in sync with `pyproject.toml`
- `mirrors-mypy` — commented in the canonical baseline; uncommented per layer once `src/` lands. Each layer pins its own mypy version via its `pyproject.toml`.

Layer-specific hooks (e.g., sieve's ReDoS-bound regex linter, airlock's
shellcheck on `scripts/`) are appended to the layer's copy of the file.

---

## 4. Pinning

Every third-party action and pre-commit hook is pinned to a 40-character
commit SHA with a trailing `# vX.Y.Z` comment naming what that SHA points at.
Tags are never used directly. The pinning procedure (run once at apply time;
re-run per the maintenance cadence below):

1. For each action / hook, pick the highest tag matching the floor in the
   trailing comment, then resolve it to a commit SHA. The `commits/<ref>`
   endpoint dereferences both lightweight and annotated tags in one hop:
   ```bash
   # Pick the highest tag matching the version floor, e.g. v4.2.x:
   gh api 'repos/actions/checkout/tags?per_page=100' --jq '.[].name' \
     | grep -E '^v4\.2\.' | sort -V | tail -1
   # Then resolve that tag to a commit SHA:
   gh api 'repos/actions/checkout/commits/v4.2.2' --jq '.sha'
   ```
   For monorepo sub-actions (e.g., `anchore/sbom-action/download-syft`,
   `chainguard-dev/actions/setup-gitsign`), resolve against the parent
   repository; the same commit SHA pins the sub-path. For pre-commit hooks
   on a workstation that has `pre-commit` installed:
   ```bash
   pre-commit autoupdate
   ```
2. Apply the resolved SHAs to:
   - `.github/workflows/*.yml`  (each `uses: ...@<sha>` line)
   - `.pre-commit-config.yaml`  (each `rev: <sha>` line)
   Keep the trailing `# vX.Y.Z` comment in sync with the tag the SHA
   resolves to.
3. Commit with `chore(ci): pin third-party actions to SHA`.

**Loose-pin exceptions.** Two pins do not have semver tags upstream and pin
to `main` HEAD:
- `chainguard-dev/actions/setup-gitsign` — used by `signature-verify.yml`.
- (No others as of v1.) When a loose pin exists, the trailing comment names
  it as "main HEAD as of <YYYY-MM-DD>" so future bumps are reviewable.

**Why SHA pinning matters.** Tag-based pinning (`actions/checkout@v4`)
re-resolves on every CI run; a malicious force-push to the tag can swap in
hostile code. SHA pinning (`actions/checkout@<40-char-sha>`) is immutable.
This is the same security stance Constraint 6 enforces for Spektralia
nomenclature: explicitness over convenience.

**Bumping pinned SHAs across all consumer repos.** Open a PR per repo updating
the `@<sha>` ref (and the trailing `# vX.Y.Z` comment that documents what the
SHA points at). For the reusable-workflow refs (`tidereach/hull/.github/...@main`),
the recommended bump cadence is "monthly or after a hull release tag" — never
mid-feature-PR.

---

## 4a. OIDC → Fulcio → Rekor → cosign verify chain (image-sign)

`image-sign.yml` is a **reusable** workflow; the actual tag trigger lives in
the consumer repo's `release.yml` (see [`../.github/workflows/release-template.yml`](../.github/workflows/release-template.yml)).
The end-to-end signing-and-verification chain has five hops that operators
must understand to debug a failed `cosign verify`:

1. **Caller runs on a tag push.** The consumer repo's `release.yml` is
   triggered by `push: tags: ['v*']`. GitHub Actions issues an OIDC token
   to that job. Important claims on the JWT:

   | Claim | Example value | Why it matters |
   |---|---|---|
   | `iss` | `https://token.actions.githubusercontent.com` | Fulcio's accepted issuer. |
   | `sub` | `repo:tidereach/airlock:ref:refs/tags/v1.0.0` | Identifies the job-context. |
   | `repository` | `tidereach/airlock` | Caller repo (NOT hull). |
   | `ref` | `refs/tags/v1.0.0` | The tag that triggered the run. |
   | `job_workflow_ref` | `tidereach/airlock/.github/workflows/release.yml@refs/tags/v1.0.0` | **The entry-point workflow**, not the reusable workflow. |

2. **cosign requests a Fulcio cert.** When `cosign sign` runs inside hull's
   `image-sign.yml`, it presents the GHA OIDC token to Fulcio. Fulcio
   constructs the **SAN (URI)** on the issued cert from `job_workflow_ref`:

   ```
   https://github.com/tidereach/airlock/.github/workflows/release.yml@refs/tags/v1.0.0
   ```

   The reusable workflow's path (`hull/.github/workflows/image-sign.yml`) does
   NOT appear in the SAN. This is the single most common confusion: people
   read hull's identity regex and assume the SAN names hull. It names the
   caller.

3. **Rekor records the entry.** `cosign sign` uploads the signature, the
   Fulcio cert (carrying the SAN above), and a hashed-rekord body to the
   Rekor transparency log. The Rekor entry's UUID is logged in the cosign
   output; you can re-fetch it later with `rekor-cli get --uuid <uuid>`.

4. **Verifier asserts the SAN matches the regex.** hull's `image-sign.yml`
   pins the accepted identities to:

   ```
   ^https://github\.com/tidereach/[^/]+/\.github/workflows/.+@refs/(heads/main|tags/v.+)$
   ```

   This matches `tidereach/<any-repo>/.github/workflows/<any-workflow>.yml`
   on `main` or any `v*` tag — and only that. Forks to non-`tidereach` orgs
   fail by design (Decision 17). The OIDC issuer must also match the literal
   `https://token.actions.githubusercontent.com`.

5. **Verifier confirms attestations.** `cosign verify-attestation` runs the
   same SAN + issuer assertion against the SBOM (`--type cyclonedx`) and the
   SLSA provenance (`--type slsaprovenance1`) DSSE envelopes. All three
   attestations (signature, SBOM, provenance) MUST verify; partial passes
   are not acceptable per Decision 17.

The verifier invocation is documented in § 5 "image-sign verification
cookbook" below.

---

## 4b. Creating and pushing tags (prerequisite for image-sign)

`image-sign.yml` is a reusable workflow; the actual cosign signing chain only fires when a consumer-side `release.yml` is triggered by a `v*`-prefixed git tag push. This section is a primer on creating, inspecting, and (if needed) deleting those tags. If you're already fluent with `git tag` and `gh release`, skip to § 5's cookbook.

### Tag types

| Type | Command | Use in Tidereach |
|---|---|---|
| **Lightweight** | `git tag v1.0.0` | Bookmark-only; no metadata; no signature. **Don't use for releases.** |
| **Annotated** | `git tag -a v1.0.0 -m "release v1.0.0"` | Metadata only; no signature. Use only for non-release markers. |
| **Signed** | `git tag -s v1.0.0 -m "release v1.0.0"` | Annotated + cryptographically signed. **Required for any tag that feeds image-sign**, per Decision 10's gitsign chain. |

### Prerequisite: gitsign configured locally

Before `git tag -s` works, your local git must route signing through gitsign (sigstore). One-time setup per machine:

```bash
git config --global commit.gpgsign true
git config --global gpg.x509.program gitsign
git config --global gpg.format x509
git config --global tag.gpgsign true
```

The last line is the tag-specific addition that makes `git tag -s` route through gitsign rather than asking for a GPG key. The first sign event triggers an OIDC dance in your browser to authenticate to Fulcio; subsequent signs reuse the short-lived cert until it expires.

### Create the tag

From the repo root, at the commit you want to release:

```bash
# At the current HEAD:
git tag -s v0.0.0-rc1 -m "first image-sign chain dry run"

# Or at a specific commit:
git tag -s v0.0.0-rc1 -m "first image-sign chain dry run" <commit-sha>
```

### Push the tag (this is what triggers the workflow)

```bash
git push origin v0.0.0-rc1
```

`git push` alone does NOT push tags. You must either push the specific tag (`git push origin <tag>`) or use `git push --tags` (which pushes ALL local tags — rarely what you want).

### Verify the tag exists

Locally:

```bash
git tag -l 'v*'              # list all v* tags
git show v0.0.0-rc1 --stat   # show the signed commit + diff
git tag -v v0.0.0-rc1        # verify the tag's gitsign signature locally
```

On the remote (requires `gh auth login` first):

```bash
git ls-remote --tags origin 'v*'                           # raw refs from the remote
gh api repos/:owner/:repo/git/refs/tags --jq '.[].ref'     # via the GitHub API
gh release list                                            # if a GitHub Release was created
```

### Verify the workflow triggered

```bash
gh run list --workflow=release.yml --limit 5
# Note the run ID of the v0.0.0-rc1 run, then:
gh run watch <run-id>          # live tail
gh run view  <run-id> --log    # full logs after completion
```

If no run appears, the workflow file is missing on the tag's commit OR the tag doesn't match the trigger pattern (`tags: ['v*']`). Verify the workflow file exists at the tagged commit:

```bash
git show v0.0.0-rc1:.github/workflows/release.yml | head -20
```

### Delete a tag (cleanup for failed dry runs)

If a dry run goes wrong and you want to retry from scratch:

```bash
git push --delete origin v0.0.0-rc1   # remote
git tag -d v0.0.0-rc1                 # local
gh release delete v0.0.0-rc1 --yes    # only if a GitHub Release was auto-created
```

Then re-tag and re-push. **Never delete a tag that's been merged into the release history** — downstream consumers may pin against it. Deletion is fine for `*-rc*` and `*-test*` tags during dry-runs; it is not fine for any tag a consumer has cited.

### Next

Once the tag is pushed and the workflow has run green, walk through the verification commands in § 5's [image-sign verification cookbook](#image-sign-verification-cookbook) to confirm the cosign + Rekor chain matches the expected SAN regex.

---

## 5. Troubleshooting

### legacy-name-guard failed

The grep hit a `Spektralia` / `spektralia` reference outside the allowed
locations. Two fixes:

1. **Genuine drift** — the reference is unintentional. Rename to `tidereach`.
2. **Intentional historical reference** — wrap the block:
   ```markdown
   <!-- legacy-name-allowed -->
   The pre-migration `src/spektralia/sessions/writer.py` had no internal callers.
   <!-- /legacy-name-allowed -->
   ```
   Use sparingly. Every exempt block is an audit-trail artifact, not a
   convenience pass.

**Hull special case.** Hull (this meta-repo) carries the migration planning
docs (`migration/MAIN.md`, `migration/layer0_interlock.md`, …, `LICENSE` copyright line). Per
[migration/MAIN.md § 3](../migration/MAIN.md), Stage 1 moves these docs into a `migration/`
subdirectory, after which the workflow's built-in `migration/` exemption
covers them. Until Stage 1 completes, hull's own `ci.yml` does NOT call
`legacy-name-guard` on hull itself; the workflow is invoked from layer repos
(`interlock`, `sieve`, `arbiter`, `airlock`, `drydock`) which start
greenfield with no legacy references. The workflow file itself also
self-skips (`.github/workflows/legacy-name-guard.yml` is excluded from its
own scan) because its documentation contains the pattern by necessity.

### gitleaks flagged a false positive

Two options:

1. Add a `gitleaks:allow` comment on the offending line (the action respects it).
2. Add a `[allowlist]` entry in `.gitleaks.toml` at repo root. Keep the
   allowlist short and reviewed.

### signature-verify reports a commit without a valid signature

The contributor's commits were not signed with gitsign. Fix:

```bash
# Configure gitsign once (per machine):
git config --global commit.gpgsign true
git config --global gpg.x509.program gitsign
git config --global gpg.format x509

# Re-sign the existing branch:
git rebase --exec 'git commit --amend --no-edit -S' main
git push --force-with-lease
```

If gitsign itself fails (Fulcio cert request errors), check that the
contributor's OIDC chain (GitHub login or `gh auth login`) is intact.

### image-sign verification failed

cosign verification compares the signing identity against the
`EXPECTED_IDENTITY_REGEXP` in `image-sign.yml`:

```
^https://github\.com/tidereach/[^/]+/\.github/workflows/.+@refs/(heads/main|tags/v.+)$
```

A failure usually means the build ran from a non-tidereach fork or from a
branch other than `main` / a `v*` tag. Confirm the workflow trigger and the
repo owner.

### image-sign verification cookbook

Use this section both for the **first-release dry run** (push a
`v0.0.0-rc1` test tag from a fresh-org test repo to confirm the chain
end-to-end before the real release) and for ad-hoc verification of any
published image.

**1. Dry run on a test tag.** From a test repo seeded with airlock's
`Containerfile`, `release-template.yml`, and a `tidereach/`-prefixed clone:

```bash
git tag -s v0.0.0-rc1 -m 'image-sign chain drill'
git push origin v0.0.0-rc1
# Watch the `release` workflow in GitHub Actions; the in-workflow
# `cosign verify` and `cosign verify-attestation` steps must pass.
```

After the workflow turns green, inspect Rekor to confirm the entry is
present and the cert SAN is what you expect:

```bash
# Find the Rekor entry for the image manifest digest:
rekor-cli search --sha sha256:<manifest-digest>

# Pull the full entry and dump the cert SAN:
rekor-cli get --uuid <uuid-from-search> --format json \
  | jq -r '.Body.HashedRekordObj.signature.publicKey.content' \
  | base64 -d \
  | openssl x509 -text -noout \
  | grep -A1 'Subject Alternative Name'
```

The expected SAN line is:

```
URI:https://github.com/tidereach/airlock/.github/workflows/release.yml@refs/tags/v0.0.0-rc1
```

(Substitute the test repo name and tag.) If the URI prefix mentions
`hull` or omits `tidereach/`, the caller-side `release.yml` wiring is
wrong — re-read § 4a hop 2.

**2. Verify any published image.** The verifier-side commands match
`image-sign.yml`'s in-workflow assertions. Run from any machine with
`cosign` installed; no OIDC login is required for verification.

```bash
IMAGE=ghcr.io/tidereach/airlock:v1.0.0
IDENTITY_REGEXP='^https://github\.com/tidereach/[^/]+/\.github/workflows/.+@refs/(heads/main|tags/v.+)$'
ISSUER='https://token.actions.githubusercontent.com'

# (a) Signature on the manifest list:
cosign verify \
  --certificate-identity-regexp "$IDENTITY_REGEXP" \
  --certificate-oidc-issuer "$ISSUER" \
  "$IMAGE"

# (b) CycloneDX SBOM attestation:
cosign verify-attestation \
  --type cyclonedx \
  --certificate-identity-regexp "$IDENTITY_REGEXP" \
  --certificate-oidc-issuer "$ISSUER" \
  "$IMAGE"

# (c) SLSA provenance v1 attestation:
cosign verify-attestation \
  --type slsaprovenance1 \
  --certificate-identity-regexp "$IDENTITY_REGEXP" \
  --certificate-oidc-issuer "$ISSUER" \
  "$IMAGE"
```

All three commands MUST exit 0 for a release to be considered verified.

**3. Walk the per-arch images.** A multi-arch publish signs the manifest
list AND each per-arch digest separately (see `image-sign.yml`). To verify
every arch:

```bash
docker buildx imagetools inspect "$IMAGE" --format '{{json .Manifest}}' \
  | jq -r '.manifests[] | "\(.platform.os)/\(.platform.architecture) \(.digest)"' \
  | while read -r platform digest; do
      echo "=== $platform ==="
      cosign verify \
        --certificate-identity-regexp "$IDENTITY_REGEXP" \
        --certificate-oidc-issuer "$ISSUER" \
        "ghcr.io/tidereach/airlock@$digest"
    done
```

**4. Show the full Rekor inclusion proof.** `cosign tree` walks every
signature and attestation referenced from an image and shows the Rekor
log indexes:

```bash
cosign tree "$IMAGE"
```

Use this when audit-trail provenance is the goal (e.g., responding to a
downstream consumer asking "prove this image came from your CI").

### PR-title-lint rejected the title

Reformat the PR title to match Conventional Commits, e.g.:

| Good | Bad |
|---|---|
| `feat: add SquidAccessReader to interlock` | `Adding SquidAccessReader` |
| `fix(sieve): bound entropy decoder loop` | `Fix entropy bug` |
| `breaking!: bump session-stream-jsonl to v2.0.0` | `BREAKING: schema bump` |

See [`../.github/workflows/pr-title-lint.yml`](../.github/workflows/pr-title-lint.yml)
for the full allowed-prefix list.

---

## 6. Maintenance

| Task | Cadence | How |
|---|---|---|
| Bump pinned action SHAs | Monthly or after upstream security advisory | `pre-commit autoupdate` + per-action SHA resolve; open a PR per repo |
| Promote hull's reusable workflows to a tagged release | When hull's workflow surface changes shape (input/output bumps) | Tag hull `v1.x.0`; open consumer PRs bumping `@main` to `@v1.x.0` |
| Audit branch protection rules for drift | Quarterly | See `REPO_SETTINGS.md § 5` (drift detection script) |
| Review gitleaks allowlist for staleness | Every release | Walk `.gitleaks.toml` allowlist entries; remove obsolete ones |

---

## 7. Cross-references

- [`./REPO_SETTINGS.md`](./REPO_SETTINGS.md) — GitHub repo-settings cookbook (the org-side complement to this doc)
- [`../migration/MAIN.md` § 7 Decisions 10, 11, 17, 18, 19](../migration/MAIN.md) — provenance for every assertion above
- [`../migration/MAIN.md` § 8 Constraint 6](../migration/MAIN.md) — the legacy-name grep gate's authoritative source
- [`../migration/MAIN.md` § 11 Stage 1](../migration/MAIN.md) — these files as Stage 1 deliverables
- [`../.github/workflows/`](../.github/workflows) — the canonical reusable workflows
- [`../.pre-commit-config.yaml`](../.pre-commit-config.yaml) — the canonical pre-commit baseline
