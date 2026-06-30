# Tidereach Roadmap

Items deferred to v2 (or later) with their re-open triggers. The canonical home for "we know about this; we picked not-now; here's what makes us re-evaluate."

When work surfaces a new candidate (a gap, limitation, or deferred feature), append it here before closing the task — don't wait to be asked. Each entry follows the shape below.

## v2 candidates

### 1. `interlock-contracts` distribution mechanism

v1 ships git submodule pinned at SHA in each consumer. v2 picks a proper mechanism (likely PyPI package `tidereach-interlock-contracts`; tarball if non-Python consumers appear).

**Why deferred:** pre-1.0 schema churn is cheap with SHA pins; a publish/bump cycle for every iteration is not. The cost asymmetry flips once contracts stabilize.

**Re-open trigger:** contracts stabilize at v1.0.0, OR a non-Python consumer appears, OR submodule UX friction outweighs the publish friction we avoided.

**Linked:** `migration/MAIN.md § 10` v1 distribution paragraph; resolved as a v1-vs-v2 split on 2026-06-29.

### 2. Team-permissions model across all repos

v1 ships single-operator governance, captured in `docs/GOVERNANCE.md` (Stage 1 deliverable; see `migration/MAIN.md § 11 Stage 1`): `main` accepts commits only from the operator, `CODEOWNERS` is a `* @dotknewt` wildcard in each of the four sibling layer repos + meta-repo, no team-permissions design is authored.

**Why deferred:** inventing five-role RBAC for an audience of one is overhead. The wildcard CODEOWNERS still gives branch-protection a hook to assert on.

**Re-open trigger** (named in GOVERNANCE.md): first non-operator commit on `main` of any new repo, OR first external PR merged to any of the five repos.

**Linked:** `migration/MAIN.md § 11 Stage 1` GOVERNANCE.md deliverable; resolved 2026-06-29.

### 3. Contract-bump reviewer subagent

Per `migration/MAIN.md § 7 Decision 19(a)`: build at Stage 2 when `contracts/` lands in interlock; not before (no schemas exist to review pre-Stage-2). v1 of any layer ships without it.

**Why deferred:** the subagent's job is to verify that `contracts/*/v*.0.0/schema.json` bumps come with matching changelog + semver. Until the first such file exists, there is nothing to review against.

**Re-open trigger:** Stage 2 begins; first `contracts/*/v*.0.0/schema.json` lands in `tidereach/interlock`. At that point, the first PR introducing it is the worked example the subagent gets built against.

**Linked:** `migration/MAIN.md § 7 Decision 19(a)`; resolved 2026-06-29.

### 4. SLOs / error budgets beyond sieve hook latencies

v1 specifies per-hook p95 latency budgets for sieve (500ms PreToolUse, 300ms PostToolUse, 200ms UserPromptSubmit). v1 does **not** specify availability SLOs, error budgets, graceful-degradation contracts beyond per-component `fail_open=False` defaults, or end-to-end stack-level latency budgets.

**Why deferred:** the project is OSS without an operations team behind it; SLOs imply a service-level commitment that single-operator governance (Decision 19) cannot honor. Per-hook latency budgets are sufficient for "the hook doesn't make the agent CLI feel broken"; broader uptime/error budgets are post-v1 concerns.

**Re-open trigger:** first operator running Tidereach as part of a managed service offering, OR first SLA contract that cites Tidereach as a dependency, OR any operator-pageable incident pattern emerging from the Stage 6 cross-repo soak.

**Linked:** sieve latency budgets live in `migration/layer1_sieve.md`; resolved-as-deferred 2026-06-29.

### 5. Single-operator + `required_approving_review_count: 1` merge deadlock

v1 originally shipped `required_approving_review_count: 1` in `docs/REPO_SETTINGS.md § 1` paired with single-operator governance in `docs/GOVERNANCE.md § 1`. GitHub forbids a PR author from self-approving, so the spec applied verbatim made every PR unmergeable — surfaced by PR #146 on `tidereach/hull` immediately after the Stage 1 transfer. **Resolved 2026-06-30 by adopting path (a): drop `required_approving_review_count` to 0 and `require_code_owner_reviews` to false; rely on signed commits + Rekor + linear history + required status checks as the authenticity gates.** The discipline-only fallback rationale lives in `docs/GOVERNANCE.md § 1`.

**Why this resolution.** Two alternatives were considered and rejected. Path (b) — second operator account approving the primary — contradicts `docs/GOVERNANCE.md § 1`'s "`main` accepts commits only from the operator" and grows the spec change rather than shrinking it. Path (c) — relax `enforce_admins` so the operator can bypass branch protection deliberately — turns every merge into an admin bypass and destroys the audit signal distinguishing "passed the gates" from "operator forced through."

**Re-open trigger:** same as item 2 above — first non-operator commit on `main` of any new repo, OR first external PR merged to any of the five repos. When v2 team-permissions design lands under item 2, the count and code-owner-reviews flag bump back up as part of that work.

**Linked:** `docs/REPO_SETTINGS.md § 1` (count + code-owner-reviews rows); `docs/GOVERNANCE.md § 1` (discipline-fallback rationale); `docs/TRANSFER.md § 4.4`; PR #146 on `tidereach/hull` (the worked example of the deadlock and its resolution). Resolved 2026-06-30.

### 6. GitHub native signature verifier doesn't recognize sigstore/Fulcio certs

`migration/MAIN.md § 7 Decision 10` commits to sigstore via OIDC (gitsign). GitHub's native commit-signature verifier — the "Verified" badge in the UI and the `verified: true` field returned by `repos/{owner}/{repo}/commits/{sha}` — accepts GPG keys uploaded to the account and SSH keys uploaded to the account; it does **not** accept Fulcio short-lived certs. Branch protection's "Require signed commits" rule checks this native verifier, so `required_signatures: true` in branch protection blocks every gitsign-signed PR with `reason: bad_cert`. Surfaced 2026-06-30 by PR #146 on `tidereach/hull` — the first PR carrying gitsign-signed commits to a branch with `required_signatures: true` applied per the original spec.

v1 resolves the operational conflict by setting `required_signatures: false` in branch protection and treating the `signature-verify / verify` required-status-check (which runs `gitsign verify` against Rekor) as the canonical Decision 10 gate. The CI check is what enforces; the GitHub UI badge is informational and currently misleading for gitsign-signed commits.

**Why deferred:** the upstream gap is GitHub's, not the project's. Sigstore tracks integration ([sigstore/gitsign](https://github.com/sigstore/gitsign) issues + GitHub's response). Until GitHub ships native Fulcio chain support — or until sigstore + GitHub agree on a co-signing scheme that uploads a stable proof to the account — every gitsign-signed commit will read "Unverified" in the GitHub UI even though Rekor and `gitsign verify` say otherwise.

**Re-open trigger:** GitHub announces native Fulcio / sigstore signature verification, OR the project decides that the misleading UI badge outweighs Rekor's audit chain and amends Decision 10 to a GitHub-recognized signing method (GPG / SSH with keys uploaded to the operator account).

**Linked:** `migration/MAIN.md § 7 Decision 10` (sigstore via OIDC); `docs/REPO_SETTINGS.md § 1` (the now-off `Require signed commits` row); `docs/CI.md § 2` (the signature-verify workflow as the canonical gate); PR #146 (the worked example). Resolved 2026-06-30.

---

## Entry format for new items

When appending, copy this shape:

```
### N. <Short title>

<One-paragraph problem statement: what is deferred, what v1 ships instead.>

**Why deferred:** <Cost asymmetry / dependency / risk reason in 1–2 sentences.>

**Re-open trigger:** <Concrete observable signal that makes this re-evaluable. Not "when we have time"; not "if it becomes a problem." Name the event.>

**Linked:** <migration/MAIN.md section or Decision reference; resolved date; relevant layer spec.>
```

The re-open trigger is the load-bearing part. An entry without one is not a roadmap item, it is wishful thinking — file it elsewhere or refine the trigger before committing.
