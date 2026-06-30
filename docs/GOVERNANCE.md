# Governance

Stage 1 deliverable per [`../migration/MAIN.md § 11 Stage 1`](../migration/MAIN.md).
Captures the v1 governance posture for every repository under the
`tidereach` GitHub organization: `hull` (this meta-repo), `interlock`,
`sieve`, `arbiter`, `airlock`, and `drydock`.

This document is about *who decides* and *who commits*. The mechanical
"how" — branch-protection settings, required status checks, merge rules
— lives in [`./REPO_SETTINGS.md`](./REPO_SETTINGS.md); the CI assertions
that complement those rules live in [`./CI.md`](./CI.md).

---

## 1. Governance posture (v1)

**Single-operator.** Until the re-open trigger in § 3 fires, every
`tidereach/*` repo runs under one human operator: `@dotknewt`. `main`
accepts commits only from the operator. No team-permissions model is
designed for v1.

Rationale, per [`../ROADMAP.md`](../ROADMAP.md) item 2: inventing a
multi-role RBAC for an audience of one is overhead the project does not
need to carry through v1. The single-operator posture is honest about
who is shipping the code; it lets the CI assertions in
[`./CI.md`](./CI.md) and the branch-protection rules in
[`./REPO_SETTINGS.md`](./REPO_SETTINGS.md) do their work without an
unused permissions hierarchy on top.

The single-operator posture is also why the `docs/REPO_SETTINGS.md`
"Restrict who can push to matching branches" rule lists exactly one
authorized pusher: `dormant-warlock` at the current repo URL, becoming
`dotknewt` post the Stage 1 transfer to `tidereach/hull`. The two
identity strings refer to the same human; the transfer is a GitHub-
namespace move, not an operator handoff.

---

## 2. CODEOWNERS convention

Every repo carries a `CODEOWNERS` file with one rule:

```
* @dotknewt
```

In this meta-repo the file is at [`../.github/CODEOWNERS`](../.github/CODEOWNERS).
Each sibling layer repo's bootstrap scaffold ships an identical file at
the same path.

The wildcard is what gives branch protection a hook to assert on
("require code-owner reviews" in [`./REPO_SETTINGS.md § 1`](./REPO_SETTINGS.md))
even with a single reviewer. Without the file, "require code-owner
reviews" has nothing to evaluate and the rule no-ops. With the file,
the operator is structurally named as the reviewer-of-record for every
file in the repo — making the rule meaningful for v1 and making the
upgrade to per-area code-owners (when team permissions arrive) a
search-and-replace on one file per repo.

---

## 3. Re-open trigger

This posture is **not** "we never want team permissions"; it is "we
have not yet designed them." The trigger conditions for re-opening
team-permissions design, captured verbatim from
[`../ROADMAP.md`](../ROADMAP.md) item 2:

> first non-operator commit on `main` of any new repo, OR first
> external PR merged to any of the five repos.

Either event is observable, unambiguous, and load-bearing: the moment a
second human contributes, the "audience of one" reasoning above no
longer applies and the deferred RBAC work becomes real. At that point
[`../ROADMAP.md`](../ROADMAP.md) item 2 is the canonical home for the
follow-up; this document gets updated with the chosen posture once the
design lands.

The five repos the trigger covers: `tidereach/interlock`,
`tidereach/sieve`, `tidereach/arbiter`, `tidereach/airlock`,
`tidereach/drydock`. (`tidereach/hull` is the meta-repo; the same
trigger applies to it implicitly under "any new repo".)

---

## 4. Cross-references

- [`../ROADMAP.md`](../ROADMAP.md) item 2 — canonical home for the
  v2 team-permissions deferral and the re-open trigger
- [`../migration/MAIN.md § 11 Stage 1`](../migration/MAIN.md) — the
  Stage 1 deliverable that mandates this document
- [`../migration/MAIN.md § 7 Decision 19`](../migration/MAIN.md) —
  single-operator governance source decision
- [`./REPO_SETTINGS.md`](./REPO_SETTINGS.md) — branch-protection +
  required-status-check rules; the mechanical complement to this doc
- [`./CI.md`](./CI.md) — the CI assertions that complement those rules
- [`../.github/CODEOWNERS`](../.github/CODEOWNERS) — the wildcard rule
  this document references
