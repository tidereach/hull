# Tidereach Roadmap

Items deferred to v2 (or later) with their re-open triggers. The canonical home for "we know about this; we picked not-now; here's what makes us re-evaluate."

When work surfaces a new candidate (a gap, limitation, or deferred feature), append it here before closing the task — don't wait to be asked. Each entry follows the shape below.

## v2 candidates

### 1. `interlock-contracts` distribution mechanism

v1 ships git submodule pinned at SHA in each consumer. v2 picks a proper mechanism (likely PyPI package `tidereach-interlock-contracts`; tarball if non-Python consumers appear).

**Why deferred:** pre-1.0 schema churn is cheap with SHA pins; a publish/bump cycle for every iteration is not. The cost asymmetry flips once contracts stabilize.

**Re-open trigger:** contracts stabilize at v1.0.0, OR a non-Python consumer appears, OR submodule UX friction outweighs the publish friction we avoided.

**Linked:** `MAIN.md § 10` v1 distribution paragraph; resolved as a v1-vs-v2 split on 2026-06-29.

### 2. Team-permissions model across all repos

v1 ships single-operator governance, captured in `docs/GOVERNANCE.md` (Stage 1 deliverable; see `MAIN.md § 11 Stage 1`): `main` accepts commits only from the operator, `CODEOWNERS` is a `* @<operator-handle>` wildcard in each of the five repos, no team-permissions design is authored.

**Why deferred:** inventing five-role RBAC for an audience of one is overhead. The wildcard CODEOWNERS still gives branch-protection a hook to assert on.

**Re-open trigger** (named in GOVERNANCE.md): first non-operator commit on `main` of any new repo, OR first external PR merged to any of the five repos.

**Linked:** `MAIN.md § 11 Stage 1` GOVERNANCE.md deliverable; resolved 2026-06-29.

### 3. Contract-bump reviewer subagent

Per `MAIN.md § 7 Decision 19(a)`: build at Stage 2 when `contracts/` lands in interlock; not before (no schemas exist to review pre-Stage-2). v1 of any layer ships without it.

**Why deferred:** the subagent's job is to verify that `contracts/*/v*.0.0/schema.json` bumps come with matching changelog + semver. Until the first such file exists, there is nothing to review against.

**Re-open trigger:** Stage 2 begins; first `contracts/*/v*.0.0/schema.json` lands in `tidereach/interlock`. At that point, the first PR introducing it is the worked example the subagent gets built against.

**Linked:** `MAIN.md § 7 Decision 19(a)`; resolved 2026-06-29.

---

## Entry format for new items

When appending, copy this shape:

```
### N. <Short title>

<One-paragraph problem statement: what is deferred, what v1 ships instead.>

**Why deferred:** <Cost asymmetry / dependency / risk reason in 1–2 sentences.>

**Re-open trigger:** <Concrete observable signal that makes this re-evaluable. Not "when we have time"; not "if it becomes a problem." Name the event.>

**Linked:** <MAIN.md section or Decision reference; resolved date; relevant layer spec.>
```

The re-open trigger is the load-bearing part. An entry without one is not a roadmap item, it is wishful thinking — file it elsewhere or refine the trigger before committing.
