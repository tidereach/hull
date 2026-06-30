# Troubleshooting Tidereach

Symptoms-to-diagnosis index for the assembled five-repo stack. Pair
with [`./INSTALL.md`](./INSTALL.md) for setup and with each layer's
spec in [`../migration/`](../migration/) for component-level detail.

> **Status: skeleton.** Headers and section intent are locked; content
> is filled as live incidents and soak findings surface failure modes
> worth documenting.

---

## 1. How to read a failure

<!-- TODO: fill -->
The canonical diagnostic order: **audit chain → component log → host
log**. Why: the audit chain (interlock) is the first place a hostile
or anomalous action lands an envelope; the component log adds local
context; the host log is the last resort for kernel- or container-
runtime-level failures. Examples of envelope shapes worth knowing on
sight.

## 2. Common failures by symptom

<!-- TODO: fill -->
A symptom-first index. For each entry: what the operator sees, where
to look first, the likely root cause, and the canonical fix.

- **Hook timeout (sieve)** — agent CLI hangs at PreToolUse /
  PostToolUse / UserPromptSubmit boundaries.
- **Freeze flag stuck (interlock)** — workspace stays frozen after
  the trigger condition cleared.
- **Sandbox won't start (airlock)** — container fails health-check;
  Landlock / bwrap / seccomp init error.
- **Policy rule miss (jettison module)** — expected `rule_hit` did
  not fire on a known-triggering session event.
- **`signature-verify` rejected a commit** — gitsign chain failure on
  a PR or push to `main`.
- **`cosign verify` rejected an image** — Fulcio SAN does not match
  `EXPECTED_IDENTITY_REGEXP`; usually fork or wrong trigger.
- **`gitleaks` false positive blocking a PR** — when allowlist is the
  right answer vs. when the finding is real.
<!-- legacy-name-allowed -->
- **`legacy-name-guard` hit** — a `spektralia` reference outside the
  exempt locations.
<!-- /legacy-name-allowed -->
- **Heartbeat stale (interlock)** — what a healthy cadence looks like
  and how to recover from a stuck writer.
- **Audit-chain divergence** — hash continuity broken; recovery
  procedure for live and offline cases.
- **Squid access-log not appended to audit chain** — the
  `SquidAccessReader` lag / failure symptoms.

## 3. Diagnostic commands

<!-- TODO: fill -->
Per-component probes the operator can run cold. Cross-link to
`docs/CI.md § 5` for the cosign verification cookbook; this section
covers the runtime side. Examples (subject to final CLI surface):

- `tidereach interlock heartbeat --recent`
- `tidereach interlock audit tail --component <name>`
- `tidereach sieve probe --pattern <regex>`
- `tidereach airlock inspect-sandbox`
- `tidereach arbiter rules-lint <path>`
- Direct envelope-stream inspection via `jq` on the substrate volume.

## 4. Bug-report template

<!-- TODO: fill -->
What to attach when filing an issue against a sibling repo:

- Component versions (each repo's `tidereach <component> --version`)
- Host OS + kernel + container runtime versions
- Relevant audit-chain envelopes (redacted)
- The exact CLI invocation that reproduces
- A short transcript of agent input/output around the failure
- Whether the failure reproduces with sieve in
  `fail_open=False` vs. `fail_open=True`

## 5. Escalation

<!-- TODO: fill -->
v1 is single-operator (see [`./GOVERNANCE.md`](./GOVERNANCE.md)).
Escalation is to the operator via GitHub issues on the affected
repo. The re-open trigger in [`./GOVERNANCE.md § 3`](./GOVERNANCE.md)
defines when the escalation surface itself changes shape.

---

## Cross-references

- [`./INSTALL.md`](./INSTALL.md) — install order and state-directory
  layout (where to look on the filesystem)
- [`./CI.md`](./CI.md) — CI-side troubleshooting (signature-verify,
  cosign, gitleaks, legacy-name-guard, pr-title-lint)
- [`./REPO_SETTINGS.md`](./REPO_SETTINGS.md) — branch-protection /
  merge-strategy rules the CI assertions back into
- [`./GOVERNANCE.md`](./GOVERNANCE.md) — escalation context
- [`../migration/MAIN.md`](../migration/MAIN.md) — architecture and
  per-layer specs (source of truth for component behavior)
