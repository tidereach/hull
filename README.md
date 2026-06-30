# Tidereach

An attestation-bounded, human-in-the-loop substrate for coding-agent
CLIs. The project layers an identity-anchored audit chain (interlock),
a sensitivity gate on agent inputs and outputs (sieve), an intent
control plane (arbiter), and a sandboxed execution surface (airlock)
into a stack where every action a coding agent takes is observable,
constrained, and revocable.

This repository is `tidereach/hull` — the **meta-repo**. It carries the
migration plan, the shared CI infrastructure, the operator docs, and
the governance posture. It does not ship a Python source tree; every
runtime component lives in one of the sibling repos below.

> **Project status:** pre-Stage-1-gate. `main` is docs-only. Greenfield
> rebuild from prior-art per
> [`migration/MAIN.md § 8 Constraint 1`](migration/MAIN.md).

---

## Repository map

| Repo | Layer | Purpose | Spec |
|---|---|---|---|
| [`tidereach/hull`](https://github.com/tidereach/hull) | — | Meta-repo: migration plan, shared CI, operator docs, governance. **You are here.** | [`migration/MAIN.md`](migration/MAIN.md) |
| `tidereach/interlock` | L0 | Attestation / glue: hash-pinning, supply-chain verification, audit chain, freeze switch, canary harness, policy module (rule engine + actions). | [`migration/layer0_interlock.md`](migration/layer0_interlock.md) + [`migration/layer4_jettison.md`](migration/layer4_jettison.md) |
| `tidereach/sieve` | L1 | Data plane: content scanning (regex, entropy, classifier, sanitizer, NER, output gating) for agent inputs and outputs. | [`migration/layer1_sieve.md`](migration/layer1_sieve.md) |
| `tidereach/arbiter` | L2 | Control plane: intent policy with pluggable policy-engine integration; engine-agnostic. | [`migration/layer2_arbiter.md`](migration/layer2_arbiter.md) |
| `tidereach/airlock` | L3 | Execution plane: sandbox (container + Squid + Landlock/bwrap + seccomp) and the session-stream substrate the policy module reads from. | [`migration/layer3_airlock.md`](migration/layer3_airlock.md) |
| `tidereach/drydock` | — | Cross-repo integration testing; the soak surface where the assembled stack runs end-to-end. | (no per-repo spec; see [`migration/MAIN.md § 11 Stage 6`](migration/MAIN.md)) |

The L4 policy module (rule authoring, baseline rules, audit-event
emission) ships in-process inside `interlock` per the 2026-06-29
layer-4 collapse; there is no standalone `tidereach/jettison` repo.

---

## A note on layer names

The names **interlock**, **sieve**, **arbiter**, **airlock**,
**jettison**, **hull**, and **drydock** are documentation handles —
memorable names for what each layer does. They may be renamed by
stakeholders in the future. Per
[`AGENTS.md`](AGENTS.md) "Project code standards", layer names appear
in docs but MUST NOT appear in code identifiers, env vars, or settings
keys — a doc rename is a search-and-replace; a code rename is a
breaking change for consumers. CI enforces this for the pre-rebrand
<!-- legacy-name-allowed -->
`spektralia` names via the `legacy-name-guard` workflow; the same
<!-- /legacy-name-allowed -->
discipline applies to the post-rebrand names by convention.

---

## Start here

If you are new to the project, read in this order:

1. [`AGENTS.md`](AGENTS.md) — the canonical entry point for what this
   repo contains and how to work in it.
2. [`migration/MAIN.md`](migration/MAIN.md) — architecture, locked
   decisions, and the staged execution order (Stage 0 through Stage 6).
3. [`ROADMAP.md`](ROADMAP.md) — items deferred to v2 (or later), each
   with a concrete re-open trigger. Append new candidates here when
   they surface.
4. [`docs/CI.md`](docs/CI.md) — operator overview of the shared CI
   workflows that every sibling repo inherits.
5. [`docs/REPO_SETTINGS.md`](docs/REPO_SETTINGS.md) — GitHub
   repo-settings cookbook (branch protection, OIDC, merge strategy).
6. [`docs/GOVERNANCE.md`](docs/GOVERNANCE.md) — v1 governance posture
   and the re-open trigger for team-permissions design.

---

## Operating the assembled stack

- [`docs/INSTALL.md`](docs/INSTALL.md) — install order and prerequisites
  across the five-repo stack (**skeleton, to be filled**).
- [`docs/TROUBLESHOOT.md`](docs/TROUBLESHOOT.md) — diagnosing failures
  across the audit chain, components, and host (**skeleton, to be
  filled**).
- [`docs/TRANSFER.md`](docs/TRANSFER.md) — runbook for the Stage 1
  GitHub org transfer.

---

## License

See [`LICENSE`](LICENSE).
