# Installing Tidereach

Operator-facing install guide for the assembled five-repo stack
(`interlock`, `sieve`, `arbiter`, `airlock`, with `drydock` as the
optional integration-test surface). Audience: a single operator
standing up Tidereach against one or more coding-agent CLIs on one
host.

> **Status: skeleton.** Headers and section intent are locked; content
> is filled as each layer's Stage release lands. See
> [`../migration/MAIN.md § 11`](../migration/MAIN.md) for stage gates.

---

## 1. Overview — the five-repo topology

<!-- TODO: fill -->
What gets installed where: which components are host processes, which
run inside the airlock sandbox, which are libraries imported by the
agent CLI shim. One-paragraph mental model + a diagram pointing at
[`../migration/MAIN.md § 3`](../migration/MAIN.md).

## 2. Prerequisites

<!-- TODO: fill -->
Host requirements: supported OS, Python version floor, container
runtime (Docker / Podman + buildx for multi-arch), Squid build/runtime
dependencies, Landlock + bwrap kernel features, OIDC identity provider
(GitHub login for gitsign), free disk for image cache and audit chain.

## 3. Component install order

<!-- TODO: fill -->
Canonical order: `interlock` → `sieve` → `airlock` → `arbiter` →
(optional) `drydock`. Per-component install (uv, pip, container pull)
with the specific commands. Note the contracts submodule that each
component pins.

## 4. Configuration

<!-- TODO: fill -->
State directory layout (`~/.tidereach/`). Per-component settings files
and their canonical locations. Cross-references to each layer's
settings table in `migration/layer*_*.md`.

## 5. First-run verification

<!-- TODO: fill -->
Smoke commands that confirm each component is reachable and the
inter-component contracts are wired correctly. Examples (subject to
final CLI surface):

- `tidereach interlock heartbeat`
- `tidereach sieve probe`
- `tidereach airlock check-sandbox`
- `tidereach arbiter dry-run`
- End-to-end: run a single agent turn through the assembled stack and
  inspect the audit-chain envelopes.

## 6. Upgrading

<!-- TODO: fill -->
SHA-pin bump cadence for shared CI workflows. Contracts-submodule bump
procedure. Per-component upgrade order (interlock first, then
consumers). Rollback notes.

## 7. Uninstall

<!-- TODO: fill -->
Order for clean removal. State-directory cleanup. Container image
pruning. Audit-chain retention guidance — what to keep, what to
archive, what is safe to drop.

---

## Cross-references

- [`../migration/MAIN.md`](../migration/MAIN.md) — architecture and
  staged execution order; the source of truth for what each layer
  ships and what depends on what
- [`../migration/layer0_interlock.md`](../migration/layer0_interlock.md)
- [`../migration/layer1_sieve.md`](../migration/layer1_sieve.md)
- [`../migration/layer2_arbiter.md`](../migration/layer2_arbiter.md)
- [`../migration/layer3_airlock.md`](../migration/layer3_airlock.md)
- [`./TROUBLESHOOT.md`](./TROUBLESHOOT.md) — symptoms-to-diagnosis
  index once you are running
- [`./GOVERNANCE.md`](./GOVERNANCE.md) — escalation context for
  operator-side issues
