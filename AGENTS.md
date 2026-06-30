# Tidereach — Migration Planning Repo

Main branch contains only migration planning specs. The migration is a greenfield rebuild per `migration/MAIN.md § 8` Constraint 1 — no source is copied forward from any prior implementation.

**Status (2026-06-30):** Stage 1 complete. Repo lives at `tidereach/hull` (public). Branch protection applied per `docs/REPO_SETTINGS.md § 1` (amended — see `ROADMAP.md` items 5 + 6). Remaining Stage 1 gate items: `docs/BLUEPAPER.md`, `docs/JETTISON.md`.

## Files

<!-- legacy-name-allowed -->
- `migration/` — historical planning specs preserved as the canonical migration record. Exempted from `legacy-name-guard` so layer specs may reference pre-migration `spektralia` names where required for narrative accuracy.
<!-- /legacy-name-allowed -->
- `migration/MAIN.md` — architecture, decisions, execution order. **Read this first.**
- `ROADMAP.md` — v2 candidates and other deferred items, each with a concrete re-open trigger. Append new candidates here as they surface; don't wait to be asked.
- `README.md` — meta-overview pointing at the four sibling layer repos + drydock.
- `migration/layer0_interlock.md` — L0 Attestation/Glue (Stage 2; ships before other layers)
- `migration/layer1_sieve.md` — L1 Data Plane / sensitivity gate (Stage 3)
- `migration/layer2_arbiter.md` — L2 Control Plane / intent integration (Stage 5)
- `migration/layer3_airlock.md` — L3 Execution Plane / sandbox + session-stream substrate (Stage 4)
- `migration/layer4_jettison.md` — L4 Visibility Plane / deterministic rules + actions (Stage 2; policy module ships alongside interlock per the 2026-06-29 layer-4 collapse)
- `.github/CODEOWNERS` — `* @dotknewt` wildcard per `docs/GOVERNANCE.md § 2`.
- `.github/workflows/ci.yml` — hull's own CI; calls the four reusable workflows via local-path notation. Distinct from `ci-template.yml` (which is the layer-repo template).
- `.github/workflows/legacy-name-guard.yml` — reusable workflow enforcing migration/MAIN.md § 8 Constraint 6 (legacy-name grep gate)
- `.github/workflows/gitleaks.yml` — reusable workflow for migration/MAIN.md § 7 Decision 18(a) (secrets scanner)
- `.github/workflows/pr-title-lint.yml` — reusable workflow for migration/MAIN.md § 7 Decision 18(b) (Conventional Commit PR titles)
- `.github/workflows/signature-verify.yml` — reusable workflow for migration/MAIN.md § 7 Decision 10 per-PR gitsign signature check
- `.github/workflows/image-sign.yml` — airlock-only reusable workflow for migration/MAIN.md § 7 Decision 17 (cosign keyless + multi-arch + SBOM/provenance attestations)
- `.github/workflows/ci-template.yml` — example layer-repo CI; copied to each layer at bootstrap
- `.github/workflows/release-template.yml` — example layer-repo release workflow (image-publishing layers only, currently airlock); wires the consumer-side `push: tags: ['v*']` trigger that calls hull's `image-sign.yml`
- `.pre-commit-config.yaml` — canonical pre-commit baseline (gitleaks, hygiene set, uv-lock, commented-in mypy)
- `docs/REPO_SETTINGS.md` — operator cookbook for GitHub repo-side rules (branch protection, merge strategy, OIDC) per migration/MAIN.md § 7 Decisions 10, 11, 17, 18, 19
- `docs/CI.md` — operator overview of the CI infrastructure (inheritance model, the six assertions, pinning, troubleshooting, maintenance)
- `docs/GOVERNANCE.md` — v1 single-operator posture, CODEOWNERS convention, re-open trigger; cites Decision 19.
- `docs/INSTALL.md` — system-level install guide for the assembled five-repo stack. Skeleton; content fills as each layer's Stage release lands.
- `docs/TROUBLESHOOT.md` — symptoms-to-diagnosis index for the assembled stack. Skeleton; populated as live incidents surface failure modes.
- `docs/TRANSFER.md` — Stage 1 org-transfer runbook with pre-transfer audit findings inline. Historical reference now that the transfer is done; useful as a template if any layer repo migrates from another origin.

## Commands

| Command | Purpose |
|---|---|
| `pre-commit run --files <paths>` | Hygiene + gitleaks + (when uncommented) mypy. Install via `python3 -m venv ~/.venvs/pc && ~/.venvs/pc/bin/pip install pre-commit && ~/.venvs/pc/bin/pre-commit install`. |
| `gitsign verify HEAD` | Verify the most recent commit's sigstore signature against Rekor. The CI workflow `signature-verify.yml` runs this on every PR. |
| `gh api -X PUT repos/tidereach/hull/branches/main/protection ...` | Apply branch protection per `docs/REPO_SETTINGS.md § 4` (amended apply script — count=0, code-owner-reviews=false, required_signatures=false). |

**Signing setup** (one-time per machine, per `docs/CI.md § 4b`): install `gitsign` (Arch: `pacman -S gitsign`; or download to `~/.local/bin/` from sigstore/gitsign releases), then `git config --global commit.gpgsign true && git config --global tag.gpgsign true`. `gpg.format=x509` and `gpg.x509.program=gitsign` must also be set. **GitHub UI will show "Unverified" — that's ROADMAP item 6, not a real failure; `gitsign verify` and the signature-verify workflow are the truth.** If gitsign's pure-Go DNS resolver hits a UDP timeout on systemd-resolved, export `GODEBUG=netdns=cgo` to switch to NSS.

## Project code standards

Layer names (`interlock`, `sieve`, `arbiter`, `airlock`, `jettison`, `hull`, `drydock`) may be rejected by stakeholders. Keep code resilient to a layer rename — the doc-level name is one search-and-replace away, but a Python identifier or env var carrying a layer name is a breaking change for consumers.

- Use layer names in **documentation** as memorable handles for the layers.
- Avoid using layer names in **code**. Instead use descriptive, best-practice naming conventions for files, classes, functions, and variables.
<!-- legacy-name-allowed -->
- See also `migration/MAIN.md § 8 Constraint 6`: legacy `spektralia` names MUST NEVER propagate into the new repositories; CI grep gate enforces.
<!-- /legacy-name-allowed -->

## Working with specs

- Ember agent (`ember:Ember`) works well for planning revision sessions — spawn once, relay follow-ups via `SendMessage` with the returned agentId.
- When Ember's default model fails to spawn (`claude-opus-4.7` access issue), retry with `model: opus`.
- Before any layer spec work begins in parallel, three pre-parallel artifacts must be locked in `interlock-contracts`: `contracts/integrity-inputs/v1.0.0/`, `governance/audit-event-ownership.md`, `governance/freeze-manager-constraint.md`.
- Settings tables: always verify the stated field count matches the actual row count (layer0 said 13/had 15; layer1 said 15/had 20).
- Audit event ownership uses a two-tier model: layer-exclusive events (interlock only) vs. cross-layer shared-namespace events (defined by interlock, emitted by named layer).

## Live operator gotchas (post-Stage-1)

- **PRs to `main` need the merge dance.** Branch protection's `required_status_checks` lists four contexts (`legacy-name-guard / grep-gate`, `gitleaks / scan`, `pr-title-lint / lint`, `signature-verify / verify`). Until ci.yml is on main + PR-author setup is complete, those checks pend forever. See `ROADMAP.md` item 5 + `docs/TRANSFER.md § 4.4`.
- **gitsign signatures show "Unverified" in GitHub UI.** GitHub's verifier doesn't accept Fulcio short-lived certs; `signature-verify.yml` is the canonical Decision 10 gate. `ROADMAP.md` item 6.
- **Single operator + 1-approval is structurally deadlocked.** Resolved as path (a) in `ROADMAP.md` item 5 — `required_approving_review_count: 0`. Don't bump that knob back to 1 without amending governance.

## Git

- Greenfield rebuild — no pre-migration codebase is treated as a source of truth in this repo. Any artifact authored under Stages 1–7 is written against the migration specs, not lifted from earlier history.
