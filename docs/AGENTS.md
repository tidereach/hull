# Documentation

Operator docs under `docs/`. All are human-authored; no generated content.

## Files

- `docs/CI.md` — operator overview of the CI infrastructure (inheritance model, the six assertions, pinning, troubleshooting, maintenance). Canonical home for pre-commit install (`§ 3`), gitsign setup (`§ 4b → "Prerequisite: gitsign configured locally"`), and troubleshooting runbooks (`§ 5`).
- `docs/REPO_SETTINGS.md` — operator cookbook for GitHub repo-side rules (branch protection, merge strategy, OIDC) per `migration/MAIN.md § 7` Decisions 10, 11, 17, 18, 19. `§ 4` has the canonical `gh api` apply script.
- `docs/GOVERNANCE.md` — v1 single-operator posture, CODEOWNERS convention, re-open trigger; cites Decision 19.
- `docs/INSTALL.md` — system-level install guide for the assembled five-repo stack. Skeleton; content fills as each layer's Stage release lands.
- `docs/TROUBLESHOOT.md` — symptoms-to-diagnosis index for the assembled stack. Skeleton; populated as live incidents surface failure modes.
- `docs/TRANSFER.md` — Stage 1 org-transfer runbook with pre-transfer audit findings inline. Historical reference; useful as a template if any layer repo migrates from another origin.
- `docs/BLUEPAPER_TEMPLATE.md` — scaffold for the eventual `docs/BLUEPAPER.md` (5–10 page architectural distillation per Decision 12). Graduates when Stage 2+ implementation stabilizes; see the template's "When to graduate" header.
- `docs/JETTISON_TEMPLATE.md` — scaffold for the eventual `docs/JETTISON.md` (policy-module rule-authoring + baseline guide). Graduates when interlock Stage 2 ships the policy module + baseline rules.

## Template-first acceptance rule

BLUEPAPER and JETTISON ship as templates until their named graduation conditions are met (`migration/MAIN.md § 11 Stage 1`). Accept the template as the Stage gate deliverable — do not block on the full doc — until the graduation condition fires. Graduation conditions are stated in each template's "When to graduate" header.
