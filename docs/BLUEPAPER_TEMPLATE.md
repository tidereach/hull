# BLUEPAPER template

> **Status: scaffold, not the doc.**
> Per `migration/MAIN.md § 7 Decision 12`, `docs/BLUEPAPER.md` is
> "authored once architecture stabilizes." Implementation is pre-Stage-2
> as of 2026-06-30; the architecture in code does not yet exist. This
> template captures the outline, audience, voice, and per-section
> intent locked in 2026-06-30 so the eventual author (probably the
> operator + the agent partner that helped lock these decisions) does
> not re-derive them when Stage 2+ stabilizes.
>
> **When to graduate this template to `docs/BLUEPAPER.md`:** when at
> least `tidereach/interlock` (Stage 2) has shipped v1 and the action
> surface (`LogAction` minimum) is observable in `drydock` cross-repo
> soak. Without those, sections § 4 (attestation spine) and § 5 (action
> surface) describe vapor.

---

## Audience, length, voice

**Audience priority** (locked per Decision 12, in this order):

1. Security teams evaluating adoption
2. Auditors
3. Contributors wanting the gestalt before per-layer reading

**Length:** 5–10 pages rendered (~1800–3300 words). Target 7–8 pages.
Decision 12 explicitly says "not a one-page exec summary" and "not a
deep dive" — overshooting in either direction is a failure mode.

**Voice:** plain-spoken declarative, RFC-style. Active voice. Short
paragraphs. No marketing register. No hedging except where precision
demands it (v1 limits, residual risk). Closer to RFC 8446's tone than
to a vendor whitepaper. The reader should feel they're being told the
truth by someone who has lived inside the code — not pitched.

**Distinct from MAIN.md:** MAIN.md is *how we split the code*; this
document is *what Tidereach is and why*. Don't duplicate MAIN.md's
decision-table density; don't duplicate per-layer specs' depth.

---

## Compression rules (the hardest cuts)

- **L1 sieve internals:** one sentence. The regex / entropy /
  classifier / sanitizer / NER stack is contributor-interesting but a
  sinkhole for the gestalt audience.
- **Freeze-switch + canary mechanics:** one line each. Detail lives in
  `migration/layer0_interlock.md`.
- **CI pipeline details:** zero lines. Link `docs/CI.md`.
- **Audit-chain integrity proof:** one paragraph then link. Quote only
  the 3-line envelope skeleton (`record_hash` / `prev_hash` / `seq`).
- **Per-layer dependencies and feedback loops:** name them in § 7
  (Known Seams); don't elaborate per-loop. Each seam gets one bullet
  + one cost-accepted reason.

---

## Outline — 9 sections

Section order matches a security-team scan path (threats → architecture
→ trust → evidence). Architecture map is mid-doc, not top, because the
security-team reader doesn't need it to evaluate § 2.

### § 1. What Tidereach is

<!-- TODO: fill -->
One paragraph distillation: an **attestation-bounded human-in-the-loop
substrate for coding-agent CLIs** — every action observable,
constrained, revocable. One sentence on scope boundary: substrate, not
SaaS; meta-repo + four sibling layer repos.

Approximate: ½ page.

### § 2. What it defends against — and doesn't

<!-- TODO: fill -->
The CISO-first section. Flat threat list:

- Prompt-injection-driven data exfil
- Runaway egress (agent attempting unintended network reach)
- Supply-chain compromise on agent or its dependencies
- History poisoning / unsigned-commit substitution

Explicit non-coverage (with one line each on why deferred or out of
scope):

- Operator account compromise (single-operator posture defers this;
  see § 6)
- Kernel exploits below the container boundary
- Side-channel attacks
- Real-time threat intel / IOC feeds

Approximate: 1 page.

### § 3. The architecture in one view

<!-- TODO: fill -->
Four planes plus an attestation cross-cut. One ASCII diagram + one
sentence per layer:

- **L0 interlock** — attestation/glue
- **L1 sieve** — data plane (content scan)
- **L2 arbiter** — control plane (intent policy)
- **L3 airlock** — execution plane (sandbox + session-stream substrate)
- **L4 jettison** — visibility plane, **ships in-process inside
  interlock** per the 2026-06-29 layer-4 collapse

Name the in-process placement here, not in a footnote. End the section
with a single line: *"Where these conceptually-clean planes get
operationally-coupled is § 7 (Known Seams)."*

Approximate: 1 page (most of it the diagram).

### § 4. The attestation spine

<!-- TODO: fill -->
The auditor's anchor. Four sub-blocks:

- **Commit signing** (Decision 10) — gitsign via OIDC → Fulcio →
  Rekor; the `signature-verify / verify` CI gate is the canonical
  enforcement (`required_signatures: true` in branch protection
  doesn't work because GitHub's native verifier doesn't accept Fulcio
  certs — `ROADMAP.md` item 6).
- **Image signing** (Decision 17) — cosign keyless, multi-arch
  manifest signing, CycloneDX SBOM + SLSA-provenance-v1 as DSSE
  attestations, all to Rekor.
- **AuditChain** — JSON envelope shape (`record_hash` / `prev_hash` /
  `seq`, fsync + atomic-rename persistence on every append). Quote
  the 3-line envelope skeleton inline; link to per-layer envelope
  specs for the full field list.
- **Operator-signed Ed25519** (Decision 13) — CI verifies the
  signatures, never holds the key. Hardware-token (YubiKey)
  recommended.

Approximate: 1 page.

### § 5. The action surface

<!-- TODO: fill -->
What Tidereach can actually do when it detects something.
**Emit-before-execute is a property, not a footnote.**

- v1: `LogAction` (observer; `action_logged` audit envelope)
- v2 Soft: `BlockAction` (cooperative; Stop-hook honors a per-session
  flag file)
- v2 Hard: `KillAgentContainerAction`, `SeverEgressAction`,
  `FreezeWorkspaceAction` — each opt-in, each emits an audit envelope
  *before* execution

Plus one paragraph on detection primitives: freeze-switch +
canary harness, both owned by interlock. Details live in
`migration/layer0_interlock.md`.

Approximate: ½ page.

### § 6. Governance and what compensates for it

<!-- TODO: fill -->
The most defensible-or-indefensible thing in the doc for a
security-team reader. **Frame as constraint → compensating controls →
residual risk, in that order.** Recommended language:

> Tidereach v1 has one operator. `main` admits commits only from that
> operator's gitsign identity (Decision 10). The compensating controls
> are: linear history, required status checks, hash-chained audit with
> fsync persistence, Rekor transparency for every commit and every
> image, and an operator-signed Ed25519 manifest envelope that CI
> verifies but never holds. The residual risk this does not address is
> operator compromise; team-permissions design is roadmap, not v1.

The ordering matters — controls-first reads as deflection, residual-
risk-omitted reads as overclaim. Link `docs/GOVERNANCE.md` for the
full discipline-fallback rationale and the re-open trigger.

Approximate: ½ page.

### § 7. Known seams

<!-- TODO: fill -->
Open with: *"The four-plane model is the intent; the implementation
has four named seams. Each is deliberate."* Then bullets with one-line
cost-accepted reasoning per seam:

- **L4-in-L0** — the policy module ships inside interlock (2026-06-29
  layer-4 collapse). Reason: data locality; the rule engine already
  calls AuditChain.append, touches freeze state, bumps anomaly
  counters. IPC for fundamentally local state is the wrong shape.
- **L0 ↔ L1 feedback** — sieve calls `FreezeManager.check` at gate
  entry. Reason: a frozen stack must not allow data-plane work.
- **L0 ↔ L4 bidirectional** — policy module reads the session
  substrate (L3) and invokes container-runtime primitives in v2.
  Reason: visibility plane needs both eyes (read) and hands
  (intervene).
- **`SquidAccessReader` reaches "down" from L0 to L3 infra** —
  interlock tails airlock's Squid access log. Reason: egress is the
  highest-fidelity signal for exfil attempts; the audit chain wants
  it first-class.

Naming seams earns credibility with a security-team reader. Claiming
clean layers loses it.

Approximate: ½ page.

### § 8. What Tidereach is not

<!-- TODO: fill -->
Tight bullet list of non-goals:

- No SLO commitments (no ops team; per-hook p95 latencies only)
- No team-permissions design (single-operator v1)
- No LLM-based detection in jettison (deterministic rules only; CI
  asserts zero `httpx` / `requests` / `ollama` imports in the policy
  module)
- No session-stream writer in any layer (agent CLI writes JSONL
  directly to the substrate volume)
- Not a SaaS — this is a substrate operators run on their own host

Approximate: ⅓ page.

### § 9. Reading paths

<!-- TODO: fill -->
Per-audience pointers. One line each, no annotations:

- **Security teams** → `docs/GOVERNANCE.md`, `docs/THREATS.md`
  (forthcoming), `docs/CI.md § 4a` (Fulcio chain)
- **Auditors** → `migration/MAIN.md § 7 Decisions 10/13/17`,
  `interlock-contracts/audit-envelope/v1.0.0/`,
  `docs/COMPLIANCE.md` (forthcoming)
- **Contributors** → `migration/MAIN.md` first, then per-layer
  `migration/layer*_*.md`

Approximate: ⅓ page.

---

## Source material the future author should consult

These were the inputs to the framing decisions captured here. Re-read
them when authoring so the gestalt voice stays grounded:

<!-- legacy-name-allowed -->
- `migration/MAIN.md § 1` (the project's elevator pitch — origin from
  Spektralia, scope bloat, migration rationale)
<!-- /legacy-name-allowed -->
- `migration/MAIN.md § 2` (the four-plane + attestation-cross-cut
  framing)
- `migration/MAIN.md § 7 Decisions 10, 12, 13, 17, 18, 19` (locked
  decisions — never re-litigate; cite verbatim)
- `migration/MAIN.md § 8 Constraints` (especially Constraint 6 —
  legacy-name discipline — and any "MUST NEVER" lines)
- `migration/MAIN.md § 11 Stage 1` (gate criteria; BLUEPAPER is one)
- `migration/layer0_interlock.md` (attestation spine, FreezeManager,
  canary, AuditChain)
- `migration/layer1_sieve.md`, `layer2_arbiter.md`,
  `layer3_airlock.md`, `layer4_jettison.md` (one-sentence pulls; do
  not deep-dive)
- `docs/GOVERNANCE.md § 1` (discipline-fallback paragraph — cite,
  don't duplicate)
- `docs/CI.md § 4a` (OIDC → Fulcio → Rekor → cosign chain — link,
  don't quote)
- `docs/REPO_SETTINGS.md § 1` (branch protection — link only)
- `ROADMAP.md` items 4, 5, 6, 7 (the deferral framing matters: BLUEPAPER
  acknowledges what's intentionally not in v1)

---

## Verification criteria (for the eventual full doc)

When `docs/BLUEPAPER.md` gets authored from this template, the
acceptance checks are:

1. **Length** — `wc -w docs/BLUEPAPER.md` between 1800 and 3300 words.
   Below 1800 = under-distilled; above 3300 = too long. Target
   ~2500 (7–8 pages).
2. **Audience scan** — read top-to-bottom imagining each audience in
   order:
   - Security team: do they see threats + non-coverage by page 1.5?
   - Auditor: do they see the envelope shape + Rekor anchor by page 4?
   - Contributor: can they get from "what is this" to "where do I read
     next" without per-layer detail?
<!-- legacy-name-allowed -->
3. **Legacy-name-guard sim** — 0 hits across `docs/BLUEPAPER.md`. Wrap
   any intentional `spektralia` reference in
   `<!-- legacy-name-allowed -->` blocks per `docs/CI.md § 5`.
<!-- /legacy-name-allowed -->
4. **Hygiene** — trailing whitespace = 0; EOF newline present.
5. **Cross-reference integrity** — every `[link](path)` resolves
   against the working tree, or is suffixed `(forthcoming)` for
   intentionally-deferred targets (THREATS.md, COMPLIANCE.md).
6. **Decision-citation discipline** — every claim about behavior that
   could be debated cites a decision number from `migration/MAIN.md
   § 7` or a section of one of the linked docs. No naked assertions.
7. **No marketing register** — re-read and remove any sentence that
   reads like a vendor pitch. The voice test: does it sound like an
   RFC or like a launch announcement?

---

## What this template explicitly does NOT prescribe

The eventual author retains discretion on:

- **Section sub-headings** within each numbered section
- **The ASCII diagram's exact shape** in § 3 (try one, iterate)
- **Word-level phrasing** beyond the recommended-language quotes in § 6
- **Which specific re-open triggers** to cite from ROADMAP
- **Whether to inline the audit-envelope JSON schema or just the
  three-line skeleton** (skeleton is safer for the length budget)
