# Spektralia — Compliance Notes

Spektralia makes no compliance certification claims. The notes below describe how
gate components align with common regulatory and security frameworks, for use as
reference by deployers assessing the system. This is not legal advice.

See also: [docs/THREATS.md](THREATS.md) | [SPEC.md](../SPEC.md)

---

## GDPR

Spektralia acts as a **processor of personal data** when run. The lawful basis
depends on the deployer: legitimate interest suffices for self-hosted personal use;
an organisational deployment requires a controller/processor agreement.

**Data minimisation** is a normative design constraint, not an aspiration. It is
enforced mechanically: `test_no_secret_in_exceptions.py` verifies that no exception
path ever includes raw personal-data values; `test_audit_no_values.py` verifies that
no audit-log field ever contains a known secret.

**Retention.** `spektralia audit-rotate` rotates the audit log on a configurable
schedule. Operators must apply a retention period appropriate to their controller's
purposes.

**Right to Erasure.** `spektralia audit-purge` purges audit records and re-anchors
the hash chain with a documented re-anchor event, preserving chain continuity while
removing the purged data.

**Cross-border transfer.** Spektralia is a technical measure under Art. 32 that data
exporters may cite as a safeguard when framing data-protection impact assessments —
it reduces the volume of personal data reaching the cloud LLM. This is a framing
observation, not legal advice.

**Note:** The audit log itself (see below) contains personal data and falls under
GDPR obligations; see the "Audit log as personal data" section for retention and
access rules.

---

## Datatilsynet (Norway)

Spektralia ships a `NO_PID` pattern that detects Norwegian national identity numbers
(fødselsnummer) using the official MOD-11 algorithm. This means valid Norwegian
identity numbers are flagged and blocked before reaching any cloud LLM service.

The design aligns with Datatilsynet's published AI guidance, which calls for
technical measures that prevent personal-data leakage to AI systems. Deployers
operating under Norwegian jurisdiction should verify alignment with the current
Datatilsynet guidance document (see Datatilsynet's official website,
`datatilsynet.no`, for the most recent AI-specific publications).

---

## PCI-DSS

**Never-log-values** is a PCI-DSS compliance constraint in Spektralia, not a
stylistic choice. No audit log, exception message, or debug output ever contains
a raw card number or other payment-card value.

**PAN detection** covers Luhn-valid card number candidates across all major card
network ranges. Luhn-invalid candidates that look like PANs are flagged with lower
confidence via the generic pattern; Luhn-valid candidates are flagged as
`CREDIT_CARD` and blocked.

**Explicit gap.** Magnetic-stripe track data and CVV2/CVC2 security codes are
**not detected** in v1. Deployers in PCI-DSS scope should treat this as a known
gap and consider whether compensating controls are required.

**Cache safety.** Cache entries are keyed on sanitized text and the effective
configuration hash; original card values are never cached.

---

## HIPAA

**No PHI patterns ship in v1.** Spektralia does not include US Protected Health
Information pattern sets (ICD-10 codes, NPI numbers, MRN heuristics). Deployers
in US healthcare contexts must not rely on Spektralia alone to prevent PHI from
reaching cloud LLM services.

**Roadmap.** PHI pattern support is a v2 roadmap item: ICD-10 code detection, NPI
number detection (using a Luhn variant), and institution-configurable MRN heuristics
are planned. Healthcare adopters should make their requirements known.

---

## Audit log as personal data

The Spektralia audit log records metadata about each gate decision: labels of
detected personal-data categories (e.g., `EMAIL`, `NO_PID`), classifier confidence
scores, timestamps, and the hash-chain anchors. These labels are themselves personal
data under GDPR Art. 4(1) because they indicate that a natural person's identifying
information was present in the input.

**Obligations for deployers:**
- Apply a data-retention period to the audit log consistent with the controller's
  purposes; use `audit-rotate` and `audit-purge` accordingly.
- Restrict access to the audit log file (`~/.spektralia/audit.jsonl`) to authorised
  personnel; the file is created with mode 0600 by default.
- If data subjects exercise the Right to Erasure, purge relevant audit records
  with `spektralia audit-purge` and retain the re-anchor event as evidence.
- Include the audit log in your Record of Processing Activities (ROPA).

---

## OWASP Agentic Security Initiative (ASI) Top 10

> The canonical version of this table lives in [SPEC.md §21](../SPEC.md). This copy
> is provided here for compliance-document completeness; consult SPEC.md for updates.

| Risk | Status | Where covered |
|------|--------|--------------|
| ASI-01 Prompt Injection | PASS | §9 (injection-framed prompt, two-framing, enum-bounded output), §13.3 (canary corpus), §18 (default-deny MCP matchers) |
| ASI-02 Tool Use | N/A | Library |
| ASI-03 Excessive Agency | N/A | Library |
| ASI-04 Escalation | N/A | Library |
| ASI-05 Trust Boundary | PASS | §8 (no public `restore`), §11 (Ollama channel), §14 (no values in `Detection`), §18 (`unsafe_restore` schema-aware) |
| ASI-06 Audit | PASS | §13.1 (hash chain across restarts, sink abstraction) |
| ASI-07 Identity | N/A | Library |
| ASI-08 Policy Bypass | PASS | §14 (`rule_hit OR classifier_high`), §18 (default-deny MCP, `Task` covered, `SessionStart` integrity gate) |
| ASI-09 Supply Chain | PASS | §11 (Ollama UDS/PID/exe pinning), §12 (pattern hash, model digest, hash-pinned deps, SBOM, `verify-installed` at SessionStart) |
| ASI-10 Anomaly | PASS | §13.2 (rolling counters, auto-freeze), §13.3 (canary drift, heartbeat), §13.5 (mutation-pattern detector, override-rate), §13.4 (kill switch) |
