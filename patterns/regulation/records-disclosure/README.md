# Records Disclosure
**Pattern URI:** `urn:utoronto:security:pattern:records-disclosure`

## Purpose

The **records-disclosure** pattern defines obligations related to the **lawful disclosure of institutional records** in response to regulatory, legal, or policy-based requests.

This pattern asserts that a system produces or manages records that may be subject to disclosure obligations and that such obligations are **governed externally** by institutional records, privacy, and legal authorities.

---

## Scope

This pattern applies to systems that:

- Generate or retain institutional records
- Are subject to freedom of information, access to information, or similar disclosure regimes
- Provide audit or evidentiary records used in oversight or investigations

---

## Normative Assertions

A system asserting **records-disclosure** guarantees that:

1. Records subject to disclosure are **identified and preserved** in accordance with institutional requirements.
2. Disclosure decisions are made by **authoritative institutional functions**, not by the system or its operators.
3. The system supports **traceability and controlled extraction** of records when disclosure is lawfully required.
4. Unauthorized or informal disclosure of records is **prohibited**.

---

## Out of Scope

This pattern does not define:

- Disclosure procedures or workflows
- Legal interpretation of disclosure requests
- Redaction or review processes
- Retention schedules (see `data-retention`)

---

## Relationship to Other Patterns

This pattern is commonly composed with:

- `trusted-data`
- `data-retention`
- `regulated-digital-service`

---

## Summary

The **records-disclosure** pattern establishes a clear boundary between **record production** and **record disclosure authority**, enabling systems to remain compliant without embedding legal or procedural logic.
