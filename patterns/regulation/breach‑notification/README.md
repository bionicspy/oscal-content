# Mandatory Breach Notification
**Pattern URI:** `urn:utoronto:security:pattern:mandatory-breach-notification`

## Purpose

The **mandatory-breach-notification** pattern defines obligations related to the **notification of regulators, affected individuals, and other parties** following a security or privacy breach, as required by law or institutional policy.

This pattern asserts that breach notification is a **regulatory and governance obligation**, distinct from incident response, record disclosure, or communications strategy, and that such obligations are **non-optional and assessable**.

The pattern does **not** define timelines, notification thresholds, message content, or incident handling procedures.

---

## Scope

This pattern applies to systems that:

- Process personal, sensitive, or regulated data
- Could experience security or privacy incidents triggering statutory notification duties
- Participate in institutional breach response and reporting processes
- Generate records or evidence related to breach determination and notification

---

## Out of Scope

This pattern explicitly does **not** define:

- Incident detection or technical response procedures
- Risk scoring or threshold calculation (e.g., “real risk of significant harm”)
- Notification timelines (e.g., 72-hour requirements)
- Message templates or notification workflows
- Legal interpretation of breach notification statutes

Those elements are governed by authoritative privacy, legal, and incident response functions.

---

## Normative Assertions

A system asserting **mandatory-breach-notification** guarantees that:

1. **Breach Notification Obligations Are Recognized**  
   The system acknowledges that security and privacy breaches may trigger mandatory notification duties.

2. **Notification Authority Is External**  
   Determinations regarding whether notification is required, who must be notified, and what is disclosed are made by authorized institutional functions (e.g., Privacy Office, Legal Counsel).

3. **Multi-Party Notification Is Supported**  
   Notification obligations may apply to regulators, affected individuals, and other parties as required by applicable law.

4. **Notification Activity Is Auditable**  
   Evidence of breach determination decisions and notifications issued is retained for accountability and regulatory review.

5. **Regulatory Change Is Monitored**  
   Emerging and evolving legislation affecting breach notification obligations is tracked and assessed for impact.

---

## Authoritative References

This pattern relies on external authoritative sources, including but not limited to:

- **Office of the Privacy Commissioner of Canada (OPC)**  
  Guidance on breach notification obligations under PIPEDA.

- **Digital Charter Implementation Act, 2022 (Bill C‑27)**  
  Proposed legislative changes strengthening privacy obligations and breach notification requirements.

These sources are referenced for authority, not duplicated or interpreted within the pattern.

---

## Relationship to Other Patterns

This pattern is **complementary**, not substitutive.

Common compositions include:

- `regulated-digital-service`  
  Establishes that regulatory obligations apply to the system.

- `records-disclosure`  
  Governs disclosure of records after or during breach investigations.

- `data-retention`  
  Governs retention of breach records and notification evidence.

- `public-communications`  
  Governs institutional authority and controls for outward-facing communications.

- Incident response and detection patterns (where defined)

---

## SSPP Integration Guidance (Normative)

In a System Security and Privacy Plan (SSPP), a system asserting this pattern MUST:

- Reference this pattern as a **regulatory obligation**
- Avoid embedding breach notification timelines or legal interpretation
- Declare any jurisdictional scope constraints, if applicable

Example SSPP assertion:

> “This system is subject to statutory breach notification obligations and inherits the mandatory-breach-notification pattern.”

---

## Assessment Considerations (Informative)

Assessment of this pattern may include:

- Confirmation that breach notification obligations are formally recognized
- Evidence of governance processes for breach determination
- Review of retained breach notification records
- Verification that regulatory changes are monitored

Assessment outcomes may result in risk statements or POA&Ms but do not require system-level procedural implementations.

---

## Pattern Stability

- **Intended durability:** Long-lived  
- **Expected change frequency:** Low  
- **Change drivers:** Legislative or regulatory updates

This pattern is designed to remain stable as notification laws evolve.

---

## Summary

The **mandatory-breach-notification** pattern establishes a clear, enforceable boundary for **statutory breach notification obligations**.

It enables SSPPs to remain architectural and compositional while ensuring that breach notification duties are **explicit, governed, auditable, and aligned with external authority**.