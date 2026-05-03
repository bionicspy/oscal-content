# Regulated Digital Service
**Pattern URI:** `urn:utoronto:security:pattern:regulated-digital-service`

## Purpose

The **regulated-digital-service** pattern defines trust and compliance obligations that apply to **public-facing or user-interacting digital services** due to **external regulation or institutional policy**, independent of security controls.

This pattern asserts that a system is subject to **mandatory non-security requirements** (e.g., accessibility, branding, notices, mandated disclosures) and that those requirements are **in scope for assurance**, even when satisfied outside traditional security tooling.

This pattern does **not** specify design, implementation, or legal interpretation details. It provides a **normative compliance boundary** that systems inherit.

---

## Scope

This pattern applies to systems that:

- Present interfaces to users (web, email, mobile, or API-mediated communications)
- Generate or distribute official institutional communications
- Are subject to legislative, regulatory, or policy-driven obligations beyond security controls

The pattern is **technology-agnostic** and may apply to SaaS platforms, internally developed systems, or hybrid services.

---

## Out of Scope

This pattern explicitly does **not** define:

- Visual design standards or brand assets
- UX or UI implementation details
- Specific WCAG criteria or testing procedures
- Legal interpretations of statutes or policy
- Security controls covered by other patterns

Those elements are owned by authoritative policy, legal, and design bodies and are referenced, not duplicated.

---

## Normative Assertions

A system asserting **regulated-digital-service** guarantees the following:

### 1. Regulatory Applicability Declaration
The system acknowledges that it is subject to **externally imposed obligations** (legislative, regulatory, or institutional) that govern how digital services are delivered and represented.

### 2. Accessibility Compliance Obligation
The system is obligated to conform to **applicable accessibility legislation and standards** for digital services, as defined by authoritative institutional policy.

Accessibility obligations are **non-optional** and apply regardless of delivery channel (web, email, application).

### 3. Institutional Branding and Communications Standards
The system adheres to **institutional branding, identity, and official communications requirements**, including required notices, disclaimers, and representations.

### 4. Jurisdictional and Disclosure Requirements
Where applicable, the system satisfies **jurisdiction-specific disclosure, language, or notification obligations** associated with regulated digital communications.

### 5. Assessability
Compliance with this pattern is **assessable** through policy alignment, governance artifacts, and institutional attestations, even where no direct technical control exists.

---

## Relationship to Other Patterns

This pattern is **complementary**, not substitutive.

Common compositions include:

- `secure-identity`  
  Identity authenticity for regulated interactions

- `secure-endpoint`  
  Trusted administrative access to regulated systems

- `secure-sdlc`  
  Governance of how regulated capabilities are built and changed

- `trusted-cloud`  
  Assurance that regulated obligations are met on approved platforms

The **regulated-digital-service** pattern defines *what obligations apply*, while other patterns define *how trust is technically established*.

---

## SSPP Integration Guidance (Normative)

In a System Security and Privacy Plan (SSPP), a system asserting this pattern MUST:

- Reference this pattern as a **trust dependency**
- Avoid embedding detailed legal or design requirements
- Declare any system-specific scope limitations or exclusions, if present

Example SSPP assertion:

> “This system is subject to institutional regulatory obligations for digital service delivery and inherits the regulated-digital-service trust pattern.”

---

## Assessment Considerations (Informative)

Assessment of this pattern may include, but is not limited to:

- Confirmation of applicable institutional policies
- Evidence of accessibility and communications governance
- Review of approved attestations or certifications
- Verification that regulated obligations are acknowledged and tracked

Assessment outcomes may result in **risk statements or POA&Ms** but do not require local control implementations.

---

## Pattern Stability

- **Intended durability:** Long-lived  
- **Expected change frequency:** Low  
- **Change drivers:** New legislation, institutional policy changes

This pattern is designed to remain stable even as individual regulations evolve.

---

## Summary

The **regulated-digital-service** pattern establishes a clear, enforceable boundary for **non-security regulatory trust** in digital services.

It allows SSPPs to remain architectural and compositional while ensuring that accessibility, branding, disclosure, and similar obligations are **explicit, inherited, and assessable**.