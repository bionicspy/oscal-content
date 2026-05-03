# Cross-Border Data Transfer
**Pattern URI:** `urn:utoronto:security:pattern:cross-border-transfer`

## Purpose

The **cross-border-transfer** pattern defines obligations related to the **movement of data across national or jurisdictional boundaries**.

This pattern asserts that cross-border data transfer is subject to **external regulatory and policy controls** and must be explicitly governed and approved.

---

## Scope

This pattern applies to systems that:

- Store or process data outside the home jurisdiction
- Use third-party services in foreign regions
- Replicate, back up, or transmit data internationally

---

## Normative Assertions

A system asserting **cross-border-transfer** guarantees that:

1. Data residency and transfer constraints are **explicitly recognized**.
2. Cross-border transfers occur only with **institutional approval**.
3. Jurisdictional risks and obligations are **documented and assessable**.
4. Unauthorized cross-border data movement is **prohibited**.

---

## Out of Scope

This pattern does not define:

- Legal interpretations of jurisdictional law
- Encryption or transport mechanisms
- Data classification rules (see `trusted-data`)

---

## Relationship to Other Patterns

This pattern is commonly composed with:

- `trusted-cloud`
- `trusted-data`
- `regulated-digital-service`

---

## Summary

The **cross-border-transfer** pattern ensures that jurisdictional obligations are visible and governable without embedding regulatory logic inside systems.