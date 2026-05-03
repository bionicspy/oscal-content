# Data Retention
**Pattern URI:** `urn:utoronto:security:pattern:data-retention`

## Purpose

The **data-retention** pattern defines obligations related to the **retention, preservation, and defensible disposition** of institutional data and records.

This pattern asserts that data persists according to **externally defined retention schedules** and that disposition decisions are governed outside the system itself.

---

## Scope

This pattern applies to systems that:

- Store institutional data or records
- Generate audit logs or historical artifacts
- Retain data beyond immediate operational use

---

## Normative Assertions

A system asserting **data-retention** guarantees that:

1. Data is retained according to **institutionally approved retention schedules**.
2. Retention duration and disposition are **not decided locally** by system operators.
3. Legal holds and preservation requirements are honored when applicable.
4. Disposition actions are **defensible, auditable, and authorized**.

---

## Out of Scope

This pattern does not define:

- Specific retention periods
- Storage technologies
- Backup or recovery mechanisms
- Disclosure processes (see `records-disclosure`)

---

## Relationship to Other Patterns

This pattern is commonly composed with:

- `trusted-data`
- `records-disclosure`
- `regulated-digital-service`

---

## Summary

The **data-retention** pattern ensures that systems participate correctly in institutional information lifecycle governance without becoming policy authorities themselves.