# Secure Survey Architecture — README

## Purpose

**Secure Survey** defines how institutional survey capabilities are designed, governed, and consumed so that **data collection does not become implicit surveillance, coercion, or unbounded data aggregation**.

Surveys are treated as a **first‑class security, privacy, and ethics domain**, recognizing that every survey represents an explicit or implicit **promise to participants** about:
- purpose,
- consent,
- identity handling,
- anonymity,
- and data protection.

Secure Survey exists to ensure those promises are **explicit, enforceable, auditable, and consistent** across the institution.

---

## Scope

The Secure Survey architecture governs:

- research surveys,
- administrative and service feedback surveys,
- instructional and assessment surveys,
- internal and external respondent populations,
- survey lifecycle from design to data retirement.

It deliberately **does not** govern:
- analytics or reporting platforms,
- experimental instrumentation,
- marketing or persuasion systems,
- systems of record.

Those concerns are handled elsewhere.

---

## Core Design Principles

### 1. Surveys Are Promises
A survey is not just a form — it is a commitment to participants about how their input will be handled.

### 2. Consent Is Architectural
Consent and ethics are not UI features; they are **enforced system properties**.

### 3. Identity Is Explicitly Declared
Whether a survey is anonymous, pseudonymous, or identifiable must be:
- declared before participation,
- enforced throughout execution,
- honored after collection.

### 4. Purpose Is Binding
Survey data must not be reused, re‑identified, or retained beyond its stated purpose without explicit approval.

### 5. Distribution ≠ Governance
Email, web, and application delivery mechanisms **do not govern surveys**; they merely deliver invitations under Secure Survey constraints.

---

## Secure Survey Pattern Structure

Secure Survey is decomposed into **one composite governance pattern**, **one foundational trust pattern**, and **orthogonal constraint patterns**.

### Composite Pattern
- **`secure-survey`**  
  Governs *why* surveys are treated as a security and privacy domain.

### Foundational Trust Pattern
- **`survey-core`**  
  Defines non‑negotiable survey invariants:
  - authority and stated purpose
  - response integrity
  - eligibility enforcement

### Constraint / Aspect Patterns
- **`survey-consent-and-ethics`**  
  Ethical commitments, informed consent, voluntariness.
- **`survey-identity-and-anonymity`**  
  Identity exposure models and re‑identification prevention.
- **`survey-data-protection`**  
  Retention, access, protection, and post‑collection governance.

Each pattern addresses a distinct dimension of survey risk without entangling responsibilities.

---

## SSPP Stack (Survey)

Secure Survey assurance is delivered through a layered SSPP stack:

1. **Secure Survey Platform SSPP**  
   Primary governance and assurance anchor

2. **External / Research Survey SSPP**  
   Heightened constraints for external respondents and human‑participant research

3. **Secure Survey Relying System SSPP**  
   Template for systems that embed or trigger surveys (LMS, research platforms, admin systems)

This mirrors the SSPP structure used across Secure Identity, Secure Network, Secure Email, and Secure Collaboration.

---

## Application Integration

Applications **do not implement survey ethics or privacy controls themselves**.  
They rely on Secure Survey and add **context‑specific constraints**.

The authoritative integration guidance is documented in:

➡ **./MAPPING.md** — *Secure Survey → Application Integration*  

That document explains:
- how LMS, research, and administrative systems use surveys,
- what constraints must be added at the application SSPP level,
- what responsibilities remain with Secure Survey vs the application.

---

## Email Integration

Survey invitations and notifications integrate with **Secure Email** as:

- **Application Send‑Only Email**
- Never as campaigns
- Never as human mailboxes
- Never as emergency channels

**Key distinction**
- Secure Email ensures **delivery integrity**
- Secure Survey ensures **ethical participation and privacy integrity**

---

## Standards Alignment

Secure Survey is aligned at an **architectural level** with:

- NIST SP 800‑53 (security & privacy control lineage)
- NIST SP 800‑47 (external trust boundaries)
- NIST SP 800‑184 (availability during disruption)
- NIST Privacy Framework (ethical and privacy governance)

ATT&CK and D3FEND are used to justify Secure Survey as a domain, not to prescribe survey content or methodology.

---

## What Secure Survey Is *Not*

Secure Survey is not:
- a research ethics board,
- a statistical analysis platform,
- a monitoring system,
- a campaign or persuasion engine.

Those responsibilities remain explicitly outside this architecture.

---

## Architectural Invariant

> **Secure Survey provides ethical, privacy, and identity trust.  
> Applications provide context and purpose.  
> Neither replaces the other.**

---

## Status

✅ Secure Survey patterns complete  
✅ Threat modeling complete  
✅ SSPP stack complete  
✅ Application integration mapped  

Secure Survey is now **architecturally mature, auditable, and safe to embed institution‑wide**.

---