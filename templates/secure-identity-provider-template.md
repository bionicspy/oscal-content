# Secure Identity Provider
**SSPP Template Companion **`secure-identity-provider` SSPP template**:**SSPP Template Companion README**

- **Asserts** the secure‑identity pattern at the provider level
- **Decomposes** that assertion into constituent identity patterns
- Enables assessors to ask:
  > *Does this provider meet, fail, or compensate for each identity pattern?*

This separation ensures:
- Clear semantics
- Auditable traceability
- No ambiguity between *requirements* and *assurance claims*

---

## Identity Patterns Referenced

This SSPP template explicitly references the following identity patterns to establish meaning and traceability:

- **identity-core**
- **identity-authentication**
- **identity-authorization**
- **identity-lifecycle**
- **identity-federation**
- **identity-assurance**
- **identity-logging-and-audit**
- **identity-privileged-access**
- **identity-non-human**
- **identity-device-binding**
- **secure-identity** (composite)

Each SSPP **instance** must demonstrate how the provider satisfies or compensates for each referenced pattern.

---

## Scope of Assurance

The secure‑identity‑provider SSPP governs **identity assurance outcomes**, including:

### Authentication & Credentials
- Mandatory MFA for interactive users
- Strong password policies where passwords exist
- Protection against password reuse and breached credentials

### Session Security
- Limits on session persistence
- Protection against replay, token theft, and misuse
- Explicit treatment of “remember me” / persistent sessions

### Identity Protection & Monitoring
- Continuous evaluation of identity risk signals
- Detection of anomalous behavior and potential compromise
- Automated and manual response to identity threats

### Federation Integrity
- Protection of federated assertions against downgrade or replay
- Management of upstream trust dependencies
- Assurance preservation across boundaries

### Privileged Identity Safeguards
- Restriction of local or native privileged accounts
- Break‑glass access controls
- Separation of duties and monitoring

### Logging & Evidence
- Generation and retention of identity‑relevant logs
- Audit‑grade evidence for investigations and compliance

---

## Technologies Covered

This template is deliberately **technology‑agnostic** and may be instantiated for:

- **On‑premises Active Directory**
- **Microsoft Entra ID (cloud)**
- **Hybrid AD + Entra ID**
- **Future sovereign or third‑party IdPs**

The same assurance bar applies to all providers; differences emerge through **SSPP instances and SARs**, not by changing the template.

---

## Assessment Semantics

Findings derived from this SSPP follow consistent rules:

### 🔴 Red (Severe Assurance Failure)
- MFA bypass or absence
- Persistent sessions that undermine assurance (e.g., KMSI)
- Lack of breached‑password protection
- Silent downgrade of assurance during failure

### 🟡 Amber (Governance / Transitional Risk)
- Custom or non‑native MFA overlays
- Federation dependency risks
- Limited identity risk detection
- Known gaps with defined remediation plans

### 🟢 Green
- Provider meets identity assurance expectations as asserted

---

## Composition with Other SSPPs

This SSPP is designed to compose cleanly with:

- **trusted-cloud** — platform trust, residency, sovereignty
- **entra-id-sso** — SSO mechanics and conditional access
- **application SSPPs** — authorization and business logic
- **IGA SSPPs** (future) — provisioning, deprovisioning, DRP

Each SSPP answers a **different question**, avoiding overlap and control sprawl.

---

## Usage Guidance

When using this template:

1. Create a **secure‑identity‑provider SSPP instance** for each IdP
2. Declare provider‑specific facts and integrations
3. Assess conformance against referenced identity patterns
4. Generate SARs for any assurance gaps discovered
5. Do **not** duplicate cloud trust or lifecycle logic here

---

## Summary

The **Secure Identity Provider SSPP Template** establishes a **single, defensible assurance baseline** for evaluating identity providers.

It ensures that:
- Identity assertions are trustworthy
- Credentials and sessions are protected
- Identity threats are detected and managed
- Federation and privilege do not erode assurance
- Identity remains secure even under failure

This template is foundational to a mature, layered identity governance program.

**SSPP Template:** `secure-identity-provider`  
**Scope:** Identity Provider (IdP) assurance  
**Applies to:** On‑premises Active Directory, Microsoft Entra ID, Hybrid IdPs

---

## Purpose

The **Secure Identity Provider SSPP Template** defines the **institutional assurance requirements** that an **identity provider (IdP)** must satisfy to be trusted as the source of identity assertions.

This SSPP answers the question:

> *Can this identity provider correctly, continuously, and securely assert who someone is — even under attack, misuse, or failure scenarios?*

It is **provider‑centric**, not application‑centric, and is explicitly distinct from the **`secure-identity` pattern**, which defines *what secure identity means* at a conceptual and control level.

---

## What This Template Is (and Is Not)

### ✅ This template **is**
- A **normative assurance baseline** for identity providers
- A way to **evaluate IdPs consistently**, regardless of technology
- A mechanism to **assert or reject trust** in an IdP’s identity claims
- A bridge between **identity patterns** and **assessment artifacts (SARs)**

### ❌ This template **is not**
- A replacement for the `secure-identity` pattern
- A cloud‑trust or data‑residency assessment (see `trusted-cloud`)
- An identity provisioning or lifecycle design (see IGA SSPPs)
- An application authorization model
- Vendor‑specific configuration guidance

---

## Relationship to the Secure Identity Pattern

The **`secure-identity` pattern** defines the *required characteristics* of secure identity (authentication strength, assurance, federation, logging, etc.).
