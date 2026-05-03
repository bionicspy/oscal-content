# Entra ID Single Sign-On (SSO)
**SSPP Template Companion README**

**SSPP Template:** `entra-id-sso`  
**Identity Provider:** Microsoft Entra ID  
**Primary Focus:** Authentication and coarse‑grained access control  
**Out of Scope:** Identity lifecycle governance (IGA)

---

## Purpose

The **Entra ID SSO SSPP Template** defines the **institutional baseline for authentication, session assurance, and access gating** using Microsoft Entra ID.

This SSPP establishes **what must be true** for:
- centralized authentication,
- multi‑factor enforcement,
- conditional access,
- coarse‑grained access control,
- and identity logging.

It is intentionally narrow in scope and **does not attempt to govern the full identity lifecycle or fine‑grained application permissions**.

---

## Scope

This SSPP applies to:

- All applications and platforms that authenticate users via Entra ID
- Interactive access to:
  - SaaS platforms
  - Web applications
  - Administrative portals
- Coarse‑grained access control:
  - determining **who may access a service at all**

This SSPP explicitly **does not cover**:

- Joiner / mover / leaver processes
- Authoritative data sources (e.g., HRIS, SIS)
- Identity provisioning or entitlement workflows
- Fine‑grained application roles and permissions

Those concerns belong to **Identity Governance & Administration (IGA)** and are addressed in separate SSPPs (e.g., SailPoint or equivalent).

---

## Trust Boundary and Responsibility Model

### Authoritative Identity Provider

**Microsoft Entra ID** is the **authoritative identity provider** for:

- user authentication,
- session establishment,
- conditional access evaluation,
- enforcement of MFA and login restrictions.

Applications relying on this SSPP consume Entra ID assertions; they **do not independently authenticate users**.

---

### Governance Model

Authentication and access control are **centrally governed**:

- MFA and Conditional Access policies are defined institution‑wide
- Applications may not bypass or relax these controls
- Delegation of identity controls is limited and explicitly approved

This ensures consistent identity assurance across all services.

---

## Authorization Model (Critical Clarification)

This SSPP intentionally distinguishes **two layers of authorization**.

### 1. Coarse‑Grained Authorization (**Required**)

Entra ID enforces **coarse‑grained access control**, meaning:

- Only authorized users may access a service at all
- Access is gated via:
  - Entra ID enterprise application assignments
  - Entra ID security groups or identities

This prevents:
- wide‑open tenant access,
- unmanaged user sprawl,
- unauthorized login.

Failure to enforce coarse‑grained access at the Entra ID level is an **identity control failure** and typically results in a **Red (high‑severity) finding**.

---

### 2. Fine‑Grained Authorization (**Recommended**)

Fine‑grained authorization (e.g., application roles such as *Author*, *Admin*, *Manager*) may be:

- enforced using Entra ID group mappings **where feasible**, or
- enforced internally by the application or service.

Using Entra ID groups for fine‑grained roles is **preferred** because it:
- improves role visibility,
- enables centralized access reviews,
- supports timely de‑provisioning.

However, **service‑internal role models are permitted** provided that:

- Entra ID continues to enforce coarse‑grained access to the service, and
- the residual risk is managed through governance controls.

Lack of Entra‑based fine‑grained authorization is treated as a **governance and access‑lifecycle issue**, not an SSO or authentication failure.

---

## Identity Lifecycle (Explicitly Out of Scope)

Identity lifecycle management — including:

- joiner, mover, and leaver events,
- authoritative source systems,
- entitlement provisioning and removal,

is **not governed by this SSPP**.

These functions belong to **IGA** and are addressed in separate SSPPs.

The Entra ID SSO SSPP assumes that:
- identities presented to Entra ID already exist,
- lifecycle correctness is enforced elsewhere.

---

## Authentication Expectations

All SSPP instances inheriting this template MUST ensure:

- **Single Sign‑On** via Entra ID for all interactive users
- **No local application passwords** unless explicitly approved
- Use of **modern authentication protocols** (OIDC, OAuth 2.0, SAML 2.0)
- **Multi‑Factor Authentication** enforced via Entra ID
- **Conditional Access** policies applied and not bypassed

---

## Logging and Monitoring

The following events MUST be logged and centrally monitored:

- authentication attempts,
- MFA challenges and failures,
- conditional access decisions,
- risky sign‑in indicators.

Identity events are forwarded to the **institutional SIEM** for:
- investigation,
- compliance verification,
- correlation with other security telemetry.

---

## Assessment and Findings

Assessment outcomes follow clear semantics:

### Red (High Severity)
- Entra ID SSO bypassed
- Service accessible without Entra ID gating
- MFA or Conditional Access disabled
- Unauthorized users able to authenticate

### Amber (Moderate Severity)
- Fine‑grained roles enforced only within the service
- Lack of centralized role enumeration or attestation
- Delayed role removal risk after access revocation

These Amber findings reflect **governance and lifecycle challenges**, not authentication weaknesses.

---

## SSPP Instance Usage Guidance

When creating an SSPP instance that inherits from this template:

1. Reference this SSPP template
2. Declare:
   - authentication protocol (OIDC/SAML),
   - how Entra ID gates access to the service,
   - whether local credentials are disabled
3. Document:
   - whether fine‑grained authorization is Entra‑based or service‑internal

Do **not** restate MFA, Conditional Access, or identity lifecycle rules.

---

## Relationship to Other SSPPs

This SSPP typically composes with:

- **Application SSPPs** (e.g., Envoke, portals)  
  → document fine‑grained roles and authorization

- **IGA SSPPs** (future)  
  → govern provisioning, entitlements, and lifecycle assurance

- **DNS and email SSPPs**  
  → secure sender identity and communications trust

---

## Summary

The **Entra ID SSO SSPP Template** defines the institution’s **non‑negotiable identity trust baseline**:

- centralized authentication,
- enforced MFA,
- conditional access,
- coarse‑grained access gating,
- auditable identity events.

It intentionally separates **identity assurance** from **application authorization** and **identity governance**, enabling scalable, accurate, and fair assessments across diverse services.
