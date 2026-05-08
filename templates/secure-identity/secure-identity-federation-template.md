# Secure Identity Federation
SSPP Template Companion
secure-identity-federation
**SSPP Template Companion README**
**Scope:** Identity federation and assertion trust  
**Applies to:** Microsoft Entra ID SSO, Shibboleth, ADFS, Hybrid Federated Identity Fabrics

---

## Purpose

The **Secure Identity Federation SSPP Template** defines the **institutional assurance requirements for identity federation**—the mechanisms by which identity assertions are created, exchanged, and trusted **across systems, providers, and security domains**.

This SSPP answers the question:

> *Can identity assertions be safely transferred and relied upon across trust boundaries without degrading identity assurance?*

It is intentionally **vendor-neutral** and **protocol-agnostic**, covering modern and legacy federation mechanisms alike.

---

## Why “Secure Identity Federation”

This SSPP replaces the earlier **`entra-id-sso`** naming to reflect its true scope.

- **SSO** describes a *user experience*
- **Federation** describes a *trust fabric*

This SSPP governs federation, not just sign‑in flows.

By renaming to **Secure Identity Federation**, the template correctly includes:

- Microsoft Entra ID (OIDC / OAuth2)
- Active Directory Federation Services (WS‑Fed / SAML)
- Shibboleth (SAML)
- Hybrid and chained identity providers
- Claims transformation and assertion propagation

---

## What This Template Governs

The Secure Identity Federation SSPP governs **how identity trust moves**, including:

### Federation Trust Boundaries
- Establishment of trust relationships between identity providers
- Protection of trust anchors and signing keys
- Explicit understanding of upstream and downstream dependencies

### Assertion Integrity
- Protection against token replay, forgery, and tampering
- Assurance preservation across hops
- Resistance to authentication downgrade during federation

### Assurance Continuity
- Preservation of MFA and identity confidence across boundaries
- Explicit prohibition of silent assurance downgrades
- Handling of mixed‑assurance identity providers

### Claims & Attribute Handling
- Minimization of claims to required scope
- Protection of sensitive attributes
- Prevention of over‑sharing or unintended disclosure

### Federation Availability & Resilience
- Understanding blast radius of upstream IdP outages
- Safe failure modes
- Explicit dependencies on external identity infrastructure

---

## What This Template Does *Not* Govern

This SSPP intentionally does **not** cover:

| Topic | Governed By |
|----|----|
Identity provider control quality | **secure‑identity‑provider** SSPP |
Authentication method strength | **secure‑identity‑provider** SSPP |
SSO policy design / Conditional Access | IdP‑specific SSPPs |
Lifecycle provisioning / DRP | Identity Governance (IGA) SSPPs |
Cloud residency / sovereignty | **trusted‑cloud** SSPPs |
Application authorization | Application SSPPs |

This separation prevents control overlap and audit confusion.

---

## Relationship to Other Identity Artifacts

The Secure Identity Federation SSPP sits **between identity providers and applications**: