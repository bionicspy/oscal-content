# DNS Secure Email
**SSPP Template Companion README**

**Pattern / SSPP:** `dns-secure-email`  
**Related Patterns:**  
- `secure-email`  
- `email-bulk-messaging-gateway`  
- `email-notification-gateway`  
- `dns-secure-pki`  

---

## Purpose

The **DNS Secure Email SSPP Template** defines the **institutional governance, security, and assurance expectations** for DNS‑based email security across all domains owned, operated, or represented by the University.

This SSPP establishes **what must be true** for email identity, authentication, and transport security, independent of specific platforms or vendors. It is intentionally **normative and non‑technical**, enabling consistent reuse across mailbox services, campaign platforms, and notification gateways.

---

## Scope

This SSPP applies to:

- **All apex domains and subdomains** owned or operated by the University
- **Email‑sending domains** (mailboxes, campaigns, notifications)
- **Non‑sending domains**, which must still publish protective DNS records
- **Central and delegated email services**, under formal governance

This SSPP **does not** define:
- DNS record syntax or examples
- Vendor‑specific configuration steps
- Email platform UI or operational procedures

Those details belong in **platform SSPPs** or operational runbooks.

---

## Governance & Ownership Model

### Institutional Owner
**Branding and Communications**

- Owns institutional email identity and sender reputation
- Approves sender domains and SPF delegation
- Ensures alignment with institutional brand and external representation

### Technical Owner
**Information Security**

- Defines security posture and enforcement standards
- Monitors authentication and transport reports
- Assesses risk and drives remediation through SARs and POA&Ms

### Governance Model
**Centrally governed with limited, controlled delegation**

- Central authority defines policy and posture
- Delegation is:
  - explicit,
  - approved,
  - auditable,
  - revocable
- No uncontrolled or implicit delegation is permitted

---

## Normative Security Expectations

### Domain Coverage
- All domains **must participate** in DNS Secure Email governance
- Non‑sending domains must publish DMARC to prevent spoofing
- Subdomains may not weaken parent domain posture without approval

---

### DMARC
- DMARC is **mandatory**
- Sending domains must enforce **strict DMARC**
- Unauthorized senders **must not pass**
- Aggregate reporting (**rua**) must be enabled and monitored

DMARC failures on sending domains typically result in **high‑severity findings**.

---

### SPF
- SPF is **centrally governed**
- Limited delegation is permitted **only to the institutional email team**
- All SPF inclusions require:
  - documented ownership
  - lifecycle management
  - branding and communications approval

SPF sprawl or unmanaged entries are treated as **governance findings**.

---

### DKIM
- DKIM is required for **all institutional senders**
- Standards for key strength, selector lifecycle, and rotation are centrally defined
- Platform‑specific selectors are permitted under governance controls

---

### Transport Security
- Email transport security is **in scope**
- **MTA‑STS must be enabled**
- **TLS reporting (TLS‑RPT) must be enabled and monitored**

Transport downgrade risks are considered security‑relevant and assessable.

---

## Pattern Composition

This SSPP is **not used in isolation**. Instead, it composes with:

- **`secure-email`**  
  Governs mailbox platforms (e.g., Exchange Online)

- **`email-bulk-messaging-gateway`**  
  Governs campaign and marketing platforms (e.g., Envoke)

- **`email-notification-gateway`**  
  Governs transactional or system‑generated email  
  Requires **dedicated sending subdomains**

- **`dns-secure-pki`**  
  Governs DNS‑based PKI controls (e.g., CAA records)

Email SSPP instances link to this SSPP to assert **inheritance of DNS Secure Email guarantees**.

---

## Workforce Accountability (NIST NICE Alignment)

The SSPP aligns accountability to the **NIST NICE Cybersecurity Workforce Framework** to clarify responsibility without binding to individual roles or org charts.

Key aligned roles include:

- **SP‑PLN‑001 – Cybersecurity Policy and Strategy Planner**  
  Defines DNS Secure Email posture and governance rules

- **SP‑ARC‑001 – Enterprise Architect**  
  Ensures consistency across email platforms and patterns

- **OM‑NET‑001 – Infrastructure Support Specialist**  
  Executes approved DNS and email security changes

- **PR‑CY‑001 – Systems Security Analyst**  
  Validates enforcement of required controls

- **PR‑CDA‑001 – Cyber Defense Analyst**  
  Monitors DMARC and transport reports

- **SP‑RSK‑001 – Security Control Assessor**  
  Performs assessments and issues findings

A non‑technical **Email Identity and Branding Governance** role ensures institutional reputation and sender legitimacy.

---

## Assessment & Findings

Assessment outcomes commonly include:

- **Red findings**
  - Sending domain without DMARC
  - DMARC not enforced on campaign domains
  - Unauthorized senders passing authentication

- **Amber findings**
  - DMARC present but reporting not monitored
  - SPF lifecycle gaps
  - Missing MTA‑STS or TLS‑RPT

Findings are documented in **OSCAL SARs** and tracked via **POA&Ms**.

---

## Future Capabilities

The following are tracked for future adoption and are **not mandatory** at present:

- **BIMI** (Brand Indicators for Message Identification)
- **ARC** (Authenticated Received Chain)
- **DANE** (DNS‑Based Authentication of Named Entities)

These capabilities may be introduced once prerequisites such as consistent DMARC enforcement, DNSSEC maturity, and ecosystem readiness are met.

---

## SSPP Usage Guidance

When instantiating this SSPP:

1. **Reference this template**
2. Declare:
   - which domain(s) are used for sending
   - whether the domain inherits central policy or has approved delegation
3. Link to:
   - the relevant email platform SSPP(s)
   - applicable application SSPPs
4. Document data exchange and governance approvals

**Do not restate DNS rules or standards in instance SSPPs.**

---

## Summary

The **DNS Secure Email SSPP Template** establishes a **single, authoritative contract** for institutional email trust at the DNS layer.

It ensures:
- consistent sender authentication,
- protected non‑sending domains,
- secure transport,
- auditable governance,
- clear accountability.

This SSPP enables scalable assurance across mailbox, campaign, and notification email while remaining flexible, composable, and future‑ready.