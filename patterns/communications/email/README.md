# Secure Email Architecture — README
Secure Email **authoritative access models**, and **defensible governance** for all institutional email use cases: human mailboxes, shared and role‑based access, application email (send‑only and bi‑directional), campaigns, collaboration lists, and emergency notifications.

The design emphasizes:
- **One human authentication boundary**
- **Explicit, auditable delegation for non‑personal mailboxes**
- **Purpose‑driven segmentation** (no “one mailbox fits all”)
- **Least privilege, lifecycle governance, and auditability**
- **Selective cyber‑resiliency framing (NIST SP 800‑184) only where warranted**

---

## Architecture at a Glance

```
Secure Email Platform (Tier‑0)
├── Human Email
│   ├── Individual Email
│   ├── Delegated Send‑As / Send‑On‑Behalf (authority transfer)
│   │   ├── Shared Mailboxes
│   │   └── Role‑Based Mailboxes
│   └── External Partner Mailboxes (delegation‑only, cross‑boundary)
├── Application Email
│   ├── Email Application Notification (Send‑Only)
│   └── Email Application Bi‑Directional (Automated Ingress/Egress)
├── Broadcast & Collaboration
│   ├── Distribution Groups (internal broadcast)
│   └── Listserv / Discussion Lists (opt‑in collaboration)
└── Emergency Notification System (Email • SMS • Voice)
```


---

## Core Invariants (Non‑Negotiable)

1. **Single Human Authentication Boundary**  
   Humans authenticate **only** to *Individual Email*.

2. **Delegation‑Only Access to Non‑Personal Mailboxes**  
   Shared, role‑based, and partner mailboxes **do not allow direct login**.  
   All interaction occurs via **Delegated Send‑As / Send‑On‑Behalf**, which is:
   - Explicitly approved
   - Time‑bounded
   - Least privilege
   - Dual‑attributed (actor + represented identity)

3. **Purpose‑Constrained Services**  
   Each SSPP defines *what the service is for* and *what it is not for* (e.g., no bulk on individual mailboxes; no replies on notifications).

4. **Separation of Concerns**  
   - Notification ≠ Campaign ≠ Collaboration ≠ Conversation
   - Emergency ≠ Routine broadcast

5. **Auditability Everywhere**  
   Every message is attributable to a **human actor**, **application identity**, or **authorized authority**, as appropriate.

---

## Patterns Used

- **email-core** — baseline delivery, identity binding, accountability  
- **email-identity** — sender identity and impersonation resistance  
- **email-threat-protection** — malicious content detection/response  
- **email-data-protection** — misuse and leakage prevention  
- **email-records** — retention, legal hold, eDiscovery  
- **email-notification-gateway** — send‑only application notifications  
- **email-collaboration-gateway** — email‑based workflows/collaboration  
- **dns-secure-email** — SPF/DKIM/DMARC enforcement and isolation

---

## System Security & Privacy Plans (SSPPs)

### Platform & Special‑Purpose
- **Secure Email Platform SSPP** — Tier‑0 enabling service  
- **Email Campaign Platform SSPP** — regulated, high‑volume outbound  
- **Emergency Notification System SSPP** — life‑safety, multi‑channel

### Human‑Centric
- **Individual Email SSPP** — human baseline (intent, lifecycle, disclosure)  
- **Shared Mailbox SSPP** — functional mailboxes (delegation‑only)  
- **Role‑Based Mailbox SSPP** — authority bound to roles/offices  
- **Delegated Send‑As / Send‑On‑Behalf SSPP** — sole authority transfer  
- **External Partner Mailbox SSPP** — cross‑boundary, contractual, delegated

### Application
- **Email Application Notification SSPP** — send‑only, no‑reply  
  - Dedicated subdomain, strict DMARC
  - Institutional recipients only
- **Email Application Bi‑Directional SSPP** — automated receive/send  
  - Defensive parsing; no human login or delegation

### Broadcast & Collaboration
- **Distribution Group SSPP** — internal broadcast only  
  - Students/Staff/Faculty/Librarians/Affiliates; no external members  
- **Listserv / Discussion List SSPP** — opt‑in collaboration  
  - Invitation‑based membership, timely opt‑out
  - Periodic membership review and attestation

---

## Cyber Resiliency (NIST SP 800‑184)

SP 800‑184 is referenced **only where survivability and recovery are explicit obligations**:
- **Secure Email Platform SSPP** (primary anchor)
- **Emergency Notification System SSPP** (required)
- **Email Campaign Platform SSPP** (optional, abuse‑at‑scale framing)
- **Email Application Notification SSPP** (contextual, if operationally critical)

It is **intentionally excluded** from individual, shared, role‑based, delegation, partner, distribution, and listserv SSPPs to avoid dilution.

---

## DNS & Identity Posture

- **Dedicated subdomains** for application notifications and emergency messaging
- **Strict DMARC** (aligned SPF/DKIM)
- **No‑reply naming** for notifications
- **No external forwarding** where prohibited by SSPP
- **Directory‑verified recipients** where required

---

## Governance Highlights

- **Lifecycle‑Driven Access**: employment/affiliation status governs access; role continuity preserved via role‑based mailboxes.  
- **Data Classification Ceilings**: each SSPP sets a maximum (e.g., Level 3 for most; lower for notifications).  
- **Non‑Repository Rule**: email is communication, not a file store.  
- **Disclosure Boundaries**: access/disclosure only under lawful or policy‑authorized processes; auditable.  
- **Opt‑Out Rules**: enforced where appropriate (mandatory for lists; not permitted for emergency alerts).

---

## Validation & Implementation Notes

- Enforce **delegation‑only** access for non‑personal mailboxes.
- Reject **automation creep** in human contexts; reject **human login** in application contexts.
- Ensure **periodic reviews/attestation** for group memberships and delegations.
- Maintain **centralized audit pipelines** for attribution and investigations.
- Use **escalation paths**: Distribution → Campaign; Routine → Emergency only under authority.

---

## Status

✅ **Complete and defensible Secure Email architecture**  
All major email use cases are covered with clear intent, boundaries, and auditability.
