# Trusted Cloud
- **SSPP Template Companion README**
- **Scope:** Third‑party cloud platforms (primarily SaaS)  
- **Assessment Level:** Platform / provider trust

---

## Purpose

The **Trusted Cloud SSPP Template** defines the **institutional baseline for trusting third‑party cloud platforms** that host, process, or manage institutional workloads or data.

This SSPP answers a single, foundational question:

> *Can this cloud platform be trusted as an operating environment for institutional services and data?*

It establishes **normative trust expectations** for cloud providers, independent of:
- business function,
- application logic,
- identity integration,
- email or communications behavior,
- regulatory overlays.

The template is designed to be **inherited by platform SSPPs** and evaluated **once per cloud provider**, not repeatedly per application.

---

## Scope

This SSPP applies to:

- SaaS platforms used by the institution
- Cloud services hosting institutional data or workloads
- Provider‑level controls and assurances
- Multi‑tenant environments operated by third parties

This SSPP focuses on **how the provider operates the platform**, not how the institution configures or uses applications hosted on it.

---

## Trust Boundary and Responsibility Model

### Platform‑Level Trust

The trusted‑cloud SSPP evaluates controls and guarantees that are:

- implemented by the **cloud provider**, and
- common across all customer tenants.

Examples include tenant isolation, provider administrative access, and subprocessor use.

### Shared Responsibility

The SSPP acknowledges a **shared responsibility model**:

- The **provider** is responsible for the security and integrity of the underlying cloud platform.
- The **institution** is responsible for:
  - who can access the service,
  - how features are configured,
  - what data is stored or processed.

The SSPP does not attempt to shift or redefine these boundaries.

---

## In‑Scope Trust Domains

### 1. Cloud Service Model and Boundaries
- Identification of SaaS (primary), with extensibility to PaaS/IaaS if required
- Clear responsibility demarcation between provider and customer
- No overlap with application‑level SSPPs

---

### 2. Tenant Isolation and Multi‑Tenancy
- Logical isolation between customer tenants
- Separation of data planes and control planes
- No cross‑tenant data access under normal operations

**Assessment expectation:**  
Weak, undefined, or opaque tenant isolation is treated as a **Red platform trust failure**.

---

### 3. Data Residency and Sovereignty (Declarative)
- Regions used for:
  - primary data storage
  - backups
  - disaster recovery
- Clarity on whether residency is configurable, fixed, or opaque

This SSPP declares **transparency**, not regulatory compliance.
Regulatory obligations are handled elsewhere.

---

### 4. Provider Administrative Access
- Provider privileged access model (high‑level)
- Existence of:
  - access controls,
  - separation of duties,
  - emergency access procedures
- Auditability of provider admin actions

Customers are not expected to control provider staff; they must be able to **trust the controls exist**.

---

### 5. Security Baseline and Assurance
- Independent security attestations (e.g., SOC 2 Type II, ISO 27001)
- Secure development and vulnerability management posture
- Assurance evidence is **referenced**, not reproduced

The SSPP does not restate report contents or test details.

---

### 6. Logging, Observability, and Evidence Availability
- Platform‑level logs relevant to:
  - security incidents,
  - investigations,
  - audits
- Whether customer‑relevant evidence can be:
  - accessed,
  - exported,
  - retained

This does not replace application logging or SIEM integration.

---

### 7. Incident Response and Notification
- Provider incident response posture
- Notification obligations to customers
- Coordination expectations during incidents

This SSPP evaluates **provider behavior**, not customer incident runbooks.

---

### 8. Subprocessor Governance
- Use of subcontractors and subprocessors
- Transparency of subprocessor lists
- Change notification expectations
- Flow‑down of security obligations

Unbounded or undisclosed subprocessors introduce platform‑level risk.

---

### 9. Exit, Decommissioning, and Portability
- Ability to export institutional data
- Contractual commitments to data deletion
- Handling of customer termination

This addresses **platform trust at end‑of‑relationship**, not operational off‑boarding procedures.

---

## Explicitly Out of Scope

The trusted‑cloud SSPP does **not** cover:

- Authentication and MFA → **Entra ID SSO SSPP**
- Authorization models → **Application SSPPs**
- Identity lifecycle and provisioning → **IGA SSPPs**
- Email identity and transport → **dns‑secure‑email**
- Data retention schedules → **data‑retention**
- Records disclosure → **records‑disclosure**
- Business functionality or workflows

This separation prevents duplicate controls and conflicting findings.

---

## Composition Model

The trusted‑cloud SSPP is designed to be **composed**, not duplicated.

Typical usage:

