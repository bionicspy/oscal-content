# How the Email Campaign Findings Roll Up into an Enterprise Dashboard

### Scenario Context  
- **Finding:** Email campaign executed without branded templates 
- **Instance:** Email Campaign Platform – Medicine Advancement Communications  
- **Category:** Governance / Branding
- **Severity:** **Moderate**

This scenario represents a **non-material regulatory risk**, in governance preferences or technical variation. The failure affects a **delegable legal obligation** and therefore does not receive immediate enterprise visibility.


## 1. Enterprise Dashboard View — Conceptual Layout
At the enterprise level, the dashboard is not showing SSPP details.
It rolls up assurance posture, risk, and exceptions.
Think in layers:
```
Enterprise Risk & Compliance Dashboard
│
├── Capability / Service Domain
│   └── Digital Communications
│       └── Email Campaign Platforms
│
├── Governance Posture
│   ├── Compliant (Green ✅)
│   ├── Deviations (Amber ⚠️)
│   └── Non-Compliant (Red 🔴)
│
├── Open Findings & POA&Ms
│
└── Trends & Aging
```
The Medicine Advancement case appears as one row, not a stack of documents.

## 2. Email Campaign Platforms — Portfolio View

### Email Campaign Platforms
Whether centrally approved institutional templates are inherited or locally developed.
- **Consent**, **Opt‑Out**, and **Audit** reflect compliance with SSPP template requirements and applicable regulation.
- **Overall Posture** is derived from open findings and POA&Ms, not from template variance alone.

### Interpretation

- All instances satisfy **legal and regulatory requirements** for consent, opt‑out, and auditability.
- Medicine‑Advancement‑Comms has a **documented governance deviation** related to branding only.
- No systemic risks or recurring control failures are observed across the portfolio.
- The portfolio remains **Green with a single Amber exception** under active governance

This view provides a **portfolio‑level snapshot** of all Email Campaign Platform instances, highlighting governance posture and quickly distinguishing **systemic compliance** from **localized deviations**.

| Platform Instance | Owner | Branding | Consent | Opt‑Out | Audit | Overall Posture |
|------------------|-------|----------|---------|---------|-------|-----------------|
| Advancement‑Comms | Central Advancement | ✅ Centrally Inherited | ✅ Compliant | ✅ Compliant | ✅ Compliant | ✅ Green |
| **Medicine‑Advancement‑Comms** | Faculty of Medicine | ⚠️ Local Templates | ✅ Compliant | ✅ Compliant | ✅ Compliant | ⚠️ Amber |
| Alumni‑Relations | Central Alumni | ✅ Centrally Inherited | ✅ Compliant | ✅ Compliant | ✅ Compliant | ✅ Green |

### Notes
What this tells leadership immediately
* Only branding governance is different
* No consent, opt‑out, or audit risk
* No regulatory breach
* No production outage risk

✅ This prevents overreaction.

## 3. Drill‑Down: Medicine Advancement Communications
When someone clicks Medicine‑Advancement, the dashboard does not show controls.
It shows one finding, clearly scoped.
### Findings Summary Panel
- **Open Findings:** 1
- **Severity:** Moderate
- **Category:** Governance / Branding
- **Controls Affected:** Public Communications

### Finding Card
- **Finding:** Local Branding Templates Not Centrally Inherited
- **Pattern:** public-communications
- **Nature:** Governance deviation (non-technical)
- **Impact Area:** Reputational consistency
- **Status:** Managed via POA&M

✅ This communicates context, not just risk.

## 4. POA&M Tracking View (Executive‑Safe)

### 4.1 POA&M Tracking — Email Campaign Platform  

| POA&M ID | Finding ID |Category | Owner | Status|Target|Residual Risk|
|----------|-----------------|----------|-------|--------|-------------|---------------|
| POAM‑EMCP‑BRANDING‑001 | F‑EMCP‑BRANDING‑001 | Governance / Branding | Medicine Advancement Comms | In Progress | 2027‑03‑31 | Low–Moderate |

---

### 4.2 POA&M Details (Expanded View when needed)

**POA&M ID:** POAM‑EMCP‑BRANDING‑001  
**Finding ID:** F‑EMCP‑BRANDING‑001  
**Title:** Branding Governance Alignment Plan  

**Description:**  
This POA&M addresses a documented governance deviation in which the Medicine Advancement Communications Email Campaign Platform instance does not inherit centrally approved institutional branding templates. Remediation focuses on governance alignment rather than technical control changes.

---

#### Planned Remediation Activities

##### Milestone M1 — Local Branding Alignment Checklist
- **Description:**  
  Document a local branding checklist aligned with institutional branding standards to be used for all locally developed templates.
- **Owner:** Medicine Advancement Communications
- **Status:** Planned
- **Target Date:** 2026‑09‑30

---

##### Milestone M2 — Branding Governance Attestation
- **Description:**  
  Establish an annual branding governance attestation process with Central Communications to confirm ongoing alignment.
- **Owner:** Medicine Advancement Communications / Central Communications
- **Status:** Planned
- **Target Date:** 2026‑12‑31

---

##### Milestone M3 — Central Template Inheritance Evaluation
- **Description:**  
  Evaluate the feasibility of optionally inheriting centrally approved branding templates for selected future campaigns while retaining local flexibility.
- **Owner:** ITS / Medicine Advancement Communications
- **Status:** Planned
- **Target Date:** 2027‑03‑31

---

#### Compensating Controls

- Sender identities are centrally approved.
- Campaign release requires managerial and branding approval.
- Consent, opt‑out enforcement, audit logging, and retention controls are fully inherited from institutional platforms.

---

#### Residual Risk Assessment

- **Residual Risk Level:** Low–Moderate  
- **Rationale:**  
  Branding divergence is limited in scope, governed locally, and does not affect regulatory compliance, consent enforcement, opt‑out handling, or auditability.

---

#### Risk Acceptance

- **Risk Acceptance Required:** No  
- **Acceptance Authority:** Not applicable at this time  

---

#### Current Status

**POA&M Status:** Open — Managed through governance controls  
**Next Review:** Upon completion of Milestone M1 or annual assessment cycle

#### POA&M Summary
* Branding checklist aligned to institutional standards
  * ✅ Planned
* Annual branding attestation with Central Comms
  * ✅ Planned
* Evaluate optional template inheritance
  * ✅ Planned

- ✅ No “fix now” pressure
- ✅ No engineering tickets
- ✅ Governance‑appropriate remediation

## 5. Cross‑Cutting Risk & Trend View

This view aggregates findings and POA&Ms across all Email Campaign Platform instances to identify **systemic risk, local exceptions, and trends over time**. It is derived from SSPP templates, instance SSPPs, SARs, and POA&Ms.

---

### 5.1 Findings by Pattern (Current Snapshot)

| Pattern | Open Findings | Severity | Notes |
|--------|----------------|----------|-------|
| Regulated Digital Service | 0 | — | No statutory deviations identified |
| Data Retention | 0 | — | Obligations inherited and implemented |
| Records Disclosure | 0 | — | FOI-ready across instances |
| **Public Communications** | **1** | Moderate | Local branding deviation (Medicine) |
| Identity / Access | 0 | — | Central identity consistently inherited |
| Email Bulk Messaging Gateway | 0 | — | Core platform controls intact |

---

### 5.2 Trends Over Time

- **Branding deviations:**  
  - Stable at one instance
  - No upward trend across new tenants

- **Consent & Opt‑Out:**  
  - Zero findings across all instances
  - Unsubscribe, suppression, and audit guarantees consistently enforced

- **Records & Audit:**  
  - No aging findings
  - Audit evidence availability unchanged across releases

---

### 5.3 Aging and Remediation Health

| Category | Open | >90 Days | >180 Days |
|--------|------|-----------|------------|
| Governance / Branding | 1 | No | No |
| Regulatory | 0 | — | — |
| Technical Security | 0 | — | — |

All open items are tracked through governance‑level POA&Ms with defined milestones.

---

### 5.4 Systemic vs Localized Risk

- **Systemic Risk:** None identified  
- **Localized Risk:**  
  - Medicine Advancement Communications (branding governance only)
  - No impact to consent, opt‑out, auditability, or regulatory compliance

---

### 5.5 Executive Summary

- Email Campaign Platforms remain **compliant with legal and regulatory requirements**.
- One **managed governance deviation** exists related to local branding autonomy.
- No trends indicate degradation in consent, opt‑out enforcement, or audit readiness.
- Overall risk posture remains **Green with a single Amber exception**.

This cross‑cutting view enables leadership to focus on **material risk** without conflating localized governance choices with systemic control failures.

## 6. Why This Works So Well (Architecturally)
Your design enables the dashboard without custom logic because:
### a) SSPP Template defines expectations
* What “compliant” means is already encoded

### b) SSPP Instance declares deviations
* Explicitly, not implicitly

### c) SAR captures reality
* What actually differs
* No reinterpretation needed

### d) POA&M limits blast radius
* Only the affected expectation
* Only the affected instance

✅ The dashboard becomes a projection of artifacts, not an opinionated tool.

## 7. What This Prevents (Very Important)

The model avoids:
- ❌ Treating local branding as a security failure
- ❌ Inflating minor governance issues into enterprise risk
- ❌ Re‑assessing unchanged core controls
- ❌ Forcing technical remediation for governance choices
- ❌ Losing traceability between policy and reality

## 8. One‑Screen Executive Summary (What the CIO Sees)

Email Campaign Platforms:
* All instances compliant with consent, opt‑out, audit, and regulatory requirements.
* One managed governance deviation related to local branding in Medicine Advancement.
* No immediate action required.

That statement is only possible because of your SSPP → SAR → POA&M discipline.

## 9. Final Takeaway
You’ve designed a system where:
* SSPPs define truth
* Instances define context
* SARs define reality
* POA&Ms define intent
* Dashboards show signal

This is exactly how mature enterprises operationalize OSCAL.