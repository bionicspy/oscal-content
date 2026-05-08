# COBO L2 – Enhanced‑Assurance Managed Endpoint
**System Security Plan Profile (SSPP)**

## Overview

**COBO L2** defines an **enhanced‑assurance** tier for institution‑owned, centrally managed, general‑purpose endpoints. It builds directly on the **COBO L1 baseline** by introducing additional security controls and tighter enforcement suitable for **higher‑risk institutional workflows**.

COBO L2 is intended for users with elevated responsibilities or access needs, while remaining a general‑purpose computing environment. It is **not** a dedicated secure workstation and does not replace DAW‑class devices.

---

## Purpose

The purpose of the COBO L2 SSPP is to:

- Provide a **controlled step‑up in endpoint assurance** above COBO L1
- Support participation in **higher‑risk workflows** with stronger device assurances
- Preserve a **clean, auditable inheritance model** from COBO L1
- Avoid conflating endpoint assurance with data classification or entitlement

COBO L2 exists to reduce risk, not to expand privilege by default.

---

## Scope

This SSPP applies to:

- Institution‑owned endpoints
- Centrally managed platforms
- General‑purpose devices used by staff or faculty with elevated access needs

This SSPP does **not** define:

- Application‑specific authorization rules
- Data classification entitlements
- Dedicated high‑sensitivity work environments
- Research‑ or admin‑only workstation models

Those concerns are addressed in **application SSPPs**, **data SSPPs**, or **DAW SSPPs**.

---

## Key Principles

### Device ≠ Data

Endpoint assurance levels **are not equivalent to data classification levels**.

- Endpoint classifications describe **device security characteristics and governance**
- Data classifications describe **information sensitivity**
- A device’s classification does **not** grant automatic entitlement to any data class

COBO L2 improves assurance but does not change how data access decisions are made.

---

## Endpoint Characteristics

COBO L2 endpoints MUST:

- Meet **all COBO L1 requirements**
- Be **institution‑owned and centrally managed**
- Enforce **stricter configuration and security baselines**
- Apply **tighter health, posture, and threat‑response enforcement**

COBO L2 endpoints remain general‑purpose and user‑focused.

---

## Pattern Inheritance

COBO L2 inherits the **Secure Endpoint** composite pattern **through COBO L1**, including:

- Endpoint Core  
- Endpoint Identity and Posture  
- Endpoint Configuration and Hardening  
- Endpoint Health and Compliance  
- Endpoint Threat Protection  
- Endpoint Lifecycle  

COBO L2 introduces **only explicit, documented deltas** to these patterns.

---

## Enhanced Assurance (What COBO L2 Adds)

Relative to COBO L1, COBO L2 introduces:

- **Stricter authentication and session assurance**
- **More restrictive configuration and application control**
- **Lower tolerance for health or compliance drift**
- **More aggressive local threat containment**
- **Faster remediation and investigation expectations**

These enhancements are **mandatory** and consistently enforced.

---

## Data Eligibility

COBO L2 endpoints are **eligible** to participate in workflows involving:

- **Data Classification Levels 1–3**

Eligibility:
- Is **necessary but never sufficient**
- Remains subject to policy, user role, contextual risk, and safeguards
- Does **not** imply entitlement to Level 3 data by default

COBO L2 does not assert eligibility for Level 4 or higher data.

---

## Enforcement Model

For COBO L2 endpoints:

- Health and compliance enforcement is **strict**
- Deviations are corrected **quickly or access is revoked**
- Threat detections trigger **immediate containment**
- Risk acceptance is **not implicit** and must be explicitly approved

---

## COBO L1 vs COBO L2 – Comparison

### Assurance and Governance

| Area | COBO L1 | COBO L2 |
|----|--------|---------|
| Endpoint Purpose | Baseline general‑purpose use | Enhanced‑assurance general‑purpose use |
| Ownership | Institution‑owned | Institution‑owned |
| Management | Centrally managed | Centrally managed |
| Assurance Level | Baseline | Enhanced |

---

### Configuration and Protection

| Area | COBO L1 | COBO L2 |
|----|--------|---------|
| Configuration Baseline | Standard enterprise | More restrictive |
| Application Control | Baseline allow/deny | Reduced flexibility |
| Health Enforcement | Binary (compliant / blocked) | Stricter thresholds |
| Threat Response | Standard containment | Faster and broader containment |

---

### Data Eligibility (Not Entitlement)

| Endpoint Tier | Eligible Data Classes |
|-------------|----------------------|
| COBO L1 | Level 1–2 |
| COBO L2 | Level 1–3 |

> Eligibility does not grant access on its own. Policy always decides.

---

## What COBO L2 Is *Not*

COBO L2 is **not**:

- A dedicated administrative workstation (DAW)
- A data classification construct
- A substitute for application‑ or data‑specific SSPPs
- A blanket approval for high‑sensitivity data handling

If workflows require tighter scope, stronger isolation, or direct alignment to sensitive data, **DAW‑class endpoints must be used**.

---

## Relationship to Other Endpoint Tiers

- **COBO L1**  
  Baseline trust; starting point for all managed endpoints

- **COBO L2**  
  Controlled enhancement of COBO L1; higher assurance, same general‑purpose model

- **DAWs**  
  Purpose‑built secure environments with tightly scoped use

COBO L2 always remains **derivative of COBO L1**.

---

## Status

**Authoritative Enhanced Tier**  
This SSPP defines the institution’s standard enhanced‑assurance endpoint tier. Changes should be rare and driven by risk or baseline evolution, not individual use cases.