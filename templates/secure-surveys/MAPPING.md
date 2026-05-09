# Secure Survey → Application Integration Mapping
*(LMS · Research · Administrative Systems)*

This document defines **how applications integrate with Secure Survey** without re‑implementing survey ethics, consent, identity, or data‑protection logic. It mirrors the Secure Collaboration mapping but emphasizes **ethical trust** and **privacy obligations**.

> **Core Rule:**  
> **Applications trigger or embed surveys; Secure Survey enforces consent, identity handling, and data protection.**

---

## Architectural Invariants (Apply to All Applications)

- Surveys are **purpose‑bound promises**, not generic data collection.
- **Consent and anonymity are enforced by Secure Survey**, not the application.
- Applications define **context and audience**, but **do not process raw responses**.
- Survey distribution uses **Secure Email – Application Send‑Only** patterns.
- Survey results **do not become systems of record** unless explicitly governed.

---

## 1. Learning Management Systems (LMS)

### Examples
Canvas, Brightspace, Moodle, Blackboard

### Why LMS Uses Surveys
- Course feedback
- Teaching evaluations
- Learning effectiveness assessments

### SSPP Inheritance
- ✅ Secure Survey Platform SSPP  
- ✅ Secure Survey Relying System SSPP  
- ✅ Secure Email Platform SSPP (application send‑only)

### Allowed Survey Characteristics
- **Course‑scoped** and **term‑bounded**
- Participation is **voluntary unless policy explicitly states otherwise**
- Anonymity/pseudonymity **declared prior to participation**
- Results aggregated; **no individual tracking**

### Constraints (Must Be Enforced)
- No impact on grades or academic standing
- No persistent identity linkage beyond declared purpose
- No reuse of survey data across courses or terms

### Prohibited
- ❌ Mandatory surveys without clear consent
- ❌ Linking responses to student identity post‑collection
- ❌ Using surveys for behavioral monitoring

**Canonical LMS SSPP Statement**  
> “The LMS relies on Secure Survey for ethical survey execution and does not implement survey consent or identity enforcement locally.”

---

## 2. Research Platforms

### Examples
Research portals, project hubs, lab collaboration environments

### Why Research Uses Surveys
- Human‑participant data collection
- Interviews and questionnaires
- Longitudinal studies

### SSPP Inheritance
- ✅ Secure Survey Platform SSPP  
- ✅ External / Research Survey SSPP  
- ✅ Secure Survey Relying System SSPP

### Allowed Survey Characteristics
- **Project‑scoped** and **ethics‑approved**
- **Anonymity or pseudonymity by default**
- Explicit identity collection **only when justified**
- Retention aligned to research lifecycle

### Constraints (Must Be Enforced)
- Consent language approved by ethics authority
- Membership and data access reviewed periodically
- Separation between **survey responses** and **research datasets** unless approved

### Prohibited
- ❌ Silent re‑identification
- ❌ Indefinite retention
- ❌ Treating survey tools as data governance systems

**Canonical Research SSPP Statement**  
> “The research platform defines study context and purpose; Secure Survey enforces consent, anonymity, and response protection.”

---

## 3. Administrative Systems

### Examples
HR systems, Finance systems, Student administration, Case management

### Why Admin Systems Use Surveys
- Service feedback
- Compliance questionnaires
- Post‑interaction assessments

### SSPP Inheritance
- ✅ Secure Survey Platform SSPP  
- ✅ Secure Survey Relying System SSPP  
- ✅ Secure Email Platform SSPP (application send‑only)

### Allowed Survey Characteristics
- **Case‑ or service‑scoped**
- Purpose and audience explicitly declared
- Aggregated analysis preferred

### Constraints (Must Be Enforced)
- Surveys must not function as surveillance
- Identity handling explicitly declared
- Results do **not** automatically join systems of record

### Prohibited
- ❌ Ongoing monitoring via repeated surveys
- ❌ Implicit or coerced participation
- ❌ Using surveys as audit logs

**Canonical Administrative SSPP Statement**  
> “Administrative surveys support services and feedback; they do not monitor individuals or replace records.”

---

## Email Integration (Canonical)

All survey invitations and notifications:

- ✅ Use **Secure Email – Application Send‑Only**
- ✅ Include purpose and consent context
- ❌ Do not use campaign tooling
- ❌ Do not escalate to emergency channels

**Key Distinction**  
- **Email ensures delivery integrity.**  
- **Secure Survey ensures ethical participation.**

---

## Comparative Summary

| Dimension | LMS | Research | Administrative |
|---|---|---|---|
| Primary Purpose | Course feedback | Human research | Service assessment |
| External Respondents | Students | Community / partners | Vendors / users |
| Anonymity Default | Preferred | Strongly preferred | Case‑dependent |
| Identity Collection | Limited | Justified only | Declared |
| Retention Risk | Medium | High | Medium |
| SSPP Emphasis | Time‑bound, fairness | Ethics, lifecycle | Scope restriction |

---

## Final Invariant

> **Secure Survey provides ethical and privacy trust.  
> Applications provide context and purpose definition.  
> Neither replaces the other.**