# Secure Data → Application Integration Mapping
*(LMS · Research · Administrative Systems)*

This document defines how **Secure Data** is **consumed and enforced** by institutional applications without requiring those applications to re‑define data trust, protection, or lifecycle rules themselves.

> **Core Rule:**  
> **Applications produce and consume data; Secure Data defines what must be true about that data.**

Applications inherit Secure Data guarantees and add **context**, not **controls**.

---

## Architectural Invariants (Apply to All Applications)

- Secure Data defines:
  - ownership
  - classification
  - permitted use
  - protection requirements
  - retention and disposal
- Applications:
  - do **not** redefine data classification rules
  - do **not** bypass encryption, DLP, or retention
  - do **not** create new data trust semantics
- Data obligations follow the data, not the application.

---

## 1. Learning Management Systems (LMS)

### Examples
Canvas, Brightspace, Moodle, Blackboard

### Role of Data in LMS
- Student records
- Assignment submissions
- Grades and evaluations
- Course materials and recordings
- Survey and assessment responses

### Secure Data Reliance

**Inherited Patterns**
- `trusted-data`
- `data-core`
- `data-classification`
- `data-handling-and-use`
- `data-encryption`
- `data-loss-prevention`
- `records-and-retention`

### Typical Data Classifications
- Student PII (high sensitivity)
- Academic records (regulated)
- Instructional content (moderate)
- Survey data (classification dependent on survey design)

### Required Constraints
- Student data retained only for approved academic and legal periods
- Grades and assessments:
  - encrypted at rest and in transit
  - protected from unauthorized modification
- Collaboration artifacts (chats, files, recordings):
  - governed under Secure Collaboration
  - classified and retained under Secure Data

### Explicit Prohibitions
- ❌ LMS may not redefine retention schedules
- ❌ LMS may not bypass DLP for data exports
- ❌ LMS analytics may not reuse data beyond declared purpose

**Canonical LMS SSPP Statement**  
> “The LMS relies on Secure Data for classification, protection, and lifecycle governance of educational records and artifacts.”

---

## 2. Research Platforms

### Examples
Research portals, project hubs, lab data environments

### Role of Data in Research Systems
- Human‑participant data
- Research datasets
- Survey responses
- Experimental results
- Collaboration and provenance metadata

### Secure Data Reliance

**Inherited Patterns**
- `trusted-data`
- `data-core`
- `data-classification`
- `data-handling-and-use`
- `data-encryption`
- `key-management`
- `public-key-infrastructure`
- `data-loss-prevention`
- `records-and-retention`

### Typical Data Classifications
- Regulated personal data
- Confidential research data
- Intellectual property
- Public or open datasets

### Required Constraints
- Classification must align with:
  - consent commitments
  - ethics approvals
  - funding and contractual obligations
- Encryption mandatory for:
  - sensitive and regulated datasets
- DLP enforced for:
  - data sharing with external collaborators
- Retention bound to:
  - research lifecycle
  - legal and funding requirements

### Explicit Prohibitions
- ❌ Research systems may not self‑classify data inconsistently
- ❌ Anonymized data may not be re‑identified outside approved scope
- ❌ Data exports may not bypass Secure Data DLP controls

**Canonical Research SSPP Statement**  
> “Research platforms rely on Secure Data to enforce classification, protection, sharing, and retention of research information.”

---

## 3. Administrative Systems

### Examples
HR systems, Finance systems, Student administration, Case management platforms

### Role of Data in Administrative Systems
- Employment records
- Financial data
- Case files
- Transaction logs
- Decisions and approvals

### Secure Data Reliance

**Inherited Patterns**
- `trusted-data`
- `data-core`
- `data-classification`
- `data-handling-and-use`
- `data-encryption`
- `data-loss-prevention`
- `records-and-retention`

### Typical Data Classifications
- Highly sensitive PII
- Financial and payroll data
- Legal and case records
- Audit logs

### Required Constraints
- Strong encryption and key management for all sensitive data
- Strict access enforcement and logging
- DLP enforced on:
  - email attachments
  - exports
- Retention and legal holds strictly enforced

### Explicit Prohibitions
- ❌ Admin systems may not implement ad‑hoc retention rules
- ❌ Case data may not be reused for analytics without approval
- ❌ Data sharing outside system scope must go through approved channels

**Canonical Administrative SSPP Statement**  
> “Administrative systems rely on Secure Data for mandatory classification, encryption, loss prevention, and records retention.”

---

## Comparative Summary

| Dimension | LMS | Research | Administrative |
|---|---|---|---|
| Primary Data Risk | Student privacy | Ethics & IP | Legal & financial |
| External Data Sharing | Limited | Common | Rare |
| Retention Sensitivity | Moderate–High | High | Very High |
| Encryption Requirements | High | High | High |
| DLP Importance | Moderate | High | High |

---

## Final Invariant

> **Secure Data defines trust, protection, and lifecycle for information.  
> Applications provide context and functionality — they do not define data trust.**

This mapping is the authoritative reference for how LMS, Research, and Administrative systems inherit and apply Secure Data controls.