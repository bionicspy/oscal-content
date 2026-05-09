# Secure Data Architecture — README

## Purpose

**Secure Data** defines how institutional data is governed, protected, and trusted so that information can be **used confidently, shared appropriately, and retained defensibly** without eroding privacy, security, or institutional credibility.

Data is treated as a **first‑class security domain**, not merely as a by‑product of applications or infrastructure. Secure Data exists to prevent common failure modes such as:

- data being used outside its intended purpose,
- sensitive information leaking through trusted channels,
- cryptographic protections being inconsistently applied,
- records being retained too long or destroyed too early,
- loss of accountability over who owns and governs data.

---

## Scope

The Secure Data architecture governs **what must be true about data**, regardless of:
- where the data is stored,
- which application produced it,
- whether it is at rest, in motion, or in use.

It applies to:
- transactional data,
- records,
- survey data,
- collaboration artifacts,
- research data,
- administrative and operational datasets.

It explicitly does **not** govern:
- specific storage platforms,
- databases or analytics engines,
- backup tooling,
- application business logic.

Those are **relying systems**, not trust foundations.

---

## Core Design Principles

### 1. Data Has an Owner
All institutional data is attributable to an accountable authority responsible for its accuracy, protection, and appropriate use.

### 2. Meaning Comes Before Protection
Data must first be understood (purpose, sensitivity, obligation) before encryption, DLP, or retention can be correctly applied.

### 3. Purpose Is Binding
Data may only be accessed, processed, shared, or retained in ways consistent with its declared and approved purpose.

### 4. Protection Is Layered
No single mechanism is sufficient. Classification, handling rules, cryptography, DLP, and retention each play distinct roles.

### 5. Lifecycle Discipline Is Required
Data must be retained **no longer and no shorter** than required, with defensible holds and verified disposal.

---

## Secure Data Pattern Structure

Secure Data is decomposed into a **composite trust assertion**, a **foundational core**, and a set of **orthogonal constraint patterns**.

### Composite Pattern
- **`trusted-data`**  
  The governance and assurance anchor asserting institutional trust in data.

### Foundational Pattern
- **`data-core`**  
  Defines non‑negotiable data invariants:
  - ownership and accountability  
  - authoritative scope and purpose  
  - baseline integrity  
  - observability and auditability  

### Constraint Patterns

| Pattern | Role |
|------|-----|
| **`data-classification`** | Defines sensitivity, criticality, and protection obligations |
| **`data-handling-and-use`** | Governs how data may be accessed, processed, and shared |
| **`data-encryption`** | Enforces confidentiality through approved cryptography |
| **`key-management`** | Governs cryptographic key lifecycle |
| **`public-key-infrastructure`** | Establishes trust anchors and certificate validation |
| **`data-loss-prevention`** | Prevents unauthorized data egress |
| **`records-and-retention`** | Governs lifecycle, legal holds, archival, and disposal |

Each pattern addresses **one dimension** of trust and deliberately avoids overlapping responsibilities.

---

## SSPP Stack (Data)

Secure Data assurance is delivered via a layered SSPP model:

1. **Trusted Data Platform SSPP**  
   Tier‑1 governance and assurance anchor

2. **Secure Data Platform SSPP**  
   Documents how Secure Data patterns are implemented institutionally

3. **Secure Data Relying System SSPP**  
   Template for applications and services that consume data (LMS, research platforms, admin systems)

This mirrors the SSPP structures used for:
- Secure Survey
- Secure Collaboration
- Secure Email

---

## Cross‑Domain Alignment

### Secure Survey
- Survey responses are **data with promises**
- Classification, handling, encryption, and retention must respect consent and ethics
- Secure Data underpins survey trust

### Secure Collaboration
- Messages, files, recordings, and transcripts are all data
- Secure Data governs their classification, DLP, encryption, and retention

### Secure Email
- Email content is data in motion
- Encryption, DLP, and retention are driven by Secure Data

### Secure Identity & Secure Network
- Identity answers *who*
- Network answers *how*
- Secure Data answers *what* and *under what obligation*

---

## Standards Alignment

Secure Data is aligned at an **architectural level** with:

- **NIST SP 800‑53** — security and privacy control foundations  
- **NIST SP 800‑60** — information categorization  
- **NIST SP 800‑57 / 800‑130** — cryptographic key management and agility  
- **NIST SP 800‑52 / 800‑111** — encryption in transit and at rest  
- **NIST SP 800‑137** — continuous monitoring  
- **NIST SP 800‑47** — interconnecting systems  
- **NIST Privacy Framework** — purpose limitation and minimization  

ATT&CK and D3FEND references appear only to justify Secure Data as a domain and to explain systemic risks, not to prescribe product‑level controls.

---

## What Secure Data Is *Not*

Secure Data is not:
- a storage architecture,
- a database design standard,
- a backup strategy,
- a data science methodology,
- an analytics or reporting platform.

Those concerns are governed elsewhere.

---

## Architectural Invariant

> **Secure Data provides trust in what information is, how it may be used, and how it is protected.  
> Applications consume that trust — they do not define it.**