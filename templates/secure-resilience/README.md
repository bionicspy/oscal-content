# Secure‑Resilience Templates
## SSPPs, Usage, and Governance

---

## Purpose

The **Secure‑Resilience Templates** define how the Secure‑Resilience architecture is **instantiated, governed, and enforced** across environments.

These templates are **System Security and Privacy Plans (SSPPs)**. They do **not** introduce new controls, tooling, or procedures. Instead, they:

- Apply Secure‑Resilience semantics to real systems
- Define **decision authority**, **reliance constraints**, and **safety precedence**
- Prevent unsafe recovery, implicit resume, and automation overreach
- Provide **audit‑ready, regulator‑credible** resilience governance

---

## Key Architectural Rule

> **Templates consume resilience decisions — they do not invent them.**

All templates inherit from the Secure‑Resilience semantic layer and **may only specialize constraints**, never weaken them.

---

## Template Categories
```
Secure‑Resilience Templates
│
├─ Platform Templates (Authority)
│   ├─ Secure‑Resilience Platform SSPP
│   └─ Secure‑Resilience Relying System SSPP
│
├─ Domain Specialization Templates
│   ├─ IT / Server Resilience SSPP
│   ├─ Integration Resilience SSPP
│   ├─ OT Resilience SSPP
│   └─ IoMT Resilience SSPP
│
└─ Optional Extensions
├─ IoT / Low‑Assurance Resilience SSPP
└─ Crisis & Coordination SSPP (SP 800‑184 Aligned)
```


---

## Platform Templates (Mandatory)

### 1. Secure‑Resilience Platform SSPP

**Role:**  
The **authoritative decision plane** for resilience.

**Defines:**
- Whether restore, DR, degradation, halt, isolate, or decommission are permitted
- Resume eligibility and authorization
- Non‑equivalence rules (restore ≠ resume)
- Recall precedence and safety dominance
- Relationship to NIST SP 800‑53 CP controls and SP 800‑184 coordination guidance

**Explicitly forbids:**
- Automatic resume after restore
- DR or backup bypassing safety
- Recall override
- Optimistic recovery under uncertainty

✅ **Exactly one per organization**

---

### 2. Secure‑Resilience Relying System SSPP

**Role:**  
Constrains **how tools, automation, AI, and humans consume resilience signals**.

**Applies to:**
- Backup systems
- DR tooling
- SOAR / playbooks
- Incident response tooling
- Orchestration platforms
- AI agents
- Human operators

**Guarantees:**
- Resilience signals are non‑transitive
- Restore success ≠ permission to resume
- Automation defaults to halt or isolate
- Coordination ≠ authority

✅ **Mandatory** — without this, resilience authority collapses under automation

---

## Domain Specialization Templates

These templates apply Secure‑Resilience semantics **with domain‑specific assumptions**.

---

### 3. IT / Server Resilience SSPP

**Applies to:**
- Servers
- Virtual infrastructure
- Enterprise IT systems
- Applications and data platforms

**Assumptions:**
- State is **primarily reversible**
- Restore and DR are usually allowed
- Resume is still explicitly gated

**Bias:**
- Restore or degrade preferred
- Halt is rare but valid

**Still forbids:**
- Implicit resume after restore
- Automation‑driven restart

---

### 4. Integration Resilience SSPP

**Applies to:**
- APIs
- Messaging systems
- Event streams
- Workflow engines
- Orchestration layers

**Unique risks:**
- Partial irreversibility
- Amplification via replay
- Downstream side effects

**Bias:**
- Halt or degrade over replay
- Replay treated as command re‑issuance
- Compensation preferred over rollback

**Explicitly forbids:**
- Automatic replay
- Transport‑up = resume inference

---

### 5. OT Resilience SSPP

**Applies to:**
- Industrial control systems
- Building automation
- Utilities
- Robotics
- Lab equipment
- Safety‑critical infrastructure

**Anchors:**
- IEC 62443
- NIST SP 800‑82

**Assumptions:**
- State is **often irreversible**
- Restore is frequently unsafe

**Bias:**
- Safe‑halt, isolate, or de‑energize
- Manual or local control preferred
- Resume requires safety authority

---

### 6. IoMT Resilience SSPP

**Applies to:**
- Medical devices
- Life‑sustaining equipment
- Diagnostic systems
- Clinical monitoring platforms

**Anchors:**
- FDA guidance
- EU MDR
- IEC 80001
- ISO 13485

**Assumptions:**
- Patient outcomes are non‑recoverable
- Restore is exceptional
- Resume is rare

**Bias:**
- Halt or monitoring‑only operation
- Recall is absolute
- Resume requires explicit clinical authorization

---

## Optional Templates

### IoT / Low‑Assurance Resilience SSPP
For commodity or opaque devices:
- Minimal trust
- Replace over restore
- Rapid isolation and decommission

### Crisis & Coordination SSPP (SP 800‑184)
For large organizations:
- Defines human coordination
- Aligns communications and escalation
- **Explicitly does not authorize recovery or resume**

---

## Control & Standards Alignment

### NIST SP 800‑53 (CP Family)
All templates consume (not redefine):
- CP‑2 Planning
- CP‑3 Alternate / Degraded Operation
- CP‑7 Alternate Processing
- CP‑8 Continuity & Suppression
- CP‑9 Backup
- CP‑10 Recovery

### NIST SP 800‑184
- Used only for **coordination guidance**
- Never as recovery authority

### MITRE ATT&CK & D3FEND
- ATT&CK explains *cause* of disruption
- D3FEND describes *possible defensive actions*
- Secure‑Resilience templates decide *whether actions are allowed*

---

## Common Anti‑Patterns These Templates Prevent

- Restore ⇒ Resume
- DR success ⇒ Safe operation
- Ransomware removal ⇒ Business normal
- Automation optimizing uptime
- Replay hiding downstream harm
- Recall bypass via restore
- Coordination mistaken for authority

---

## How to Use These Templates

1. **Adopt Platform SSPPs first**
2. Apply **exactly one domain SSPP per system**
3. Ensure recovery tooling is governed by the Relying System SSPP
4. Never mix domain assumptions (e.g., IT logic in OT)
5. Treat halt and isolation as valid success outcomes

---

## Executive‑Level Summary

> **Secure‑Resilience templates ensure that recovery itself cannot become the next incident.  
> They separate capability from authority, possibility from permission, and recovery from safety.**

These templates complete the Secure‑Resilience domain and make resilience:
- Auditable
- Regulator‑credible
- Automation‑safe
- Future‑proof