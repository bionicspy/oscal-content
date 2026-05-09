# Foundational Resilience Semantics

## Purpose

Foundational Resilience Semantics define **how recovery, restoration, continuation, and halt decisions are interpreted and constrained** across IT systems, integrations, and cyber‑physical devices.

These semantics exist to prevent a critical failure mode common to traditional resilience designs:

> **Treating technical recoverability as equivalent to safe or permissible recovery.**

This layer establishes **non‑equivalence**, **eligibility**, and **safe outcomes** as architectural truths.

---

## Core Principle

> **Resilience is not the ability to restore state.  
> Resilience is the ability to reach a safe outcome without introducing new harm.**

---

## Semantic Invariants (Non‑Negotiable)

The following statements are **structural truths**, not policy preferences:

- Backup ≠ Safe Restore  
- Restore ≠ Resume  
- Resume ≠ Safe Operation  
- Continuity ≠ Business as Usual  
- Recovery ≠ Authorization  
- Availability ≠ Safety  

No pattern, procedure, automation, or human decision may violate these invariants.

---

## State Semantics

### Reversible State
A system or process state is **reversible** if:
- Restoration does not invalidate reality
- No unsafe physical, clinical, or legal condition results
- No external irreversible actions have already occurred

**Examples**
- Corrupted database row  
- Failed virtual machine  
- Misconfigured integration route  

✅ Restore may be eligible  
✅ Resume may be permitted  

---

### Partially Reversible State
A system or process state is **partially reversible** if:
- Data or configuration can be restored
- External effects require reconciliation or compensation
- Resume requires explicit evaluation

**Examples**
- Financial transaction systems  
- Workflow orchestration with side effects  
- Automated provisioning pipelines  

⚠ Restore may be allowed  
⚠ Resume is conditional  

---

### Irreversible State
A system or process state is **irreversible** if:
- Physical, biological, or safety‑critical actions have occurred
- External harm cannot be undone
- Restoration would conceal or compound risk

**Examples**
- Medical dosage delivery  
- Mechanical movement or actuation  
- Pressure release or energy discharge  
- Safety interlock bypass  
- Device subject to recall  

❌ Restore prohibited  
❌ Resume prohibited  
✅ Halt, isolate, or decommission required  

---

## Resilience Outcomes (Only These Are Permitted)

All resilience activity must result in **one and only one** of the following outcomes:

### Restore
Return to a prior known‑good state  
✅ Only if state is reversible  

---

### Degrade
Continue operation in reduced or constrained mode  
✅ Only if safety and correctness are preserved  

---

### Halt
Stop execution to prevent further harm  
✅ Default for uncertain or unsafe states  

---

### Isolate
Remove system or component from participation  
✅ Required for suspected compromise or unsafe behavior  

---

### Decommission
Permanently remove from service  
✅ Required for recalled or non‑recoverable entities  

---

## Resume Eligibility

Resumption of operation is **not automatic**.

Resume eligibility requires **all** of the following:
- State classified as reversible or safely degraded
- Integrity and identity re‑established
- Safety overlays satisfied (if applicable)
- Explicit authorization by relying systems

If any condition cannot be met, **resume is forbidden**.

---

## Resilience vs Domain Safety

Resilience decisions **never override** domain safety rules.

| Domain | Safety Authority |
|------|-----------------|
| IT / Servers | Data integrity & correctness |
| Integrations | Trust propagation constraints |
| OT | Physical and process safety |
| IoMT | Patient safety |
| Devices | Fail‑safe execution |

If resilience actions conflict with safety:
> **Resilience yields to safety. Always.**

---

## Relationship to Existing Resilience Patterns

Foundational Resilience Semantics **do not replace** existing patterns.

They govern **when those patterns may be used**.

| Existing Pattern | Governed By Semantics |
|-----------------|----------------------|
| Backup & Recovery | Restore allowed only if state is reversible |
| Disaster Recovery | Resume allowed only if resume‑eligible |
| Ransomware Resilience | Clean state must be safe and valid |
| Continuity of Operations | Degradation must be permitted |
| Recall Procedures | Always irreversible |

---

## Human and Automation Constraints

### Automation
- Automation must never infer resume eligibility
- Automation may only execute pre‑approved outcomes
- Automation must default to halt or isolate on ambiguity

### Human Decision‑Making
- Human override cannot bypass safety invariants
- Escalation does not convert unsafe into safe
- Coordination ≠ authority

---

## Coordination vs Decision Authority

- **Decision authority** is defined by safety and resilience eligibility
- **Coordination guidance** (e.g., NIST SP 800‑184) governs *how people align*, not *what is permitted*

Coordination informs decisions.  
It never legalizes unsafe recovery.

---

## Why These Semantics Exist

Without foundational resilience semantics:
- Backup becomes harm concealment
- DR becomes unsafe replay
- Continuity becomes denial of reality
- Automation amplifies failure
- Regulators lose trust

With them:
- Recovery is bounded
- Recall is correct
- Safety is preserved
- Domains align cleanly
- Architecture scales

---

## Summary (Executive)

> **Foundational Resilience Semantics ensure that recovery actions are safe, not merely possible.  
> They separate “can we restore?” from “should we restore?” — and make that distinction structural.**

This layer is what allows Secure‑Resilience, Secure‑Device, Secure‑Integration, and Secure‑Server to coexist without creating catastrophic failure modes.
