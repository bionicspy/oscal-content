# Secure‑SDLC Templates
## SSPPs — Governance, Authority, and Safe Reliance

---

## Purpose

The **Secure‑SDLC Templates** define how the Secure‑SDLC architecture is **operationalized, governed, and enforced** across environments.

These templates are **System Security and Privacy Plans (SSPPs)**.  
They do **not** introduce new controls, tooling, or pipelines. Instead, they:

- Establish **authoritative boundaries** for Secure‑SDLC
- Constrain **how SDLC outputs may be relied upon**
- Prevent SDLC from becoming an **implicit deployment authority**
- Ensure safety, regulatory, and operational domains override delivery outcomes
- Make CI/CD automation and AI **safe by construction**

---

## Core Principle (Non‑Negotiable)

> **Secure‑SDLC produces trusted delivery artifacts, not permission to deploy or execute them.**

Every SSPP in this folder exists to enforce that principle under real operating conditions.

---

## What These Templates Are (and Are Not)

### ✅ These templates **ARE**
- Governance and constraint documents (SSPPs)
- The authority model for **software delivery**
- Pre‑runtime only (no execution, no deployment)
- Compatible with full CI/CD automation
- Explicitly aligned with:
  - NIST SP 800‑53 (SA, CM, IA, AU, SI, SR)
  - NIST SP 800‑218 (SSDF)
- Designed to prevent **implicit trust escalation**

### ❌ These templates **ARE NOT**
- Deployment pipelines
- Runtime authorization mechanisms
- Safety certification artifacts
- Clinical approval documents
- Device or resilience controls

Those responsibilities live in **other Secure‑* domains**.

---

## Template Structure
```
Secure‑SDLC Templates
│
├─ Platform Authority
│   ├─ Secure‑SDLC Platform SSPP
│   └─ Secure‑SDLC Relying System SSPP
│
├─ Domain Specializations
│   ├─ IT / General SDLC SSPP
│   ├─ OT SDLC SSPP
│   └─ IoMT SDLC SSPP
│
└─ (Optional Extensions)
  └─ Procurement / Supply Chain SDLC SSPP
```

---

## Platform Authority SSPPs (Mandatory)

### 1. **Secure‑SDLC Platform SSPP**

**Role:**  
Defines **what Secure‑SDLC governs** and what it explicitly **does not**.

**Establishes:**
- Secure‑SDLC scope (pre‑runtime only)
- Non‑equivalence rules:
  - build ≠ release
  - test ≠ approval
  - signed artifact ≠ deployable
- Explicit prohibition of implicit deployment authority
- Priority of other domains:
  - Secure‑Device
  - Secure‑Resilience

**This SSPP is the SDLC trust root.**

✅ Exactly one per organization

---

### 2. **Secure‑SDLC Relying System SSPP**

**Role:**  
Constrains **any system or person that consumes SDLC outputs**.

**Applies to:**
- CI/CD platforms
- GitOps controllers
- Deployment automation
- Policy engines
- AI agents
- Humans invoking automation

**Enforces:**
- Non‑transitive trust
- “Deny or hold” by default
- No auto‑deploy from SDLC success
- No AI‑driven authority escalation
- Domain precedence (device & resilience override SDLC)

**Without this SSPP, Secure‑SDLC will fail under automation.**

✅ Mandatory

---

## Domain Specialization SSPPs

These SSPPs **do not change Secure‑SDLC**.  
They apply **additional constraints** based on safety and regulatory context.

---

### 3. **IT / General SDLC SSPP**

**Applies to:**
- Enterprise applications
- Internal services
- Cloud‑native systems
- General software workloads

**Characteristics:**
- High automation permitted
- Frequent releases expected
- Mostly reversible runtime state

**Still enforces:**
- No implicit deploy
- External deployment authority
- SDLC remains pre‑runtime only

✅ Recommended for most environments

---

### 4. **OT SDLC SSPP**

**Applies to:**
- PLC logic
- Industrial controllers
- Robotics software
- Building automation
- Safety‑critical control systems

**Characteristics:**
- Infrequent changes
- Often irreversible physical effects
- Mandatory human safety review

**Explicitly forbids:**
- Auto‑deploy to OT
- CI/CD energization
- Treating assurance as safety approval

**Operational enablement requires safety governance outside SDLC.**

✅ Required where OT exists

---

### 5. **IoMT SDLC SSPP**

**Applies to:**
- Medical device firmware
- Clinical software
- Therapy‑control logic
- Diagnostic and monitoring systems

**Anchored to:**
- FDA guidance
- EU MDR
- IEC 80001
- ISO 13485

**Characteristics:**
- Patient harm is non‑recoverable
- Automation is highly restricted
- Recall overrides patching

**Explicitly forbids:**
- SDLC‑driven clinical activation
- Auto‑updates in patient contexts
- Using tests or signatures as safety proof

**Clinical and regulatory authority supersede SDLC outcomes.**

✅ Required where IoMT exists

---

## Optional SSPPs

### Procurement / Supply Chain SDLC SSPP *(Optional)*

Extends Secure‑SDLC Supply Chain controls into:
- Vendor onboarding
- Contracts
- Risk acceptance

Useful for:
- Highly regulated industries
- Third‑party heavy ecosystems

---

## Relationship to Other Secure‑* Domains

| Domain | Relationship |
|-----|-------------|
| Secure‑Device | Enforces device safety regardless of SDLC outcomes |
| Secure‑Resilience | Decides if runtime execution may occur |
| Secure‑Integration | Governs propagation, not delivery |
| Secure‑Network | Governs transport, not artifact trust |

Secure‑SDLC outputs are **inputs**, not **authority**, everywhere else.

---

## Common Failure Modes These Templates Prevent

- Pipeline success ⇒ deploy
- Signed artifact ⇒ safe runtime
- SBOM present ⇒ trust
- Assurance clean ⇒ approval
- AI recommendation ⇒ execution

All of the above are **architecturally forbidden**.

---

## Executive Summary

> **Secure‑SDLC Templates ensure software can be delivered at scale without ever becoming an unsafe shortcut to execution.**

They:
- enable automation without blind trust  
- preserve safety and regulatory authority  
- prevent AI and tooling from escalating privileges  
- make Zero Trust real in CI/CD environments  

With these templates in place, **software can move fast without breaking safety or trust**.

---