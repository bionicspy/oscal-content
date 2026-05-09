# Mapping Secure Collaboration into Application SSPPs
*(LMS · Research · Administrative Systems)*

This section shows how **Secure Collaboration** is **consumed and constrained** by three major classes of institutional applications.  
It does **not** introduce new SSPPs; instead, it defines **how application SSPPs rely on and inherit Secure Collaboration**.

---

## Architectural Rule (Applies to All)

> **Applications consume Secure Collaboration services; they do not implement collaboration trust.**

All application SSPPs:
- inherit collaboration trust, identity, and observability,
- contextualize collaboration usage,
- retain responsibility for **their own data governance**.

---

## 1. Learning Management Systems (LMS)

### Examples
Canvas, Brightspace, Moodle, Blackboard, LMS-integrated video platforms

### Role of Collaboration
- Instructional delivery
- Student–instructor interaction
- Group work and discussion
- Office hours and tutorials
- Lecture recording and playback

### Secure Collaboration Reliance

**Inherited SSPPs**
- Secure Collaboration Platform SSPP
- External / Federated Collaboration SSPP *(students, guest lecturers)*
- Secure Collaboration Relying System SSPP

**Typical Collaboration Modalities**
- Conference Bridges (lectures, tutorials)
- Real-Time Messaging (live class chat)
- Instant Messaging (student–instructor)
- File Sharing & Sync (assignments, group work)
- Shared Collaborative Workspaces (course groups)

### LMS-Specific Constraints
- Collaboration is **course-scoped**
- Participation is **term-bounded**
- Student access expires automatically
- Recording governed by academic policy
- External participants require explicit approval

### Explicit Non-Responsibilities
- Identity management
- Chat/video security
- Workspace lifecycle enforcement

**Canonical LMS SSPP Statement**
> “The LMS relies on Secure Collaboration services for instructional interaction and does not implement collaboration trust controls locally.”

---

## 2. Research Platforms

### Examples
Research portals, project hubs, lab collaboration environments, multi-institution research systems

### Role of Collaboration
- Long-lived project coordination
- Cross-institution teams
- External partners and sponsors
- Persistent shared knowledge
- Sensitive and regulated data contexts

### Secure Collaboration Reliance

**Inherited SSPPs**
- Secure Collaboration Platform SSPP
- External / Federated Collaboration SSPP *(primary relevance)*
- Secure Collaboration Relying System SSPP

**Typical Collaboration Modalities**
- Shared Collaborative Workspaces **(primary)**
- File Sharing & Sync **(high risk)**
- Instant / Real-Time Messaging
- Conference Bridges (reviews, coordination)

### Research-Specific Constraints
- Explicit workspace ownership
- Periodic membership review
- Workspace lifecycle tied to project lifecycle
- Clear separation between:
  - collaboration metadata
  - research data governance (IRB, contracts)

### Critical Distinction
> Secure Collaboration governs **interaction trust**.  
> Research platforms govern **data governance and compliance**.

### Explicit Non-Responsibilities
- Data classification via workspaces
- Permanent external access
- Using collaboration logs as data-system audit trails

**Canonical Research SSPP Statement**
> “The research system relies on Secure Collaboration for interaction and coordination, while retaining sole responsibility for research data governance.”

---

## 3. Administrative Systems

### Examples
HR systems, Finance applications, Student administration, Case management platforms

### Role of Collaboration
- Case-based communication
- Inter-staff coordination
- Reviews and interviews
- Vendor or auditor interaction

### Secure Collaboration Reliance

**Inherited SSPPs**
- Secure Collaboration Platform SSPP
- External / Federated Collaboration SSPP *(vendor cases)*
- Secure Collaboration Relying System SSPP

**Typical Collaboration Modalities**
- Instant Messaging (internal coordination)
- Real-Time Messaging (incident handling)
- Conference Bridges (interviews, reviews)
- *Limited* File Sharing
- *Rare / constrained* Workspaces

### Administrative-Specific Constraints
- Collaboration strictly workflow- or case-scoped
- Informal persistent workspaces prohibited
- Strong separation between:
  - collaboration artifacts
  - system-of-record data

### Compliance Note
Collaboration activity **does not replace**:
- HR records
- Financial audit trails
- Regulatory logging

**Canonical Administrative SSPP Statement**
> “Collaboration services are used only to support administrative workflows and do not constitute a system of record.”

---

## Comparative Summary

| Dimension | LMS | Research | Administrative |
|--------|-----|----------|----------------|
| Primary Modality | Meetings + Workspaces | Workspaces + Files | IM + Meetings |
| External Participants | Students, guests | Partners, institutions | Vendors |
| Persistence Risk | Medium | High | Low–Medium |
| Data Sensitivity | Medium | High / regulated | High / regulated |
| Workspace Usage | Course-scoped | Project-scoped | Rare |
| SSPP Emphasis | Time-bound | Lifecycle governance | Scope restriction |

---

## Final Invariant

> **Secure Collaboration provides interaction trust.  
> Applications provide context and data governance.  
> Neither replaces the other.**