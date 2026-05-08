# Secure Network Architecture — README

## Purpose

The **Secure Network** architecture defines how institutional network connectivity is designed, governed, and assured to support modern service delivery **without relying on implicit trust**. It establishes network connectivity as a **policy-driven, identity-aware, and resilient service**, rather than a security boundary or authorization mechanism.

This repository contains the **authoritative Secure Network patterns and SSPPs** used to:
- Govern network design and operation
- Anchor assurance and audit activities
- Support application and platform SSPPs
- Align with Zero Trust and cyber‑resiliency standards

Secure Network is a **Tier‑0 institutional dependency**: failure or misuse has cascading impact across identity, applications, communications, and operations.

---

## Design Principles

The Secure Network architecture is founded on the following non‑negotiable principles:

### 1. No Implicit Trust
Network location, address space, or transport **never implies trust**. All trust decisions are explicit, policy‑driven, and continuously evaluated.

### 2. Identity‑Aware, Not Identity‑Owned
The network **consumes identity and assurance signals** from Secure Identity services but **does not define authentication or authorization**.

### 3. Policy Before Transport
Access policy is evaluated **before** traffic is allowed—transport mechanisms (VPNs, VLANs, tunnels) never create security semantics.

### 4. Segmentation Is Mandatory
Flat networks are prohibited. All connectivity exists within **explicitly governed trust zones** with controlled inter‑zone flow.

### 5. Explicit Egress
Outbound traffic is **not implicitly permitted**. Egress is explicitly governed to reduce data exfiltration and blast radius.

### 6. Continuous Visibility
Network behavior is continuously monitored, auditable, and responsive to detected risk.

### 7. Designed for Failure
The network must degrade safely and recover predictably under fault, attack, or overload conditions.

---

## Standards Alignment (Intentional and Selective)

Secure Network is aligned to modern, architecture‑level guidance:

- **NIST SP 800‑207 — Zero Trust Architecture**  
  Principles: no implicit trust, continuous evaluation, separation of decision and enforcement

- **NIST SP 800‑215 — Zero Trust Networking**  
  Identity‑aware, policy‑mediated networking across ingress, lateral, and egress paths

- **NIST SP 800‑46 — Remote, Guest, and Third‑Party Access**  
  Modernized for Zero Trust and unmanaged endpoints

- **NIST SP 800‑184 — Cyber Resiliency**  
  Applied **only where resiliency is a primary concern** (platform, monitoring, resiliency patterns)

Standards are used as **guidance frameworks**, not prescriptive implementation checklists.

---

## Secure Network Pattern Set

The architecture is decomposed into focused, composable patterns. Each pattern declares **intent and governance**, while threats and defenses are expressed at the capability level.

### Composite Pattern
- **secure-network**  
  Governance and assurance anchor for all Secure Network capabilities

### Foundational Connectivity
- **network-core**  
  Core transport, routing, addressability — no policy or trust logic

### Access & Control
- **network-access-control**  
  Identity- and context‑aware admission decisions
- **network-mediation-and-policy-enforcement**  
  Separation of policy decision (PDP) and enforcement (PEP)

### Segmentation & Movement
- **network-segmentation-and-zones**  
  Explicit trust zones and inter‑zone controls

### Outbound Control
- **network-egress-discipline**  
  Explicit, governed outbound connectivity

### Monitoring & Response
- **network-monitoring-and-response**  
  Telemetry, detection, and response triggers

### Resiliency
- **network-resiliency**  
  Fault containment, graceful degradation, and recovery

### Access Variants
- **network-remote-access**  
  Identity‑aware remote connectivity
- **network-wireless-access**  
  Wireless access with no location‑based trust
- **network-third-party-connectivity**  
  Contract‑bounded external connectivity

---

## Logical Extensions (VPNs, VLANs, Overlays)

Transport mechanisms such as VPNs, VLANs, VXLANs, tunnels, and peering are governed via:

- **Secure Network Logical Extension SSPP**

Key assertion:
> **Logical extensions provide transport only. They must never extend trust, bypass gateways, or redefine policy.**

All extensions:
- Terminate within Secure Network control planes
- Remain subject to segmentation, access control, egress discipline, and monitoring
- Are explicitly approved, auditable, and revocable

---

## Guest, BYOD, and Unmanaged Access

Unmanaged endpoints are governed by:

- **Secure Network Guest & Unmanaged Access SSPP**

This SSPP applies to:
- Student Wi‑Fi
- Residence networks
- Guest access
- Staff personal devices (BYOD)
- Visiting users (e.g., eduroam)

Core assertions:
- Devices are **assumed unmanaged**
- User authentication ≠ trust
- Access limited to Internet and public‑facing services
- No lateral movement or internal reachability

---

## Secure Network SSPP Stack

The Secure Network SSPP hierarchy mirrors Secure Identity and Secure Email:

```
Secure Identity SSPPs
↓
Secure Network Platform SSPP
↓
Secure Network Gateway SSPP
↓
Secure Network Logical Extension SSPP
↓
Secure Network Guest & Unmanaged Access SSPP
↓
Secure Network Relying System SSPP
↓
Applications / Services
```

### SSPPs Included
- Secure Network Platform SSPP (Tier‑0 anchor)
- Secure Network Gateway SSPP
- Secure Network Logical Extension SSPP
- Secure Network Guest & Unmanaged Access SSPP
- Secure Network Relying System SSPP

Each SSPP is **inheritance‑driven** and avoids duplicating controls or redefining policy.

---

## What Secure Network Is *Not*

To preserve architectural integrity:

- Secure Network is **not an authorization system**
- Secure Network is **not a device management plane**
- Secure Network is **not a firewall rule catalog**
- Secure Network is **not a substitute for Secure Identity**

Those concerns are handled by their respective domains.

---

## How to Use This Repository

Use Secure Network artifacts to:

- Anchor new application and platform SSPPs
- Review network designs for compliance and assurance
- Support audits and architectural assessments
- Prevent regression to perimeter‑based trust models

**Patterns define intent.  
SSPPs define assurance.  
Implementations remain flexible.**


## The mental model that prevents confusion
Use this three-plane separation, which your architecture already implies:
1️⃣ Data plane — “moves packets”
* Switch ASIC
* Router forwarding
* Overlay encapsulation

➡️ This is network-core

2️⃣ Control plane — “decides paths”
* Routing protocols
* VLAN / VRF configs
* Overlay control

➡️ Still network-core or segmentation substrate

3️⃣ Policy enforcement plane — “decides trust”
* Allow / deny
* Zone transitions
* Identity-aware enforcement
* Egress controls
* Monitoring hooks

➡️ Secure Network Gateway

A single physical switch may host all three planes, but only plane 3 is the gateway.

## Mapping

See `MAPPING.md`
