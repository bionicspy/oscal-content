Identity & Trust Pattern Family
(Conceptual / SABSA Layer – OSCAL Component‑Definitions)

How to Read This Section

Patterns define distinct trust capabilities
Components (sub‑capabilities) exist only where decomposition adds clarity
Composites answer business‑level trust questions
Workforce responsibility comes from NIST NICE via the R&R framework (referenced, not embedded)


1. identity-core
Institutional Digital Identity

Purpose:
* Defines what an identity is in the institution and how identity functions as the root trust construct.

Scope:
* Human identities
* Non‑human identities (workloads, services, devices)
* Identity uniqueness and authority
* Identity as a persistent trust object

Components
identity-core/
├── identity-authority
├── identity-namespace
├── identity-uniqueness
└── identity-attribution

Answers the question:
* “What does it mean to have an identity the institution recognizes?”


2. identity-authentication
Proof of Identity at Time of Use
Purpose
Defines how identities prove who or what they are at interaction time.
Scope

Authentication events (conceptual)
Contextual evaluation
Re‑authentication expectations

Components
identity-authentication/
├── authentication-events
├── authentication-context
├── step-up-authentication
└── session-establishment

Answers the question:

“How do we know this identity is really who (or what) it claims to be right now?”


3. identity-authorization
What an Identity Is Allowed to Do
Purpose
Defines how access decisions are made, independent of enforcement.
Scope

Entitlement concepts
Delegation
Policy decision logic
Role vs attribute based concepts

Components
identity-authorization/
├── entitlement-model
├── delegation
├── policy-decision
└── enforcement-separation

Answers the question:

“What may this identity do once authenticated?”


4. identity-lifecycle
Creation, Change, Suspension, and Termination
Purpose
Defines identity existence over time.
Scope

Join / move / leave
Dormancy
Revocation
Exception handling

Components
identity-lifecycle/
├── onboarding
├── changes-in-status
├── suspension-and-revocation
└── deprovisioning

Answers the question:

“When should an identity exist—and when should it not?”


5. identity-federation
Trust Across Organizational Boundaries
Purpose
Defines cross‑organization identity trust.
Scope

External identity acceptance
Trust boundary definition
Assertion handling
Assurance inheritance

Components
identity-federation/
├── trust-relationships
├── assertion-consumption
├── external-identity-assurance
└── responsibility-boundaries

Answers the question:

“Whose identities do we trust, and under what conditions?”


6. identity-assurance
Confidence in Identity and Authentication Strength
Purpose
Defines how much trust the institution places in identity claims.
Scope

Assurance levels (conceptual)
Risk signaling
Context propagation
Degradation of confidence

Components
identity-assurance/
├── assurance-levels
├── confidence-signals
├── risk-context
└── assurance-propagation

Answers the question:

“How confident are we in this identity assertion?”


7. identity-logging-and-audit
Accountability and Traceability
Purpose
Defines how identity actions are recorded for accountability and investigation.
Scope

Authentication events
Authorization decisions
Identity lifecycle events
Delegation actions

Components
identity-logging-and-audit/
├── authentication-logging
├── authorization-logging
├── lifecycle-event-logging
└── traceability

Answers the question:

“Can we reconstruct and attribute identity actions after the fact?”


8. identity-privileged-access
High‑Risk Identity Usage
Purpose
Defines elevated trust modes for identities with expanded authority.
Scope

Privileged identity concepts
Just‑in‑time access
Enhanced accountability
Segregation of duties

Components
identity-privileged-access/
├── privileged-identities
├── temporary-elevation
├── privileged-session-control
└── enhanced-accountability

Answers the question:

“How do we handle identities that carry exceptional risk?”


9. identity-non-human
Machine and Workload Identity
Purpose
Defines identity for services, workloads, and automation.
Scope

Service identities
Workload identities
API and system‑to‑system trust

Components
identity-non-human/
├── service-identities
├── workload-identities
├── identity-binding
└── rotation-and-revocation

Answers the question:

“How do non‑human actors authenticate and gain trust?”


10. identity-device-binding
Identity–Device Relationship
Purpose
Defines how identities bind to devices or execution contexts.
Scope

User‑device trust relationships
Context validation
Device‑bound identity

Components
identity-device-binding/
├── device-association
├── trust-binding
└── context-validation

Answers the question:

“Is this identity using an acceptable execution environment?”


11. Composite Pattern: trusted-identity
Acceptable Institutional Identity Trust Posture
Purpose
Defines when the institution considers identity usage acceptable and trustworthy.
Composed Of
trusted-identity/
├── identity-core
├── identity-authentication
├── identity-authorization
├── identity-lifecycle
├── identity-federation
├── identity-assurance
├── identity-logging-and-audit
├── identity-privileged-access
├── identity-non-human
└── identity-device-binding

Answers the business question:

“Can we trust actions taken in the name of this identity?”


Identity Patterns at a Glance (Hierarchy)
identity/
├── identity-core
├── identity-authentication
├── identity-authorization
├── identity-lifecycle
├── identity-federation
├── identity-assurance
├── identity-logging-and-audit
├── identity-privileged-access
├── identity-non-human
├── identity-device-binding
└── trusted-identity (composite)