# Compute & Execution Environments — Trust Plane Overview
## Description
The Compute & Execution Environments trust plane defines where code runs and how execution is constrained, monitored, and governed.

It establishes institutional trust in endpoints, servers, and workloads as execution environments, not just as assets.

This plane answers whether a given device or workload may be trusted to:
* execute code safely,
* protect credentials and data in use,
* resist compromise,
* and be monitored and remediated when things go wrong.

## Purpose
The purpose of the Compute & Execution Environments plane is to ensure that:
* Software executes only in controlled, hardened environments
* Identity and network trust assumptions are not undermined by compromised compute
* Execution environments are configurable, attestable, observable, and recoverable
* Risk introduced by user-operated devices differs clearly from server/workload risk

This plane explicitly separates:
* User-operated endpoints from
* Managed servers and workloads

because their threat models, trust assumptions, and assurance mechanisms differ materially.

## Scope
This plane applies to any environment that executes institutional code:

### In scope
* User desktops, laptops, kiosks, and mobile compute
* Virtual machines, containers, and bare-metal servers
* Cloud workloads and on‑premises compute
* Runtime execution contexts
* Host‑level controls, not application logic

### Out of scope
* Application‑level authorization logic
* Network connectivity (handled by Network plane)
* Identity proofing and authentication (handled by Identity plane)

## 1. Endpoints (User‑Operated Compute)
Endpoints represent the least deterministic execution environments:
* users control behavior,
* environments are mobile,
* compromise probability is higher,
* and blast radius often crosses trust planes.

Endpoints therefore emphasize posture, health, threat resistance, and recovery.

### Endpoint Pattern Decomposition
```
endpoint/
├── endpoint-core
├── endpoint-identity-and-posture
├── endpoint-configuration-and-hardening
├── endpoint-health-and-compliance
├── endpoint-threat-protection
├── endpoint-lifecycle
└── secure-endpoint (composite)
```

Pattern-Level Purpose & Scope
### 1. endpoint-core
#### Purpose
Define what it means for a device to be an institutional endpoint at all, independent of configuration, health, or threat state.
#### Scope
* Endpoint enrollment and classification
* Execution environment boundaries
* Baseline trust assumptions

#### Components
* endpoint-enrollment
  * Formal registration of devices into institutional management
* endpoint-classification
  * Device type, ownership model, and allowed usage
* execution-boundaries
  * Boundary definition between endpoint and institutional systems
* baseline-trust-assumptions
  * Minimum execution expectations (managed, non-anonymous, governed)

#### Answers the question

“Is this device an endpoint we recognize and manage?”


### endpoint-identity-and-posture
#### Purpose
Bind endpoint identity and posture to institutional trust decisions.
#### Scope
* Device identity
* Hardware and OS characteristics
* Trust signals used by Identity and Network planes

#### Answers the question
“What is this device, and what trust signals does it present?”


endpoint-configuration-and-hardening
Purpose
Ensure endpoints are configured to minimize attack surface and enforce institutional security expectations.
Scope

OS configuration
Security baselines
Local policy enforcement

Answers the question

“Is this endpoint configured safely by design?”


endpoint-health-and-compliance
Purpose
Continuously evaluate whether the endpoint remains compliant with required security posture.
Scope

Patch posture
Configuration drift
Compliance evaluation

Answers the question

“Is this endpoint still safe to trust right now?”


endpoint-threat-protection
Purpose
Detect, prevent, and contain malicious activity occurring on endpoints.
Scope

Malware detection
Behavioral protection
Local containment actions

Answers the question

“Can the endpoint defend itself against active threats?”


endpoint-lifecycle
Purpose
Manage endpoints from provisioning through retirement in a controlled and auditable way.
Scope

Enrollment
Reassignment
Decommissioning and wipe

Answers the question

“Is this endpoint being responsibly managed over time?”


secure-endpoint (Composite)
Purpose
Assert that endpoints are acceptable execution environments for institutional use.
Scope

Composition only
No direct controls

Answers the question

“Can we trust endpoints to execute code and access resources?”


2.2 Servers & Workloads
Servers and workloads are operator-controlled execution environments:

more deterministic,
less user-driven,
higher blast radius,
stronger attestation opportunities.

They emphasize baseline integrity, runtime protection, and controlled change.

Server Pattern Decomposition
server/
├── server-core
├── server-attestation-and-trust
├── server-configuration-and-baseline
├── server-patch-and-vulnerability-posture
├── server-runtime-protection
├── server-monitoring-and-response
└── secure-server (composite)


Pattern-Level Purpose & Scope
server-core
Purpose
Define what it means for a system to be a managed server or workload.
Scope
* Server classification
* Execution boundary definition
* Trust assumptions

Answers the question

“Is this a server or workload we operate and control?”


server-attestation-and-trust
Purpose
Establish cryptographic and verifiable trust in server integrity.
Scope

Boot attestation
Hardware and runtime trust
Identity binding for workloads

Answers the question

“Can we prove this server is what we think it is?”


server-configuration-and-baseline
Purpose
Ensure servers run only approved, hardened configurations.
Scope

Golden images
Baseline enforcement
Drift prevention

Answers the question

“Is this server running an approved configuration?”


server-patch-and-vulnerability-posture
Purpose
Reduce exposure by keeping servers up to date and addressing known weaknesses.
Scope

Patch management
Vulnerability assessment
Risk prioritization

Answers the question

“Is this server exposed to known weaknesses?”


server-runtime-protection
Purpose
Protect servers while they are actively executing workloads.
Scope

Memory protection
Runtime exploit prevention
Execution constraints

Answers the question

“Can this server defend itself while running code?”


server-monitoring-and-response
Purpose
Detect compromise and respond to incidents affecting server environments.
Scope

Telemetry
Detection
Automated or coordinated response

Answers the question

“Can we see and respond to attacks against servers?”


secure-server (Composite)
Purpose
Assert trust in servers and workloads as safe execution environments.
Scope

Composition only
No direct controls

Answers the question

“Can we trust servers and workloads to run institutional services?”


Canonical Rule (Lock This In)

Code may only be trusted to run if it executes on a secure endpoint or a secure server.

This rule ties:

Identity trust
Network trust
Compute trust
into a single, defensible architecture story.


Next Step (Recommended)
Just like before, we should now:
➡️ Start with endpoint-core, since it anchors the endpoint family
then:

endpoint-identity-and-posture
endpoint-configuration-and-hardening
…

When you’re ready, say:

“Show endpoint-core JSON.”

You’re building the third trust plane — and this is exactly the right way to do it.
Provide your feedback on BizChatShow endpoint-core JSONExplain endpoint-identity-and-postureHow does secure-server differ?