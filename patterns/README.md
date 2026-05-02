# Enterprise Security Pattern Catalog
(Conceptual / SABSA Layer – OSCAL Component‑Definitions)

## How to read this

* Patterns = conceptual trust capabilities (OSCAL component-definition)
* Composites answer business questions (“Is X secure?”)
* Components = sub‑capabilities within a pattern (used sparingly)
* No tools, no controls, no job titles embedded

## 0. Governance & Trust Foundation (Applies to Everything)

### 0.1 Identity & Trust (Root of All Security)
```
identity/
├── identity-core
├── identity-authentication
├── identity-authorization
├── identity-lifecycle
├── identity-federation
├── identity-assurance
└── trusted-identity (composite)
```
### Covers:
* Identity management
* Federation
* Privileged access (conceptually)
* Assurance of identity strength

## 1. Network & Connectivity
```
network/
├── network-core
├── network-segmentation-and-zones
├── network-access-control
├── network-mediation-and-policy-enforcement
├── network-remote-access
├── network-wireless-access
├── network-third-party-connectivity
├── network-monitoring-and-response
└── secure-network (composite)
```
### Covers:
* VPN / ZTNA
* Wireless
* Third‑party access
* East‑west / north‑south trust boundaries

## 2. Compute & Execution Environments
```
compute/
```

### 2.1 Endpoints (User‑Operated Compute)
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
### 2.2 Servers & Workloads
```
server/
├── server-core
├── server-attestation-and-trust
├── server-configuration-and-baseline
├── server-patch-and-vulnerability-posture
├── server-runtime-protection
├── server-monitoring-and-response
└── secure-server (composite)
```

## 3. Platform & Infrastructure
```
platform/
├── hosting-model-trust
├── infrastructure-management-plane-trust
```

### 3.1 Bare Metal
```
bare-metal/
└── bare-metal-core
```

### 3.1 Virtualization & Bare Metal
```
platform/
├── virtualization-core
├── hypervisor-trust
└── secure-virtualization (composite)
```
### 3.2 Cloud
```
cloud/
├── cloud-iaas-core
├── cloud-paas-core
├── cloud-saas-core
├── cloud-identity-and-access
├── cloud-networking
├── cloud-configuration-and-posture
├── cloud-monitoring-and-logging
├── cloud-third-party-access
├── cloud-access-security-broker (CASB)
└── trusted-cloud (composite)
```
### 3.3 High‑Performance Computing (HPC)
```
hpc/
├── hpc-core
├── hpc-identity-and-access
├── hpc-data-protection
└── secure-hpc (composite)
```

## 4. Data & Information Protection
```
data/
├── data-core
├── data-classification
├── data-handling-and-use
├── data-encryption
├── key-management
├── public-key-infrastructure (PKI)
├── data-loss-prevention
├── records-and-retention
└── trusted-data (composite)
```
Covers:
* Data handling rules
* Encryption at rest/in transit
* Keys & certificates
* Legal retention


## 5. Communications & Collaboration
```
communications/
```
### 5.1 Email
```
email/
├── email-core
├── email-identity
├── email-threat-protection
├── email-data-protection
├── email-records
├── email-notification-gateway
├── email-collaboration-relay
├── email-bulk-messaging-gateway
└── secure-email (composite)
```
#### Intent:
Trust in asynchronous, directed communication for both human and system‑initiated messages, including identity assurance, content protection, delivery integrity, and records obligations.

### 5.2 Collaboration & Messaging
```
collaboration/
├── collaboration-core
├── instant-messaging
├── presence-and-availability
├── conference-bridges
├── file-sharing-and-sync
├── real-time-messaging
└── secure-collaboration (composite)
```
#### Intent:
Trust in synchronous and near‑synchronous human collaboration systems, including chat, presence signals, meetings, shared workspaces, and live interaction.
#### Explicitly included:
* Instant messaging (high‑velocity, informal communication)
* Presence & availability (signal exposure and inference risk)
* Conference bridges (remote teaching, meetings, webinars)
  * recording & playback authority
  * participant awareness and consent
  * scope of capture (audio/video/chat/screen)
  * access to recordings, transcripts, and artifacts

### 5.3 Printing
```
printing/
├── printing-core
├── secure-print-release
├── print-data-protection
├── print-accountability
└── secure-printing (composite)
```
#### Intent:
Trust in physical output of digital content, including identity binding, data leakage prevention, secure release, and accountability for printed artifacts.

Printing remains a first‑class egress channel, not a legacy afterthought.

### 5.4 Survey & Feedback Systems
```
surveys/
├── survey
├── survey-core
├── survey-data-protection
├── survey-consent-and-ethics
└── secure-survey (composite)
```
#### Intent:
Trust in intentional data solicitation systems, including anonymity guarantees, consent, ethical obligations, and protection of responses across teaching, administration, and research use cases.

Surveys are treated as communications systems that create data, not merely data stores.

## 6. Application Integration & Messaging
```
integration/
├── integration-core
├── event-streaming
├── message-queuing
├── service-bus-and-esb
├── schema-and-contract-governance
├── message-security-and-integrity
├── replay-and-retention
└── trusted-integration (composite)
```

## 7. Secure Software Delivery (SDLC)
```
sdlc/
├── sdlc-core
├── sdlc-identity-and-attribution
├── sdlc-change-integrity
├── sdlc-supply-chain
├── sdlc-assurance
├── sdlc-operations-handover
└── secure-sdlc (composite)
```
Covers:
* Secure SDLC
* Software supply chain
* IaC
* DevSecOps assurance

## 8. Monitoring, Detection & Response
```
security-operations/
├── logging-and-telemetry
├── security-monitoring
├── threat-detection
├── incident-response
├── digital-forensics
└── security-operations (composite)
```

## 8. Resilience & Continuity
```
resilience/
├── backup-and-recovery
├── ransomware-resilience
├── disaster-recovery
├── continuity-of-operations
└── operational-resilience (composite)
```

## 10. Supply Chain & Third‑Party Risk
```
supply-chain/
├── vendor-risk-management
├── third-party-privileged-access
├── software-supply-chain
├── dependency-transparency (SBOM)
└── trusted-supply-chain (composite)
```

## 11. Domain‑Specific Systems

### 11.1 OT (Operational Technology)
```
ot/
├── ot-core
├── safety-zones-and-conduits
├── engineering-access-control
├── change-management
├── command-integrity
└── safe-and-secure-operations (composite)
```

### 11.2 IoT
```
iot/
├── device-core
├── device-identity
├── device-attestation
├── device-lifecycle
├── telemetry-data-protection
└── secure-iot (composite)
```

### 11.3 IoMT (Medical / Clinical)
```
iomt/
├── medical-device-core
├── patient-safety-assurance
├── clinical-data-protection
├── device-lifecycle-and-recall
└── safe-and-trusted-medical-operations (composite)
```

## 12. Artificial Intelligence & Research Systems
```
ai/
├── ai-core
├── ai-identity-and-access
├── accountability-and-oversight
├── decision-authority-and-human-reliance
├── agentic-behavior-governance
├── model-lifecycle-governance
├── training-and-derived-data-protection
├── context-and-tooling-security (MCP)
├── inference-protection
├── output-validity-and-uncertainty
├── bias-and-explainability
├── ai-telemetry-and-observability
├── ai-semantic-dlp
├── misuse-and-abuse-detection
├── ai-incident-response
├── ai-red-teaming-and-evaluation
├── agent-interconnection-and-delegation (A2A)
├── economic-and-resource-protection
├── knowledge-decommissioning
└── trustworthy-ai (composite)
```

## 13. Enterprise‑Wide Composite Views
These answer executive‑level questions:
```
enterprise/
├── secure-compute-environment
├── secure-communication-services
├── secure-software-delivery
├── safe-device-operations
└── enterprise-trust-posture
```