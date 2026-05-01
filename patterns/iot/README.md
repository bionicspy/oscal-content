# IoT (Internet of Things) - Trust Plane Overview

The IoT (Internet of Things) trust plane defines how the institution secures, governs, and operates large populations of connected devices that often exhibit:
* limited compute and storage,
* long or irregular lifecycles,
* intermittent connectivity,
* physical exposure,
* and vendor‑dependent firmware and cloud services.

Unlike OT systems, IoT systems typically prioritize scale, manageability, and data integrity over deterministic safety guarantees. Unlike traditional IT endpoints, IoT devices often cannot support full endpoint security stacks and must rely on identity, attestation, and lifecycle governance for trust.

This trust plane establishes device‑centric trust, ensuring that IoT devices are:
* known,
* authenticated,
* trustworthy at boot and runtime,
* lifecycle‑managed,
* and unable to exfiltrate or poison telemetry data.

## Purpose
The purpose of the IoT trust plane is to ensure that:
* Only authorized devices join the environment
* Devices possess verifiable identities
* Device software and state can be attested
* Devices can be securely provisioned, updated, and decommissioned
* Telemetry data is authentic, protected, and policy‑constrained
* Fleet‑scale risk is managed systematically

This plane allows the institution to assert:
* “We trust the devices producing data and acting at the edge.”

## Scope
### In Scope
The IoT trust plane applies to:
* Embedded and connected devices
* Sensors, actuators, meters, and controllers (non‑OT)
* Smart devices and appliances
* Mobile and edge‑deployed devices with device identity
* Device provisioning and onboarding
* Firmware, OS, and application lifecycle management
* Device telemetry and command channels

### Out of Scope
This trust plane does not define:
* Human user identity (Identity plane)
* Safety‑critical industrial control (OT plane)
* Traditional servers or workstations (Compute planes)
* SOC detection logic (Security Operations)
* Supply‑chain governance of vendors (Supply Chain plane)

Those planes interoperate with IoT, but do not establish device trust themselves.

## Pattern Decomposition
```
iot/
├── device-core
├── device-identity
├── device-attestation
├── device-lifecycle
├── telemetry-data-protection
└── secure-iot (composite)
```

Each pattern answers a distinct device‑trust question, avoiding the common mistake of conflating identity, firmware trust, fleet management, and data integrity.

### 1. device-core
Defines what constitutes an IoT device and its trust boundaries.
#### Purpose
To establish which devices are considered IoT and what baseline assumptions apply.
#### Scope
* Device classification and roles
* Physical and network trust boundaries
* Baseline security and capability assumptions
#### Components
* device-identification-and-classification
  * Identification of device types and roles
* device-trust-boundaries
  * Physical, logical, and network boundaries
* baseline-device-assumptions
  * Constraints on software, storage, and connectivity
#### Answers the Question
“What is an IoT device, and what can we reasonably trust it to do?”

### 2. device-identity
Provides cryptographic identity to devices.
#### Purpose
To ensure each device is uniquely identifiable and authenticable.
#### Scope
* Device identifiers and credentials
* Enrollment and authentication
* Identity binding to hardware
#### Components
* device-identity-provisioning
  * Secure issuance of device identities
* hardware-root-of-trust
  * TPM, secure element, or equivalent
* device-authentication
  * Mutual authentication with platforms
#### Answers the Question
“Which device is this?”

### 3. device-attestation
Verifies the software and runtime state of devices.
#### Purpose
To prevent compromised or unauthorized devices from participating.
#### Scope
* Boot integrity
* Firmware and OS measurement
* Runtime integrity assertions
#### Components
* boot-and-firmware-integrity
  * Measured and verified boot
* runtime-attestation
  * Ongoing trust signals
* attestation-verification
  * Validation of device claims
#### Answers the Question
“Is this device in a trustworthy state?”

### 4. device-lifecycle
Manages devices from onboarding to retirement.
#### Purpose
To ensure devices remain secure over long lifespans.
#### Scope
* Provisioning and onboarding
* Firmware updates and patching
* Decommissioning and revocation
#### Components
* secure-provisioning – Initial onboarding workflows
* update-and-patch-management – Controlled firmware updates
* decommissioning-and-revocation – Secure retirement
#### Answers the Question
“How do we manage devices over time?”

### 5. telemetry-data-protection
Protects data produced and consumed by devices.
#### Purpose
To ensure IoT data is authentic, confidential where required, and policy‑compliant.
#### Scope
* Telemetry integrity and authenticity
* Data confidentiality
* Command and response protection
#### Components
* telemetry-authentication-and-integrity
  * Prevent spoofed data
* telemetry-confidentiality
  * Encryption in transit
* telemetry-policy-enforcement
  * Data minimization and scope
#### Answers the Question
“Can we trust the data coming from devices?”

### 6. secure-iot (Composite)
Asserts holistic IoT device trust.
#### Purpose
To provide an enterprise‑level assertion that IoT devices are governed and trustworthy.
#### Scope
* Composition only
* No independent controls
#### Components (References)
```
device-core
device-identity
device-attestation
device-lifecycle
telemetry-data-protection
```
#### Answers the Question
“Are our IoT devices trustworthy?”