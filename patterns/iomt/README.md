# IoMT (Medical / Clinical) - Trust Plane Overview

The IoMT (Internet of Medical Things) trust plane defines how the institution operates, secures, and governs network‑connected medical and clinical devices whose primary purpose is diagnosis, treatment, monitoring, or patient care.

IoMT systems are fundamentally different from both:
* OT systems, which focus on industrial and environmental safety, and
* General IoT, which focuses on device identity and telemetry at scale.

IoMT systems are governed by clinical safety, patient outcomes, and regulatory obligations, where cybersecurity failures can directly result in patient harm, misdiagnosis, or interruption of care.

This trust plane explicitly integrates:
* Patient safety
* Clinical workflows
* Regulatory compliance
* Medical device lifecycle realities
* Cybersecurity as a safety control

## Purpose
The purpose of the IoMT trust plane is to ensure that:
* Medical devices operate safely and predictably
* Cybersecurity controls do not interfere with clinical care
* Device behavior cannot endanger patient safety
* Clinical data is accurate, protected, and trustworthy
* Device vulnerabilities are managed responsibly across long lifecycles
* Recall, patching, and remediation do not interrupt critical care
* The institution can demonstrate regulatory and safety diligence

This trust plane allows the institution to assert:
* “Our medical devices are safe, trustworthy, and appropriate for clinical use.”

## Scope
### In Scope
The IoMT trust plane applies to:
* Network‑connected medical devices
* Diagnostic, therapeutic, and monitoring equipment
* Bedside devices (infusion pumps, monitors, ventilators)
* Wearable or implantable medical devices (where applicable)
* Clinical gateways and device aggregation platforms
* Device‑generated clinical data
* Medical device maintenance, patching, and recall processes

## Out of Scope
This trust plane does not define:
* General hospital IT systems (Endpoint / Server planes)
* Clinical identity (identity plane governs staff, not devices)
* IoT devices used outside regulated medical contexts
* Supply‑chain governance (handled in Section 9)
* SOC detection logic (Security Operations plane)

Those planes support IoMT, but do not define medical device trust.

##Pattern Decomposition
```
iomt/
├── medical-device-core
├── patient-safety-assurance
├── clinical-data-protection
├── device-lifecycle-and-recall
└── safe-and-trusted-medical-operations (composite)
```
Each pattern answers a distinct medical trust question, explicitly separating clinical safety, data integrity, and device lifecycle governance.

### 1. medical-device-core
Defines what constitutes a medical device and its clinical risk context.
#### Purpose
To establish which devices fall under medical governance and what safety assumptions apply.
#### Scope
* Medical device identification
* Intended clinical use
* Device risk classification (patient impact)
#### Components
* medical-device-identification
  * Identification of regulated medical devices
* clinical-risk-classification
  * Impact of malfunction or misuse
* baseline-clinical-assumptions
  * Safe operating expectations
#### Answers the Question
“What devices are medical, and how could failure affect patients?”

### 2. patient-safety-assurance
Ensures cybersecurity supports patient safety rather than undermining it.
#### Purpose
To make patient safety the primary design and operational constraint.
#### Scope
* Cyber‑physical safety impact
* Fail‑safe and degradation behavior
* Safety validation and testing
#### Components
* safety-hazard-identification
  * Cyber risks to patient safety
* fail-safe-and-safe-state-controls
  * Safe degradation behavior
* safety-validation-and-testing
  * Cyber‑informed safety assurance
#### Answers the Question
“Can this device fail safely?”

### 3. clinical-data-protection
Protects the integrity and privacy of clinical data.
#### Purpose
To prevent incorrect clinical decisions due to corrupted or exposed data.
#### Scope
* Device‑generated clinical data
* Data integrity and authenticity
* Confidentiality and regulatory constraints
#### Components
* clinical-data-integrity
  * Prevention of data manipulation
* clinical-data-confidentiality
  * Protection of sensitive health data
* clinical-data-access-policy
  * Role‑ and context‑appropriate access
#### Answers the Question
“Can clinicians trust the data produced by devices?”

### 4. device-lifecycle-and-recall
Manages medical devices across long, regulated lifecycles.
#### Purpose
To ensure devices remain safe over time and during recalls.
#### Scope
* Installation and commissioning
* Patch and update constraints
* Vulnerability remediation
* Recall and retrofit processes
#### Components
* validated-device-provisioning
  * Clinical commissioning
* controlled-update-and-patching
  * Safety‑aware updates
* recall-and-decommissioning
  * Regulatory response controls
#### Answers the Question
“How do we update or retire devices without harming patients?”

### 5. safe-and-trusted-medical-operations (Composite)
Asserts holistic clinical device trust.
#### Purpose
To provide an enterprise‑level assertion of safe medical operations.
#### Scope
* Composition only
* No independent controls
#### Components (References)
```
medical-device-core
patient-safety-assurance
clinical-data-protection
device-lifecycle-and-recall
```
#### Answers the Question
“Are our medical devices safe, trustworthy, and appropriate for care delivery?”