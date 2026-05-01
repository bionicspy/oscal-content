# Secure Software Delivery (SDLC) - Trust Plane Overview

Description
The Secure Software Delivery (SDLC) trust plane defines how software is designed, built, changed, verified, and handed over to operations in a secure, attributable, and auditable way.

This trust plane establishes trust in the software production process, not in runtime execution or business logic. It governs:
* who can introduce change,
* how change is authorized and protected,
* how software artifacts are produced and verified,
* and how assurance is carried from development into operations.

The SDLC trust plane is foundational to DevSecOps, Infrastructure‑as‑Code, and software supply chain security.

## Purpose
The purpose of the Secure SDLC trust plane is to ensure that:
* All software changes are attributable to identities
* Changes are authorized, reviewed, and protected from tampering
* Build and deployment pipelines are integrity‑preserving
* Software supply chain risks are managed and constrained
* Security assurance is built into delivery, not bolted on
* Operational handover preserves assurance continuity
* Software entering production is defensible, repeatable, and auditable

This trust plane allows the institution to assert that software arriving in execution environments is trustworthy by origin and process.

## Scope
### In Scope
The Secure SDLC trust plane applies to:
* Application code
* Infrastructure as Code (IaC)
* Build, test, and deployment pipelines
* Software artifacts and images
* Dependency and package supply chains
* Security testing and assurance activities
* Promotion and release processes
* Operational handover and evidence preservation

### Out of Scope
This trust plane does not define:
* Runtime execution security (Endpoint / Server planes)
* Network delivery paths (Network plane)
* Data classification or protection (Data plane)
* End‑user access controls (Identity plane)
* Business logic authorization

Those concerns consume SDLC trust, but do not establish it.

## Pattern Decomposition
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
Each pattern answers a distinct trust question about software delivery.

Pattern‑by‑Pattern Overview

### 1. sdlc-core
Defines what constitutes institutional software delivery and establishes baseline expectations.
#### Purpose
To establish legitimacy and scope for software delivery activities before controls are applied.
#### Scope
* Definition of SDLC activities
* Supported delivery models
* Baseline expectations for automation and governance

#### Components
* sdlc-scope-definition
  * Defines what delivery activities fall under institutional SDLC
* delivery-models
  * Defines supported delivery models (CI/CD, IaC, etc.)
* baseline-sdlc-trust-assumptions
  * Establishes minimum delivery expectations

#### Answers the Question
“What software delivery activities are governed by the institution?”


### 2. sdlc-identity-and-attribution
Establishes identity, accountability, and attribution for changes.
#### Purpose
To ensure every software change is traceable to a responsible identity.
#### Scope
* Developer identities
* Service and pipeline identities
* Commit, build, and deployment attribution

#### Components
* developer-and-contributor-identity
  * Identity of human contributors
* pipeline-and-automation-identity
  * Identity of CI/CD and automation actors
* change-attribution
  * Binding of changes to identities

#### Answers the Question
“Who introduced this software change?”


### 3. sdlc-change-integrity
Protects the integrity of software changes throughout the delivery pipeline.
#### Purpose
To prevent tampering, unauthorized changes, and unreviewed modifications.
#### Scope
* Source control protection
* Change approval and review
* Artifact immutability

#### Components
* change-authorization-and-approval
  * Required approvals for changes
* source-and-artifact-integrity
  * Protection of code and build outputs
* pipeline-integrity-controls
  * Integrity of CI/CD execution

#### Answers the Question
“Has this change been authorized and protected from tampering?”


### 4. sdlc-supply-chain
Manages risks introduced by third‑party and open‑source components.
#### Purpose
To ensure dependencies do not undermine software trust.
#### Scope
* External libraries and packages
* Build tools and base images
* Artifact provenance

#### Components
* dependency-identification-and-inventory
  * Identification of included components
* supply-chain-risk-evaluation
  * Assessment of third‑party risk
* provenance-and-origin-tracking
  * Tracking component origin

#### Answers the Question
“Where did this software come from?”


### 5. sdlc-assurance
Provides security assurance during software delivery.
#### Purpose
To detect defects and weaknesses before production release.
#### Scope
* Security testing
* Policy checks
* Compliance validation

#### Components
* secure-development-practices
  * Required secure coding expectations
* automated-and-manual-testing
  * SAST, DAST, SCA, reviews
* assurance-evidence-generation
  * Evidence for audits and traceability

#### Answers the Question
“Has this software been evaluated for security and policy compliance?”

### 6. sdlc-operations-handover
Ensures secure and complete transition from delivery to operations.
#### Purpose
To preserve SDLC assurance into runtime environments.
#### Scope
* Release promotion
* Deployment handover
* Operational documentation

#### Components
* release-authorization-and-promotion
  * Controlled promotion to environments
* deployment-artifact-integrity
  * Integrity of deployed artifacts
* assurance-continuity
  * Preservation of assurance context

#### Answers the Question
“Can operations trust what they are deploying?”

### 7. secure-sdlc (Composite)
Asserts holistic trust in the software delivery process.
#### Purpose
To provide an enterprise‑level assertion that software is delivered securely.
#### Scope
* Composition only
* No independent controls

#### Components (References)
```
sdlc-core
sdlc-identity-and-attribution
sdlc-change-integrity
sdlc-supply-chain
sdlc-assurance
sdlc-operations-handover
```
#### Answers the Question
“Can the institution trust this software delivery process?”