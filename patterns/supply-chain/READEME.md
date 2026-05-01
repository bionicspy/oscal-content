# Supply Chain & Third‑Party Risk - Trust Plane Overview

The Supply Chain & Third‑Party Risk trust plane defines how the institution assesses, governs, constrains, and monitors risks introduced by external vendors, suppliers, and third‑party software components.

This plane recognizes that modern systems are composed ecosystems, not closed environments. It establishes trust boundaries, accountability, and assurance for:
* vendors and service providers,
* third‑party identities and access,
* software supply chains and dependencies,
* and transparency into what external components are present.

The focus is risk ownership and trust decisions, not detection or recovery.

## Purpose
The purpose of the Supply Chain & Third‑Party Risk trust plane is to ensure that:
* External vendors are assessed and governed proportionally to risk
* Third‑party access is explicit, limited, and auditable
* Software supply chains are understood and constrained
* Dependencies are transparent and traceable
* External risk does not silently bypass internal controls
* Institutional accountability for third‑party risk is clear

This plane allows the institution to assert:
* “We understand and control the risks introduced by third parties.”

## Scope
### In Scope
The Supply Chain & Third‑Party Risk trust plane applies to:
* Vendor onboarding, assessment, and ongoing risk review
* Third‑party identities and privileged access
* External service providers and SaaS platforms
* Software supply chains (build tools, packages, image bases)
* Dependency visibility and SBOMs
* Contractual and technical third‑party controls

### Out of Scope
This trust plane does not define:
* Internal identity governance (Identity plane)
* Network enforcement or segmentation (Network plane)
* Runtime defenses or exploit prevention (Compute planes)
* Security monitoring or response (Security Operations)
* Business continuity and recovery (Resilience plane)

Those planes consume supply‑chain trust decisions, but do not establish them.

## Pattern Decomposition
```
supply-chain/
├── vendor-risk-management
├── third-party-privileged-access
├── software-supply-chain
├── dependency-transparency (SBOM)
└── trusted-supply-chain (composite)
```
Each pattern answers a distinct third‑party trust question, avoiding overlap between organizational risk, access control, and software composition.

### 1. vendor-risk-management
Governs institutional risk arising from external vendors and service providers.
#### Purpose
To ensure vendors are assessed, approved, and monitored according to risk.
#### Scope
* Vendor due diligence and onboarding
* Periodic reassessment and assurance
* Contractual and control expectations

#### Components
* vendor-identification-and-classification
  * Categorization of vendors by risk and criticality
* risk-assessment-and-due-diligence
  * Initial and ongoing vendor risk evaluation
* contractual-and-control-requirements
  * Enforceable requirements and assurances

#### Answers the Question
“Can this vendor be trusted?”

### 2. third-party-privileged-access
Controls elevated access granted to third parties.
#### Purpose
To prevent vendors from becoming unbounded insiders.
#### Scope
* Privileged access by vendors
* Identity and access constraints
* Session monitoring and termination

#### Components
* third-party-identity-governance
  * Managed vendor identities
* privileged-access-constraints
  * Least‑privilege and just‑in‑time access
* access-monitoring-and-revocation
  * Oversight and rapid removal

#### Answers the Question
“What can vendors do inside our environment?”

### 3. software-supply-chain
Manages risk from third‑party software and build inputs.
#### Purpose
To ensure software trust is not undermined upstream.
#### Scope
* External libraries and packages
* Build tools and pipelines
* Artifact provenance

#### Components
* third-party-software-identification
  * Identification of external components
* supply-chain-risk-evaluation
  * Risk assessment of dependencies
* artifact-provenance-verification
  * Validation of software origin

#### Answers the Question
“Can we trust the software we did not write?”

### 4. dependency-transparency (SBOM)
Provides visibility into software composition.
#### Purpose
To make dependencies known, queryable, and governable.
#### Scope
* Software Bills of Materials (SBOMs)
* Dependency inventories
* Vulnerability correlation

#### Components
* sbom-generation-and-maintenance
  * Creation of SBOMs
* dependency-inventory-and-tracking
  * Ongoing visibility into components
* dependency-risk-analysis
  * Linking dependencies to risk intelligence

#### Answers the Question
“What third‑party components are we running?”

### 5. trusted-supply-chain (Composite)
Asserts holistic trust in third‑party relationships and software supply chains.
#### Purpose
To provide an enterprise‑level assertion of controlled supply‑chain risk.
#### Scope
* Composition only
* No independent controls

#### Components (References)
```
vendor-risk-management
third-party-privileged-access
software-supply-chain
dependency-transparency
```
#### Answers the Question
“Is our supply chain governed and trustworthy?”