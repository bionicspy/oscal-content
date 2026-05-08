# COBO L1 – Managed Endpoint
**System Security Plan Profile (SSPP)**

## Overview
COBO L1 defines the baseline security and governance requirements for institution‑owned, centrally managed, general‑purpose endpoints. It represents the minimum acceptable assurance level for endpoints participating in routine institutional academic and administrative activities.

This SSPP establishes what must be true for an endpoint to be considered a trusted execution environment at a baseline level. All higher‑assurance endpoint tiers (for example, COBO L2 or Dedicated Administrative Workstations) build upon COBO L1 as a controlled extension.

## Purpose
The purpose of the COBO L1 SSPP is to:
* Establish a clear baseline of endpoint trust and governance
* Define non‑exceptional, default endpoint expectations
* Provide a stable inheritance root for higher‑assurance endpoint profiles
* Enable consistent, auditable access control decisions across the institution

COBO L1 is intentionally conservative, universal, and non‑specialized.

## Scope
This SSPP applies to:
* Institution‑owned endpoint devices
* Centrally managed computing platforms
* General‑purpose academic and administrative use

This SSPP does not define:
* Application‑specific authorization
* Data classification enforcement rules
* User role entitlements
* Exceptional or high‑risk workflows

Those concerns are addressed in application SSPPs, data SSPPs, or higher‑assurance endpoint profiles.

## Key Principles
### Device ≠ Data
Endpoint assurance levels are not equivalent to data classification levels.

* Endpoint classification describes the security posture, governance, and trustworthiness of a device.
* Data classification describes the sensitivity of information.
* A device’s classification does not, by itself, grant entitlement to any data classification.

Access decisions are made through policy by combining endpoint assurance with user role, context, and additional safeguards.

## Endpoint Characteristics
COBO L1 endpoints MUST be:
* Institution‑owned
* Centrally enrolled and managed
* Subject to full lifecycle governance
* Configured to a standard security baseline
* Continuously evaluated for health and compliance
* Protected against active threats at runtime

Endpoints that do not meet these criteria are not considered COBO L1.

## Pattern Inheritance
COBO L1 inherits the Secure Endpoint composite pattern and requires full realization of the following constituent patterns:

* **Endpoint Core**
  * Endpoint identity, enrollment, classification, and baseline trust
* **Endpoint Identity and Posture**
  * Unique device identity and posture signaling
* **Endpoint Configuration and Hardening**
  * Secure‑by‑default configuration and application control
* **Endpoint Health and Compliance**
  * Continuous health and compliance evaluation
* **Endpoint Threat Protection**
  * Runtime detection, prevention, and local containment of threats
* **Endpoint Lifecycle**
  * Formal provisioning, transition, recovery, and retirement

COBO L1 introduces no exceptions to these patterns.

## Data Eligibility
COBO L1 endpoints are eligible to participate in workflows involving:
* Data Classification Level 1
* Data Classification Level 2

Eligibility does not imply entitlement.

Actual access is determined through policy and remains conditional on user role, context, and applicable controls.

COBO L1 does not assert eligibility for Level 3 or higher data.

## Enforcement Model
For COBO L1 endpoints:
* Health and compliance are binary (compliant or blocked)
* Threat protection is mandatory and enforced
* Configuration drift or unmanaged state results in loss of trust
* No compensating controls or risk acceptances are defined at this tier

## What COBO L1 Does Not Include
COBO L1 does not include:
* Elevated developer tooling
* Privileged administrative workflows
* Specialized research environments
* Direct handling of high‑sensitivity data
* Conditional access rule definitions

These are addressed in higher‑assurance endpoint SSPPs or system‑specific SSPPs.

## Relationship to Higher Tiers
* COBO L2 builds upon COBO L1 by adding explicit additional assurance and governance controls.
* Dedicated Administrative Workstations (DAWs) represent purpose‑built trust environments with tighter scope and stronger alignment to sensitive data workflows.

COBO L1 remains the baseline reference point for all endpoint trust discussions.

## Status
**Authoritative Baseline**

This SSPP is intended to be stable over time. Changes should be rare, deliberate, and driven by institutional baseline updates rather than specific use cases.