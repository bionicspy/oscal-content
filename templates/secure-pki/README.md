## PKI & Key Management — Institutional Dependency Model

```mermaid
flowchart TB
    %% Core Trust Platforms
    ID["Secure Identity Platform"]
    NET["Secure Network Platform"]
    DATA["Secure Data Platform"]

    %% Crypto Platforms
    KM["Key Management Platform<br>(FIPS 140‑3)<br>• HSMs<br>• TPMs"]
    PKI["PKI Platform<br>(FIPS 140‑3)<br>• HSM‑backed CAs<br>• TPM‑backed identities"]

    %% Application Platforms
    APP1["LMS"]
    APP2["Research Platforms"]
    APP3["Administrative Systems"]
    COLLAB["Secure Collaboration"]
    EMAIL["Secure Email"]

    %% Dependencies
    DATA --> KM
    DATA --> PKI

    ID --> PKI
    NET --> PKI
    NET --> KM

    PKI --> APP1
    PKI --> APP2
    PKI --> APP3
    PKI --> COLLAB
    PKI --> EMAIL

    KM --> APP1
    KM --> APP2
    KM --> APP3
    KM --> COLLAB
    KM --> EMAIL

    %% Styling
    classDef platform fill:#e3f2fd,stroke:#0d47a1,stroke-width:2px;
    classDef crypto fill:#f3e5f5,stroke:#4a148c,stroke-width:2px;
    classDef app fill:#f8f9fa,stroke:#000;

    class ID,NET,DATA platform;
    class KM,PKI crypto;
    class APP1,APP2,APP3,COLLAB,EMAIL app;
```

---

## What this diagram enforces (architecturally)

- **Key Management and PKI are infrastructure, not features**
- **All crypto flows through KM and PKI**
- **Applications cannot own cryptographic trust**
- **Identity and Network anchor trust, but crypto is centralized**
- **FIPS 140‑3, HSMs, and TPMs sit at the foundation**

---

## Key Management Platform — Internal Trust Model

```mermaid
flowchart LR
    %% Hardware Roots
    TPM["TPM<br>(Device & Server Keys)"]
    HSM["HSM<br>(Shared / Privileged Keys)"]

    %% KM Services
    KMCORE["Key Management Platform<br>• Generation<br>• Rotation<br>• Revocation<br>• Destruction"]

    %% Consumers
    ENC["Data Encryption"]
    SIGN["Signing Services"]
    TLSK["TLS Private Keys"]

    TPM --> KMCORE
    HSM --> KMCORE

    KMCORE --> ENC
    KMCORE --> SIGN
    KMCORE --> TLSK

    %% Styling
    classDef hardware fill:#ede7f6,stroke:#311b92,stroke-width:2px;
    classDef core fill:#e8f5e9,stroke:#1b5e20,stroke-width:2px;
    classDef consumer fill:#fff3e0,stroke:#e65100,stroke-width:2px;

    class TPM,HSM hardware;
    class KMCORE core;
    class ENC,SIGN,TLSK consumer;
```

---

## What this diagram kills off

- ❌ Raw `.pem` / `.pfx` files
- ❌ App‑generated private keys
- ❌ Long‑lived, copied secrets
- ❌ Crypto hidden inside applications

---

## PKI Platform — Trust Establishment Model

```mermaid
flowchart TB
    %% Trust Anchors
    ROOT["Offline Root CA<br>(HSM‑Protected)"]
    INT["Intermediate CAs<br>(HSM‑Protected)"]

    %% PKI Services
    PKISVC["PKI Platform<br>• Issuance<br>• Validation<br>• Revocation"]

    %% Identities
    USER["User Certificates"]
    DEV["Device / Server Certificates<br>(TPM‑Backed)"]
    SVC["Service Certificates<br>(HSM / TPM‑Backed)"]

    %% Validation
    TLS["TLS / mTLS"]
    SIGN["Code / Data Signing"]

    ROOT --> INT
    INT --> PKISVC

    PKISVC --> USER
    PKISVC --> DEV
    PKISVC --> SVC

    USER --> TLS
    DEV --> TLS
    SVC --> TLS
    SVC --> SIGN

    %% Styling
    classDef anchor fill:#fff3e0,stroke:#e65100,stroke-width:2px;
    classDef pki fill:#e1f5fe,stroke:#01579b,stroke-width:2px;
    classDef identity fill:#f1f8e9,stroke:#33691e,stroke-width:2px;
    classDef use fill:#fce4ec,stroke:#880e4f,stroke-width:2px;

    class ROOT,INT anchor;
    class PKISVC pki;
    class USER,DEV,SVC identity;
    class TLS,SIGN use;
```

---

## What this diagram enforces

- **No application‑local CAs**
- **No self‑signed production certificates**
- **Mandatory revocation checking**
- **TPM‑backed device and server identity**
- **HSM‑backed CA private keys**

---

## Executive One‑Line Summary (Use This Verbally)

> **All cryptographic trust flows through Key Management and PKI.  
> Applications consume trust — they never create it.**

---

## Where this fits in your architecture

These diagrams complete your **crypto trust story**, sitting cleanly alongside:

- Secure Data SSPPs
- Secure Network SSPPs
- Secure Identity SSPPs

They give auditors, engineers, and executives **the same mental model**, which is exactly how you eliminate crypto debt permanently.