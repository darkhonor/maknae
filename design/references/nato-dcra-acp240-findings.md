> **IMPORTED COMPANION REFERENCE (2026-07-15).** Copied verbatim from the
> operator's Security MCP Server repository
> (`data/dcs/NATO-DCRA-ACP240-Findings.md`,
> https://gitlab.com/homelab-systems/security-mcp-server) as supporting
> reference for [`../abac-dcs-architecture.md`](../abac-dcs-architecture.md)
> section 14 (ACP 240 / NATO DCRA gap). Findings extract only — the full
> ACP 240 text remains a required reference before final design. Treat as a
> read-only snapshot; the origin repository owns the living document.

<!--
  Filename: NATO-DCRA-ACP240-Findings.md
  Last Modified: 2026-01-30
  Summary: Research findings from NATO Data Centric Reference Architecture (DCRA v2)
           and ACP 240 / Zero Trust Data Format with design objectives, data tagging
           standards, and model change requirements for Allied/Partner MCP interoperability
  Sources: https://nhqc3s.hq.nato.int/apps/DCRA_Report/index.html
           AC/322-D(2025)0056 - Data Centric Reference Architecture v2
  Compliant With: DoD STIG, NIST SP800-53 Rev 5, FIPS 140-3
  Classification: UNCLASSIFIED
-->

# NATO Data Centric Reference Architecture (DCRA v2) & ACP 240

## Research Findings for Security MCP Server — Allied/Partner Interoperability

**Date Reviewed:** 2026-01-30
**Publication:** AC/322-D(2025)0056 — Data Centric Reference Architecture for the
Alliance, Version 2 (28 May 2025)
**Interactive Model:** <https://nhqc3s.hq.nato.int/apps/DCRA_Report/index.html>
**Publishing Body:** NATO C3 Staff (AC/322)
**Cross-Reference:** [NIST-SP-1800-35-ZTA-Findings.md](./NIST-SP-1800-35-ZTA-Findings.md)

---

## Table of Contents

1. [Document Overview](#1-document-overview)
2. [NATO Data Principles](#2-nato-data-principles)
3. [DCRA Sub-Architectures](#3-dcra-sub-architectures)
4. [Data Tagging Standards (Critical)](#4-data-tagging-standards-critical)
5. [ACP 240 & Zero Trust Data Format](#5-acp-240--zero-trust-data-format)
6. [Data Classification Framework](#6-data-classification-framework)
7. [Data Standards Framework](#7-data-standards-framework)
8. [Metadata Association Requirements](#8-metadata-association-requirements)
9. [CMBAC Access Control Model](#9-cmbac-access-control-model)
10. [MCP Model Changes for Allied/Partner Use](#10-mcp-model-changes-for-alliedpartner-use)
11. [Cross-Reference: ZTA Gap Analysis](#11-cross-reference-zta-gap-analysis)
12. [References](#12-references)

---

## 1. Document Overview

The NATO Data Centric Reference Architecture (DCRA) is NATO's foundational
blueprint for transitioning from an application-centric to a **data-centric
organization**. Version 2 was released 28 May 2025 and provides common
functionality, security, and interoperability requirements for organizations
defining target or solution architectures.

### Strategic Drivers

- **Digital Transformation Implementation Strategy**
- **Data Exploitation Framework Strategic Plan**
- **Data Strategy for the Alliance (DaSA)** — approved February 2025

### Key Distinction from US-Only Standards

> The DCRA is **architecture-agnostic** — it does not prescribe specific systems,
> Communities of Interest, or domains. This means our MCP must implement
> interoperability at the **data layer**, not the application layer, to operate
> within Allied environments.

### Related NATO Architectures

| Architecture | Relationship to DCRA |
|-------------|---------------------|
| Architecture for Interoperability of Digital Technologies (AIDA) | Parent framework |
| Identity Reference Architecture | Identity federation for Allied users |
| NATO Digital Backbone Reference Architecture (Increment 1) | Infrastructure layer |

---

## 2. NATO Data Principles

The **Data Strategy for the Alliance** defines eight data principles that form the
cornerstone of NATO's data governance framework. All programmes that employ,
generate, or create data must adhere to these principles.

| # | Principle | Description | MCP Impact |
|---|-----------|-------------|------------|
| 1 | **Discoverable Data** | Data must be searchable with visible metadata to authorized users | MCP must expose metadata for STIG rules to Allied discovery services |
| 2 | **Accessible Data** | Available through appropriate mechanisms to authorized entities | MCP API must support NATO-standard access protocols |
| 3 | **Quality-Managed Data** | Maintaining high data standards and integrity | STIG data provenance and versioning must be verifiable |
| 4 | **Interoperable & Curated Data** | Compatibility among allies and enterprises | Data models must align with NATO Core Data Framework |
| 5 | **Trusted Data** | Users can verify data integrity and system reliability | Cryptographic integrity verification required |
| 6 | **Regulated Data** | Managed per international agreements and NATO policies | Access policies must support multinational release markings |
| 7 | **Shared Data** | Distributed securely among authorized parties | MCP must support secure cross-domain data sharing |
| 8 | **Secured Data** | Protected throughout lifecycle per owner specifications | Data-centric security labels must travel with data |

---

## 3. DCRA Sub-Architectures

The DCRA encompasses eight specialized reference architectures:

| Sub-Architecture | MCP Relevance |
|-----------------|---------------|
| **Data Space Reference Architecture** | Defines shared data exchange spaces — MCP could participate as a data product provider |
| **Data Mesh Reference Architecture** | Decentralized data ownership — aligns with MCP microservices model |
| **Data Analytics Reference Architecture** | AI/ML consumers of STIG data must receive properly labeled data |
| **Data Labelling Reference Architecture** | **CRITICAL** — Defines how security labels are applied to data objects |
| **Data Modelling & Design Reference Architecture** | Data models must follow NATO standards for interoperability |
| **Data Centric Governance Reference Architecture** | Governance rules for data stewardship apply to MCP as data provider |
| **Data Standardization Reference Architecture** | Standards compliance (STANAGs) required for Allied use |
| **Zero Trust / Data Centric Security Reference Architecture** | Directly overlaps with our ZTA design objectives |

---

## 4. Data Tagging Standards (Critical)

These three standards form the **"metadata infrastructure trinity"** that ALL
NATO data systems must implement. This is the single most significant gap between
our current US DoD-only MCP design and Allied/Partner interoperability.

### 4.1 STANAG 4774 — Confidentiality Metadata Label Syntax (ADatP-4774)

**Edition:** A Version 1 (20 December 2017)
**Responsible Body:** DPC CaP1 Data Management Capability Team
**Based On:** NSA SDN.801c model

#### Purpose

Defines an XML schema for confidentiality (security) labels that travel with
data objects. This is the **machine-readable security classification label**.

#### Classification Levels

```
UNCLASSIFIED → RESTRICTED → CONFIDENTIAL → SECRET → TOP SECRET
```

> **Note:** NATO uses `RESTRICTED` between UNCLASSIFIED and CONFIDENTIAL.
> The US does not have a `RESTRICTED` level. This is a model change.

#### Label Structure

```xml
<ConfidentialityLabel>
  <PolicyIdentifier>
    <OID>2.16.840.1.101.2.1.3.13</OID>   <!-- Globally unique OID -->
    <Name>NATO</Name>
  </PolicyIdentifier>
  <Classification>SECRET</Classification>
  <Category>
    <Type>PERMISSIVE</Type>
    <TagName>REL TO</TagName>
    <GenericValue>USA, GBR, CAN, AUS, NZL</GenericValue>
  </Category>
  <Category>
    <Type>RESTRICTIVE</Type>
    <TagName>ATOMAL</TagName>
  </Category>
  <CreatedDateTime>2026-01-30T14:00:00Z</CreatedDateTime>
  <ExpirationDateTime>2027-01-30T14:00:00Z</ExpirationDateTime>
</ConfidentialityLabel>
```

#### Encoding Formats

| Format | Use Case |
|--------|----------|
| **XML** | Primary format, full schema support |
| **JSON** | REST APIs, modern web services |
| **CBOR** | Constrained environments (IoT, tactical edge) |

#### Category Mechanism

| Category Type | Purpose | Example |
|--------------|---------|---------|
| **Restrictive** | Limits access to specific communities | `ATOMAL`, `CRYPTO`, `BOHEMIA` |
| **Permissive** | Enables release to specified nations/orgs | `REL TO USA, GBR, CAN` |

#### Lifecycle Metadata

- Creator identity
- Creation timestamp (ISO 8601)
- Expiration/review date
- Policy identifier (OID + name)

#### Companion Documents

| Document | Content |
|----------|---------|
| **ADatP-4774.1** | Implementation guidance for Confidentiality Metadata Label Syntax |
| **ADatP-4774.2** | Guidance on the Digital Labelling of NATO Information |

---

### 4.2 STANAG 4778 — Metadata Binding Mechanism (ADatP-4778)

**Edition:** A Version 1 (26 October 2018)
**Responsible Body:** DPC CaP1 Data Management Capability Team
**Origin:** NATO STO Research Task Group IST-068/RTG-031 on Cross Domain Security
Solutions (2010)

#### Purpose

Defines how metadata (including STANAG 4774 confidentiality labels) is **bound**
to data objects throughout their lifecycle and between sharing parties. This
ensures labels cannot be separated from the data they protect.

#### Key Capabilities

- XML Schema for binding arbitrary metadata to information objects
- **Cryptographic binding** via digital signature mechanisms
- **Portion marking** — multiple labels for different data segments within a
  single object
- References IETF RFC 6901 (JSON Pointer) and IETF RFC 7159 (JSON)

#### Binding Profiles (ADatP-4778.2, Edition A Ver 1, December 2020)

| Profile | Use Case | MCP Relevance |
|---------|----------|---------------|
| **REST** | RESTful API responses | **HIGH** — Primary MCP transport |
| **SOAP** | Web services | Medium — Legacy integration |
| **XMPP** | Chat/messaging | Low |
| **SMTP** | Email / military messaging | Low |
| **Common XML Artefacts** | General XML documents | Medium — XCCDF/SCAP content |
| **Cryptographic Artefact Binding** | Signed/encrypted objects | **HIGH** — Integrity verification |
| **XMP (Extensible Metadata Platform)** | Embedded file metadata | Low |
| **Generic Open Packaging** | Container formats | Low |
| **Office Open XML** | Documents (OOXML) | Low |
| **Sidecar Files** | External metadata files | Medium — Could apply to STIG exports |

> **MCP Impact:** The REST binding profile and Cryptographic Artefact Binding
> are directly applicable to our MCP API responses. Every API response containing
> STIG data must carry a bound confidentiality label.

---

### 4.3 STANAG 5636 — NATO Core Metadata Specification (ADatP-5636)

**Edition:** A Version 1 (18 November 2022)
**Responsible Body:** DPC CaP1 Data Management Capability Team

#### Purpose

Defines a common set of structured metadata attributes that support **discovery
and effective use** of data assets using search tools. This is the metadata that
makes data findable across the Alliance.

#### Technical Details

- Incorporates practices from Dublin Core Metadata Initiative (DCMI)
- References ISO 19115-1 (Geographic information — Metadata)
- Aligns with ISO and military/civilian metadata standards
- Provides XML schema definitions for implementation

#### Relationship to Other Standards

- **STANAG 4774** security labels **must** accompany each data asset
- **STANAG 4778** binding **must** be used to associate metadata with data
- Together they form the **mandatory metadata infrastructure** for NATO systems

---

## 5. ACP 240 & Zero Trust Data Format

### 5.1 ACP 240 — Allied Communication Publication 240

**Origin:** Combined Communications-Electronics Board (CCEB / Five Eyes)
**Ratification:** 2025 — adopted through NATO CCEB process

#### Paradigm Shift

ACP 240 represents a fundamental shift from **network-centric security** to
**data-centric security**:

| Network-Centric (Legacy) | Data-Centric (ACP 240) |
|--------------------------|----------------------|
| Security at the perimeter | Security embedded in data |
| Classification by network | Classification by data attributes |
| Access = network membership | Access = user attributes + policy |
| Static policies | Dynamic, attribute-based policies |
| Cross-domain solutions (CDS) required | Data flows across boundaries with embedded protection |
| Months to add partners | Minutes to add/remove access |

#### Key Characteristics

- Security attributes **embedded within data objects**
- Classification determined by **data properties, not network location**
- Compatible across email, file shares, and collaboration platforms
- Built on the **Zero Trust Data Format (ZTDF)**

### 5.2 Zero Trust Data Format (ZTDF)

**Foundation:** Virtru's Trusted Data Format (TDF)
**Adoption:** 2025, ratified through NATO CCEB

#### Capabilities

- Embeds access controls and classification metadata directly into documents
- Every interaction with protected data is **logged and traceable**
- Personnel added/removed from access in **minutes, not months**
- Data decryption requires proper user attributes (independent of network)

#### Operational Validation — Operation HIGHMAST

The UK Royal Navy's global carrier strike group deployment validated ACP 240
under real operational conditions:

- **Multi-partner data sharing** across allied commands ✓
- **Classified information exchange** while maintaining security ✓
- **Operational agility** improvement over legacy approaches ✓
- Data shared across **multiple command boundaries and allied partners** ✓

### 5.3 ACP 240 Implementation Timeline

**Critical Deadline: 2027** — Defense organizations must operationalize
data-centric security capabilities.

**Ecosystem Partners:** Everfox, Pexip, and others building ACP 240-compliant
solutions for Google Workspace, Microsoft 365, and specialized defense systems.

---

## 6. Data Classification Framework

The DCRA defines a classification framework with **eight dimensions**:

| Dimension | Description | Values/Examples |
|-----------|-------------|-----------------|
| **Data Domain** | Business area categorization | Finance, operations, intelligence, logistics |
| **Data Ownership** | Stewardship accountability | Nation, NATO body, partner organization |
| **Data Sensitivity** | Security classification | UNCLASSIFIED → RESTRICTED → CONFIDENTIAL → SECRET → TOP SECRET |
| **Lifecycle Stage** | Current data state | Raw, Processed, Archived, Purged |
| **Data Quality** | Integrity metrics | Accuracy, completeness, consistency, timeliness, validity |
| **Format Type** | Structure level | Structured, semi-structured, unstructured |
| **Access Frequency** | Usage priority | Hot, warm, cold |
| **Geographic Origin** | Regulatory jurisdiction | Regional classification for legal compliance |

> **MCP Impact:** Our current model only captures US DoD classification
> (UNCLASSIFIED / CUI / CONFIDENTIAL / SECRET / TOP SECRET). The NATO model adds
> `RESTRICTED` and requires all eight classification dimensions.

---

## 7. Data Standards Framework

The DCRA's data standards layer requires:

| Standard | Requirement | MCP Impact |
|----------|-------------|------------|
| **RDF 1.1** | Semantic data description | STIG rule relationships could be expressed as RDF |
| **JSON-LD 1.1** | Linked data serialization (conformance required) | MCP API responses could embed JSON-LD context |
| **NATO Data Space Transfer Protocol** | Secure data exchange (mandatory) | Required for data space participation |
| **DIN SPEC 27070:2020-03** | Security gateway requirements | Three-tier security conformance model |
| **NATO Domain Ontology** | Defence & Security semantics | Semantic interoperability and AI support |

### DIN SPEC 27070 Security Tiers

| Tier | Level | Description |
|------|-------|-------------|
| 1 | **Basic** | Minimum security requirements |
| 2 | **Trust** | Enhanced trust verification |
| 3 | **Trust Plus** | Maximum security assurance |

---

## 8. Metadata Association Requirements

### Mandatory Implementation

From the DCRA's "Associate Metadata with Data Assets" element
(Source: AC/322-D(2024)0166):

> All data posted to shared data spaces **MUST** include metadata per STANAG 5636
> (NCMS). Security-related metadata **MUST** accompany each data asset per
> STANAG 4774. Metadata binding **MUST** follow STANAG 4778.

### Implementation Mandate

From the DCRA's "Facilitate Implementation of NATO Core Metadata Standards"
(Source: PO(2023)0191 (INV), Processing Code 06.03):

> "Allies and the NATO Enterprise are to pursue Alliance data interoperability by
> implementing NATO Core Metadata Standards (STANAGs 4774, 4778, and 5636),
> including location (as per geospatial metadata standards) as the **first step**
> towards NATO becoming a data-centric organization."

---

## 9. CMBAC Access Control Model

**Confidentiality Metadata-Based Access Control (CMBAC)** is the enforcement
mechanism for data-centric security. It implements the "Holy Trinity":

```
┌─────────────────────┐
│   STANAG 4774       │    Associated with a RESOURCE
│   Confidentiality   │    (e.g., a STIG rule or API response)
│   Label             │
└────────┬────────────┘
         │
         │  compared against
         ▼
┌─────────────────────┐
│   STANAG 4774       │    Associated with a USER/APPLICATION/
│   Confidentiality   │    DEVICE/SERVICE
│   Clearance         │    (e.g., MCP client identity)
└────────┬────────────┘
         │
         │  using rules defined in
         ▼
┌─────────────────────┐
│   XMLSPIF           │    Security Policy Information File
│   (Security Policy  │    Defines label-to-clearance matching
│    Information File) │    rules, equivalence mappings, and
│                     │    cross-domain transformations
└─────────────────────┘
```

### CMBAC Enforcement Functions

| Function | Description | MCP Application |
|----------|-------------|-----------------|
| **Delivery Authorization** | Match user clearance to data label | MCP gateway checks client clearance before returning STIG data |
| **Onward Transfer Validation** | Prevent unauthorized redistribution | MCP prevents export of data beyond authorized release markings |
| **Channel Clearance Verification** | Verify transport path is authorized | Ensures MCP transport meets classification requirements |
| **Label Transformation** | Convert between security policies | Map between US DoD and NATO classification schemes |

### SPIF (Security Policy Information File)

The XMLSPIF defines:

- Label display specifications (multilingual support)
- Label-to-clearance matching rules
- **Equivalence mappings** for cross-domain label transformation
- Policy-specific category definitions and constraints
- Color coding for user interface presentation

> **Critical for MCP:** The SPIF enables **label transformation** between US DoD
> and NATO classification schemes. This is how our MCP bridges between
> `CUI // REL TO USA` and `NATO RESTRICTED // REL TO USA, GBR, CAN, AUS, NZL`.

---

## 10. MCP Model Changes for Allied/Partner Use

Based on the DCRA, ACP 240, and STANAG requirements, the following model changes
are required for our Security MCP Server to operate with Allied and Partner
nations.

### 10.1 Database Schema Changes

#### New: Confidentiality Label Table

```
confidentiality_labels
├── label_id (UUID, PK)
├── policy_oid (VARCHAR) -- e.g., "2.16.840.1.101.2.1.3.13"
├── policy_name (VARCHAR) -- e.g., "NATO", "US-DoD"
├── classification (ENUM) -- UNCLASSIFIED, RESTRICTED, CONFIDENTIAL, SECRET, TOP_SECRET
├── categories (JSONB) -- Array of {type, tag_name, values}
├── created_by (VARCHAR) -- Creator identity
├── created_at (TIMESTAMPTZ) -- ISO 8601 UTC
├── expires_at (TIMESTAMPTZ) -- Review/expiration date
├── label_xml (TEXT) -- Full STANAG 4774 XML
├── label_json (JSONB) -- JSON encoding
└── digital_signature (BYTEA) -- Optional cryptographic binding
```

#### New: Metadata Binding Table

```
metadata_bindings
├── binding_id (UUID, PK)
├── data_object_type (VARCHAR) -- 'stig_rule', 'checklist', 'assessment'
├── data_object_id (UUID, FK)
├── label_id (UUID, FK → confidentiality_labels)
├── binding_profile (VARCHAR) -- 'REST', 'XML', 'CRYPTO', 'SIDECAR'
├── portion_path (VARCHAR) -- JSON Pointer (RFC 6901) for portion marking
├── signature (BYTEA) -- Cryptographic binding signature
├── bound_at (TIMESTAMPTZ)
└── bound_by (VARCHAR)
```

#### New: Core Metadata Table (STANAG 5636 / NCMS)

```
core_metadata
├── metadata_id (UUID, PK)
├── data_object_type (VARCHAR)
├── data_object_id (UUID, FK)
├── title (VARCHAR) -- Dublin Core: Title
├── creator (VARCHAR) -- Dublin Core: Creator
├── subject (VARCHAR[]) -- Dublin Core: Subject/Keywords
├── description (TEXT) -- Dublin Core: Description
├── publisher (VARCHAR) -- Dublin Core: Publisher
├── date_created (TIMESTAMPTZ) -- Dublin Core: Date
├── format (VARCHAR) -- MIME type
├── identifier (VARCHAR) -- Unique resource identifier
├── language (VARCHAR) -- ISO 639 language code
├── coverage_spatial (GEOMETRY) -- ISO 19115 geospatial
├── data_domain (VARCHAR) -- NATO classification dimension
├── data_ownership (VARCHAR) -- Steward nation/org
├── lifecycle_stage (VARCHAR) -- Raw, Processed, Archived
├── quality_score (JSONB) -- Accuracy, completeness, etc.
└── label_id (UUID, FK → confidentiality_labels)
```

#### Modified: Existing Tables

| Table | Change | Reason |
|-------|--------|--------|
| `stig_rules` | Add `label_id` FK | Every rule needs a confidentiality label |
| `stig_rules` | Add `release_markings` (VARCHAR[]) | REL TO nations list |
| `stig_rules` | Add `originating_nation` (VARCHAR) | Data ownership tracking |
| `checklists` | Add `label_id` FK | Assessment results need classification |
| `benchmarks` | Add `label_id` FK | STIG benchmarks need classification |
| `cci_mappings` | Add `label_id` FK | CCI data needs classification |

### 10.2 API Response Changes

#### Current US DoD-Only Response

```json
{
  "rule_id": "SV-230221r858695_rule",
  "title": "RHEL 9 must implement NIST FIPS-validated cryptography",
  "severity": "high",
  "check_content": "...",
  "fix_text": "..."
}
```

#### Required Allied/Partner Response (STANAG-Compliant)

```json
{
  "@context": "https://w3id.org/nato/dcra/v2",
  "rule_id": "SV-230221r858695_rule",
  "title": "RHEL 9 must implement NIST FIPS-validated cryptography",
  "severity": "high",
  "check_content": "...",
  "fix_text": "...",
  "confidentiality_label": {
    "policy": {
      "oid": "2.16.840.1.101.2.1.3.13",
      "name": "NATO"
    },
    "classification": "UNCLASSIFIED",
    "categories": [
      {
        "type": "PERMISSIVE",
        "tag": "REL TO",
        "values": ["NATO"]
      }
    ],
    "created": "2026-01-30T14:00:00Z",
    "creator": "security-mcp-server"
  },
  "metadata_binding": {
    "profile": "REST",
    "signature": "base64-encoded-signature",
    "algorithm": "SHA-256"
  },
  "core_metadata": {
    "publisher": "DISA",
    "language": "en",
    "data_domain": "cybersecurity",
    "data_ownership": "USA",
    "lifecycle_stage": "processed",
    "format": "application/json"
  }
}
```

### 10.3 Gateway / PEP Changes

| Change | Description | Priority |
|--------|-------------|----------|
| **CMBAC Engine** | Implement label-to-clearance matching in the security-gateway | Critical |
| **SPIF Parser** | Parse XMLSPIF files defining security policy rules | Critical |
| **Label Generator** | Generate STANAG 4774 labels for API responses | Critical |
| **Binding Engine** | Implement STANAG 4778 REST binding profile | Critical |
| **Clearance Store** | Store client/user clearance attributes alongside identity | High |
| **Label Transformation** | Map between US DoD and NATO classification policies | High |
| **Portion Marking** | Support different labels for different parts of a response | Medium |

### 10.4 Classification Level Mapping

| US DoD | NATO | Notes |
|--------|------|-------|
| UNCLASSIFIED | UNCLASSIFIED | Direct equivalence |
| CUI | *(no direct equivalent)* | May map to NATO RESTRICTED depending on CUI category |
| CUI // REL TO FVEY | NATO RESTRICTED // REL TO USA, GBR, CAN, AUS, NZL | Requires SPIF equivalence mapping |
| CONFIDENTIAL | CONFIDENTIAL | Direct equivalence |
| SECRET | SECRET | Direct equivalence |
| TOP SECRET | COSMIC TOP SECRET | NATO uses COSMIC prefix |

> **⚠️ WARNING:** Classification equivalence mapping is a **policy decision**,
> not a technical one. The SPIF defines the rules, but the rules themselves must
> be approved by appropriate classification authorities. Our MCP implements the
> mechanism; the policy comes from the customer's security office.

### 10.5 New MCP Tools Required

| Tool | Purpose | STANAG |
|------|---------|--------|
| `get_label` | Retrieve the confidentiality label for a data object | 4774 |
| `set_label` | Apply a confidentiality label to a data object | 4774 |
| `validate_label` | Verify a label against a SPIF policy | 4774 |
| `check_clearance` | Verify if a user/client has clearance for a labeled object | 4774 CMBAC |
| `transform_label` | Convert a label between security policies (US↔NATO) | 4774 + SPIF |
| `bind_metadata` | Cryptographically bind metadata to a data object | 4778 |
| `get_core_metadata` | Retrieve NCMS metadata for a data object | 5636 |
| `search_by_metadata` | Discover data objects via NCMS metadata search | 5636 |

---

## 11. Cross-Reference: ZTA Gap Analysis

Mapping the NATO DCRA requirements against our existing ZTA design objectives
from [NIST-SP-1800-35-ZTA-Findings.md](./NIST-SP-1800-35-ZTA-Findings.md):

### Objectives That Require Enhancement for NATO

| ZTA Objective | Current Scope | NATO Enhancement Required |
|---------------|--------------|--------------------------|
| **MCP-ZTA-02** (Federated Identity) | OAuth 2.0 / OIDC | Add support for NATO Identity Reference Architecture, SAML for legacy Allied systems |
| **MCP-ZTA-06** (Policy Engine) | Identity + request type + resource sensitivity | Add CMBAC label-to-clearance evaluation and SPIF-based policy decisions |
| **MCP-ZTA-07** (Per-tool ACLs) | Tool-level access control | Add data-level access control based on confidentiality labels per STANAG 4774 |
| **MCP-ZTA-09** (RBAC Roles) | Reader, assessor, admin | Add nation-based and coalition-based roles (e.g., FVEY reader, NATO assessor) |
| **MCP-ZTA-12** (Resource-level ACL) | By classification/org | By STANAG 4774 label with REL TO nation checks |
| **MCP-ZTA-14** (Audit Logging) | Identity, timestamp, tool, params, result, IP | Add classification label of accessed data, client clearance used, label transformation events |
| **MCP-ZTA-17** (TLS 1.2+) | Transport encryption | Must also support data-at-rest labeling per ACP 240 (security travels WITH data, not just in transit) |
| **MCP-ZTA-18** (Data Classification) | UNCLASSIFIED / CUI markings | Full STANAG 4774 label with policy OID, categories, and NATO classification levels |

### New Objectives Required (Not in ZTA Document)

| Objective | Description | Priority | Standards |
|-----------|-------------|----------|-----------|
| **MCP-NATO-01** | Implement STANAG 4774 confidentiality label generation and parsing (XML, JSON, CBOR) | Critical | STANAG 4774 |
| **MCP-NATO-02** | Implement STANAG 4778 REST metadata binding profile for all API responses | Critical | STANAG 4778, ADatP-4778.2 |
| **MCP-NATO-03** | Implement STANAG 5636 (NCMS) core metadata for STIG data asset discovery | High | STANAG 5636 |
| **MCP-NATO-04** | Implement CMBAC engine with XMLSPIF policy evaluation | Critical | STANAG 4774, XMLSPIF |
| **MCP-NATO-05** | Support classification level transformation between US DoD and NATO policies | High | STANAG 4774 + SPIF |
| **MCP-NATO-06** | Add `RESTRICTED` classification level to data model (not present in US system) | Critical | NATO classification policy |
| **MCP-NATO-07** | Support REL TO (release marking) with nation codes per STANAG 1059 | Critical | STANAG 4774, STANAG 1059 |
| **MCP-NATO-08** | Implement portion marking for mixed-classification API responses | Medium | STANAG 4778 |
| **MCP-NATO-09** | Support JSON-LD 1.1 context in API responses for linked data interoperability | Medium | DCRA Data Standards |
| **MCP-NATO-10** | Implement data provenance tracking (originating nation, data ownership) | High | DaSA Principle 5 (Trusted Data) |
| **MCP-NATO-11** | Support ACP 240 / ZTDF for data-centric security on exported data objects | High | ACP 240, ZTDF |
| **MCP-NATO-12** | Implement NATO Core Data Framework (NCDF) API alignment when ADatP-5659 is finalized | Low | STANAG 5653 (study phase) |

### Maturity Path Extension

| Phase | NATO Objectives | Description |
|-------|----------------|-------------|
| **Crawl** (US DoD + basic NATO) | MCP-NATO-01, 06, 07 | STANAG 4774 labels, RESTRICTED level, REL TO markings |
| **Walk** (NATO interoperable) | MCP-NATO-02, 03, 04, 05, 10 | REST binding, NCMS metadata, CMBAC engine, label transformation, provenance |
| **Run** (Full Allied/Partner) | MCP-NATO-08, 09, 11, 12 | Portion marking, JSON-LD, ACP 240/ZTDF export, NCDF API alignment |

---

## 12. References

### NATO Standards (STANAGs)

| Standard | Title | Date |
|----------|-------|------|
| STANAG 4774 / ADatP-4774 | Confidentiality Metadata Label Syntax | Dec 2017 |
| ADatP-4774.1 | Implementation Guidance for CMLS | — |
| ADatP-4774.2 | Guidance on Digital Labelling of NATO Information | — |
| STANAG 4778 / ADatP-4778 | Metadata Binding Mechanism | Oct 2018 |
| ADatP-4778.2 | Profiles for Binding Metadata to Data Objects | Dec 2020 |
| STANAG 5636 / ADatP-5636 | NATO Core Metadata Specification (NCMS) | Nov 2022 |
| STANAG 5653 / ADatP-5653 | NATO Core Data Framework (NCDF) | Study phase |
| ADatP-5659 | NCDF Application Programming Interfaces | Study phase |
| STANAG 1059 | National Distinguishing Letters | — |

### NATO Publications

| Document | Title | Date |
|----------|-------|------|
| AC/322-D(2025)0056 | Data Centric Reference Architecture for the Alliance, v2 | May 2025 |
| AC/322-D(2024)0166 | DC-Data Vision | 2024 |
| PO(2023)0191 (INV) | Implementation of NATO Core Metadata Standards | 2023 |
| DaSA | Data Strategy for the Alliance | Feb 2025 |

### ACP & FVEY

| Document | Title | Date |
|----------|-------|------|
| ACP 240 | Allied Communication Publication 240 (Data-Centric Security) | 2025 |
| ZTDF | Zero Trust Data Format | 2025 |

### Supporting Standards

| Standard | Title |
|----------|-------|
| DIN SPEC 27070:2020-03 | Security Gateway Requirements for Industry Data Exchange |
| ISO 19115-1 | Geographic Information — Metadata |
| Dublin Core (DCMI) | Metadata Element Set |
| IETF RFC 6901 | JavaScript Object Notation (JSON) Pointer |
| IETF RFC 7159 | JSON Data Interchange Format |
| NSA SDN.801c | Security Label Model |

### Online Sources

- [DCRA Interactive Model](https://nhqc3s.hq.nato.int/apps/DCRA_Report/index.html)
- [DCRA v2 PDF](https://nhqc3s.hq.nato.int/apps/public/AC322-D(2025)0056-Data_Centric_Reference_Architecture_v2.pdf)
- [Data Strategy for the Alliance](https://www.nato.int/en/about-us/official-texts-and-resources/official-texts/2025/05/05/data-strategy-for-the-alliance)
- [Operation HIGHMAST Validates ACP 240 — Virtru](https://www.virtru.com/blog/data-centric-security/operation-highmast-validates-acp-240-the-new-standard-powering-coalition-data-sharing)
- [Isode Data-Centric Security with NATO Labels](https://www.isode.com/whitepaper/isode-approach-to-data-centric-security-using-nato-confidentiality-labels/)
- [STANAG 4774 — NISP Nation](https://nisp.nw3.dk/coverdoc/nato-stanag4774.html)
- [STANAG 4778 — NISP Nation](https://nisp.nw3.dk/coverdoc/nato-stanag4778.html)
- [STANAG 5636 — NISP Nation](https://nisp.nw3.dk/coverdoc/nato-stanag5636ed1.html)
- [ADatP-4778.2 Binding Profiles PDF](https://storage.nisp.nw3.dk/ADatP-4778.2_EDA_V1_E.pdf)

---

*Research conducted by Claude Code for the Security MCP Server project.*
*Author: Alex Ackerman*
*Security Contact: security@securitymcp.io*
