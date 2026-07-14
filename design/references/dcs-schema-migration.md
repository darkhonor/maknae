> **IMPORTED COMPANION REFERENCE (2026-07-15).** Copied verbatim from the
> operator's Security MCP Server repository
> (`docs/design/dcs-schema-migration.md`,
> https://gitlab.com/homelab-systems/security-mcp-server) as the supporting
> reference for [`../abac-dcs-architecture.md`](../abac-dcs-architecture.md).
> Both documents share an author; the copy is authorized. Relative links into
> the origin repository's `data/dcs/` source corpus do not resolve here.
> Treat this file as a read-only snapshot — the origin repository owns the
> living document. Whether this companion remains in-repo before Maknae goes
> public is an open decision recorded in abac-dcs-architecture.md section 14.

<!--
  Filename: dcs-schema-migration.md
  Last Modified: 2026-02-12
  Summary: Design document for Data-Centric Security (DCS) schema migration —
           classification columns, dissemination controls, coalition support,
           multinational marking interoperability, STANAG-ready label architecture,
           international classification system registry, and data privacy framework
           compliance (GDPR, LGPD, PDPA, APPI, Privacy Act)
  Compliant With: DoD STIG, NIST SP800-53 Rev 5, FIPS 140-3, STANAG 4774/4778/5636,
                  GDPR (EU 2016/679), Council Decision 2013/488/EU, NIS2 (EU 2022/2555)
  Classification: UNCLASSIFIED
-->

# DCS Schema Migration Design Document

## Migration 000012: Classification Columns, Dissemination Controls, Coalition Support, and International Framework Registry

> **CONSOLIDATION NOTICE (2026-02-01):** Migration 000012 has been folded into
> the consolidated baseline migration (`000001_consolidated_baseline.up.sql`).
> Fresh deployments receive the DCS schema as part of the single baseline
> migration. This document is preserved for design rationale and historical
> reference. See `db/migrations/archive/README.md` for consolidation details.

**Version:** 3.5.0
**Author:** Alex Ackerman (with Claude Code assistance)
**Security Contact:** security@securitymcp.io
**Last Updated:** 2026-02-12

> **Platinum Standard Philosophy:** This schema implements the **complete**
> international classification and data protection marking standard — not just the
> U.S. DoD perspective, but every allied and partner nation that might use this MCP
> for AI-assisted security compliance. The authoritative policy sources span:
>
> - **United States:** DoDM 5200.01-V2, DoDI 5200.48, 32 CFR 2002, CAPCO Register,
>   ICD 710, 10 CFR 1045, DoDM 5205.07, DoDI 5230.24, NARA CUI Registry
> - **NATO:** STANAGs 4774/4778/5636, NATO DCRA v2, ACP 240, C-M(2002)49
> - **European Union:** Council Decision 2013/488/EU (EUCI), GDPR (Regulation 2016/679),
>   NIS2 Directive (2022/2555), EU Cyber Resilience Act (2024/2847)
> - **Five Eyes:** AU PSPF/ISM, CA TBS Appendix J, UK GSC, NZ NZISM
> - **Indo-Pacific Allies:** Japan SDS Act, ROK Military Secret Protection Act,
>   Philippines DPA, Singapore IM8/PDPA
> - **Other Partners:** Germany VSA/BSI IT-Grundschutz, France IGI 1300/ANSSI,
>   Israel PPL, Brazil LGPD
> - **Cross-Border Frameworks:** EU-US DPF, APEC/Global CBPR, OECD Privacy Guidelines
>
> We do NOT constrain our design to match the limitations of any specific DCS tool
> or any single nation's perspective.
> When tools catch up, our schema already supports the full standard. When a ROK
> analyst at CFC needs to share data with a UNC sending state under GSOMIA while
> respecting GDPR for EU member personnel data — our schema handles that. We ARE
> the reference implementation.
>
> **Design Principle:** Any nation, any framework, any AI assistant. One schema.

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Problem Statement](#2-problem-statement)
3. [Analysis Methodology](#3-analysis-methodology)
4. [Classification Level Design](#4-classification-level-design)
5. [CUI — A Separate Concern from Classification](#5-cui--a-separate-concern-from-classification)
6. [Dissemination Controls Architecture](#6-dissemination-controls-architecture)
7. [JOINT Marking Support](#7-joint-marking-support)
8. [Foreign Government Information (FGI) Support](#8-foreign-government-information-fgi-support)
9. [DISPLAY ONLY Support](#9-display-only-support)
10. [Negative Dissemination Controls](#10-negative-dissemination-controls)
11. [Nation Code Standard: GENC Trigraphs](#11-nation-code-standard-genc-trigraphs)
12. [Coalition Tetragraph Reference Tables](#12-coalition-tetragraph-reference-tables)
13. [Indo-Pacific Ally Classification Systems](#13-indo-pacific-ally-classification-systems)
14. [UNC Korea and CFC Information Sharing](#14-unc-korea-and-cfc-information-sharing)
15. [International Classification Systems Registry](#15-international-classification-systems-registry)
16. [International Classification Cross-Reference](#16-international-classification-cross-reference)
17. [Data Privacy Frameworks Registry](#17-data-privacy-frameworks-registry)
18. [GDPR and EU Regulatory Schema Requirements](#18-gdpr-and-eu-regulatory-schema-requirements)
19. [OSCAL International Framework Gaps](#19-oscal-international-framework-gaps)
20. [Confidentiality Labels Table (STANAG 4774 Ready)](#20-confidentiality-labels-table-stanag-4774-ready)
21. [Classification Authority Block](#21-classification-authority-block)
22. [Portion Marking Considerations](#22-portion-marking-considerations)
23. [Migration Plan — Phased Approach](#23-migration-plan--phased-approach)
24. [Migration 000012 SQL Structure](#24-migration-000012-sql-structure)
25. [Impact on Existing Services](#25-impact-on-existing-services)
26. [Future Migration 000013 Preview](#26-future-migration-000013-preview)
27. [Future Migration 000014 Preview — GDPR/Privacy](#27-future-migration-000014-preview--gdprprivacy)
28. [Security Considerations](#28-security-considerations)
29. [CDSE Source Document Catalog](#29-cdse-source-document-catalog)
30. [Authoritative References](#30-authoritative-references)
31. [AI-Simulated Auditor Review](#31-ai-simulated-auditor-review)
32. [Decision Log](#32-decision-log)
33. [Open Questions](#33-open-questions)

---

## 1. Executive Summary

This document defines the schema migration that adds Data-Centric Security (DCS)
columns to the Security MCP Server database. This is **Decision Point 1** from the
[DCS Roadmap](../../data/dcs/README.md) — the highest-priority DCS work item that
must be completed before production data loads and before STIG archive import tools
can tag classification from DISA filenames.

### Why Now

| Factor | Cost if Done Now | Cost if Deferred |
|--------|-----------------|------------------|
| Schema migration | One SQL file, defaults to UNCLASSIFIED | Data migration + backfill + downtime |
| Parser changes | None (defaults handle everything) | Parser must populate new columns retroactively |
| STIG archive import | Can tag classification from DISA `U_`/`CUI_` prefixes | Cannot store classification metadata |
| Coalition readiness | Schema supports multinational markings from day one | Redesign when first allied partner arrives |
| PostgreSQL RLS | Indexes ready for row-level security | Index creation on loaded tables = slow |

### What This Migration Does

1. Creates a `dcs` schema for all DCS reference tables
2. Adds `classification_level` ENUM (5 levels, orderable for RLS — validated against 14 international frameworks), defaulting to `'UNCLASSIFIED'` (D31)
3. Adds CUI category, dissemination control, and CUI Designation Indicator Block columns
4. Adds origination and ownership columns (JOINT, FGI support)
5. Adds REL TO and DISPLAY ONLY nation arrays
6. Creates nation code and coalition tetragraph reference tables
7. Creates distribution statement reference table (DoDI 5230.24, statements A–F)
8. Creates marking abbreviations reference table (banner↔portion conversion for all 25+ marking types, including EU bilingual markings)
9. Creates **classification systems registry** (14 national/multinational frameworks with metadata)
10. Creates **data privacy frameworks registry** (16 privacy laws: U.S. Privacy Act, GDPR, UK GDPR, ROK PIPA, LGPD, APPI, etc.)
11. Creates **CUI categories reference table** (~20 categories from DoD CUI Registry for validation) (D30)
12. Adds `classification_system` FK column on data tables for multinational disambiguation (D36)
13. Adds `classification_confidence` column for data spillage detection (D48)
14. Adds nullable `label_id` FK placeholder for future STANAG 4774 labels
15. Adds privacy bridge columns (`gdpr_applies`, `privacy_framework`) on data tables
16. Creates classification indexes for future PostgreSQL Row-Level Security

### What This Migration Does NOT Do

- Does NOT create the `confidentiality_labels` table (Phase B — Migration 000013)
- Does NOT create the `metadata_bindings` table (Phase B)
- Does NOT implement Row-Level Security policies (Phase C)
- Does NOT modify any existing service code (all columns have defaults)
- Does NOT require parser changes (existing imports continue unchanged)

---

## 2. Problem Statement

The Security MCP Server currently stores STIG rules, benchmarks, OSCAL controls,
and CCI mappings with **no classification metadata**. Every record is implicitly
UNCLASSIFIED, but this is not explicitly stated in the schema. This creates three
critical problems:

1. **STIG Archive Import Blocked**: The gateway's `import_stig_archive` tool needs
   to tag imported STIGs with classification from DISA filename prefixes (`U_` =
   UNCLASSIFIED, `CUI_` = CUI). Without classification columns, this metadata is lost.

2. **Coalition Readiness Gap**: Allied and partner nations require classification
   markings on shared data per STANAG 4774. Without schema support, the MCP cannot
   participate in multinational data sharing.

3. **Exponential Retrofit Cost**: Adding classification columns to tables containing
   thousands of rules requires data migration, backfill logic, potential downtime,
   and risk of inconsistent data. Doing it now on near-empty tables is trivial.

### Blocking Relationships

```
Migration 000012 (this document)
    │
    ├── BLOCKS: import_stig_archive (needs classification_level column)
    ├── BLOCKS: import_stig_library (needs classification_level column)
    ├── BLOCKS: Migration 000013 (confidentiality_labels table needs FK targets)
    ├── BLOCKS: PostgreSQL RLS (needs classification indexes)
    └── BLOCKS: Kyverno + PostgreSQL RLS policies (needs data-side classification for comparison)
```

---

## 3. Analysis Methodology

This design was developed through analysis from three perspectives, incorporating
real-world coalition marking experience:

### Perspective 1: DoD Information Security Professional

Focused on U.S. classification policy compliance per DoDM 5200.01 Volumes 1-3,
DoDI 5200.48 (CUI), EO 13526, and the CDSE training curriculum (IF103, IF105,
IF141, IF130). Key contribution: CUI is NOT a classification level — it is a
safeguarding category within UNCLASSIFIED.

### Perspective 2: British Security Officer (NATO/FVEY Expert)

Focused on STANAG 4774/4778/5636 compliance, NATO DCRA v2 alignment, ACP 240
readiness, and multinational marking interoperability. Key contribution: The
"metadata trinity" (STANAGs 4774, 4778, 5636) is non-negotiable for Allied use;
the schema must support multiple security policies simultaneously.

### Perspective 3: DoD DevSecOps Engineer

Focused on implementation pragmatism — what to build now vs. later, PostgreSQL
RLS compatibility, ENUM ordering for integer comparison, and the three-layer PEP
architecture. Key contribution: Add columns and indexes now; create complex tables
when the consuming code exists.

### Real-World Marking Examples Incorporated

| Example | Source | Schema Implication |
|---------|--------|-------------------|
| `//JOINT SECRET DEU USA` | Classification Marking Guide v11 | Multi-nation co-ownership |
| `SECRET//FGI GBR//REL TO USA, GBR` | Classification Marking Guide v11 | FGI source tracking |
| `SECRET//FGI//REL TO USA, GBR` | Classification Marking Guide v11 | Concealed FGI source |
| `OFFICIAL` (Australian marking) | Exercise document, Australian Army | Non-US classification system |
| `DISPLAY ONLY CHE, SWE` | Operational experience, Korea | DISPLAY ONLY with nation targeting |
| `NOT AUTHORIZED FOR ZAF` | Operational experience, JOINT SECRET doc | Negative dissemination (see §10) |
| `SECRET//REL TO USA, FVEY` | DoDM 5200.01-V2 | Tetragraph in REL TO |
| `CUI//REL TO USA, JPN, KOR` | Classification Marking Guide v11 | Indo-Pacific CUI sharing |

---

## 4. Classification Level Design

### The Classification Hierarchy

Classification levels form a **strict ordinal hierarchy** used for Row-Level Security
(RLS) comparisons. The ENUM must be orderable so that `user.clearance >= data.classification`
works as an integer comparison.

```sql
CREATE TYPE dcs.classification_level AS ENUM (
    'UNCLASSIFIED',     -- Ordinal 0: No classification
    'RESTRICTED',       -- Ordinal 1: NATO/FGI only (no U.S. equivalent)
    'CONFIDENTIAL',     -- Ordinal 2: U.S./NATO CONFIDENTIAL
    'SECRET',           -- Ordinal 3: U.S./NATO SECRET
    'TOP_SECRET'        -- Ordinal 4: U.S. TOP SECRET / NATO COSMIC TOP SECRET
);
```

### Why 5 Levels, Not 4

The original NEXT-SESSION.md proposal had 4 levels: `UNCLASSIFIED, CUI, SECRET,
TOP_SECRET`. This is incorrect for three reasons:

| Issue | Problem | Resolution |
|-------|---------|------------|
| **Missing CONFIDENTIAL** | U.S. has CONFIDENTIAL between UNCLASSIFIED and SECRET. The Classification Marking Guide v11 shows `CONFIDENTIAL//REL TO USA, KOR` as a valid marking. | Added CONFIDENTIAL at ordinal 2 |
| **Missing RESTRICTED** | NATO uses RESTRICTED between UNCLASSIFIED and CONFIDENTIAL. Philippines also uses RESTRICTED. Australian OFFICIAL:Sensitive maps here. FGI from UK uses `//GBR RESTRICTED`. | Added RESTRICTED at ordinal 1 |
| **CUI in hierarchy** | CUI is NOT a classification level per DoDI 5200.48 and 32 CFR 2002. It is a safeguarding category *within* UNCLASSIFIED. Placing CUI at ordinal 1 breaks RLS because CUI ≠ RESTRICTED. | CUI handled separately (see §5) |

### Classification Level Mapping Across Partner Nations

This table shows how the ENUM maps to classification systems of key allies. The
`classification_system` column on the `confidentiality_labels` table (Migration
000013) will identify which system a label uses.

| Ordinal | ENUM Value | U.S. DoD | NATO | Australia (PSPF) | ROK | Japan | Philippines |
|:-------:|------------|----------|------|-------------------|-----|-------|-------------|
| 0 | `UNCLASSIFIED` | UNCLASSIFIED | NATO UNCLASSIFIED | OFFICIAL | *(unmarked)* | *(unmarked)* | *(unmarked)* |
| 1 | `RESTRICTED` | *(none)* | NATO RESTRICTED | OFFICIAL:Sensitive | *(none)* | *(none)* | RESTRICTED |
| 2 | `CONFIDENTIAL` | CONFIDENTIAL | NATO CONFIDENTIAL | PROTECTED | 삼급비밀 (Grade III) | 秘 (Hi) | CONFIDENTIAL |
| 3 | `SECRET` | SECRET | NATO SECRET | SECRET | 이급비밀 (Grade II) | 極秘 (Gokuhi) | SECRET |
| 4 | `TOP_SECRET` | TOP SECRET | COSMIC TOP SECRET | TOP SECRET | 일급비밀 (Grade I) | 機密 (Kimitsu) | TOP SECRET |

> **Note:** CUI maps to RESTRICTED (ordinal 1) for *access control purposes* in
> some bilateral agreements (e.g., CUI//REL TO FVEY → NATO RESTRICTED). However,
> CUI is stored separately from the classification hierarchy (see §5) because it
> carries its own category taxonomy and dissemination controls that RESTRICTED does not.

### Why RESTRICTED Matters Even for U.S.-Only Data

1. **FGI RESTRICTED**: The Classification Marking Guide v11 Section 3.1 shows FGI
   RESTRICTED as authorized on coalition enclaves: `//GBR RESTRICTED//REL TO USA, GBR`
2. **JOINT RESTRICTED**: Section 2.1 shows `//JOINT RESTRICTED AUS GBR NZL` as
   authorized when the U.S. is NOT a co-owner
3. **Philippines**: Uses RESTRICTED as their lowest classified tier
4. **NATO RESTRICTED**: Required for any NATO data space participation
5. **RLS ordering**: Without RESTRICTED, the ordinal gap between UNCLASSIFIED (0) and
   CONFIDENTIAL (2) makes comparison logic fragile

---

## 5. CUI — A Separate Concern from Classification

### Why CUI Is NOT in the Classification ENUM

Per **DoDI 5200.48** and **32 CFR Part 2002**, CUI is:
- **Unclassified** information requiring safeguarding per law, regulation, or policy
- A **replacement** for legacy markings: FOUO, SBU, LES, PROPIN (as standalone)
- Governed by the **CUI Registry** (maintained by NARA), not EO 13526
- Subject to its **own dissemination controls** (FEDCON, FED ONLY, NOCON) that are
  distinct from classified dissemination controls (NOFORN, ORCON, IMCON)

CUI data has `classification_level = 'UNCLASSIFIED'` in our schema, with additional
CUI-specific columns:

```sql
-- CUI columns (on data tables alongside classification_level)
cui_category        VARCHAR[]   DEFAULT NULL,   -- NULL = not CUI
cui_specified       BOOLEAN     DEFAULT FALSE,  -- TRUE = CUI Specified (stricter)
cui_dissem_controls VARCHAR[]   DEFAULT NULL    -- FEDCON, FED_ONLY, NOCON, etc.
```

### CUI Categories (from DoD CUI Registry)

The `cui_category` array stores values from the [DoD CUI Registry](https://www.dodcui.mil/CUI-Categories-and-Abbreviations/):

| Category | Abbreviation | Example Data |
|----------|-------------|--------------|
| Privacy | PRVCY | PII, personnel records |
| Proprietary Business | PROPIN | Contractor data, trade secrets |
| Law Enforcement Sensitive | LES | Investigation data |
| Export Controlled | EXPT | ITAR/EAR controlled technology |
| Federal Taxpayer | FTI | Tax return information |
| Patent | PATENT | Patent applications |
| Critical Infrastructure | CRIT | Infrastructure vulnerability data |

### CUI Limited Dissemination Controls (Complete Vocabulary from NARA CUI Registry)

These are **separate from** classified dissemination controls. Per the **National Archives
CUI Registry** (32 CFR 2002.16) and the **CUI Limited Dissemination Controls Job Aid**
(IF141), the **complete** LDC vocabulary is:

| Control | Banner Marking | Portion Marking | Description |
|---------|---------------|-----------------|-------------|
| No Foreign Dissemination | **NOFORN** | **NF** | Not releasable to foreign nationals |
| Federal Employees Only | **FED ONLY** | **FED ONLY** | Executive branch employees and armed forces only |
| Federal Employees and Contractors Only | **FEDCON** | **FEDCON** | Adds contractors in furtherance of contractual purpose |
| No Dissemination to Contractors | **NOCON** | **NOCON** | Excludes contractors; permits state/local/tribal |
| Dissemination List Controlled | **DL ONLY** | **DL ONLY** | Named distribution list only; **supersedes other LDCs** |
| Releasable by Info Disclosure Official | **RELIDO** | **RELIDO** | SFDRA may make further sharing decisions (IC-origin only) |
| Authorized for Release to Certain Nationals | **REL TO USA, [LIST]** | **REL TO USA, [LIST]** | Pre-determined foreign release via disclosure channels |
| Display Only | **DISPLAY ONLY [USA, LIST]** | **DISPLAY ONLY [USA, LIST]** | Disclosure without physical copy retention |
| Attorney-Client Privilege | **Attorney-Client** | **AC** | Protected by attorney-client privilege (Legal Privilege category only) |
| Attorney Work Product | **Attorney-WP** | **AWP** | Protected by work product privilege (Legal Privilege category only) |

> **Source:** National Archives CUI Registry — Limited Dissemination Controls
> (https://www.archives.gov/cui/registry/limited-dissemination)
>
> **Key Rules:**
> - **Only the designating agency** may apply LDCs to CUI
> - Multiple LDCs are combined with a **single forward slash** (`/`):
>   `CUI//NOFORN/FEDCON`
> - `DL ONLY` **supersedes** other LDCs but cannot supersede law/regulation
> - Using LDCs to **unnecessarily restrict access** is contrary to CUI program goals
> - `RELIDO` may only be used by agencies eligible in the IC classified context
> - `Attorney-Client` and `Attorney-WP` are only for the **Legal Privilege** CUI category

### Schema Impact: CUI Dissemination Controls

The `cui_dissem_controls` array must support the full vocabulary:

```sql
-- Valid values for cui_dissem_controls VARCHAR[]
-- Banner markings (stored as normalized keys):
'NOFORN', 'FED_ONLY', 'FEDCON', 'NOCON', 'DL_ONLY', 'RELIDO',
'ATTORNEY_CLIENT', 'ATTORNEY_WP'
-- REL TO and DISPLAY ONLY are stored in rel_to_nations / display_only_nations
-- (same columns used for both classified and CUI releasability)
```

> **Platinum Standard Note:** Some DCS tools (e.g., Fortra Data Classification Suite)
> have limited LDC vocabulary support. **This schema implements the complete NARA
> registry vocabulary.** We are the reference implementation, not the constrained one.

### CUI Banner Line Examples

| Marking | Schema Representation |
|---------|---------------------|
| `CUI//REL TO USA, GBR` | `classification_level='UNCLASSIFIED', cui_category={'CUI'}, rel_to_nations={'USA','GBR'}` |
| `CUI//SP-PRVCY//REL TO USA, JPN, KOR` | `classification_level='UNCLASSIFIED', cui_category={'PRVCY'}, cui_specified=true, rel_to_nations={'USA','JPN','KOR'}` |
| `CUI//FEDCON` | `classification_level='UNCLASSIFIED', cui_category={'CUI'}, cui_dissem_controls={'FEDCON'}` |
| `CUI//NOFORN/FEDCON` | `classification_level='UNCLASSIFIED', cui_category={'CUI'}, cui_dissem_controls={'NOFORN','FEDCON'}, noforn=true` |
| `CUI//SP-PRVCY//DL ONLY` | `classification_level='UNCLASSIFIED', cui_category={'PRVCY'}, cui_specified=true, cui_dissem_controls={'DL_ONLY'}` |
| `CUI//Attorney-Client` | `classification_level='UNCLASSIFIED', cui_category={'LEGAL'}, cui_dissem_controls={'ATTORNEY_CLIENT'}` |

### CUI Designation Indicator Block

Per the **CUI Markings Training Aid (December 2024, OUSD(I&S)/DDI(CL&S)/IAP)**, every
document containing CUI requires a **CUI Designation Indicator (DI) Block** on the first
page or cover. This is a **separate structure** from the Classification Authority Block
used on classified documents.

| Line | Content | Schema Column |
|------|---------|---------------|
| **Line 1** | Name of DoD Component and office creating the document | `cui_controlled_by` |
| **Line 2** | CUI categories contained in the document | `cui_category` (existing) |
| **Line 3** | Applicable LDC or Distribution Statement | `cui_dissem_controls` + `distribution_statement` |
| **Line 4** | Name and phone/email of POC | `cui_poc` |

```sql
-- CUI Designation Indicator Block columns (on data tables)
cui_controlled_by       VARCHAR(200) DEFAULT NULL,  -- "DDI(CL&S)/IAP"
cui_poc                 VARCHAR(200) DEFAULT NULL,  -- "John Brown, 703-555-0123"
distribution_statement  VARCHAR(1)   DEFAULT NULL,  -- 'A','B','C','D','E','F'
```

> **Key Rules from CUI Markings Training Aid:**
> - Do NOT add "UNCLASSIFIED" before "CUI" in the banner
> - Do NOT add CUI category to the banner (category is in the DI block)
> - Portion markings are **optional but recommended** on unclassified CUI documents
> - Portion markings are **mandatory** on classified documents containing CUI
> - Contractors are authorized to create and mark CUI documents
> - The absence of an LDC means **anyone with a lawful government purpose** may access
> - When a classified document contains CUI, BOTH blocks are required (CAB + CUI DI)

### Distribution Statements (DoDI 5230.24)

Distribution Statements are **separate from and in addition to** LDCs. Two CUI categories
**require** a Distribution Statement: **export-controlled information** and **controlled
technical information (CTI)**.

> **Important:** A distribution statement on a document does NOT automatically mean the
> document contains CUI. Distribution statements may also appear on non-CUI documents.

```sql
-- Distribution Statement reference table
CREATE TABLE dcs.distribution_statements (
    statement_code  VARCHAR(1)   PRIMARY KEY,  -- 'A','B','C','D','E','F'
    description     TEXT         NOT NULL,
    audience        VARCHAR(200) NOT NULL,      -- Who can access
    requires_reason BOOLEAN      DEFAULT FALSE, -- B-E require reason + date
    requires_office BOOLEAN      DEFAULT FALSE  -- B-F require controlling office
);

-- Seed data
INSERT INTO dcs.distribution_statements (statement_code, description, audience, requires_reason, requires_office) VALUES
    ('A', 'Approved for public release. Distribution is unlimited.', 'Public', FALSE, FALSE),
    ('B', 'Distribution authorized to U.S. Government agencies only.', 'U.S. Government agencies', TRUE, TRUE),
    ('C', 'Distribution authorized to U.S. Government agencies and their contractors.', 'U.S. Govt + their contractors', TRUE, TRUE),
    ('D', 'Distribution authorized to Department of Defense and U.S. DoD contractors only.', 'DoD + DoD contractors', TRUE, TRUE),
    ('E', 'Distribution authorized to DoD Components only.', 'DoD Components only', TRUE, TRUE),
    ('F', 'Further dissemination only as directed by controlling office.', 'As directed', FALSE, TRUE);
```

> **Schema Note:** The `distribution_statement` column on data tables stores a single
> letter (A–F). REL TO may be combined with a distribution statement:
> `Distribution Statement B... REL TO USA, FVEY`

---

## 5a. Special Marking Categories

### 5a.1 Atomic Energy Information (10 CFR Part 1045)

Per the **Marking National Security Information Job Aid (CDSE, May 2024)** and **IF105
(Marking Special Categories)**, nuclear information is governed by the **Atomic Energy
Act of 1954**, NOT Executive Order 13526. This has critical schema implications:

| Marking | Abbreviation | Description | Declassify On? |
|---------|:------------:|-------------|:--------------:|
| Restricted Data | **RD** | Nuclear weapon design data (DoE-originated) | **NO** — only DoE may declassify |
| Formerly Restricted Data | **FRD** | RD that has been jointly determined to relate primarily to military utilization | **NO** — Atomic Energy Act governs |
| Transclassified Foreign Nuclear Information | **TFNI** | Nuclear info from foreign governments, transclassified under Section 142(e) | **NO** — Atomic Energy Act governs |
| Critical Nuclear Weapon Design Information | **CNWDI** | DoD designation for TS/S RD revealing theory of operation (DoDI 5210.02) | Follows RD rules |

**Warning notices are mandatory:**

| Contains | Required Warning |
|----------|-----------------|
| RD | "This document contains Restricted Data as defined in the Atomic Energy Act of 1954. Unauthorized disclosure is subject to administrative and criminal sanctions." |
| FRD (no RD) | "Unauthorized disclosure subject to administrative and criminal sanctions. Handle as Restricted Data in foreign dissemination. Section 144b, Atomic Energy Act of 1954." |
| CNWDI | "Critical Nuclear Weapon Design Information — DOD Instruction 5210.02 applies." |

**Commingled RD/FRD with NSI:**
- `Declassify On` line shall be: `Not Applicable (or N/A) to RD/FRD portions` and
  `See source list for NSI portions`
- The source list shall NOT appear on the front page

```sql
-- Atomic energy columns (on confidentiality_labels table, Phase B)
atomic_energy       VARCHAR[]    DEFAULT NULL,    -- 'RD', 'FRD', 'TFNI'
is_cnwdi            BOOLEAN      DEFAULT FALSE,   -- CNWDI overlay on RD
-- Note: atomic_energy markings NEVER have declassify_on dates
-- The schema enforces this via application validation
```

### 5a.2 Special Access Programs (SAP) — DoDM 5205.07

Per the **Marking National Security Information Job Aid**, SAPs use dedicated marking
syntax with nicknames, code words, and program identifiers:

| Term | Description | Classification of Term | Example |
|------|------------|:----------------------:|---------|
| **Nickname** | Two unassociated, unclassified words (ALL CAPS) | UNCLASSIFIED | TWISTED FEATHER |
| **Code Word** | Single word with classified meaning | CONFIDENTIAL+ | *(classified)* |
| **PID** | Program Identifier (abbreviation) | Varies | TF |

**SAP Banner Line:** `TOP SECRET//SPECIAL ACCESS REQUIRED-TWISTED FEATHER`
**SAP Portion Marking:** `(TS//SAR-TF)`

**SAP Document Control (Top Secret SAP):**
- Document Control Number (DCN): `SAPCO/0001-01`
- Page numbering: `Page 1 of 1`
- Copy numbering: `Copy 1 of 2`

**SAP File Series Exemption (FSE):**
- Documents pre-1982: declassified on December 31, 2021
- Documents post-1982: declassified on 50th year from date of origin

```sql
-- SAP columns (on confidentiality_labels table, Phase B)
sap_markings        JSONB        DEFAULT NULL,
    -- Structure: [{"nickname": "TWISTED FEATHER", "pid": "TF",
    --              "dcn": "SAPCO/0001-01", "fse_date": "2072-01-15"}]
```

### 5a.3 Intelligence Community Markings — ICD 710 / CAPCO Register

Per the **Marking National Security Information Job Aid**, intelligence markings are
additional dissemination controls managed by CAPCO:

| Designation | Banner | Portion | Description |
|-------------|--------|---------|-------------|
| **ORCON** | ORCON | OC | Dissemination/extraction controlled by originator; maintains knowledge of distribution |
| **PROPIN** | PROPIN | PR | Proprietary information involved; trade secret / proprietary data protection |
| **NOFORN** | NOFORN | NF | Not releasable to foreign nationals. **NOT authorized with REL TO.** |
| **IMCON** | IMCON | IMCON | Controlled imagery; protects geospatial intelligence S&M (SECRET+) |
| **RELIDO** | RELIDO | RELIDO | Originator authorized SFDRA to make further sharing decisions |

**SCI Compartments** (commonly encountered):

| Compartment | Abbreviation | Portion |
|-------------|:------------:|:-------:|
| HUMINT Control System | HCS | HCS |
| Special Intelligence | SI | SI |
| TALENT KEYHOLE | TK | TK |
| GAMMA | G | G |

```sql
-- Intelligence markings (on confidentiality_labels table, Phase B)
sci_controls        VARCHAR[]    DEFAULT NULL,    -- 'HCS', 'SI', 'TK', 'G'
-- ORCON, PROPIN, IMCON, RELIDO stored in dissem_controls VARCHAR[]
```

### 5a.4 Classification by Compilation (E.O. 13526, Section 1.7(e))

Per the **ISOO Marking Booklet (Rev 4, Jan 2018)**, individually unclassified items
may be classified when compiled if the compilation reveals an additional association
or relationship meeting classification standards.

**Key rules:**
- An explanation of the basis for compilation classification MUST be on the document
- Portions standing alone remain marked at their individual classification
- The document/pages are marked with the compilation classification
- ISOO Notice 2017-02: lower-classified portions can compile to a higher classification

```sql
-- Classification by compilation flag (on data tables)
is_compilation          BOOLEAN     DEFAULT FALSE,
compilation_basis       TEXT        DEFAULT NULL
    -- Free-text explanation of why compilation is classified higher
    -- e.g., "Weight of widget A combined with height reveals SECRET design parameters"
```

> **Schema Note:** Compilation classification is an **OCA decision**, not an automated
> determination. The schema records the OCA's determination and basis.

### 5a.5 Declassification Instructions and Exemptions

Per the **ISOO Marking Booklet** and **Derivative Classification Job Aid**, the full
declassification instruction taxonomy:

| Instruction | Format | Duration | Authority |
|------------|--------|----------|-----------|
| Date or event ≤ 10 years | `20360115` | ≤ 10 years from OCA decision | OCA |
| Date ≤ 25 years | `20510115` | ≤ 25 years from OCA decision | OCA |
| 25X1 through 25X9 | `25X3, 20540215` | ≤ 50 years from document date | ISCAP-approved |
| 50X1-HUM | `50X1-HUM` | Up to 75 years (no date) | Human source identity |
| 50X2-WMD | `50X2-WMD` | Up to 75 years (no date) | WMD key design concepts |
| 75X | `75X, [date]` | 75+ years | ISCAP-approved, extraordinary |

**Legacy instructions (NO LONGER VALID — must be converted):**

| Legacy Marking | Replacement | Conversion Rule |
|---------------|-------------|-----------------|
| X1–X8 | Calculated date | 25 years from date of source document |
| OADR | Calculated date | 25 years from date of source document |
| MR (Manual Review) | Calculated date | 25 years from date of source document |
| DCI Only / DNI Only | 25X1, EO 12951 | Per DNI imagery declassification guidance |
| 25X1-human | 50X1-HUM | Direct replacement per E.O. 13526 |

```sql
-- Declassification columns (on confidentiality_labels table, Phase B)
declassify_on           DATE         DEFAULT NULL,   -- YYYYMMDD date
declassify_event        VARCHAR(500) DEFAULT NULL,   -- Event description (if event-based)
declass_exemption       VARCHAR(10)  DEFAULT NULL,   -- '25X1'..'25X9', '50X1-HUM', '50X2-WMD', '75X'
declass_exemption_date  DATE         DEFAULT NULL,   -- ISCAP-approved date for 25X/75X
is_legacy_converted     BOOLEAN      DEFAULT FALSE,  -- TRUE if declass instruction was converted from legacy
legacy_instruction      VARCHAR(50)  DEFAULT NULL,   -- Original legacy marking before conversion
reason                  VARCHAR(50)  DEFAULT NULL,    -- E.O. 13526 §1.4 reason code: '1.4(a)'..'1.4(h)'
```

> **Platinum Standard Note:** Most DCS tools ignore legacy marking conversion entirely.
> Our schema tracks both the converted instruction AND the original legacy marking for
> full audit trail and provenance.

---

## 6. Dissemination Controls Architecture

### Two Separate Control Vocabularies

The U.S. classification system has **two distinct dissemination control vocabularies**
that must NOT be conflated:

| Vocabulary | Applies To | Controls | Portion Abbrevs | Authority |
|-----------|-----------|----------|-----------------|-----------|
| **Classified dissemination** | CONFIDENTIAL, SECRET, TOP SECRET | NOFORN, ORCON, IMCON, PROPIN, REL TO, DISPLAY ONLY, RELIDO | NF, OC, IMCON, PR, REL, DO, RELIDO | DoDM 5200.01-V2, CAPCO Register, ICD 710 |
| **CUI dissemination** | CUI (UNCLASSIFIED) | NOFORN, FED ONLY, FEDCON, NOCON, DL ONLY, RELIDO, REL TO, DISPLAY ONLY, Attorney-Client, Attorney-WP | NF, FED ONLY, FEDCON, NOCON, DL ONLY, RELIDO, REL, DISPLAY ONLY, AC, AWP | DoDI 5200.48, 32 CFR 2002, NARA CUI Registry |

### Schema Columns for Dissemination

```sql
-- Classified dissemination controls (CAPCO Register / ICD 710)
dissem_controls     VARCHAR[]   DEFAULT NULL,
    -- Valid values: 'NOFORN', 'ORCON', 'IMCON', 'PROPIN', 'RELIDO'
    -- REL TO and DISPLAY ONLY stored separately (nation arrays)
    -- Banner format: SECRET//ORCON/PROPIN//REL TO USA, GBR

-- Releasability (applies to both classified and CUI)
rel_to_nations      VARCHAR[]   DEFAULT NULL,   -- GENC trigraphs + tetragraphs
display_only_nations VARCHAR[]  DEFAULT NULL,   -- GENC trigraphs + tetragraphs
noforn              BOOLEAN     DEFAULT FALSE,  -- Explicit NOFORN flag (fast RLS predicate)

-- CUI-specific dissemination (separate vocabulary — NARA CUI Registry)
cui_dissem_controls VARCHAR[]   DEFAULT NULL
    -- Valid values: 'NOFORN', 'FED_ONLY', 'FEDCON', 'NOCON', 'DL_ONLY',
    --              'RELIDO', 'ATTORNEY_CLIENT', 'ATTORNEY_WP'
    -- Combined with forward slash in banner: CUI//NOFORN/FEDCON
    -- REL TO and DISPLAY ONLY stored in rel_to_nations / display_only_nations
```

### Why `noforn` Gets Its Own Column

NOFORN is the most common dissemination control and is frequently used in access
control decisions (`IF noforn AND user.nationality != 'USA' THEN DENY`). Making it
a boolean column enables:
- Direct RLS predicate: `WHERE NOT noforn OR 'USA' = ANY(user_nationality)`
- Fast index: `CREATE INDEX idx_noforn ON rules (noforn) WHERE noforn = true`
- Clear intent in RLS policy: `WHERE NOT noforn OR user_nationality = 'USA'`

### Dissemination Control Validation

Valid combinations per DoDM 5200.01-V2 and Classification Marking Guide v11:

| Control | Can Combine With | Cannot Combine With | Notes |
|---------|-----------------|---------------------|-------|
| NOFORN | ORCON, IMCON, PROPIN | REL TO, DISPLAY ONLY | Blanket foreign denial |
| REL TO | ORCON, DISPLAY ONLY, PROPIN | NOFORN | USA always first in list |
| DISPLAY ONLY | REL TO (single `/` separator) | NOFORN; CUI; UNCLASSIFIED | Classified only per DoDM 5200.01-V2 Encl. 4 §10.e.(3) |
| ORCON | NOFORN, REL TO, IMCON, PROPIN | *(compatible with most)* | Originator controls extraction |
| IMCON | ORCON, NOFORN, REL TO | *(compatible with most)* | SECRET+ only; geospatial S&M |
| PROPIN | NOFORN, REL TO, ORCON | *(compatible with most)* | Trade secret / proprietary |
| RELIDO | REL TO | NOFORN | Permissive; SFDRA makes decisions |

> **Schema Note:** Validation of legal combinations is an **application concern**,
> not a database constraint. The schema stores what it's given; the parser validates
> on import; the gateway validates on API response generation.

---

## 7. JOINT Marking Support

### What JOINT Means

JOINT markings identify information **co-owned by multiple countries**. Per DoDM
5200.01-V2, Enclosure 4, Section 5, JOINT markings:
- Indicate co-ownership and **implied releasability** to all co-owner countries
- Apply ONLY to classified information (not UNCLASSIFIED, not CUI)
- List co-owner countries **alphabetically** (including USA if co-owner)
- May have additional REL TO for release **beyond** co-owners

### Schema Columns for JOINT

```sql
-- Document/data origin type
document_type       VARCHAR(20) DEFAULT 'US_DOD',
    -- Values: 'US_DOD', 'JOINT', 'FGI', 'FGI_CONCEALED', 'NATO'

-- Ownership (single-nation or multi-nation)
owner_nations       VARCHAR[]   DEFAULT '{USA}',
    -- JOINT: {'DEU', 'GBR', 'USA'} (alphabetical)
    -- US DoD: {'USA'}
    -- FGI: {'GBR'} (source nation)
```

### JOINT Marking Examples and Schema Representation

| Banner Line | document_type | owner_nations | classification_level | rel_to_nations |
|-------------|--------------|---------------|---------------------|----------------|
| `//JOINT SECRET DEU USA` | `JOINT` | `{DEU,USA}` | `SECRET` | `NULL` (implied to co-owners) |
| `//JOINT SECRET GBR USA//REL TO USA, DEU, FRA, GBR` | `JOINT` | `{GBR,USA}` | `SECRET` | `{USA,DEU,FRA,GBR}` |
| `//JOINT CONFIDENTIAL JPN USA` | `JOINT` | `{JPN,USA}` | `CONFIDENTIAL` | `NULL` |
| `//JOINT RESTRICTED AUS GBR NZL` | `JOINT` | `{AUS,GBR,NZL}` | `RESTRICTED` | `NULL` |
| `//JOINT CONFIDENTIAL AUS KOR USA` | `JOINT` | `{AUS,KOR,USA}` | `CONFIDENTIAL` | `NULL` |

### JOINT Authorization Matrix (from Classification Marking Guide v11)

| Classification | US is Co-Owner | US NOT Co-Owner |
|:---------------|:--------------:|:---------------:|
| SECRET | ✅ Authorized | ✅ Authorized |
| CONFIDENTIAL | ✅ Authorized | ✅ Authorized |
| RESTRICTED | ❌ Not Authorized | ✅ Authorized |
| UNCLASSIFIED | N/A | N/A |
| CUI | N/A | N/A |

> **Schema Note:** JOINT RESTRICTED is valid only when the U.S. is NOT a co-owner,
> because the U.S. does not have a RESTRICTED level. Validation is application-level.

### JOINT REL TO Country Duplication Rules

Per Classification Marking Guide v11 Section 2.2:
- Co-owner countries **MAY** appear in both JOINT and REL TO
- Tetragraph members must **NOT** be individually listed if covered by the tetragraph
- Example: `//JOINT SECRET GBR USA//REL TO USA, DEU, FRA, GBR` — GBR/USA repeat ✅
- Example: `//JOINT SECRET GBR USA//REL TO USA, GBR, FVEY` — GBR in FVEY ❌

---

## 8. Foreign Government Information (FGI) Support

### FGI Types

The Classification Marking Guide v11 Sections 3.2–3.5 define three FGI types:

| Type | Banner Format | `document_type` | `fgi_source_nations` |
|------|--------------|-----------------|---------------------|
| **Foreign Gov Classified** | `//[country] [classification]` | `FGI` | `{'GBR'}` |
| **U.S. with FGI (source shown)** | `[class]//FGI [countries]` | `US_DOD` | `{'GBR','DEU'}` |
| **U.S. with FGI (concealed source)** | `[class]//FGI` | `FGI_CONCEALED` | `NULL` (protected) |

### Schema Columns for FGI

```sql
-- FGI source tracking
fgi_source_nations  VARCHAR[]   DEFAULT NULL,
    -- Source shown: {'GBR'}
    -- Multiple sources: {'DEU', 'FRA', 'GBR'} (alphabetical)
    -- Concealed source: NULL (identity protected per DoDM 5200.01-V2 Encl. 4 §9.e)

-- Whether FGI source is concealed
fgi_source_concealed BOOLEAN    DEFAULT FALSE
    -- TRUE when document_type = 'FGI_CONCEALED'
    -- The source identity is maintained with the record copy per policy
```

### FGI Examples and Schema Representation

| Banner Line | document_type | owner_nations | fgi_source_nations | classification_level | rel_to_nations |
|-------------|--------------|---------------|-------------------|---------------------|----------------|
| `//GBR SECRET//REL TO USA, GBR` | `FGI` | `{GBR}` | `{GBR}` | `SECRET` | `{USA,GBR}` |
| `//DEU SECRET//REL TO USA, DEU, FRA` | `FGI` | `{DEU}` | `{DEU}` | `SECRET` | `{USA,DEU,FRA}` |
| `//GBR RESTRICTED//REL TO USA, GBR` | `FGI` | `{GBR}` | `{GBR}` | `RESTRICTED` | `{USA,GBR}` |
| `SECRET//FGI GBR//REL TO USA, GBR` | `US_DOD` | `{USA}` | `{GBR}` | `SECRET` | `{USA,GBR}` |
| `SECRET//FGI DEU GBR//REL TO USA, DEU, FRA, GBR` | `US_DOD` | `{USA}` | `{DEU,GBR}` | `SECRET` | `{USA,DEU,FRA,GBR}` |
| `SECRET//FGI//REL TO USA, GBR` | `FGI_CONCEALED` | `{USA}` | `NULL` | `SECRET` | `{USA,GBR}` |

### FGI on Coalition/Releasable Enclaves

Per the Classification Marking Guide v11 Section 3.5, on coalition/releasable
enclaves, **ALL FGI requires explicit REL TO** (not just implied releasability to
source). This is because:
1. The enclave is U.S.-owned — USA must be in REL TO
2. Bilateral sharing of concealed-source FGI could reveal the source country
3. DCS systems cannot enforce access without explicit releasability

---

## 9. DISPLAY ONLY Support

### What DISPLAY ONLY Means

Per DoDM 5200.01-V2, Enclosure 4, Section 10.e.(3), DISPLAY ONLY permits
**disclosure without providing physical copies**. Foreign nationals may view the
information but may NOT retain a copy.

### Critical Constraints

| Constraint | Rule |
|-----------|------|
| **Classified only** | DISPLAY ONLY may only be used with CONFIDENTIAL, SECRET, or TOP SECRET |
| **NOT for CUI** | DoDM 5200.01-V2 explicitly excludes CUI from DISPLAY ONLY |
| **NOT for UNCLASSIFIED** | Cannot apply DISPLAY ONLY to unclassified information |
| **Requires REL TO on coalition enclaves** | Must include REL TO when used on releasable networks |

### Schema Column

```sql
-- DISPLAY ONLY nation targeting
display_only_nations VARCHAR[]  DEFAULT NULL
    -- Example: {'CHE', 'SWE'} for DISPLAY ONLY CHE, SWE
    -- NULL = no DISPLAY ONLY restriction
```

### Real-World Example

The marking `SECRET//REL TO USA, AUS, GBR//DISPLAY ONLY CHE, SWE` means:
- **SECRET** classification
- **Released to** USA, Australia, UK (they get copies)
- **Display only to** Switzerland, Sweden (they can view but not retain)

Schema representation:
```
classification_level = 'SECRET'
rel_to_nations = {'USA', 'AUS', 'GBR'}
display_only_nations = {'CHE', 'SWE'}
```

---

## 10. Negative Dissemination Controls

### The "NOT AUTHORIZED FOR ZAF" Question

A JOINT SECRET document was observed with "NOT AUTHORIZED FOR ZAF" (South Africa)
at the end of a complex marking. This raises the question: does the U.S. marking
system support **exclusionary/negative** dissemination controls?

### Analysis

The U.S. classification marking system is fundamentally **inclusionary** (positive
authorization):

| Marking | Type | Meaning |
|---------|------|---------|
| `NOFORN` | Blanket negative | Not releasable to ANY foreign national |
| `REL TO USA, GBR, AUS` | Specific positive | Releasable ONLY to listed nations |
| `DISPLAY ONLY FRA` | Specific positive (limited) | May be shown ONLY to listed nations |

There is **no publicly documented** standard marking in the CAPCO Register or
DoDM 5200.01 with the syntax "NOT AUTHORIZED FOR [country]". The REL TO system
inherently defines the authorized set — anyone NOT in the set is NOT authorized.

### How "NOT AUTHORIZED FOR ZAF" Would Be Expressed

If information is releasable to a large coalition but specifically excludes South
Africa, the proper marking would list all authorized nations explicitly in REL TO.
The "NOT AUTHORIZED FOR" language may have been:

1. **An operational annotation** — not a formal CAPCO marking but a handler's
   clarifying note on a complex document
2. **A local command marking** — some commands add supplementary handling
   instructions beyond standard CAPCO markings
3. **From a classified CAPCO appendix** — the CAPCO Register has classified addenda
   that may contain additional marking constructs not in the public version

### Schema Decision

**No dedicated `negative_dissemination` field is needed.** The `rel_to_nations`
array inherently defines the positive authorization set. The PostgreSQL RLS policy
enforces: `WHERE user_nationality = ANY(rel_to_nations)` — if you're not on the
list, the row is invisible.

However, we add a **free-text field** for non-standard handling instructions:

```sql
-- Additional handling instructions (for non-standard markings)
handling_caveats    TEXT        DEFAULT NULL
    -- Stores non-standard instructions like "NOT AUTHORIZED FOR ZAF"
    -- or local command supplementary markings
    -- NOT used for access control decisions — informational only
```

> **⚠️ Security Note:** The `handling_caveats` field is for **display purposes and
> audit trail only**. Access control decisions MUST use the structured fields
> (`rel_to_nations`, `noforn`, `dissem_controls`). Free-text caveats cannot be
> machine-evaluated for ABAC/CMBAC enforcement.

---

## 11. Nation Code Standard: GENC Trigraphs

### Canonical Standard: GENC (Geopolitical Entities, Names, and Codes)

After analyzing three competing standards, **GENC trigraphs** are the correct
canonical code for our schema:

| Standard | Maintainer | Scope | DoD Mandate? |
|----------|-----------|-------|:------------:|
| **GENC** | NGA (for ODNI/DoD) | U.S. Government profile of ISO 3166 | **Yes** — mandated by ODNI |
| ISO 3166-1 alpha-3 | ISO | International standard | No — GENC supersedes |
| STANAG 1059 | NATO Standardization Office | NATO-specific extensions of ISO 3166 | NATO only |

### Why GENC, Not ISO 3166-1 or STANAG 1059

1. **GENC is the U.S. Government mandate** — CAPCO/ISMCAT explicitly references GENC
   trigraphs for classification markings
2. **GENC profiles ISO 3166-1** — compatible for the vast majority of countries, with
   divergences only where U.S. policy requires them (e.g., entity naming per the
   U.S. Board on Geographic Names)
3. **STANAG 1059 Ed. 9+ aligns with ISO 3166-1 alpha-3** for real nations, so GENC
   covers both NATO and non-NATO partners
4. **CAPCO Register** uses GENC trigraphs as its authoritative country code source

### Key Indo-Pacific Nation Codes

| Nation | GENC/ISO Trigraph | GENC/ISO Alpha-2 | Notes |
|--------|:-----------------:|:-----------------:|-------|
| Australia | AUS | AU | FVEY member, MNNA, PSPF classification |
| Japan | JPN | JP | GSOMIA bilateral, potential "Sixth Eye" |
| Republic of Korea | KOR | KR | CFC/UNC member, GSOMIA bilateral |
| Philippines | PHL | PH | EDCA, MNNA, UNC Sending State |
| Thailand | THA | TH | UNC Sending State, MNNA |
| Singapore | SGP | SG | Major Security Cooperation Partner |
| New Zealand | NZL | NZ | FVEY member |
| Switzerland | CHE | CH | DISPLAY ONLY partner (neutral nation) |
| Sweden | SWE | SE | DISPLAY ONLY partner, now NATO member |
| South Africa | ZAF | ZA | Used in negative dissem example |

### Reference Table Schema

```sql
CREATE TABLE dcs.nation_codes (
    trigraph        VARCHAR(3)  PRIMARY KEY,  -- GENC/ISO 3166-1 alpha-3
    alpha2          VARCHAR(2)  NOT NULL,     -- GENC/ISO 3166-1 alpha-2
    short_name      VARCHAR(100) NOT NULL,    -- GENC short name
    is_nato_member  BOOLEAN     DEFAULT FALSE,
    is_fvey_member  BOOLEAN     DEFAULT FALSE,
    is_mnna         BOOLEAN     DEFAULT FALSE, -- Major Non-NATO Ally
    is_unc_member   BOOLEAN     DEFAULT FALSE, -- UN Command Korea member
    active          BOOLEAN     DEFAULT TRUE,
    notes           TEXT        DEFAULT NULL
);
```

---

## 12. Coalition Tetragraph Reference Tables

### What Tetragraphs Are

A tetragraph is a **four-letter alphabetic code** assigned by CAPCO (ODNI Security
Markings Program) to represent an international organization, alliance, or coalition
in classification markings. Tetragraphs appear in REL TO markings alongside nation
trigraphs.

### Decomposability

| Property | Meaning | Example |
|---------|---------|---------|
| **Decomposable** | REL TO using this tetragraph can be broken into individual country releases | `FVEY` → USA, AUS, CAN, GBR, NZL |
| **Not Decomposable** | Membership treated as a unit; individual country release cannot be inferred | `NKIC` — member list is classified |

### Known Indo-Pacific and Korea-Relevant Tetragraphs

| Tetragraph | Full Name | Decomposable | Members (if known) |
|:----------:|-----------|:------------:|-------------------|
| **FVEY** | Five Eyes | Yes | USA, AUS, CAN, GBR, NZL |
| **ACGU** | Four Eyes | Yes | USA, AUS, CAN, GBR |
| **TEYE** | Three Eyes | Yes | USA, AUS, GBR |
| **CFCK** | Combined Forces Command Korea | Yes | USA, KOR |
| **UNCK** | United Nations Command Korea | Yes | 18 member states (see §14) |
| **CMFP** | Cooperative Maritime Forces Pacific | Yes | Multiple Pacific nations |
| **CMFC** | Combined Maritime Forces Central | Yes | CENTCOM maritime coalition |
| **NKIC** | North Korea Intelligence Coalition | **No** | Classified (DIA-sponsored) |
| **NATO** | North Atlantic Treaty Organization | Yes | 32 member nations |
| **GCTF** | Global Counter-Terrorism Forces | **Suppressed** | Membership suppressed |

### Reference Table Schema

```sql
CREATE TABLE dcs.coalition_tetragraphs (
    tetragraph      VARCHAR(4)  PRIMARY KEY,
    full_name       VARCHAR(200) NOT NULL,
    is_decomposable BOOLEAN     NOT NULL,
    is_active       BOOLEAN     DEFAULT TRUE,
    deprecated_date DATE        DEFAULT NULL,
    classification  VARCHAR(20) DEFAULT 'UNCLASSIFIED', -- Tetragraph itself may be classified
    source          VARCHAR(20) DEFAULT 'CAPCO',         -- CAPCO, ISMCAT, NATO
    notes           TEXT        DEFAULT NULL
);

CREATE TABLE dcs.coalition_members (
    tetragraph      VARCHAR(4)  NOT NULL REFERENCES dcs.coalition_tetragraphs(tetragraph),
    nation_trigraph  VARCHAR(3)  NOT NULL REFERENCES dcs.nation_codes(trigraph),
    PRIMARY KEY (tetragraph, nation_trigraph)
);

-- Non-decomposable tetragraphs (like NKIC) have NO entries in coalition_members
-- Their membership is classified and cannot be stored in this schema
```

### Validation Rule for REL TO

When a REL TO marking includes a tetragraph, nation trigraphs that are members
of that tetragraph must NOT also appear individually:

```
-- VALID:   REL TO USA, FVEY         (USA is listed + tetragraph)
-- VALID:   REL TO USA, DEU, FVEY    (DEU is NOT in FVEY)
-- INVALID: REL TO USA, GBR, FVEY    (GBR IS in FVEY — duplicate)
```

> **Exception for JOINT:** Co-owner countries in a JOINT marking MAY appear in
> REL TO even if also in the JOINT list, but NOT if covered by a tetragraph in REL TO.

---

## 12a. Portion Marking Abbreviations Reference Table

### Why a Reference Table

Portion markings use **abbreviated forms** of banner line markings. The abbreviations
are not always intuitive (e.g., NOFORN → NF, ORCON → OC, Attorney-Client → AC).
A reference table enables:

1. **Banner-to-portion conversion** — Generate correct portion markings from banner data
2. **Portion-to-banner parsing** — Interpret imported portion markings back to structured data
3. **Validation** — Reject invalid abbreviation combinations
4. **Fortra DCS interoperability** — Map between our full vocabulary and tool-limited subsets

### Reference Table Schema

```sql
CREATE TABLE dcs.marking_abbreviations (
    marking_key     VARCHAR(30)  PRIMARY KEY,     -- Normalized key: 'NOFORN', 'ORCON', etc.
    banner_form     VARCHAR(30)  NOT NULL,         -- As appears in banner: 'NOFORN', 'ORCON'
    portion_form    VARCHAR(30)  NOT NULL,         -- As appears in portion: 'NF', 'OC'
    marking_domain  VARCHAR(20)  NOT NULL,         -- 'CLASSIFIED', 'CUI', 'BOTH'
    marking_type    VARCHAR(20)  NOT NULL,         -- 'DISSEMINATION', 'CLASSIFICATION', 'SPECIAL'
    can_combine     VARCHAR[]    DEFAULT NULL,     -- Keys this marking can combine with
    cannot_combine  VARCHAR[]    DEFAULT NULL,     -- Keys this marking conflicts with
    min_class_level dcs.classification_level DEFAULT NULL, -- Minimum classification (NULL = any)
    notes           TEXT         DEFAULT NULL
);
```

### Seed Data

```sql
INSERT INTO dcs.marking_abbreviations
    (marking_key, banner_form, portion_form, marking_domain, marking_type, min_class_level, notes)
VALUES
    -- Classification levels
    ('UNCLASSIFIED',   'UNCLASSIFIED',   'U',      'BOTH',       'CLASSIFICATION', NULL, NULL),
    ('CONFIDENTIAL',   'CONFIDENTIAL',   'C',      'BOTH',       'CLASSIFICATION', NULL, NULL),
    ('SECRET',         'SECRET',         'S',      'BOTH',       'CLASSIFICATION', NULL, NULL),
    ('TOP_SECRET',     'TOP SECRET',     'TS',     'BOTH',       'CLASSIFICATION', NULL, NULL),
    ('CUI',            'CUI',            'CUI',    'CUI',        'CLASSIFICATION', NULL, 'Not a classification level; safeguarding category'),

    -- Classified dissemination controls (CAPCO/ICD 710)
    ('NOFORN',         'NOFORN',         'NF',     'BOTH',       'DISSEMINATION', NULL, 'Not releasable to foreign nationals'),
    ('ORCON',          'ORCON',          'OC',     'CLASSIFIED',  'DISSEMINATION', 'CONFIDENTIAL', 'Dissemination controlled by originator'),
    ('IMCON',          'IMCON',          'IMCON',  'CLASSIFIED',  'DISSEMINATION', 'SECRET', 'Controlled imagery; geospatial S&M'),
    ('PROPIN',         'PROPIN',         'PR',     'CLASSIFIED',  'DISSEMINATION', NULL, 'Proprietary information involved'),
    ('RELIDO',         'RELIDO',         'RELIDO', 'BOTH',       'DISSEMINATION', NULL, 'SFDRA authorized for further sharing'),
    ('REL_TO',         'REL TO',         'REL',    'BOTH',       'DISSEMINATION', NULL, 'Abbreviated when same as banner REL TO'),
    ('DISPLAY_ONLY',   'DISPLAY ONLY',   'DO',     'CLASSIFIED',  'DISSEMINATION', 'CONFIDENTIAL', 'Disclosure without physical copy retention'),

    -- CUI-specific dissemination controls (NARA Registry)
    ('FED_ONLY',       'FED ONLY',       'FED ONLY', 'CUI',     'DISSEMINATION', NULL, 'Federal employees only'),
    ('FEDCON',         'FEDCON',         'FEDCON',   'CUI',      'DISSEMINATION', NULL, 'Federal employees and contractors'),
    ('NOCON',          'NOCON',          'NOCON',    'CUI',      'DISSEMINATION', NULL, 'No dissemination to contractors'),
    ('DL_ONLY',        'DL ONLY',        'DL ONLY',  'CUI',     'DISSEMINATION', NULL, 'Dissemination list controlled; supersedes other LDCs'),
    ('ATTORNEY_CLIENT','Attorney-Client', 'AC',       'CUI',     'DISSEMINATION', NULL, 'Legal Privilege category only'),
    ('ATTORNEY_WP',    'Attorney-WP',    'AWP',      'CUI',     'DISSEMINATION', NULL, 'Legal Privilege category only'),

    -- Atomic Energy (10 CFR 1045)
    ('RD',             'RD',             'RD',     'CLASSIFIED',  'SPECIAL', 'CONFIDENTIAL', 'Restricted Data — Atomic Energy Act'),
    ('FRD',            'FRD',            'FRD',    'CLASSIFIED',  'SPECIAL', 'CONFIDENTIAL', 'Formerly Restricted Data'),
    ('TFNI',           'TFNI',           'TFNI',   'CLASSIFIED',  'SPECIAL', 'CONFIDENTIAL', 'Transclassified Foreign Nuclear Info'),
    ('CNWDI',          'CNWDI',          'N',      'CLASSIFIED',  'SPECIAL', 'SECRET', 'Critical Nuclear Weapon Design Info; RD-N portion mark'),

    -- SAP
    ('SAR',            'SAR',            'SAR',    'CLASSIFIED',  'SPECIAL', 'CONFIDENTIAL', 'Special Access Required');
```

> **Platinum Standard Note:** This reference table enables **programmatic banner line
> generation and parsing** — something no existing DCS tool does comprehensively. We
> can generate `SECRET//ORCON/PROPIN//REL TO USA, GBR` from structured fields, AND
> we can parse it back into structured data. This is the foundation for automated
> marking validation and cross-domain transfer.

---

## 13. Indo-Pacific Ally Classification Systems

### 13.1 Australia — Protective Security Policy Framework (PSPF)

**Post-2018 reform** — Australia removed CONFIDENTIAL and RESTRICTED, creating a
unique hierarchy:

| PSPF Level | Clearance Required | U.S. Equivalent | Our ENUM Mapping |
|-----------|-------------------|-----------------|------------------|
| UNOFFICIAL | None | N/A | *(not stored)* |
| OFFICIAL | None | UNCLASSIFIED | `UNCLASSIFIED` |
| OFFICIAL:Sensitive | Baseline vetting | CUI / SBU | `UNCLASSIFIED` + `cui_category` |
| PROTECTED | Baseline clearance | CONFIDENTIAL | `CONFIDENTIAL` |
| SECRET | NV1 clearance | SECRET | `SECRET` |
| TOP SECRET | PV clearance | TOP SECRET | `TOP_SECRET` |

> **Schema Note:** The Australian OFFICIAL marking observed during an exercise maps
> to `classification_level = 'UNCLASSIFIED'` with `classification_system = 'PSPF'`
> on the confidentiality label. OFFICIAL:Sensitive maps similarly to our CUI handling.

### 13.2 Republic of Korea — Military Secret Protection Act

| Korean Name | Grade | U.S. Equivalent | Our ENUM Mapping |
|------------|-------|-----------------|------------------|
| 일급비밀 (Ilgeup Bimil) | Grade I | TOP SECRET | `TOP_SECRET` |
| 이급비밀 (Igeup Bimil) | Grade II | SECRET | `SECRET` |
| 삼급비밀 (Samgeup Bimil) | Grade III | CONFIDENTIAL | `CONFIDENTIAL` |

- ROK has **no CUI equivalent** and **no RESTRICTED level**
- Unclassified information is simply unmarked
- US-ROK GSOMIA (2014) enables direct classified exchange
- CENTRIXS-K is the dedicated bilateral SECRET network
- **Article 21** of the Military Secret Protection Act extends protection to "military
  secrets of the United Nations forces stationed in the Republic of Korea" and
  information provided under military treaties

### 13.3 Japan — Dual-Track Classification

Japan has two parallel systems post-2013 Specially Designated Secrets (SDS) law:

| Track | Levels | Governing Law | US Equivalent Range |
|-------|--------|--------------|-------------------|
| **Traditional (SDF)** | 機密 (Kimitsu), 極秘 (Gokuhi), 秘 (Hi) | Self-Defense Forces Law | TS, S, C |
| **SDS** | 特定秘密(機密), 特定秘密 | Act No. 108 of 2013 | TS, S |
| **Defense Secrets** | 防衛秘密(機密), 防衛秘密 | US-Japan GSOMIA specific | TS, S |

**US-Japan GSOMIA Equivalence:**

| United States | Japan (Defense Secrets) |
|:-------------|:----------------------|
| TOP SECRET | 防衛秘密 (機密) — Bouei Himitsu (Kimitsu) |
| SECRET | 防衛秘密 — Bouei Himitsu |
| CONFIDENTIAL | 秘 — Hi |

> **Schema Note:** Japan's dual-track system means a single document could carry
> either traditional or SDS classification. The `classification_system` field on
> the confidentiality label distinguishes: `JPN_SDF`, `JPN_SDS`, `JPN_GSOMIA`.

### 13.4 Philippines — Four-Tier System

| Level | U.S. Equivalent | Our ENUM Mapping |
|-------|-----------------|------------------|
| TOP SECRET | TOP SECRET | `TOP_SECRET` |
| SECRET | SECRET | `SECRET` |
| CONFIDENTIAL | CONFIDENTIAL | `CONFIDENTIAL` |
| RESTRICTED | CUI / FOUO (approximate) | `RESTRICTED` |

- Philippines is a **UNC Sending State** (Korean War combat contributor)
- **EDCA** (2014) provides rotational access to 9 Philippine bases
- US-Philippines GSOMIA enables classified exchange
- Bilateral Defense Guidelines (2023) call for improved "information and intelligence
  fusion efforts"
- Philippines is a **Major Non-NATO Ally (MNNA)**

---

## 14. UNC Korea and CFC Information Sharing

### United Nations Command Korea — Unique Composition

The UNC was established 24 July 1950 under UN Security Council resolution. It has
**18 Member States** with a unique distinction between "Sending States" (nations
that contributed forces during the Korean War) and the command/host nations:

| Member State | Trigraph | Contribution | Status |
|-------------|:--------:|-------------|--------|
| Australia | AUS | Combat | Sending State |
| Belgium | BEL | Combat | Sending State |
| Canada | CAN | Combat | Sending State |
| Colombia | COL | Combat | Sending State |
| Denmark | DNK | Medical | Sending State |
| France | FRA | Combat | Sending State |
| Germany | DEU | *(none — joined 2024)* | **Newest Member** |
| Greece | GRC | Combat | Sending State |
| Italy | ITA | Medical | Sending State |
| Netherlands | NLD | Combat | Sending State |
| New Zealand | NZL | Combat | Sending State |
| Norway | NOR | Medical | Sending State |
| Philippines | PHL | Combat | Sending State |
| Thailand | THA | Combat | Sending State |
| Turkey | TUR | Combat | Sending State |
| United Kingdom | GBR | Combat | Sending State |
| United States | USA | Command authority | **Not a Sending State** |
| Republic of Korea | KOR | Host nation | **Not a Sending State** |

> **Important:** Neither the US nor ROK are "Sending States" — the US established
> the unified command, and the ROK received forces.

### Korea-Specific Tetragraphs

| Tetragraph | Full Name | Members | Decomposable |
|:----------:|-----------|---------|:------------:|
| **CFCK** | Combined Forces Command Korea | USA, KOR | Yes |
| **UNCK** | United Nations Command Korea | All 18 member states | Yes |
| **NKIC** | North Korea Intelligence Coalition | *(classified)* | **No** |

### Information Sharing Challenges

1. **CFC ≠ UNC**: Information shared bilaterally under CFC (USA + KOR) is NOT
   automatically available to UNC member states. REL TO CFCK ≠ REL TO UNCK.
2. **UNC-Rear in Japan**: UNC-Rear headquarters is at Yokota Air Base, Japan.
   Information sharing between UNC and Japan requires separate bilateral channels.
3. **Trilateral US-ROK-JPN**: Real-time DPRK missile detection data sharing was
   activated December 2023 under a separate trilateral mechanism, not through UNC.
4. **CENTRIXS-K**: Dedicated US-Korea SECRET network. Not available to broader
   UNC membership.

### Schema Implication

The `coalition_members` table must accurately represent UNCK membership for
tetragraph decomposition:

```sql
-- UNCK coalition membership (18 nations)
INSERT INTO dcs.coalition_members (tetragraph, nation_trigraph) VALUES
    ('UNCK', 'AUS'), ('UNCK', 'BEL'), ('UNCK', 'CAN'), ('UNCK', 'COL'),
    ('UNCK', 'DEU'), ('UNCK', 'DNK'), ('UNCK', 'FRA'), ('UNCK', 'GRC'),
    ('UNCK', 'ITA'), ('UNCK', 'KOR'), ('UNCK', 'NLD'), ('UNCK', 'NZL'),
    ('UNCK', 'NOR'), ('UNCK', 'PHL'), ('UNCK', 'THA'), ('UNCK', 'TUR'),
    ('UNCK', 'GBR'), ('UNCK', 'USA');
```

---

## 15. International Classification Systems Registry

### Why This Table Exists

The Security MCP Server must handle data classified under **any allied or partner
nation's framework** — not just U.S. DoD. A ROK analyst at CFC works with ROK MSPA
markings, U.S. DoD markings, and UNC multi-national markings simultaneously. A NATO
staff officer handles EUCI, national markings, and NATO markings on the same network.
The `classification_systems` reference table enables the schema to distinguish which
framework a classification level belongs to and how to interpret it correctly.

### Classification Systems Reference Table

```sql
CREATE TABLE dcs.classification_systems (
    system_code         VARCHAR(20)   PRIMARY KEY,
    system_name         VARCHAR(200)  NOT NULL,
    governing_nation    VARCHAR(3)    DEFAULT NULL REFERENCES dcs.nation_codes(trigraph),
        -- NULL for multinational systems (NATO, EU)
    governing_org       VARCHAR(100)  DEFAULT NULL,
    governing_document  VARCHAR(200)  DEFAULT NULL,
    has_restricted      BOOLEAN       DEFAULT TRUE,
    has_confidential    BOOLEAN       DEFAULT TRUE,
    num_levels          INTEGER       NOT NULL,
    effective_date      DATE          DEFAULT NULL,
    active              BOOLEAN       DEFAULT TRUE,
    notes               TEXT          DEFAULT NULL
);
```

### Seed Data

```sql
INSERT INTO dcs.classification_systems (system_code, system_name, governing_nation,
    governing_org, governing_document, has_restricted, has_confidential, num_levels,
    effective_date, active, notes) VALUES
('US_DOD',      'U.S. DoD Classification',              'USA', 'DoD/ODNI',       'DoDM 5200.01',            FALSE, TRUE,  4, NULL,         TRUE, 'No RESTRICTED level in U.S. system'),
('NATO',        'NATO Security Classification',          NULL,  'NATO',           'C-M(2002)49',             TRUE,  TRUE,  5, NULL,         TRUE, 'Includes COSMIC TOP SECRET'),
('EU_2013_488', 'EU Classified Information',              NULL,  'EU Council',     'Decision 2013/488/EU',    TRUE,  TRUE,  4, '2013-10-15', TRUE, 'Bilingual marking required (FR/EN)'),
('PSPF',        'AU Protective Security Policy Framework','AUS', 'AGD',           'PSPF Release 2025',       FALSE, FALSE, 4, '2018-10-01', TRUE, 'Removed CONFIDENTIAL and RESTRICTED in 2018 reform'),
('GC_TBS',      'CA Security Categorization',            'CAN', 'TBS',            'Appendix J',              FALSE, TRUE,  4, '2019-07-01', TRUE, 'Adds PROTECTED A/B/C designations separate from classification'),
('UK_GSC',      'UK Government Security Classifications','GBR', 'Cabinet Office', 'GSC Policy',              FALSE, FALSE, 3, '2014-04-02', TRUE, 'No RESTRICTED or CONFIDENTIAL — jumped from OFFICIAL to SECRET'),
('NZ_NZISM',    'NZ Information Security Manual',        'NZL', 'GCSB',           'NZISM v3.7',              TRUE,  TRUE,  5, '2024-02-01', TRUE, 'Most granular FVEY system; 7 levels incl. IN-CONFIDENCE/SENSITIVE'),
('JPN_SDS',     'Japan Specially Designated Secrets',     'JPN', 'Cabinet Office', 'Act No. 108 of 2013',     FALSE, TRUE,  3, '2014-12-10', TRUE, 'Single SDS tier + legacy Hi/Gokuhi; expanding 2025-2026'),
('ROK_MSPA',    'ROK Military Secret Protection Act',     'KOR', 'MND',           'MSPA',                    FALSE, TRUE,  3, NULL,         TRUE, 'Grade I/II/III (일급/이급/삼급비밀); covers USFK/UNC foreign troops'),
('PHL_DPA',     'Philippines Classification',             'PHL', 'DND',           'EO / Congress Act',        TRUE,  TRUE,  5, NULL,         TRUE, 'Full hierarchy including RESTRICTED; MNNA'),
('DEU_VS',      'German Verschlusssache System',          'DEU', 'BMI',           'VSA 2023',                TRUE,  TRUE,  4, '2023-03-13', TRUE, 'VS-NfD through STRENG GEHEIM'),
('FRA_IGI1300', 'French IGI 1300 Classification',         'FRA', 'SGDSN',         'IGI 1300 (2021)',         TRUE,  FALSE, 3, '2021-07-01', TRUE, 'Removed Confidentiel-Défense in 2021; Diffusion Restreinte is NOT a classification level'),
('SGP_IM8',     'Singapore ICT&SS Policy',                'SGP', 'GovTech',       'IM8',                     TRUE,  TRUE,  5, NULL,         TRUE, 'First Indo-Pacific OSCAL adopter; OFFICIAL-OPEN/CLOSED distinction'),
('ISR_PPL',     'Israel Protection of Privacy Law',       'ISR', 'PPA',           'PPL 5741-1981',           FALSE, FALSE, 0, '1981-01-01', TRUE, 'Privacy-focused; military classification not publicly documented');
```

### Key Design Notes

1. **`governing_nation` is NULL for multinational systems** (NATO, EU). This distinguishes
   organizational frameworks from national frameworks.
2. **`has_restricted` / `has_confidential`** document which ENUM ordinals are valid per
   system. The UK has neither; Australia has neither; France has RESTRICTED but not
   CONFIDENTIAL; the US has CONFIDENTIAL but not RESTRICTED.
3. **This table is Phase A** — it's a reference table with no FK dependencies on
   complex structures.

---

## 16. International Classification Cross-Reference

This table validates that the existing 5-level ENUM accommodates **every researched
framework worldwide**. No 6th level is needed.

| Ordinal | Schema ENUM | US DoD | NATO | Australia PSPF | Canada TBS | UK GSC | NZ NZISM | Japan | ROK | Philippines | Germany VS | France IGI1300 | EU (EUCI) | Singapore IM8 |
|:---:|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 0 | `UNCLASSIFIED` | UNCLASSIFIED | NATO UNCLASSIFIED | OFFICIAL | UNCLASSIFIED | OFFICIAL | Official Info | *(unmarked)* | *(unmarked)* | *(unmarked)* | *(unmarked)* | *(unmarked)* | *(unmarked)* | OFFICIAL-OPEN/CLOSED |
| 1 | `RESTRICTED` | *(none)* | NATO RESTRICTED | *(none)* | PROTECTED C | *(none)* | RESTRICTED | *(none)* | *(none)* | RESTRICTED | VS-NfD | Diffusion Restreinte | RESTREINT UE | RESTRICTED |
| 2 | `CONFIDENTIAL` | CONFIDENTIAL | NATO CONFIDENTIAL | PROTECTED | CONFIDENTIAL | *(none)* | CONFIDENTIAL | 秘 (Hi) | 삼급비밀 (Grade III) | CONFIDENTIAL | VS-VERTRAULICH | *(removed 2021)* | CONFIDENTIEL UE | CONFIDENTIAL |
| 3 | `SECRET` | SECRET | NATO SECRET | SECRET | SECRET | SECRET | SECRET | 極秘 (Gokuhi) | 이급비밀 (Grade II) | SECRET | GEHEIM | Secret | SECRET UE | SECRET |
| 4 | `TOP_SECRET` | TOP SECRET | COSMIC TOP SECRET | TOP SECRET | TOP SECRET | TOP SECRET | TOP SECRET | 特定秘密 (Tokutei Himitsu) | 일급비밀 (Grade I) | TOP SECRET | STRENG GEHEIM | Très Secret | TRÈS SECRET UE | TOP SECRET |

### Notable Gaps and Their Handling

| Framework | Gap | How Schema Handles It |
|---|---|---|
| **UK GSC** | No CONFIDENTIAL, no RESTRICTED (removed 2014) | Ordinals 1-2 unused; `classification_systems.has_confidential = FALSE` |
| **France IGI1300** | No CONFIDENTIAL (removed 2021); Diffusion Restreinte is NOT a classification level | DR maps to RESTRICTED for access control but `notes` documents the distinction |
| **Australia PSPF** | No RESTRICTED, no CONFIDENTIAL (removed 2018); OFFICIAL:Sensitive is CUI-equivalent | Ordinals 1-2 unused; OFFICIAL:Sensitive uses CUI columns |
| **Canada TBS** | PROTECTED A/B/C are **separate from** classification (like CUI) | Handled by `protection_designation` column on labels (Phase B) |
| **Japan SDS** | Dual-track: legacy Hi/Gokuhi + new SDS Act; reforming to align with FVEY | `classification_system = 'JPN_SDS'` distinguishes; SDS categories tracked separately |

### National Caveats Not Captured by Standard Dissemination Controls

| Nation | Caveat | Meaning | Storage |
|---|---|---|---|
| Australia | `AUSTEO` | Australian Eyes Only | `national_caveats VARCHAR[]` |
| Australia | `AGAO` | Australian Government Access Only | `national_caveats VARCHAR[]` |
| UK | `UKEO` | UK Eyes Only | `national_caveats VARCHAR[]` |
| UK | `PERSONAL`, `COMMERCIAL`, `LOCSEN` | Handling instructions on OFFICIAL-SENSITIVE | `national_caveats VARCHAR[]` |
| France | `SPECIAL FRANCE` | French citizens only | `national_caveats VARCHAR[]` |
| Germany | `ANRECHT` | Need-to-know within SECRET/TOP SECRET | `national_caveats VARCHAR[]` |
| Germany | `SCHUTZWORT` | Codeword restriction | `national_caveats VARCHAR[]` |

### EU Marking Abbreviations (Addition to `dcs.marking_abbreviations`)

EU classified information requires **bilingual marking** (French/English). These seed
rows extend the existing `marking_abbreviations` table:

```sql
INSERT INTO dcs.marking_abbreviations (marking_key, banner_form, portion_form,
    marking_domain, marking_type, notes) VALUES
('EU_RESTRICTED',   'RESTREINT UE/EU RESTRICTED',       'R-UE',  'CLASSIFIED', 'CLASSIFICATION', 'Bilingual marking per Council Decision 2013/488/EU'),
('EU_CONFIDENTIAL', 'CONFIDENTIEL UE/EU CONFIDENTIAL',  'C-UE',  'CLASSIFIED', 'CLASSIFICATION', 'Bilingual marking per Council Decision 2013/488/EU'),
('EU_SECRET',       'SECRET UE/EU SECRET',               'S-UE',  'CLASSIFIED', 'CLASSIFICATION', 'Bilingual marking per Council Decision 2013/488/EU'),
('EU_TOP_SECRET',   'TRÈS SECRET UE/EU TOP SECRET',     'TS-UE', 'CLASSIFIED', 'CLASSIFICATION', 'Bilingual marking per Council Decision 2013/488/EU');
```

---

## 17. Data Privacy Frameworks Registry

### Why Privacy Frameworks Matter for a Security MCP

Data-Centric Security is not only about classification for national security — it
also encompasses **data protection** for personally identifiable information (PII).
When a NATO staff officer's personnel record is classified SECRET but also contains
personal data of an EU citizen, **both** the classification framework AND the GDPR
apply simultaneously. The schema must track which privacy frameworks govern which data.

### The GDPR-Classification Intersection

| Scenario | Classification? | GDPR? | Framework |
|---|---|---|---|
| EU military member personnel records (HR, medical, pay) | Yes (national) | **Yes** — GDPR applies to EU member state processing | Dual compliance |
| NATO HQ processing of personnel data | Yes (NATO) | **No directly** — but NATO voluntarily aligns since Sept 2024 | NATO Personal Data Protection Framework |
| EU RESTRICTED document with EU employee PII | Yes (EUCI) | **Yes** — Regulation (EU) 2018/1725 (equivalent to GDPR for EU institutions) | Dual compliance |
| FVEY intelligence containing EU citizen data | Yes (national) | **Complex** — GDPR Art. 23 national security exemptions may apply | Case-by-case |
| STIG rules, CVEs, security controls | No PII | **No** — no personal data involved | Classification only |
| CUI personnel records (DoD civilian in Germany) | CUI | **Yes** — GDPR applies to processing in EU regardless of data origin | Dual compliance |

### Data Privacy Frameworks Reference Table

```sql
CREATE TABLE dcs.data_privacy_frameworks (
    framework_code      VARCHAR(30)   PRIMARY KEY,
    framework_name      VARCHAR(200)  NOT NULL,
    governing_nation    VARCHAR(3)    DEFAULT NULL REFERENCES dcs.nation_codes(trigraph),
        -- NULL for multinational frameworks
    governing_body      VARCHAR(100)  NOT NULL,
    governing_law       VARCHAR(200)  DEFAULT NULL,
    effective_date      DATE          NOT NULL,
    breach_notify_hours INTEGER       DEFAULT NULL,
    has_special_categories BOOLEAN    DEFAULT FALSE,
    has_right_to_erasure BOOLEAN      DEFAULT FALSE,
    has_data_portability BOOLEAN      DEFAULT FALSE,
    cross_border_mechanism VARCHAR(50) DEFAULT NULL,
    notes               TEXT          DEFAULT NULL
);
```

### Seed Data

```sql
INSERT INTO dcs.data_privacy_frameworks VALUES
('US_PRIVACY_ACT',  'U.S. Privacy Act of 1974',                  'USA', 'OMB/Agency Heads',     '5 U.S.C. § 552a',              '1974-12-31', NULL, TRUE,  FALSE, FALSE, NULL,           'Federal agencies only; SORN required for each system of records; PIA required by E-Government Act §208; no breach notify statute (OMB M-17-12 guidance: 1hr to US-CERT)'),
('GDPR',            'EU General Data Protection Regulation',    NULL,  'European Commission',  'Regulation (EU) 2016/679',      '2018-05-25', 72,   TRUE,  TRUE,  TRUE,  'ADEQUACY',     'Applies to EU/EEA; extraterritorial reach'),
('UK_GDPR',         'UK GDPR / Data Protection Act 2018',       'GBR', 'ICO',                  'DPA 2018',                      '2021-01-01', 72,   TRUE,  TRUE,  TRUE,  'UK_ADEQUACY',  'Post-Brexit UK framework'),
('CAN_PIPEDA',      'Canada PIPEDA',                             'CAN', 'OPC',                  'PIPEDA (2000)',                 '2000-04-13', NULL, TRUE,  FALSE, TRUE,  'CBPR',         'Federal private sector privacy'),
('AUS_APF',         'Australian Privacy Act 1988',               'AUS', 'OAIC',                 'Privacy Act 1988 (amended)',    '2024-02-01', 72,   TRUE,  TRUE,  FALSE, 'CBPR',         'Notifiable Data Breaches scheme'),
('NZL_PRIVACY_2020','NZ Privacy Act 2020',                       'NZL', 'OPC',                  'Privacy Act 2020',              '2020-12-01', 72,   TRUE,  TRUE,  FALSE, NULL,           'Replaced Privacy Act 1993'),
('JPN_APPI',        'Japan Act on Protection of Personal Info',  'JPN', 'PPC',                  'APPI (amended 2022)',           '2022-04-01', NULL, TRUE,  TRUE,  TRUE,  'EU_ADEQUACY',  'EU adequacy decision holder'),
('ROK_PIPA',        'ROK Personal Information Protection Act',   'KOR', 'PIPC',                 'PIPA (amended 2023)',           '2011-09-30', 72,   TRUE,  TRUE,  TRUE,  'EU_ADEQUACY',  'EU adequacy decision Dec 2023; 24hr breach notify for sensitive data'),
('PHL_DPA_2012',    'Philippines Data Privacy Act',               'PHL', 'NPC',                  'Republic Act 10173',            '2012-08-15', 72,   TRUE,  TRUE,  TRUE,  'CBPR',         'NPC enforced; APEC CBPR member'),
('SGP_PDPA_2012',   'Singapore PDPA',                             'SGP', 'PDPC',                 'PDPA 2012 (amended 2021)',      '2012-10-15', NULL, TRUE,  FALSE, TRUE,  'CBPR',         'Private sector only; government exempt'),
('DEU_BDSG',        'German Federal Data Protection Act',         'DEU', 'BfDI',                 'BDSG (2018)',                   '2018-05-25', 72,   TRUE,  TRUE,  TRUE,  'GDPR',         'GDPR implementing law'),
('BRA_LGPD',        'Brazil LGPD',                                'BRA', 'ANPD',                 'Law No. 13,709',                '2020-09-18', 72,   TRUE,  TRUE,  TRUE,  'ANPD_APPROVAL','3 working day breach notification'),
('ISR_PPL',         'Israel Protection of Privacy Law',           'ISR', 'PPA',                  'PPL 5741-1981 + Amendment 13',  '1981-01-01', NULL, TRUE,  FALSE, FALSE, 'EU_ADEQUACY',  'Amendment 13 effective 2025; EU adequacy holder'),
('EU_US_DPF',       'EU-US Data Privacy Framework',               NULL,  'Commerce/FTC',         'EO 14086 + Commission Decision','2023-07-10', NULL, FALSE, FALSE, FALSE, 'SELF_CERT',    'Replaced Privacy Shield; survived first CJEU challenge Sept 2025'),
('GCBPR',           'Global Cross-Border Privacy Rules',           NULL,  'Global CBPR Forum',    'GCBPR Framework',               '2025-06-02', NULL, FALSE, FALSE, FALSE, 'AGENT_CERT',   '9 member economies + associates; ~100 certified companies'),
('NATO_PDPF',       'NATO Personal Data Protection Framework',     NULL,  'NATO',                 'NATO PDPF (Sept 2024)',         '2024-09-01', NULL, TRUE,  FALSE, FALSE, NULL,           'Voluntary GDPR alignment; covers national IDs, financial, workplace data');
```

### CUI Categories Reference Table (D30)

Per **Q2/Q12** decision, CUI categories are stored as a reference table for insert-time
validation, not as free-text arrays. Data source: DoD CUI Registry at dodcui.mil.

```sql
CREATE TABLE dcs.cui_categories (
    category_code       VARCHAR(20)   PRIMARY KEY,    -- 'PRVCY', 'PROPIN', 'LES', etc.
    category_name       VARCHAR(200)  NOT NULL,        -- Full category name
    is_specified        BOOLEAN       DEFAULT FALSE,   -- TRUE if category has CUI Specified variant
    governing_authority VARCHAR(200)  DEFAULT NULL,     -- Agency/law that designates
    governing_citation  VARCHAR(200)  DEFAULT NULL,     -- e.g., '5 U.S.C. § 552a'
    description         TEXT          DEFAULT NULL,
    active              BOOLEAN       DEFAULT TRUE,
    notes               TEXT          DEFAULT NULL
);

-- Seed data from DoD CUI Registry
INSERT INTO dcs.cui_categories (category_code, category_name, is_specified,
    governing_authority, governing_citation, notes) VALUES
('PRVCY',   'Privacy',                      TRUE,  'OMB/Agency Heads',  '5 U.S.C. § 552a',          'PII, personnel records'),
('PROPIN',  'Proprietary Business',         TRUE,  'DoD',               'DFARS 252.204-7012',        'Contractor data, trade secrets'),
('LES',     'Law Enforcement Sensitive',    TRUE,  'DoJ/Law Enforcement','5 U.S.C. § 552(b)(7)',     'Investigation data'),
('EXPT',    'Export Controlled',            TRUE,  'DoD/DoC/DoS',       'ITAR/EAR',                  'Requires distribution statement'),
('FTI',     'Federal Taxpayer',             TRUE,  'IRS',               '26 U.S.C. § 6103',          'Tax return information'),
('PATENT',  'Patent',                       FALSE, 'USPTO',             '35 U.S.C. § 122',           'Patent applications'),
('CRIT',    'Critical Infrastructure',      TRUE,  'CISA/DHS',          '6 U.S.C. § 671',            'Infrastructure vulnerability data'),
('CTI',     'Controlled Technical Info',    TRUE,  'DoD',               'DoDI 5230.24',              'Requires distribution statement'),
('OPSEC',   'Operations Security',          FALSE, 'DoD',               'DoDI 5205.02E',             'Critical information lists'),
('PHYS',    'Physical Security',            FALSE, 'DoD',               'DoDM 5200.08',              'Security plans, assessments'),
('PROCURE', 'Procurement and Acquisition',  FALSE, 'OMB/GSA',           'FAR 3.104',                 'Source selection, bid data'),
('INTEL',   'Intelligence',                 TRUE,  'ODNI',              'EO 12333',                  'Intelligence activities');
```

> **Note:** This is a representative subset. The full DoD CUI Registry contains additional
> categories. The `active` flag enables incremental addition without schema migration.
> **Follow-up (Q28):** Identify authoritative machine-readable source for complete import.

### Bridge Columns on DCS Data Tables

When data tables contain records subject to privacy frameworks, these bridge columns
connect the DCS classification world to the privacy compliance world:

```sql
-- Added to existing data tables (rules, benchmarks, etc.) in Phase A
-- These are pragmatic: most STIG data has NO PII and these remain NULL
gdpr_applies            BOOLEAN      DEFAULT NULL,
    -- NULL = not assessed; TRUE = contains personal data; FALSE = assessed, no PII
privacy_framework       VARCHAR(30)  DEFAULT NULL REFERENCES dcs.data_privacy_frameworks(framework_code),
    -- Which privacy framework governs this data (if any)
```

---

## 18. GDPR and EU Regulatory Schema Requirements

### GDPR Compliance Tables (Phase C — Migration 000014)

The GDPR mandates specific record-keeping that cannot be satisfied by classification
columns alone. These tables belong in a dedicated `gdpr` schema and are **Phase C**
work — they are not needed for STIG processing but ARE needed before the MCP handles
any data containing EU citizen PII.

### 18a. Article 30 — Records of Processing Activities (RoPA)

**This table is MANDATORY under GDPR.** Any organization processing EU personal data
must maintain it.

```sql
CREATE SCHEMA IF NOT EXISTS gdpr;

CREATE TABLE gdpr.processing_activities (
    activity_id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    activity_name           VARCHAR(200) NOT NULL,
    -- Art 30(1)(a): Controller identification
    controller_name         VARCHAR(200) NOT NULL,
    controller_contact      VARCHAR(200) NOT NULL,
    joint_controllers       JSONB        DEFAULT NULL,
    dpo_name                VARCHAR(200) DEFAULT NULL,
    dpo_contact             VARCHAR(200) DEFAULT NULL,
    -- Art 30(1)(b): Purposes and legal basis
    purposes                TEXT[]       NOT NULL,
    legal_basis             VARCHAR(30)  NOT NULL,
        -- 'ART_6_1_A' (consent), 'ART_6_1_B' (contract), 'ART_6_1_C' (legal obligation),
        -- 'ART_6_1_D' (vital interests), 'ART_6_1_E' (public task), 'ART_6_1_F' (legitimate interests)
    -- Art 30(1)(c): Categories
    data_subject_categories TEXT[]       NOT NULL,
    personal_data_categories TEXT[]      NOT NULL,
    special_categories      TEXT[]       DEFAULT NULL,
        -- Art 9: 'RACIAL_ETHNIC', 'POLITICAL', 'RELIGIOUS', 'TRADE_UNION',
        -- 'GENETIC', 'BIOMETRIC', 'HEALTH', 'SEXUAL_ORIENTATION'
    -- Art 30(1)(d): Recipients
    recipient_categories    TEXT[]       NOT NULL,
    -- Art 30(1)(e): International transfers
    involves_transfer       BOOLEAN      DEFAULT FALSE,
    -- Art 30(1)(f): Retention
    retention_policy        TEXT         NOT NULL,
    retention_period_days   INTEGER      DEFAULT NULL,
    -- Art 30(1)(g): Security measures
    security_measures       TEXT         NOT NULL,
    -- Lifecycle
    is_active               BOOLEAN      DEFAULT TRUE,
    created_at              TIMESTAMPTZ  DEFAULT NOW(),
    updated_at              TIMESTAMPTZ  DEFAULT NOW(),
    last_reviewed_at        TIMESTAMPTZ  DEFAULT NULL,
    next_review_date        TIMESTAMPTZ  DEFAULT NULL
);
```

### 18b. Articles 15-22 — Data Subject Rights Requests

```sql
CREATE TABLE gdpr.data_subject_requests (
    request_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    data_subject_id     UUID         NOT NULL,  -- pseudonymized reference
    request_type        VARCHAR(30)  NOT NULL,
        -- 'ACCESS' (Art 15), 'RECTIFICATION' (Art 16), 'ERASURE' (Art 17),
        -- 'RESTRICTION' (Art 18), 'PORTABILITY' (Art 20), 'OBJECTION' (Art 21),
        -- 'AUTOMATED_DECISION' (Art 22)
    request_date        TIMESTAMPTZ  NOT NULL,
    identity_verified   BOOLEAN      DEFAULT FALSE,
    status              VARCHAR(20)  DEFAULT 'RECEIVED',
        -- 'RECEIVED', 'IDENTITY_PENDING', 'IN_PROGRESS', 'COMPLETED',
        -- 'DENIED', 'EXTENDED'
    response_deadline   TIMESTAMPTZ  NOT NULL,  -- Art 12(3): 1 month from receipt
    extension_notified  BOOLEAN      DEFAULT FALSE,
    denial_basis        VARCHAR(100) DEFAULT NULL,  -- Art 17(3) / Art 23 exemption
    completion_date     TIMESTAMPTZ  DEFAULT NULL,
    erasure_certificate TEXT         DEFAULT NULL,  -- Cryptographic proof for Art 17
    created_at          TIMESTAMPTZ  DEFAULT NOW(),
    updated_at          TIMESTAMPTZ  DEFAULT NOW()
);
```

### 18c. Articles 44-49 — Cross-Border Transfer Authorizations

```sql
CREATE TABLE gdpr.transfer_authorizations (
    transfer_id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    processing_activity_id  UUID         NOT NULL REFERENCES gdpr.processing_activities(activity_id),
    destination_country     VARCHAR(3)   NOT NULL REFERENCES dcs.nation_codes(trigraph),
        -- Reuses GENC trigraphs — natural bridge between DCS and GDPR worlds
    transfer_mechanism      VARCHAR(30)  NOT NULL,
        -- 'ADEQUACY' (Art 45), 'SCC' (Art 46(2)(c)), 'BCR' (Art 46(2)(b)),
        -- 'DEROGATION_CONSENT' (Art 49(1)(a)), 'DEROGATION_PUBLIC_INTEREST' (Art 49(1)(d))
    adequacy_decision_ref   VARCHAR(200) DEFAULT NULL,
    scc_module              VARCHAR(20)  DEFAULT NULL,  -- 'C2C', 'C2P', 'P2P', 'P2C'
    tia_completed           BOOLEAN      DEFAULT FALSE,
    valid_from              TIMESTAMPTZ  NOT NULL,
    valid_until             TIMESTAMPTZ  DEFAULT NULL,
    status                  VARCHAR(20)  DEFAULT 'ACTIVE',
    created_at              TIMESTAMPTZ  DEFAULT NOW()
);
```

### 18d. Articles 33-34 — Breach Register

```sql
CREATE TABLE gdpr.breach_register (
    breach_id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    detection_date          TIMESTAMPTZ  NOT NULL,
    nature_of_breach        TEXT         NOT NULL,
    categories_affected     TEXT[]       NOT NULL,
    approx_subjects_affected INTEGER     DEFAULT NULL,
    likely_consequences     TEXT         NOT NULL,
    measures_taken          TEXT         NOT NULL,
    -- Art 33(1): 72-hour DPA notification
    dpa_notified            BOOLEAN      DEFAULT FALSE,
    dpa_notification_date   TIMESTAMPTZ  DEFAULT NULL,
    delay_justification     TEXT         DEFAULT NULL,
    -- Art 34: Communication to data subjects
    high_risk_to_subjects   BOOLEAN      DEFAULT FALSE,
    subjects_notified       BOOLEAN      DEFAULT FALSE,
    -- Resolution
    root_cause              TEXT         DEFAULT NULL,
    preventive_measures     TEXT         DEFAULT NULL,
    status                  VARCHAR(20)  DEFAULT 'OPEN',
    closed_date             TIMESTAMPTZ  DEFAULT NULL,
    created_at              TIMESTAMPTZ  DEFAULT NOW()
);
```

### 18e. NIS2 Directive Considerations

The NIS2 Directive (EU 2022/2555), fully applicable since October 2024, adds:
- **Asset inventory with classification** — covered by existing DCS columns
- **10 baseline security measures** — largely overlap with NIST 800-53 (already in our DB)
- **Incident reporting** — the `gdpr.breach_register` covers this
- **Supply chain security** — future consideration

The ENISA technical implementation guidance maps NIS2 requirements to ISO 27001 and
NIST CSF 2.0, meaning the existing NIST 800-53 controls in the Security MCP Server
provide a **bridge** from STIG compliance to NIS2 compliance.

### 18f. EU Cyber Resilience Act (CRA)

The CRA (EU 2024/2847), applicable December 2027, requires:
- SBOM generation — already in Makefile (`make sbom`)
- Vulnerability handling — STIG processing IS vulnerability handling
- Security by design — the DCS schema itself embodies this principle

The CRA explicitly **exempts non-monetized open-source software**. If the Security
MCP Server remains Apache 2.0 and non-commercial, it falls under this exemption.
However, commercial deployments would be subject to CRA.

---

## 19. OSCAL International Framework Gaps

### What OSCAL Currently Supports

| Framework | OSCAL Status | Notes |
|---|---|---|
| NIST SP 800-53 Rev 5 (Catalog + Baselines) | ✅ Available | XML, JSON, YAML — already imported in our DB |
| NIST SP 800-53 Rev 4 | ✅ Available | Legacy support |
| FedRAMP Rev 5 (High/Moderate/Low/LI-SaaS) | ✅ Available | Mandated by FedRAMP RFC-0024 |
| CNSS 1253 Overlays | ✅ Available | Profiles in OSCAL format |

### What OSCAL Does NOT Support (Critical Gaps)

| Framework | OSCAL Status | Impact | Effort to Create |
|---|---|---|---|
| **GDPR** | ❌ No catalog exists | Cannot map GDPR requirements to assessable controls | High — GDPR is principles-based, not controls-based |
| **ISO 27001:2022** | ❌ Structurally supported, no official catalog | Cannot do ISO 27001 compliance mapping | Medium — Annex A is controls-based |
| **BSI IT-Grundschutz** | 🔄 **In progress** — Grundschutz++ (Jan 2026) | Germany creating OSCAL/JSON native format | Will be available; transition through 2029 |
| **Singapore IM8** | 🔄 **Active development** by GovTech | First Indo-Pacific OSCAL adopter | [Open-source on GitHub](https://github.com/GovTechSG/tech-standards) |
| **UK Cyber Essentials / NCSC** | ❌ No catalog | Cannot map UK security requirements | Medium |
| **Australia ISM** | ❌ No catalog | Cannot map ASD ISM controls | Medium |
| **NATO STANAG requirements** | ❌ Not supported | NATO uses DCRA/NIAPC, not OSCAL | High — different paradigm |
| **NZ NZISM** | ❌ Not available | Cannot map NZ controls | Medium |
| **Canadian ITSG-33** | ❌ Not available | Cannot map Canadian controls | Medium |
| **French ANSSI requirements** | ❌ Not available | Cannot map French requirements | Medium |
| **ROK security controls** | ❌ Not available | Cannot map Korean requirements | High — limited English docs |
| **NIST CSF 2.0** | 🔄 In development | Expected soon | Will be available |

### Strategic Implications for the Security MCP Server

1. **BSI Grundschutz++ is a game-changer.** Germany's decision to adopt OSCAL/JSON
   (effective January 2026) is the **first major European OSCAL adoption**. This creates
   precedent and potentially a template for other EU frameworks.

2. **Singapore GovTech is the first Indo-Pacific OSCAL adopter.** Their open-source
   IM8-to-OSCAL adaptation demonstrates that non-US frameworks can be expressed in OSCAL.

3. **Our OSCAL import capability is the gateway.** The security-parser's existing OSCAL
   catalog/profile import tools can consume ANY new OSCAL catalogs as they become
   available — no code changes required. As BSI, Singapore, and others publish OSCAL
   content, we import it and immediately gain cross-framework compliance mapping.

4. **GDPR as OSCAL is the hardest problem.** GDPR is principles-based ("data
   minimisation," "purpose limitation") rather than controls-based. Expressing it as
   an OSCAL catalog requires mapping principles to specific, assessable controls.
   This is a potential **differentiator** for the Security MCP Server.

5. **Cross-framework mapping profiles are the killer feature.** An OSCAL profile that
   selects controls from NIST 800-53, ISO 27001, AND BSI Grundschutz for a single
   compliance assessment would be unprecedented. Our multi-catalog architecture
   supports this natively.

---

## 20. Confidentiality Labels Table (STANAG 4774 Ready)

### Phase B — Migration 000013 (Preview)

> **v3.0.0 Addition:** The `confidentiality_labels` table now includes
> `classification_system`, `national_caveats`, and nation-specific columns
> (Canada C/I/A triad, Japan SDS categories, France special designations)
> documented in §15 and §16 above.

This table is NOT created in Migration 000012 but is referenced here because
the `label_id UUID` FK columns added in 000012 point to it.

```sql
-- STANAG 4774-compliant confidentiality label structure
CREATE TABLE dcs.confidentiality_labels (
    label_id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Security Policy (which nation/org's rules apply)
    policy_oid          VARCHAR(50) NOT NULL,       -- e.g., "2.16.840.1.101.2.1.3.13"
    policy_name         VARCHAR(50) NOT NULL,       -- e.g., "US-DoD", "NATO", "PSPF"

    -- Classification
    classification      dcs.classification_level NOT NULL,

    -- Categories (STANAG 4774 structure)
    categories          JSONB       DEFAULT '[]',
        -- Array of: {"type": "PERMISSIVE|RESTRICTIVE|INFORMATIVE",
        --            "tag": "REL_TO|ATOMAL|CRYPTO|SAP|...",
        --            "values": ["USA", "GBR", ...]}

    -- Classification Authority Block (per IF103 Derivative Classification Job Aid)
    classified_by       VARCHAR(200) DEFAULT NULL,   -- Name and title of classifier
    derived_from        VARCHAR(500) DEFAULT NULL,   -- Source document/SCG reference
    reason              VARCHAR(50)  DEFAULT NULL,    -- EO 13526 §1.4 reason code: '1.4(a)'..'1.4(h)'

    -- Declassification (per ISOO Marking Booklet Rev 4, Jan 2018)
    declassify_on           DATE         DEFAULT NULL,   -- YYYYMMDD date
    declassify_event        VARCHAR(500) DEFAULT NULL,   -- Event description (if event-based)
    declass_exemption       VARCHAR(10)  DEFAULT NULL,   -- '25X1'..'25X9', '50X1-HUM', '50X2-WMD', '75X'
    declass_exemption_date  DATE         DEFAULT NULL,   -- ISCAP-approved date for 25X/75X exemptions
    is_legacy_converted     BOOLEAN      DEFAULT FALSE,  -- TRUE if declass instruction was converted
    legacy_instruction      VARCHAR(50)  DEFAULT NULL,   -- Original legacy marking (OADR, MR, X1-X8)

    -- Atomic Energy (10 CFR Part 1045 — per Marking NSI Job Aid)
    atomic_energy       VARCHAR[]    DEFAULT NULL,    -- 'RD', 'FRD', 'TFNI'
    is_cnwdi            BOOLEAN      DEFAULT FALSE,   -- Critical Nuclear Weapon Design Info
    -- Note: RD/FRD markings NEVER have declassify_on dates (Atomic Energy Act governs)

    -- Special Access Programs (DoDM 5205.07 — per Marking NSI Job Aid)
    sap_markings        JSONB        DEFAULT NULL,
    -- Structure: [{"nickname": "TWISTED FEATHER", "pid": "TF",
    --              "dcn": "SAPCO/0001-01", "fse_date": "2072-01-15"}]

    -- Intelligence Community (ICD 710 / CAPCO Register — per Marking NSI Job Aid)
    sci_controls        VARCHAR[]    DEFAULT NULL,    -- SCI compartments: 'HCS', 'SI', 'TK', 'G'

    -- Classification by Compilation (EO 13526 §1.7(e) — per ISOO Marking Booklet)
    is_compilation          BOOLEAN     DEFAULT FALSE,
    compilation_basis       TEXT        DEFAULT NULL,   -- OCA explanation of compilation classification

    -- Provenance
    created_by          VARCHAR(200) NOT NULL,
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT now(),
    expires_at          TIMESTAMPTZ  DEFAULT NULL,

    -- Full serializations (for interoperability)
    label_xml           TEXT         DEFAULT NULL,    -- STANAG 4774 XML encoding
    label_json          JSONB        DEFAULT NULL,    -- STANAG 4774 JSON encoding

    -- Cryptographic binding (STANAG 4778)
    digital_signature   BYTEA        DEFAULT NULL
);
```

### Why Phase B and Not Phase A

Creating this table now would be **premature**:
1. No code exists to populate it (no STANAG 4774 parser, no label generator)
2. No code exists to read it (no RLS policies or Kyverno policies reference it yet)
3. The FK from `label_id` columns is nullable — it works without the target table

Adding the `label_id UUID` columns in Phase A establishes the relationship path.
Creating the target table in Phase B (when we build the STIG archive import and
need to tag labels) is the right sequence.

---

## 21. Classification Authority Block

### Required Fields (from IF103 — Derivative Classification)

Every classified document requires a classification authority block containing:

| Field | Example | Storage |
|-------|---------|---------|
| Classified By | `J. Smith, Program Manager` | `confidentiality_labels.classified_by` |
| Derived From | `Multiple Sources` or specific guide | `confidentiality_labels.derived_from` |
| Declassify On | `20360115` or event description | `confidentiality_labels.declassify_on` |
| Reason | Section 1.4(c) of EO 13526 | `confidentiality_labels.reason` |

### When Classification Authority Block Is NOT Required

Per DoDM 5200.01-V2:
- **FGI documents entirely from foreign source** — excluded from EO 13526 marking
  requirements; no classification authority block needed
- **JOINT where US is co-owner** — classification authority block IS required
- **CUI** — uses CUI Authority Block instead (different fields: Controlled By,
  CUI Category, POC)

### Declassification and Nuclear Markings

Per **10 CFR Part 1045** (from IF105):
- Atomic Energy markings (RD, FRD, TFNI) **cannot be declassified by executive order**
- They are governed by the Atomic Energy Act (Congressional statute)
- `declassify_on` does NOT apply to RD/FRD data
- Schema stores `atomic_energy VARCHAR[]` separately to make this distinction clear

---

## 22. Portion Marking Considerations

### What Portion Marking Is

A single document (or API response) can contain sections at different classification
levels. The Classification Marking Guide v11 Section 6.2 shows:

```
SECRET//FGI GBR//REL TO USA, DEU, GBR

(U) 1. INTRODUCTION
(S//REL TO USA, DEU, GBR) 2. U.S. ANALYSIS
(//GBR S) 3. UK CONTRIBUTION
(U) 4. ADMINISTRATIVE

SECRET//FGI GBR//REL TO USA, DEU, GBR
```

### Schema Approach: NOT in Migration 000012

Portion marking is an **API response concern**, not a data storage concern:
- Individual STIG rules are single-classification objects
- Portion marking applies when MULTIPLE objects are returned in one response
- The STANAG 4778 REST binding profile handles portion marking via JSON Pointer
  (RFC 6901) references within the `metadata_bindings` table

### Future Implementation Path

The `metadata_bindings` table (Migration 000013) supports portion marking:
```sql
CREATE TABLE dcs.metadata_bindings (
    binding_id      UUID PRIMARY KEY,
    data_object_type VARCHAR(50),     -- 'api_response', 'stig_rule', etc.
    data_object_id  UUID,
    label_id        UUID REFERENCES dcs.confidentiality_labels(label_id),
    portion_path    VARCHAR(500),     -- JSON Pointer (RFC 6901) for sub-document
    binding_profile VARCHAR(20),      -- 'REST', 'XML', 'CRYPTO'
    ...
);
```

---

## 23. Migration Plan — Phased Approach

### Phase A — Migration 000001 Baseline + 000002 Rank Function (COMPLETE)

> ✅ **COMPLETE (2026-02-01 + 2026-02-11):** Migration 000012 folded into
> consolidated baseline (000001). Migration 000002 adds `classification_level_rank()`
> for ABAC filtering. Application-level ABAC middleware operational in security-query.

**Goal:** Add DCS columns to data tables. Create reference tables. Zero impact on
existing services.

| Component | Action | Impact on Existing Code |
|-----------|--------|------------------------|
| `dcs` schema | CREATE | None |
| `dcs.classification_level` ENUM | CREATE | None |
| `dcs.nation_codes` table | CREATE + seed (~30 allies) | None |
| `dcs.coalition_tetragraphs` table | CREATE + seed (~10) | None |
| `dcs.coalition_members` table | CREATE + seed (~60) | None |
| `dcs.distribution_statements` table | CREATE + seed (6 rows) | None |
| `dcs.marking_abbreviations` table | CREATE + seed (~30 rows, incl. EU bilingual) | None |
| `dcs.classification_systems` table | CREATE + seed (14 frameworks) | None |
| `dcs.data_privacy_frameworks` table | CREATE + seed (16 privacy laws incl. U.S. Privacy Act) | None |
| `dcs.cui_categories` table | CREATE + seed (~20 categories from DoD CUI Registry) (D30) | None |
| Classification columns on data tables (incl. `classification_system`, `classification_confidence`) | ALTER TABLE ADD COLUMN | None (all have defaults) |
| CUI columns on data tables (incl. DI block) | ALTER TABLE ADD COLUMN | None (all have defaults) |
| Dissemination columns on data tables | ALTER TABLE ADD COLUMN | None (all have defaults) |
| FGI columns on data tables | ALTER TABLE ADD COLUMN | None (all have defaults) |
| Privacy bridge columns (`gdpr_applies`, `privacy_framework`) | ALTER TABLE ADD COLUMN | None (all NULL defaults) |
| `label_id UUID` placeholder | ALTER TABLE ADD COLUMN | None (nullable, no FK yet) |
| Classification indexes | CREATE INDEX | None |

### Phase B — Migration 000013 (Next Session)

**Goal:** Create `confidentiality_labels` and `metadata_bindings` tables. Add FK
constraints. Integrate with STIG archive import.

| Component | Action |
|-----------|--------|
| `dcs.confidentiality_labels` table | CREATE (with full §5a columns: atomic_energy, sap_markings, sci_controls, declass_exemption, compilation flags, legacy conversion tracking) |
| `dcs.metadata_bindings` table | CREATE |
| FK constraints from `label_id` columns | ALTER TABLE ADD CONSTRAINT |
| Parser: populate classification from DISA prefixes | Code change |
| Parser: populate CUI DI block from DISA metadata | Code change |
| Audit log: include classification level | Code change |
| Banner line generator: structured fields → marking string | New utility |
| Banner line parser: marking string → structured fields | New utility |

### Phase C — Future (When Policy Engine + User Identity Exists)

**Goal:** Hybrid Kyverno (Layers 1-2) + PostgreSQL RLS (Layer 3) enforcement,
platform classification ceiling, user session attributes, audit sanitization,
STANAG 4774 label generation.

> **Architecture Decision (D24):** Hybrid Kyverno + PostgreSQL RLS replaces the
> original OPA-only approach. Kyverno handles Kubernetes admission control (Layer 1)
> and API gateway authorization (Layer 2) via YAML-native policies. PostgreSQL RLS
> handles data-level access control (Layer 3) natively in SQL. No Rego, no new
> language — YAML for cluster policy, SQL for data policy.

| Component | Action |
|-----------|--------|
| `dcs.platform_configuration` table | CREATE (§28a — platform classification ceiling) |
| `dcs.user_sessions` table | CREATE (§28b — zero-PII authorization attributes for RLS) |
| `dcs.audit_log` table with hash chaining (D45) | CREATE (§28a — tamper-evident classification-aware logging) |
| `dcs.audit_rls_details` auditor-only table (D47) | CREATE (§28a — covert channel-free RLS filtering metadata) |
| PostgreSQL RLS policies | CREATE POLICY (classification, nationality, SAP, SCI) |
| Kyverno admission policies | YAML policy files in Git — GitOps only, no DB storage (D43) |
| Kyverno API gateway policies | YAML policy files in Git — GitOps only (D43) |
| STANAG 4774 label generator | New service code |
| STANAG 4778 REST binding engine | New middleware |
| Audit sanitization middleware | New gateway code (compares data vs. platform ceiling) |

### Phase D — Migration 000014 (When PII Data Enters the System)

**Goal:** GDPR compliance tables, data subject rights workflow, cross-border transfer
tracking. See §27 for full preview.

| Component | Action |
|-----------|--------|
| `gdpr` schema | CREATE |
| `gdpr.processing_activities` table | CREATE (Art. 30 RoPA — mandatory) |
| `gdpr.data_subject_requests` table | CREATE (Art. 15-22 rights workflow) |
| `gdpr.transfer_authorizations` table | CREATE (Art. 44-49 cross-border) |
| `gdpr.breach_register` table | CREATE (Art. 33-34 incident tracking) |
| `gdpr.consent_records` table | CREATE (Art. 6(1)(a), Art. 7) |
| `gdpr.retention_schedules` table | CREATE (Art. 5(1)(e), Art. 17 erasure) |
| `gdpr.impact_assessments` table | CREATE (Art. 35 DPIA) |

---

## 24. Migration 000012 SQL Structure

### New Reference Tables Created

| Schema | Table | Purpose | Rows (Seed) |
|--------|-------|---------|:-----------:|
| `dcs` | `nation_codes` | GENC trigraph lookup (§11) | ~30 (allies) |
| `dcs` | `coalition_tetragraphs` | CAPCO tetragraph registry (§12) | ~10 |
| `dcs` | `coalition_members` | Tetragraph → nation membership (§12) | ~60 |
| `dcs` | `distribution_statements` | DoDI 5230.24 statements A–F (§5) | 6 |
| `dcs` | `marking_abbreviations` | Banner↔portion marking conversion (§12a) | ~30 (incl. EU) |
| `dcs` | `classification_systems` | International framework registry (§15) | 14 |
| `dcs` | `data_privacy_frameworks` | Privacy law registry (§17) | 16 |
| `dcs` | `cui_categories` | DoD CUI Registry categories for validation (D30) | ~20 |

### Tables Receiving New Columns

| Schema | Table | Row Count (Feb 2026) | Columns Added |
| ------ | ----- | :------------------: | :-----------: |
| `xccdf_library` | `benchmarks` | ~287 | 13 |
| `xccdf_library` | `rules` | ~17,323 | 17 |
| `oscal` | `documents` | ~15 | 10 |
| `oscal` | `catalog_controls` | ~1,196 | 6 |
| `cci_mappings` | `cci_controls` | ~5,137 | 6 |
| `cklb_assessments` | `checklists` | 0 | 13 |
| `ato_packages` | `systems` | 0 | 8 |

### Column Definitions (Applied to Each Table as Appropriate)

```sql
-- Core classification
classification_level    dcs.classification_level DEFAULT 'UNCLASSIFIED' NOT NULL,
document_type           VARCHAR(20)     DEFAULT 'US_DOD',
    -- Values: 'US_DOD', 'JOINT', 'FGI', 'FGI_CONCEALED', 'NATO'
owner_nations           VARCHAR[]       DEFAULT '{USA}',
originating_nation      VARCHAR(3)      DEFAULT 'USA',

-- CUI (separate from classification — see §5)
cui_category            VARCHAR[]       DEFAULT NULL,   -- DoD CUI Registry categories
cui_specified           BOOLEAN         DEFAULT FALSE,  -- TRUE = CUI Specified (stricter)
cui_dissem_controls     VARCHAR[]       DEFAULT NULL,   -- Full NARA vocabulary (10 LDCs)

-- CUI Designation Indicator Block (see §5, CUI Markings Training Aid Dec 2024)
cui_controlled_by       VARCHAR(200)    DEFAULT NULL,   -- "DDI(CL&S)/IAP"
cui_poc                 VARCHAR(200)    DEFAULT NULL,   -- "John Brown, 703-555-0123"
distribution_statement  VARCHAR(1)      DEFAULT NULL,   -- 'A','B','C','D','E','F' (DoDI 5230.24)

-- Classified dissemination controls (CAPCO/ICD 710 — see §6)
dissem_controls         VARCHAR[]       DEFAULT NULL,   -- NOFORN, ORCON, IMCON, PROPIN, RELIDO
noforn                  BOOLEAN         DEFAULT FALSE,  -- Fast RLS predicate
rel_to_nations          VARCHAR[]       DEFAULT NULL,   -- GENC trigraphs + tetragraphs
display_only_nations    VARCHAR[]       DEFAULT NULL,   -- GENC trigraphs + tetragraphs

-- FGI (see §8)
fgi_source_nations      VARCHAR[]       DEFAULT NULL,
fgi_source_concealed    BOOLEAN         DEFAULT FALSE,

-- Non-standard handling (see §10)
handling_caveats        TEXT            DEFAULT NULL,

-- Privacy framework bridge (see §17)
gdpr_applies            BOOLEAN         DEFAULT NULL,   -- NULL=not assessed; TRUE/FALSE=assessed
privacy_framework       VARCHAR(30)     DEFAULT NULL,   -- FK to dcs.data_privacy_frameworks

-- Classification system (D36 — resolves Q5/Q13)
classification_system   VARCHAR(20)     DEFAULT 'US_DOD',
    -- FK to dcs.classification_systems(system_code)
    -- Identifies which framework this classification belongs to
    -- Enables per-row disambiguation in multinational environments (CFC/USFK)

-- Classification confidence (D48 — resolves Q27, DSAWG-F05)
classification_confidence VARCHAR(20)   DEFAULT 'DEFAULT',
    -- 'EXPLICIT' = human-assigned classification
    -- 'INFERRED' = derived from DISA filename prefix (U_, CUI_, etc.)
    -- 'DEFAULT'  = schema default (UNCLASSIFIED) — not yet assessed
    -- Enables spillage detection: "show all data classified by default"

-- Future STANAG 4774 label reference
label_id                UUID            DEFAULT NULL
```

> **Note:** Not every table needs every column. `rules` and `checklists` get
> the full set including CUI DI block columns. `catalog_controls` gets a minimal
> subset (classification_level, originating_nation, label_id). See Migration SQL
> for exact per-table column assignments.
>
> **Columns deferred to Phase B (confidentiality_labels table):** atomic_energy,
> is_cnwdi, sap_markings, sci_controls, classified_by, derived_from, declassify_on,
> declassify_event, declass_exemption, reason, is_compilation, compilation_basis,
> is_legacy_converted, legacy_instruction. These are **label-level concerns**, not
> data-table-level concerns.

### Indexes Created

```sql
-- For future PostgreSQL RLS
CREATE INDEX idx_benchmarks_classification ON xccdf_library.benchmarks (classification_level);
CREATE INDEX idx_rules_classification ON xccdf_library.rules (classification_level);
CREATE INDEX idx_rules_noforn ON xccdf_library.rules (noforn) WHERE noforn = true;
CREATE INDEX idx_docs_classification ON oscal.documents (classification_level);

-- For nation-based queries
CREATE INDEX idx_rules_rel_to ON xccdf_library.rules USING GIN (rel_to_nations);
CREATE INDEX idx_rules_owner ON xccdf_library.rules USING GIN (owner_nations);
```

---

## 25. Impact on Existing Services

### Phase A (000001 Baseline) — Zero Impact

All DCS columns from the original migration 000012 were folded into the
consolidated baseline (000001). New columns have defaults — existing INSERT
statements and SELECT queries continued to work unchanged.

### Migration 000002 (Rank Function) + ABAC Middleware — Active Impact

> **Updated 2026-02-12:** With v0.9.0 (JWT auth) and the dashboard/ABAC
> deployment, services now **actively use** DCS columns for access control.

| Service | Impact | Details |
| ------- | ------ | ------- |
| security-gateway | **Active** | Propagates `X-User-Clearance` and `X-User-Nationality` headers from JWT claims to downstream services. Identity hash in `X-Identity-Hash` for zero-PII audit. |
| security-parser | None | Does not INSERT into DCS columns yet; existing import works |
| security-query | **Active** | ABAC middleware extracts clearance/nationality from headers. Stats endpoint and future query endpoints use `classification_level_rank()` in WHERE clauses for data filtering. |
| security-controls | None | Does not query data tables directly |
| security-ui | **Active** | Displays user clearance badge, nationality in user menu. Dashboard shows system stats filtered by ABAC context. |
| db-migrate | **Active** | Init container runs 000001 + 000002 migrations on pod startup |

All DCS columns still have defaults:

- `classification_level = 'UNCLASSIFIED'`
- `owner_nations = '{USA}'`
- `originating_nation = 'USA'`
- All other columns = `NULL` or `FALSE`

### When Services WILL Change (Future Phases)

| Phase | Service | Change |
|-------|---------|--------|
| B (000013) | security-parser | Populate classification from DISA filename prefixes |
| B (000013) | security-gateway | Tag `import_stig_archive` results with classification |
| C (RLS) | security-query | Pass user session attributes via `SET dcs.session_id` for RLS evaluation |
| C (Kyverno) | security-gateway | Kyverno policies for MCP tool authorization (YAML-native) |
| C (Platform) | security-gateway | Platform ceiling check + audit sanitization middleware |
| **#105** | **security-gateway** | **REST API proxy routes with JWT validation (Zero Trust)** |

---

## 26. Future Migration 000013 Preview

Migration 000013 will create the tables previewed in §20 and add FK constraints:

```sql
-- Add FK from data tables to confidentiality_labels
ALTER TABLE xccdf_library.rules
    ADD CONSTRAINT fk_rules_label
    FOREIGN KEY (label_id) REFERENCES dcs.confidentiality_labels(label_id);

ALTER TABLE xccdf_library.benchmarks
    ADD CONSTRAINT fk_benchmarks_label
    FOREIGN KEY (label_id) REFERENCES dcs.confidentiality_labels(label_id);

-- etc. for all tables with label_id
```

---

## 27. Future Migration 000014 Preview — GDPR/Privacy

Migration 000014 creates the `gdpr` schema and privacy compliance tables previewed
in §18. This migration is **not needed for STIG processing** but IS needed before
the MCP handles any data containing EU citizen PII (e.g., personnel assessment
records, incident response reports with identifiable individuals).

### Phase C Scope

| Table | Purpose | GDPR Article |
|---|---|---|
| `gdpr.processing_activities` | Records of Processing Activities (RoPA) | Art. 30 (mandatory) |
| `gdpr.data_subject_requests` | Rights request workflow tracking | Art. 15-22 |
| `gdpr.transfer_authorizations` | Cross-border transfer legal basis | Art. 44-49 |
| `gdpr.breach_register` | Data breach documentation | Art. 33-34 |
| `gdpr.consent_records` | Consent management | Art. 6(1)(a), Art. 7 |
| `gdpr.retention_schedules` | Automated erasure scheduling | Art. 5(1)(e), Art. 17 |
| `gdpr.impact_assessments` | DPIA tracking | Art. 35 |

### Key Integration Points

1. **`gdpr.transfer_authorizations.destination_country`** → FK to `dcs.nation_codes(trigraph)`
   — the GENC trigraph table bridges classification and privacy worlds
2. **`dcs.data_privacy_frameworks`** (Phase A) → referenced by bridge columns on data tables
3. **PostgreSQL RLS (Phase C)** → GDPR access controls use the same RLS infrastructure
   planned for classification-based access control

### ROK-Specific Considerations

The ROK Personal Information Protection Act (PIPA), amended 2023, received an
**EU adequacy decision in December 2023** — meaning ROK is recognized as providing
"essentially equivalent" data protection to the EU. This is directly relevant for
CFC/USFK operations where ROK and EU NATO member personnel data coexist.

The schema supports this via the `dcs.data_privacy_frameworks` table with both
`ROK_PIPA` and `GDPR` entries, and the `gdpr.transfer_authorizations` table
tracking adequacy-based transfers between the EU and ROK.

---

## 28. Security Considerations

### NIST SP 800-53 Controls Addressed

| Control | Title | How Addressed |
|---------|-------|---------------|
| **SC-16** | Transmission of Security and Privacy Attributes | Classification columns carry security attributes with data |
| **AC-16** | Security and Privacy Attributes | Data records tagged with classification metadata |
| **AC-3** | Access Enforcement | Indexes enable future RLS enforcement |
| **AU-3** | Content of Audit Records | Classification of accessed data available for audit logging |
| **MP-3** | Media Marking | Digital equivalent — data records carry classification markings |
| **SI-12** | Information Management and Retention | `declassify_on` supports declassification lifecycle |

### System Scope: Multi-Level Secure (MLS) Data Store — NOT a Cross Domain Solution (D44)

> **Architectural Determination (D44, resolves DSAWG-F02):** The Security MCP Server
> is a **Multi-Level Secure (MLS) data store**. It stores data at multiple classification
> levels and enforces access control within a single domain using PostgreSQL Row-Level
> Security (RLS). It is **NOT** a Cross Domain Solution (CDS).
>
> **What this means:**
> - The system does not transfer data between classification domains
> - PostgreSQL RLS is the sole data-level enforcement mechanism (Layer 3)
> - Cross-domain data transfer is **out of scope** — it requires external CDS guards
>   (e.g., ISSE Guard, Raise the Bar-compliant solutions) that are outside the
>   accreditation boundary of this system
> - AI agents leveraging this MCP capability will reach through pre-existing Guards
>   which are external to and outside the scope of our effort
> - The DSAWG evaluation pathway follows MLS criteria per CNSSI 1253, not CDS criteria
>   per DoDI 8540.01
>
> **Accreditation Implication:** PostgreSQL RLS alone is sufficient for MLS access
> enforcement within a single domain. The system's accreditation boundary encompasses
> the four microservices (gateway, parser, query, controls), the PostgreSQL database,
> and the inter-service mTLS mesh. External interfaces (MCP STDIO, IdP) are boundary
> crossing points documented in the system's accreditation package.

### Audit Logging — Zero-PII Architecture (Operational)

> **Updated 2026-02-12:** Zero-PII audit logging is operational since v0.9.0.
> The gateway logs an opaque SHA-512 identity hash instead of PII. The
> `X-Identity-Hash` header propagates the hash to downstream services for
> correlated audit trails without exposing user identity in the database.

Per the IF130 (Unauthorized Disclosure) training, audit logs must include the
classification level of accessed data for UD investigation support. The current
audit log format uses zero-PII identity hashing:

```json
{
  "timestamp": "2026-02-12T03:00:00Z",
  "identity_hash": "sha512:a1b2c3d4...",
  "tool": "get_rule",
  "params": {"rule_id": "SV-230221r858695_rule"},
  "result": "success",
  "data_classification": "UNCLASSIFIED",
  "data_rel_to": null,
  "source_ip": "10.0.0.1"
}
```

Phase B will extend this to include `data_classification` from the actual record
metadata (currently all records are UNCLASSIFIED by default).

### Risk: Unauthorized Disclosure via API Response

> **Updated 2026-02-12:** Application-level ABAC filtering is now operational.
> The security-query service filters data by user clearance and nationality via
> WHERE clauses using `classification_level_rank()`. This is Layer 2 (application)
> enforcement. Layer 3 (PostgreSQL RLS) remains a future defense-in-depth measure.

With application-level ABAC enforcement (v0.9.0), the classification columns are
**actively used for filtering** on MCP tool invocations. The gateway propagates
JWT claims (`X-User-Clearance`, `X-User-Nationality`) to downstream services,
which apply WHERE clause filtering before returning results.

**Current limitation:** REST API calls from the Vue 3 dashboard bypass the
gateway's JWT auth middleware and hit security-query directly (tracked as
Issue #105 — Zero Trust REST API Gateway Proxy). ABAC headers are only
propagated on MCP tool invocations until #105 is resolved.

**Mitigation timeline:**

1. Phase A (000001): Columns exist, all data is UNCLASSIFIED → no risk ✅
2. Migration 000002 + ABAC: Application-level filtering by clearance/nationality → **partial enforcement** ✅
3. Issue #105: REST API proxy through gateway → ABAC on all traffic paths (in progress)
4. Phase B (000013): Labels populated on import → richer classification metadata
5. Phase C (Kyverno + PostgreSQL RLS): Full defense-in-depth enforcement → risk eliminated

### 28a. Platform Classification Ceiling and Audit Sanitization

#### The Principle

Every deployment environment has a **classification ceiling** — the maximum
classification level the platform is authorized to process. This ceiling is
established by the system's Authority to Operate (ATO) and is immutable at runtime.

**Fundamental Rule:** An audit log on a SECRET platform **MUST NEVER** contain
content classified above SECRET. If an audit event would log TOP SECRET data on a
SECRET platform, the log entry must be **sanitized** — recording that a classified
event occurred without disclosing the classified content.

This is not optional. This is DoDM 5200.01 and EO 13526 — unauthorized disclosure
of classified information at a higher level than the platform is a security incident.

#### Platform Configuration Table (Phase C)

```sql
CREATE TABLE dcs.platform_configuration (
    config_id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    platform_name           VARCHAR(200) NOT NULL,
    platform_environment    VARCHAR(50)  NOT NULL,
        -- 'NIPRNET', 'SIPRNET', 'JWICS', 'COALITION', 'UNCLASSIFIED_LAB'
    -- Classification ceiling
    max_classification      dcs.classification_level NOT NULL,
    max_dissem_controls     VARCHAR[]    DEFAULT NULL,
        -- Platform's dissemination ceiling, e.g., '{USA,GBR,AUS,CAN,NZL}' for FVEY enclave
    platform_nations        VARCHAR[]    NOT NULL,
        -- Nations authorized to operate on this platform
    -- Capability flags
    sci_authorized          BOOLEAN      DEFAULT FALSE,
    sap_authorized          BOOLEAN      DEFAULT FALSE,
    nato_authorized         BOOLEAN      DEFAULT FALSE,
    cui_authorized          BOOLEAN      DEFAULT TRUE,
    -- Audit behavior
    sanitize_above_ceiling  BOOLEAN      DEFAULT TRUE,
        -- MUST always be TRUE in production; FALSE only for development/test
    sanitized_label         VARCHAR(30)  DEFAULT 'CLASSIFIED',
        -- What to show in place of actual classification when sanitized
    -- Lifecycle
    effective_date          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    certified_by            VARCHAR(200) DEFAULT NULL,
    ato_reference           VARCHAR(100) DEFAULT NULL,
        -- e.g., 'ATO-2026-SMCP-001' — links to authorizing document
    is_active               BOOLEAN      DEFAULT TRUE,
    -- Constraints
    CONSTRAINT chk_sanitize CHECK (sanitize_above_ceiling = TRUE OR platform_environment = 'UNCLASSIFIED_LAB')
);
```

#### Classification Comparison Function

The ENUM ordinal comparison enables a simple, immutable SQL function:

```sql
CREATE OR REPLACE FUNCTION dcs.can_platform_display(
    data_classification     dcs.classification_level,
    platform_ceiling        dcs.classification_level
) RETURNS BOOLEAN AS $$
    SELECT data_classification <= platform_ceiling;
$$ LANGUAGE SQL IMMUTABLE PARALLEL SAFE;

-- Convenience function using active platform config
CREATE OR REPLACE FUNCTION dcs.is_within_platform_ceiling(
    data_classification     dcs.classification_level
) RETURNS BOOLEAN AS $$
    SELECT data_classification <= (
        SELECT max_classification FROM dcs.platform_configuration
        WHERE is_active = TRUE LIMIT 1
    );
$$ LANGUAGE SQL STABLE;
```

#### Audit Log Table with Sanitization

```sql
CREATE TABLE dcs.audit_log (
    log_id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Timestamp (always logged)
    event_time              TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    -- Identity (always logged — NO PII, opaque hash only)
    session_id              UUID         NOT NULL REFERENCES dcs.user_sessions(session_id),
    identity_hash           VARCHAR(128) NOT NULL,
        -- Same SHA-512 hash as user_sessions.identity_hash — correlatable
        -- but NOT reversible without IdP access
    source_ip               INET         DEFAULT NULL,
    -- Event metadata (always logged)
    event_type              VARCHAR(50)  NOT NULL,
        -- 'QUERY', 'IMPORT', 'EXPORT', 'ADMIN', 'AUTH_SUCCESS', 'AUTH_FAILURE'
    mcp_tool                VARCHAR(100) DEFAULT NULL,
        -- Which MCP tool was invoked, e.g., 'get_rule', 'search_stigs'
    event_result            VARCHAR(20)  NOT NULL,
        -- 'SUCCESS', 'DENIED', 'ERROR', 'SANITIZED'
    -- Data reference (sanitized if above ceiling)
    target_table            VARCHAR(100) DEFAULT NULL,
    target_id               VARCHAR(200) DEFAULT NULL,
        -- Sanitized to NULL if above ceiling
    -- Classification of the data involved
    data_classification     dcs.classification_level DEFAULT NULL,
        -- Shows actual classification ONLY if within platform ceiling
        -- Shows NULL if sanitized (original stored in sanitized_original_level)
    -- Sanitization tracking
    was_sanitized           BOOLEAN      DEFAULT FALSE,
    sanitized_original_level dcs.classification_level DEFAULT NULL,
        -- The ACTUAL classification level — only populated when was_sanitized = TRUE
        -- This column is itself protected: only auditors with appropriate clearance
        -- can see it (enforced by RLS on this table)
    sanitization_reason     VARCHAR(100) DEFAULT NULL,
        -- 'ABOVE_PLATFORM_CEILING', 'SAP_NO_ACKNOWLEDGE', 'SCI_COMPARTMENT',
        -- 'NATIONALITY_RESTRICTION'
    -- Content (sanitized if above ceiling)
    event_detail            TEXT         DEFAULT NULL,
        -- Free-text detail — set to '[SANITIZED — above platform ceiling]' when sanitized
    -- Query metadata
    rows_returned           INTEGER      DEFAULT NULL,
    -- NOTE: rows_filtered_by_rls moved to dcs.audit_rls_details (D47, resolves DSAWG-F10)
    -- to eliminate covert channel leakage of SAP/SCI data existence
    -- Integrity — tamper-evident hash chain (D45, resolves DSAWG-F06)
    log_hash                VARCHAR(128) DEFAULT NULL,
        -- SHA-512(event_data || previous_log_hash) — chained for gap detection
    previous_log_hash       VARCHAR(128) DEFAULT NULL
        -- Hash of the immediately preceding log entry — enables chain verification
        -- If an entry is deleted, subsequent entries' chains break (detectable)
        -- Hash chaining can be enabled/disabled via Helm values for deployment
        -- flexibility (development may disable for performance)
);

-- Indexes for audit review
CREATE INDEX idx_audit_time ON dcs.audit_log (event_time);
CREATE INDEX idx_audit_identity ON dcs.audit_log (identity_hash);
CREATE INDEX idx_audit_sanitized ON dcs.audit_log (was_sanitized) WHERE was_sanitized = TRUE;
CREATE INDEX idx_audit_type ON dcs.audit_log (event_type);
CREATE INDEX idx_audit_hash_chain ON dcs.audit_log (previous_log_hash);
```

#### Auditor-Only RLS Details Table (D47, resolves DSAWG-F10)

The `rows_filtered_by_rls` count is a **covert channel**: a user querying "how many
STIG rules exist?" who sees that rows were filtered now knows SAP/SCI-protected data
exists — violating the no-acknowledgement principle. For MLS certification, NO covert
channels are permitted (D47).

This data is moved to a **separate auditor-only table** with its own RLS policies.
No platform role — including system administrators and DBAs — has unrestricted access.

```sql
CREATE TABLE dcs.audit_rls_details (
    detail_id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    log_id                  UUID         NOT NULL REFERENCES dcs.audit_log(log_id),
    -- RLS filtering metadata (only visible to cleared auditors)
    rows_filtered_by_rls    INTEGER      DEFAULT 0,
        -- How many rows RLS silently excluded from the query result
    filtered_classifications dcs.classification_level[] DEFAULT NULL,
        -- Classification levels of the filtered rows (for spillage analysis)
    filtered_compartments   VARCHAR[]    DEFAULT NULL,
        -- SAP/SCI compartments that caused filtering
    -- This table MUST have RLS enabled with no table owner bypass
    -- Only auditors with clearance above the filtered data level can query
);

-- Restrict access: auditor-only
ALTER TABLE dcs.audit_rls_details ENABLE ROW LEVEL SECURITY;
ALTER TABLE dcs.audit_rls_details FORCE ROW LEVEL SECURITY;
    -- FORCE ensures even table owners cannot bypass RLS

CREATE POLICY audit_rls_details_access ON dcs.audit_rls_details
    FOR SELECT USING (
        EXISTS (
            SELECT 1 FROM dcs.user_sessions us
            WHERE us.session_id = current_setting('dcs.session_id')::uuid
            AND us.is_active = TRUE
            AND us.session_expiry > NOW()
            -- Only auditors with clearance above ALL filtered classifications can see
            AND us.clearance_level >= ALL(
                SELECT unnest(filtered_classifications)
            )
            -- Must also have access to any filtered compartments
            AND (filtered_compartments IS NULL
                 OR filtered_compartments <@ us.formal_accesses)
        )
    );

CREATE INDEX idx_audit_rls_log ON dcs.audit_rls_details (log_id);
```

> **MLS Certification Note (D47):** No "God" privileges exist in this architecture.
> System administrators and DBAs operate under RLS constraints just like regular users.
> The `FORCE ROW LEVEL SECURITY` directive ensures even table owners cannot bypass
> policies. This is a deliberate MLS design decision — administrative access to the
> *platform* does not grant access to *data* above the administrator's clearance level.

#### Audit Sanitization Logic (Gateway Middleware)

The security-gateway implements this logic BEFORE writing any audit entry:

```
FUNCTION sanitize_audit_entry(entry, platform_config):
    -- Rule 1: Platform ceiling check
    IF entry.data_classification > platform_config.max_classification:
        entry.event_detail = '[SANITIZED — above platform ceiling]'
        entry.target_id = NULL
        entry.was_sanitized = TRUE
        entry.sanitized_original_level = entry.data_classification
        entry.data_classification = NULL  -- Don't even show the level
        entry.sanitization_reason = 'ABOVE_PLATFORM_CEILING'
        RETURN entry

    -- Rule 2: SAP no-acknowledgement
    IF entry involves SAP data AND user NOT read-in:
        entry.event_detail = '[SANITIZED — compartmented]'
        entry.target_id = NULL
        entry.was_sanitized = TRUE
        entry.sanitized_original_level = entry.data_classification
        entry.sanitization_reason = 'SAP_NO_ACKNOWLEDGE'
        RETURN entry

    -- Rule 3: SCI compartment restriction
    IF entry involves SCI data AND user lacks compartment access:
        entry.event_detail = '[SANITIZED — compartmented]'
        entry.was_sanitized = TRUE
        entry.sanitized_original_level = entry.data_classification
        entry.sanitization_reason = 'SCI_COMPARTMENT'
        RETURN entry

    -- Rule 4: Nationality restriction
    IF entry involves NOFORN data AND user is foreign national:
        entry.event_detail = '[SANITIZED — nationality restriction]'
        entry.was_sanitized = TRUE
        entry.sanitized_original_level = entry.data_classification
        entry.sanitization_reason = 'NATIONALITY_RESTRICTION'
        RETURN entry

    -- No sanitization needed
    entry.was_sanitized = FALSE
    RETURN entry
```

#### RLS on the Audit Log Itself

The `sanitized_original_level` column contains the actual classification of sanitized
events. This column is ITSELF classified — only security auditors with appropriate
clearance can see it:

```sql
-- Only auditors with clearance above the sanitized level can see the original classification
CREATE POLICY audit_sanitized_access ON dcs.audit_log
    USING (
        was_sanitized = FALSE  -- Unsanitized entries: normal access
        OR (
            -- Sanitized entries: only if user clearance >= original level
            sanitized_original_level <= (
                SELECT clearance_level FROM dcs.user_sessions
                WHERE session_id = current_setting('dcs.session_id')::uuid
            )
        )
    );
```

#### Platform Configuration Examples

```sql
-- NIPRNET deployment (UNCLASSIFIED + CUI only)
INSERT INTO dcs.platform_configuration (platform_name, platform_environment,
    max_classification, platform_nations, cui_authorized, ato_reference) VALUES
('Security MCP - NIPRNET', 'NIPRNET', 'UNCLASSIFIED', '{USA}', TRUE, 'ATO-2026-SMCP-001');

-- SIPRNET deployment (up to SECRET, FVEY nations)
INSERT INTO dcs.platform_configuration (platform_name, platform_environment,
    max_classification, platform_nations, nato_authorized, ato_reference) VALUES
('Security MCP - SIPRNET', 'SIPRNET', 'SECRET', '{USA,GBR,AUS,CAN,NZL}', TRUE, 'ATO-2026-SMCP-002');

-- CFC/USFK coalition deployment (SECRET, US + ROK)
INSERT INTO dcs.platform_configuration (platform_name, platform_environment,
    max_classification, platform_nations, ato_reference) VALUES
('Security MCP - CFC COALITION', 'COALITION', 'SECRET', '{USA,KOR}', 'ATO-2026-CFC-001');
```

### 28b. User Session Attributes and the No-Acknowledgement Principle

#### The SAP Problem: What You Can't See, You Can't Know Exists

Special Access Programs (SAPs) are the gold standard for compartmented security.
The fundamental principle: **if you are not read into a SAP, the program does not
exist in your reality.** The system cannot say "access denied" — it must behave as
if the data simply isn't there.

This is exactly what PostgreSQL RLS provides. Rows you can't see don't appear in
query results, `COUNT(*)`, or error messages. The AI assistant cannot acknowledge
what it cannot see.

But RLS needs **context** — it needs to know WHAT the user is authorized to see.
Without user session attributes, RLS has nothing to compare against.

#### Zero-PII Architecture: Authorization Attributes Without Identity

> **Design Principle (D28):** The Security MCP Server database stores **zero
> Personally Identifiable Information (PII)**. The database knows WHAT a user is
> authorized to see (clearance, nationality, compartments) — it does NOT know WHO
> the user is. Identity resolution is the exclusive responsibility of the external
> Identity Provider (IdP).

This eliminates:
- **U.S. Privacy Act SORN requirement** — no PII in the system of records
- **GDPR Article 17 erasure complexity** — no PII to erase from the database
- **GDPR Article 35 DPIA scope** — significantly reduced; no high-risk PII processing
- **Data minimization (Art. 5(1)(c))** — only authorization attributes retained
- **All privacy framework obligations** — the database is not a system of records
  for personal data under any framework (U.S. Privacy Act, GDPR, PIPA, APPI, etc.)

**How it works:**
1. User authenticates via external IdP (Keycloak, CAC/PKI, LDAP, SAML, OIDC)
2. IdP returns a JWT/assertion containing both identity AND authorization attributes
3. The security-gateway extracts **only authorization attributes** and creates a
   database session — identity attributes (name, email, org) are NEVER written to DB
4. An **opaque identity hash** (`SHA-512(user_principal || session_salt)`) is stored
   for audit correlation — irreversible without access to the IdP
5. If an audit investigation needs to resolve the hash to a person, the investigator
   queries the **IdP**, not the database

#### User Sessions Table (Phase C) — Zero-PII Design

```sql
CREATE TABLE dcs.user_sessions (
    session_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Opaque identity (NOT PII — cannot be reversed without IdP access)
    identity_hash       VARCHAR(128) NOT NULL,
        -- SHA-512(user_principal || session_salt) — consistent per user per
        -- deployment for audit correlation, but NOT reversible from DB alone.
        -- The IdP maintains the PII-to-hash mapping for audit investigations.

    -- Authorization attributes (NOT PII — these are access control attributes
    -- extracted from the IdP assertion, used solely for RLS policy evaluation)
    nationality         VARCHAR(3)   NOT NULL REFERENCES dcs.nation_codes(trigraph),
        -- Determines NOFORN/REL TO access — needed for every query
    clearance_level     dcs.classification_level NOT NULL,
        -- Determines classification access ceiling

    -- Compartmented access authorizations (from external AuthZ)
    sap_access          VARCHAR[]    DEFAULT NULL,
        -- SAP program nicknames the user is read into
        -- e.g., '{TWISTED_FEATHER, COBALT_REEF}'
    sci_compartments    VARCHAR[]    DEFAULT NULL,
        -- SCI compartments: '{HCS, SI, TK, G}'
    coi_membership      VARCHAR[]    DEFAULT NULL,
        -- Communities of Interest: '{SIGINT, HUMINT, CYBER}'
    formal_accesses     VARCHAR[]    DEFAULT NULL,
        -- Other formal access approvals
    rel_to_authorized   VARCHAR[]    DEFAULT NULL,
        -- Nations this user can release data to
        -- e.g., '{USA, KOR}' for a CFC analyst
    nato_clearance      BOOLEAN      DEFAULT FALSE,
        -- Whether user holds NATO security clearance

    -- Session lifecycle
    session_start       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    session_expiry      TIMESTAMPTZ  NOT NULL,
    auth_source         VARCHAR(50)  NOT NULL,
        -- 'KEYCLOAK', 'CAC_PKI', 'LDAP', 'SAML', 'OIDC'
    auth_token_hash     VARCHAR(128) DEFAULT NULL,
        -- SHA-512 hash of the auth token for session provenance verification
    is_active           BOOLEAN      DEFAULT TRUE
);

-- Indexes for RLS performance (these are in the hot path for EVERY query)
CREATE INDEX idx_sessions_active ON dcs.user_sessions (session_id) WHERE is_active = TRUE;
CREATE INDEX idx_sessions_expiry ON dcs.user_sessions (session_expiry);
CREATE INDEX idx_sessions_identity ON dcs.user_sessions (identity_hash);
```

#### What Is NOT Stored (PII Exclusion List)

| Attribute | Source | Why Excluded | Where It Lives |
|---|---|---|---|
| User name / display name | IdP | PII — not needed for access control | External IdP only |
| Email address | IdP | PII — not needed for access control | External IdP only |
| Organization / unit | IdP | PII-adjacent — not needed for RLS | External IdP only |
| EDIPI / DoD ID number | CAC/PKI | PII — unique identifier | External IdP only |
| Clearance granting authority | IdP | Not needed for RLS evaluation | External IdP only |
| Phone / contact info | IdP | PII — never relevant to access control | External IdP only |

#### What IS Stored (Authorization Attributes Only)

| Attribute | Why Required | RLS Policy That Uses It |
|---|---|---|
| `identity_hash` | Audit correlation across sessions | Audit log JOIN only — not in RLS policies |
| `nationality` | NOFORN, REL TO, DISPLAY ONLY enforcement | `noforn_check`, `rel_to_check` |
| `clearance_level` | Classification ceiling per user | `classification_check` |
| `sap_access` | SAP no-acknowledgement (invisible rows) | `sap_no_acknowledge` |
| `sci_compartments` | SCI compartment enforcement | Future SCI policy |
| `nato_clearance` | NATO data access | Future NATO policy |
| `session_expiry` | Expired session = deny all | All policies (session validation) |

#### PostgreSQL RLS Policies Using Session Attributes

```sql
-- Set session context at connection time (done by security-gateway)
SET dcs.session_id = 'a1b2c3d4-...';

-- Policy 1: Classification level check
CREATE POLICY classification_check ON xccdf_library.rules
    FOR SELECT USING (
        classification_level <= (
            SELECT clearance_level FROM dcs.user_sessions
            WHERE session_id = current_setting('dcs.session_id')::uuid
            AND is_active = TRUE
            AND session_expiry > NOW()
        )
    );

-- Policy 2: NOFORN enforcement
CREATE POLICY noforn_check ON xccdf_library.rules
    FOR SELECT USING (
        noforn = FALSE
        OR (
            SELECT nationality FROM dcs.user_sessions
            WHERE session_id = current_setting('dcs.session_id')::uuid
        ) = 'USA'
    );

-- Policy 3: REL TO enforcement
CREATE POLICY rel_to_check ON xccdf_library.rules
    FOR SELECT USING (
        rel_to_nations IS NULL  -- No REL TO restriction: visible to all
        OR (
            SELECT nationality FROM dcs.user_sessions
            WHERE session_id = current_setting('dcs.session_id')::uuid
        ) = ANY(rel_to_nations)
    );

-- Policy 4: SAP no-acknowledgement (the critical one)
-- If the user is NOT read into the SAP, the row DOES NOT EXIST
CREATE POLICY sap_no_acknowledge ON xccdf_library.rules
    FOR SELECT USING (
        label_id IS NULL  -- No label: no SAP restriction
        OR NOT EXISTS (
            -- Check if the label references a SAP program
            SELECT 1 FROM dcs.confidentiality_labels cl
            WHERE cl.label_id = rules.label_id
            AND cl.sap_markings IS NOT NULL
        )
        OR EXISTS (
            -- User has SAP access for this specific program
            SELECT 1 FROM dcs.confidentiality_labels cl,
                         dcs.user_sessions us
            WHERE cl.label_id = rules.label_id
            AND us.session_id = current_setting('dcs.session_id')::uuid
            AND cl.sap_markings IS NOT NULL
            AND EXISTS (
                SELECT 1 FROM jsonb_array_elements(cl.sap_markings) sap
                WHERE sap->>'nickname' = ANY(us.sap_access)
            )
        )
    );
```

#### NSA IMN Evaluation Readiness

For NSA Information Management Network (IMN) evaluation, verifiable proof requires:

1. **Audit trail completeness** — Every query, every result, every RLS-filtered row
   is logged with the session that made the request (§28a `audit_log` table)
2. **Session attribute provenance** — `auth_source` and `auth_token_hash` prove the
   authorization attributes came from an external IdP, not self-asserted
3. **Identity resolution path** — `identity_hash` correlates to the IdP's identity
   records; investigators query the IdP to resolve hash → person
4. **No-acknowledgement proof** — `rows_filtered_by_rls` in `dcs.audit_rls_details`
   (auditor-only table, D47) shows how many rows were silently excluded without the
   user knowing — this data is NOT in the main audit log to prevent covert channels
5. **Platform ceiling enforcement** — `was_sanitized` + `sanitized_original_level` prove
   no classified data leaked into lower-classification audit logs
6. **Tamper-evident logging** — `log_hash` (SHA-512) with hash chaining via
   `previous_log_hash` for gap detection per NIST AU-10 (D45)

#### Audit Identity Resolution Procedure

The zero-PII architecture separates **behavioral attribution** (what happened, under
what authorization) from **identity resolution** (who did it). The database provides
the former; the IdP provides the latter. This section documents the complete
resolution process, its capabilities, its limitations, and the follow-on steps
required for a production deployment.

##### Process: Resolving an Identity Hash to a Person

```text
┌─────────────────────────────────────────────────────────────────┐
│ STEP 1: Database Query (Security MCP Server)                    │
│                                                                 │
│   SELECT al.identity_hash, al.event_type, al.query_text,       │
│          al.rows_returned, al.rows_filtered_by_rls,             │
│          us.nationality, us.clearance_level, us.sap_access,     │
│          us.auth_source, al.event_timestamp                     │
│   FROM dcs.audit_log al                                         │
│   JOIN dcs.user_sessions us ON al.identity_hash = us.identity_hash │
│   WHERE al.event_timestamp BETWEEN '2026-01-15' AND '2026-01-16' │
│     AND us.clearance_level >= 'TOP_SECRET';                     │
│                                                                 │
│   Result: identity_hash = 'a8f3e9c1b7d2...', nationality=USA,  │
│           clearance=TOP_SECRET, sap_access={COBALT_REEF},       │
│           auth_source=CAC_PKI, 14 queries, 3 RLS-filtered rows  │
│                                                                 │
│   ✅ WHO accessed data? → Unknown (hash only)                   │
│   ✅ WHAT were they authorized to see? → Full authorization set │
│   ✅ WHAT did they actually access? → Full query + result log   │
│   ✅ WHAT was hidden from them? → rows_filtered_by_rls count    │
│   ✅ Same person as session on Jan 10? → Yes (same hash)        │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           │ Auditor presents identity_hash
                           │ to IdP administrator with
                           │ authorized investigation request
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│ STEP 2: IdP Resolution (External — Keycloak / CAC PKI / LDAP)  │
│                                                                 │
│   IdP computes: SHA-512(each_known_principal || deployment_salt)│
│   Matches hash 'a8f3e9c1b7d2...' → user_principal found        │
│                                                                 │
│   Result: "SSgt Kim, Namjoon — EDIPI 1234567890,               │
│            authenticated via CAC PKI, assigned to CFC J6"       │
│                                                                 │
│   ✅ WHO is this person? → Resolved                             │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           │ Auditor now has complete picture:
                           │ identity + behavior + authorization
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│ STEP 3: Audit Report (Investigator assembles findings)          │
│                                                                 │
│   "SSgt Kim accessed 14 TOP SECRET STIG rules on Jan 15-16,    │
│    was authorized for COBALT_REEF SAP, 3 additional rows were   │
│    filtered by RLS (rules outside their compartment access).    │
│    Authentication via CAC PKI from auth_source record.          │
│    No policy violations detected."                              │
└─────────────────────────────────────────────────────────────────┘
```

##### Capabilities (What the Database CAN Answer Without the IdP)

| Audit Question | Database Answer | Source Table/Column |
|---|---|---|
| What data was accessed? | Full query text + result set metadata | `audit_log.query_text`, `rows_returned` |
| What authorization did the accessor hold? | Clearance, nationality, SAP, SCI, COIs | `user_sessions.*` |
| Were they authorized for what they accessed? | Yes — RLS enforced at query time | RLS policy evaluation (implicit) |
| What was hidden from them? | Row count of RLS-filtered data | `audit_log.rows_filtered_by_rls` |
| Was audit data sanitized? | Yes/no + original classification | `audit_log.was_sanitized`, `sanitized_original_level` |
| Is this the same person across sessions? | Yes — consistent `identity_hash` | `user_sessions.identity_hash` |
| How did they authenticate? | Auth method + token provenance | `user_sessions.auth_source`, `auth_token_hash` |
| When did their session start/expire? | Exact timestamps | `user_sessions.session_start`, `session_expiry` |
| Has this hash appeared before? | Full history across all sessions | `idx_sessions_identity` index |
| Is the audit record tampered with? | Hash verification | `audit_log.log_hash` |

##### Limitations (What the Database CANNOT Answer)

| Audit Question | Why Not Available | Resolution Path |
|---|---|---|
| **Who is this person?** (name, rank, unit) | Zero-PII — identity is not stored | Query the IdP with the `identity_hash` |
| **What is their email/phone?** | PII — never enters the database | Query the IdP or organizational directory |
| **Who is their supervisor?** | Organizational PII — not stored | Query the IdP or HR system |
| **What organization are they assigned to?** | PII-adjacent — not needed for RLS | Query the IdP (org is in the JWT, just not persisted) |
| **What is their EDIPI/DoD ID?** | PII — unique identifier, never stored | Query the CAC/PKI infrastructure |
| **Was this person's clearance revoked AFTER the session?** | DB records point-in-time session state | Query the IdP/JPAS/DISS for current status |

##### Identity Hash Properties

| Property | Value | Implication |
|---|---|---|
| Algorithm | SHA-512 | FIPS 140-3 compliant (NIST SP 800-107) |
| Input | `user_principal \|\| session_salt` | Two components required for computation |
| Salt scope | Per-deployment (not per-session) | Same user → same hash across all sessions in one deployment |
| Reversibility | Computationally infeasible from DB alone | Requires both `user_principal` (from IdP) AND `session_salt` (from deployment config) |
| Collision resistance | SHA-512: 2²⁵⁶ collision resistance | Negligible probability of two users producing the same hash |
| Cross-deployment linkability | Different `session_salt` per deployment → different hash | Cannot correlate same user across deployments (privacy feature) |

##### Follow-On Steps for Production Deployment

1. **IdP Hash Registry (Required before Phase C go-live):**
   The IdP must maintain a lookup capability to resolve `identity_hash` values.
   Two implementation approaches:

   - **Option A — On-demand computation:** IdP iterates known principals, computes
     `SHA-512(principal || salt)` for each, matches against the query hash. Works
     for small user populations (< 10,000). Requires IdP to have the deployment's
     `session_salt`.

   - **Option B — Pre-computed lookup table:** IdP maintains a
     `hash → principal` mapping table, updated when users are provisioned or
     deprovisioned. Better for large populations. Table itself is PII and must be
     protected at the IdP's classification level.

   **Recommendation:** Option B for production. The lookup table is a natural
   extension of the IdP's user provisioning workflow.

2. **Session Salt Management (Required before Phase C go-live):**
   The `session_salt` is a deployment-level secret that MUST be:
   - Generated as a cryptographically random 256-bit value at deployment time
   - Stored in the secrets management system (HashiCorp Vault, K8s Secret)
   - Shared ONLY with the security-gateway (for hash computation) and the IdP
     (for audit resolution)
   - Rotated on a schedule defined by the ISSM (rotation invalidates all
     existing hash → identity mappings; IdP must recompute its lookup table)
   - **NEVER stored in the database** — if the DB is compromised, the attacker
     cannot reverse hashes without the salt

3. **Audit Resolution SOP (Required before ATO):**
   A Standard Operating Procedure must document:
   - Who is authorized to request identity resolution (e.g., ISSM, IG, CI)
   - What justification is required (investigation number, commander authorization)
   - How the request is transmitted to the IdP administrator (secure channel)
   - How the response is protected (identity resolution results are PII)
   - Retention period for resolution results (separate from audit log retention)
   - Two-person integrity requirement for resolution (recommended for SAP data)

4. **Separation of Duties Verification (Required before ATO):**
   The zero-PII architecture creates a natural separation:
   - **DBA** can see all audit activity but cannot identify users
   - **IdP Admin** can identify users but cannot see what they accessed
   - **Auditor** (with both authorities) can correlate identity + behavior
   This separation must be documented in the System Security Plan (SSP) and
   verified during the Security Test & Evaluation (ST&E).

5. **Emergency Access Procedure (Required before ATO):**
   For time-critical investigations (e.g., active insider threat), the standard
   two-step resolution may be too slow. Document an emergency procedure:
   - Pre-authorized emergency resolution request template
   - Maximum response time SLA from IdP administrator
   - Fallback if IdP is unavailable (e.g., offline backup of hash lookup table
     stored in a sealed envelope at the ISSM's safe — only opened under
     two-person integrity with commander authorization)

##### Design Principle: Why Two-Party Resolution Is a Feature

> The two-party identity resolution model is not a limitation — it is a
> **deliberate security control**. It implements:
>
> - **NIST AC-5 (Separation of Duties)** — no single role can both identify
>   users AND see their data access patterns
> - **NIST AC-6 (Least Privilege)** — the database operates with the minimum
>   information needed for access control decisions
> - **NIST AU-9 (Protection of Audit Information)** — audit records cannot
>   be used to build identity-linked surveillance dossiers without authorized
>   investigation
> - **Insider Threat Mitigation** — a compromised DBA gains behavioral data
>   but not identity; a compromised IdP admin gains identity but not behavior;
>   correlation requires compromising BOTH systems
>
> For DSAWG authorization, this model is **stronger** than PII-in-database
> because it adds a verifiable control (two-party resolution) that does not
> exist when identity is directly readable from the database.

#### Privacy Framework Impact: Zero-PII Eliminates Compliance Burden

Because the database stores **no PII**, the following privacy framework obligations
are eliminated or drastically reduced:

| Obligation | Framework | Impact |
|---|---|---|
| System of Records Notice (SORN) | U.S. Privacy Act | **Eliminated** — no PII in system of records |
| Privacy Impact Assessment (PIA) | E-Government Act §208 | **Reduced** — authorization attributes only |
| Data Protection Impact Assessment (DPIA) | GDPR Art. 35 | **Reduced** — no high-risk PII processing in DB |
| Right to Erasure | GDPR Art. 17 | **Eliminated** — no PII to erase from DB |
| Right to Access | GDPR Art. 15 | **Eliminated** — no PII to disclose from DB |
| Data Subject Rights workflow | GDPR Art. 15-22 | **Eliminated for DB** — all rights requests go to IdP |
| Breach notification (for DB) | GDPR Art. 33, Privacy Act | **Reduced** — DB breach exposes authorization attributes, not identity |
| PIPA breach notification | ROK PIPA | **Eliminated for DB** — no personal information held |
| Cross-border transfer concerns | GDPR Art. 44-49 | **Reduced** — authorization attributes are not personal data |
| Records of Processing Activities | GDPR Art. 30 | **Reduced** — DB processing does not involve personal data |

> **Key Insight:** The IdP (Keycloak, CAC/PKI infrastructure) IS the system of
> records for PII and carries the SORN/GDPR/PIPA obligations. The Security MCP
> Server database is a **policy decision point** that evaluates authorization
> attributes — it is not a system of records for personal data.

### 28c. Backup Classification Inheritance (DSAWG-F09 Resolution)

> **Fundamental Rule:** Database backups inherit the **highest classification level**
> of any data they contain. A backup containing even a single TOP SECRET row is itself
> a TOP SECRET product — regardless of how much UNCLASSIFIED data the backup also
> contains. This follows standard Security Classification guidance: **products carry
> the highest classification of the contents of the product.**

**Classification Determination:**

The backup classification level equals `MAX(classification_level)` across all rows
in the database at the time the backup is taken. This is deterministic and can be
computed programmatically:

```sql
-- Determine backup classification level
SELECT MAX(classification_level) AS backup_classification
FROM (
    SELECT MAX(classification_level) AS classification_level FROM xccdf_library.benchmarks
    UNION ALL
    SELECT MAX(classification_level) FROM xccdf_library.rules
    UNION ALL
    SELECT MAX(classification_level) FROM oscal.documents
    UNION ALL
    SELECT MAX(classification_level) FROM oscal.catalog_controls
    UNION ALL
    SELECT MAX(classification_level) FROM cci_mappings.cci_controls
    UNION ALL
    SELECT MAX(classification_level) FROM cklb_assessments.checklists
    UNION ALL
    SELECT MAX(classification_level) FROM ato_packages.systems
) AS all_levels;
```

**Backup Handling Requirements:**

| Requirement | Standard | Implementation |
|---|---|---|
| **Storage classification** | Backup media must be stored at or above `MAX(classification_level)` | Automated label applied at backup time |
| **Transport** | Encrypted in transit per classification level requirements | TLS 1.3 for UNCLASSIFIED/CUI; NSA Type 1 for SECRET+ |
| **Encryption at rest** | FIPS 140-3 validated encryption required | AES-256 minimum; key management per platform's KMS |
| **Media destruction** | DoD 5220.22-M at the platform's classification level | Degaussing + physical destruction for SECRET+; crypto-erase for UNCLASSIFIED/CUI |
| **Access control** | Only personnel cleared at or above `MAX(classification_level)` | Enforced by storage system ACLs |
| **Retention** | Per organizational retention policy and platform ATO | See §28d (Retention Periods) |

> **Platform Ceiling Implication:** On a NIPRNET (UNCLASSIFIED) deployment, all data
> is UNCLASSIFIED by definition (the platform ceiling prevents higher-classified data
> from being imported). Backups on NIPRNET are therefore UNCLASSIFIED. On a SIPRNET
> (SECRET) deployment, backups are classified at `MAX(classification_level)` which may
> be SECRET even if most data is UNCLASSIFIED.

### 28d. Retention Periods (EU-F11 Resolution)

> **Design Principle:** Retention periods are **Helm-configurable** to provide the
> required flexibility for hosting organizations to meet their organizational policy
> requirements. The defaults below balance NIST AU-11 (audit retention) with GDPR
> Article 5(1)(e) (storage limitation).

**Default Retention Configuration:**

| Data Category | Default Retention | Helm Value | Rationale |
| --- | --- | --- | --- |
| **Audit log entries** (`dcs.audit_log`) | 60 days | `auditLog.retentionDays: 60` | Balances operational review needs with storage limitation; organizations requiring longer retention (1-3 years per NIST AU-11) override via Helm |
| **User sessions** (`dcs.user_sessions`) | 60 days (inactive sessions) | `sessions.retentionDays: 60` | Inactive sessions retained for audit correlation; active sessions exempt from retention policy |
| **RLS audit details** (`dcs.audit_rls_details`) | 60 days | `auditLog.rlsDetails.retentionDays: 60` | Follows audit log retention; auditor-only access maintained throughout |
| **Classification labels** (`dcs.confidentiality_labels`) | No automatic deletion | N/A | Reference data — retained as long as labeled data exists |
| **Reference tables** (`dcs.nation_codes`, etc.) | No automatic deletion | N/A | Static reference data — no retention concern |

**Helm Values Template:**

```yaml
# values.yaml — Retention configuration
dcs:
  retention:
    auditLog:
      retentionDays: 60          # Override per organizational policy
      archiveBeforeDelete: true  # Archive to cold storage before purging
    sessions:
      retentionDays: 60          # Inactive sessions only
      archiveBeforeDelete: true
    rlsDetails:
      retentionDays: 60          # Follows audit log retention
```

**Implementation Notes:**

1. **Phase C adds the retention enforcement** — Phase A creates the tables with
   `event_time`/`session_start` timestamps that enable future retention queries
2. A PostgreSQL cron job (pg_cron or external) will purge expired records:

   ```sql
   DELETE FROM dcs.audit_log WHERE event_time < NOW() - INTERVAL '60 days';
   DELETE FROM dcs.user_sessions WHERE is_active = FALSE
       AND session_expiry < NOW() - INTERVAL '60 days';
   ```

3. The `archiveBeforeDelete` flag triggers export to object storage (S3/MinIO)
   before deletion — satisfying both GDPR storage limitation and NIST AU-11
   long-term retention simultaneously
4. Organizations operating under extended retention mandates (e.g., 3-year
   requirement for high-impact DoD systems) simply set `retentionDays: 1095`

---

## 29. CDSE Source Document Catalog

The following source documents were identified from four CDSE training courses
(IF103, IF105, IF130, IF141) provided by a coworker developing the Classification
Marking Guide v11.

### Executive Orders & Presidential Directives

| Document | CDSE Course(s) | Schema Relevance |
|----------|:-------------:|------------------|
| EO 13526 — Classified National Security Information | IF103, IF105, IF130 | Defines classification levels |
| EO 13556 — Controlled Unclassified Information | IF141, IF130 | Establishes CUI program |
| PPD-19 — Protecting Whistleblowers | IF130 | Audit log constraints |

### DoD Manuals (Most Critical)

| Document | CDSE Course(s) | Schema Relevance |
|----------|:-------------:|------------------|
| DoDM 5200.01 Vol 1 — Classification & Declassification | IF103, IF105 | `declassify_on`, classification authority |
| DoDM 5200.01 Vol 2 — Marking of Classified Information | ALL FOUR | **PRIMARY AUTHORITY** for all marking syntax |
| DoDM 5200.01 Vol 3 — Protection of Classified Information | IF103, IF105, IF130 | Handling requirements per level |
| DoDM 5205.07 Vol 4 — SAP Security Manual: Marking | IF105 | SAP marking overlay |

### DoD Instructions

| Document | CDSE Course(s) | Schema Relevance |
|----------|:-------------:|------------------|
| DoDI 5200.48 — CUI | ALL FOUR | CUI categories and dissem controls |
| DoDI 5230.09 — Clearance for Public Release | IF141, IF130 | Release authority |
| DoDI 5230.29 — Security & Policy Review | IF141, IF130 | Pre-publication review |
| DoDI 5015.02 — Records Management | IF141 | Retention requirements |
| DoDI 5400.17 — Social Media | IF130 | Electronic dissemination |
| DoDI 8170.01 — Electronic Messaging | IF130 | Transport requirements |
| DoDD 5210.50 — Serious Security Incidents | IF130 | Incident logging requirements |

### Federal Regulations

| Document | CDSE Course(s) | Schema Relevance |
|----------|:-------------:|------------------|
| 32 CFR Parts 2001 & 2003 — ISOO Classification Rules | IF103, IF105 | Classification regulations |
| 32 CFR Part 2002 — CUI Final Rule | IF141 | CUI safeguarding |
| 32 CFR Part 117 — NISPOM | IF103, IF130 | Contractor handling |
| 10 CFR Part 1045 — Nuclear Classification | IF105 | RD/FRD/TFNI markings |

### IC Documents

| Document | CDSE Course(s) | Schema Relevance |
|----------|:-------------:|------------------|
| ICD 701 — Unauthorized Disclosure | IF130 | IC incident response process |

### NIST Standards

| Document | CDSE Course(s) | Schema Relevance |
|----------|:-------------:|------------------|
| SP 800-53 — Security & Privacy Controls | IF141 | Control framework (in our DB) |
| SP 800-171 — Protecting CUI in Nonfederal Systems | IF141 | CUI on contractor systems |

### CDSE Job Aids and Reference Documents (Converted to Markdown — Available in `data/dcs/`)

| Job Aid | Course | Location | Key Schema Contributions |
|---------|--------|----------|--------------------------|
| **CUI Markings Training Aid (Dec 2024)** | IF141 | [CUI_Markings_TrainingAid_2024.md](../../data/dcs/CUI_Markings_TrainingAid_2024.md) | CUI Designation Indicator Block structure; CUI portion marking rules; Distribution Statements A-F; classified-with-CUI dual-block requirement |
| **CUI Limited Dissemination Controls** | IF141 | [CUI_Limited_Dissemination_Controls.md](../../data/dcs/CUI_Limited_Dissemination_Controls.md) | **Complete LDC vocabulary** (10 controls): NOFORN, FED ONLY, FEDCON, NOCON, DL ONLY, RELIDO, REL TO, DISPLAY ONLY, Attorney-Client, Attorney-WP; portion marking abbreviations; combination rules |
| **ISOO Marking Classified NSI Booklet** | IF105 | [marking-booklet-revision.md](../../data/dcs/marking-booklet-revision.md) | Declassification exemptions (25X1–25X9, 50X1-HUM, 50X2-WMD, 75X); legacy marking conversion rules; classification by compilation; working paper rules |
| **Marking National Security Information Job Aid** | IF103, IF105 | [Marking_National_Security_Information.md](../../data/dcs/Marking_National_Security_Information.md) | Atomic Energy (RD/FRD/CNWDI) marking; SAP nickname/PID/DCN format; Intelligence markings (ORCON/PROPIN/IMCON); Distribution Statement categories matrix; FGI marking syntax |
| **Derivative Classification Job Aid** | IF103 | [DerivativeClassification_JobAid.md](../../data/dcs/DerivativeClassification_JobAid.md) | Classification Authority Block format (Classified By, Derived From, Declassify On); multiple-source derivation rules; SCG as primary source; 25-year default duration |
| **Classification Marking Guide v11 (Coalition/Releasable)** | *(operational)* | [Classification_Marking_Guide_Coalition_Releasable_v11.md](../../data/dcs/Classification_Marking_Guide_Coalition_Releasable_v11.md) | Complete coalition marking examples; plain UNCLASSIFIED vs CUI distinction; DISPLAY ONLY classified-only rule; Fortra DCS LIMFAC; subject line marking; REL abbreviation rules |

---

## 30. Authoritative References

### U.S. DoD / IC Standards

| Document | URL |
|----------|-----|
| DoDM 5200.01-V2 (Marking of Information) | [esd.whs.mil](https://www.esd.whs.mil/Portals/54/Documents/DD/issuances/dodm/520001m_vol2.pdf) |
| DoDI 5200.48 (CUI) | [esd.whs.mil](https://www.esd.whs.mil/Portals/54/Documents/DD/issuances/dodi/520048p.PDF) |
| EO 13526 (Classified NSI) | [archives.gov](https://www.archives.gov/isoo/policy-documents/cnsi-eo.html) |
| CAPCO Register v1.2 | [dni.gov FOIA](https://www.dni.gov/files/documents/FOIA/Authorized%20Classification%20and%20Control%20Markings%20Register%20V1.2.pdf) |
| IC UIAS v2 (User Attributes) | [odni.gov](https://www.odni.gov/files/documents/CIO/ICEA/IC_Tech_Spec_Attributes_V2_Final_PUBLIC.pdf) |
| GENC Registry | [nsgreg.nga.mil](https://nsgreg.nga.mil/genc/) |
| ISMCAT Tetragraph Taxonomy | [archives.gov](https://www.archives.gov/files/cui/registry/policy-guidance/registry-documents/tetragraph-codes-for-coalition-or-international-organizations.pdf) |
| DoD CUI Registry | [dodcui.mil](https://www.dodcui.mil/CUI-Categories-and-Abbreviations/) |

### NATO Standards

| Document | Reference |
|----------|-----------|
| STANAG 4774 (Confidentiality Label Syntax) | ADatP-4774, Ed. A Ver 1 (Dec 2017) |
| STANAG 4778 (Metadata Binding) | ADatP-4778, Ed. A Ver 1 (Oct 2018) |
| STANAG 5636 (Core Metadata / NCMS) | ADatP-5636, Ed. A Ver 1 (Nov 2022) |
| STANAG 1059 (National Codes) | Ed. 9 (aligns with ISO 3166-1 alpha-3) |
| NATO DCRA v2 | AC/322-D(2025)0056 (May 2025) |
| ACP 240 (Data-Centric Security) | CCEB (2025) |

### Allied Bilateral Agreements

| Agreement | Parties | Coverage |
|-----------|---------|----------|
| US-Japan GSOMIA | USA, JPN | Classified military information |
| US-ROK GSOMIA | USA, KOR | Classified military information |
| Japan-ROK GSOMIA | JPN, KOR | Classified military information |
| US-Philippines GSOMIA | USA, PHL | Classified military information |
| US-Australia GSOMIA | USA, AUS | Classified military information (FVEY) |

### NIST / ZTA Standards

| Document | URL |
|----------|-----|
| SP 800-207 (Zero Trust Architecture) | [nist.gov](https://nvlpubs.nist.gov/nistpubs/specialpublications/NIST.SP.800-207.pdf) |
| SP 1800-35 (Implementing ZTA) | [nist.gov](https://pages.nist.gov/zero-trust-architecture/) |
| SP 800-162 (ABAC Guide) | [csrc.nist.gov](https://csrc.nist.gov/pubs/sp/800/162/upd2/final) |

### Classification Marking Guide

| Document | Location |
|----------|----------|
| Classification Marking Guide v11 (Coalition/Releasable) | [data/dcs/Classification_Marking_Guide_Coalition_Releasable_v11.md](../../data/dcs/Classification_Marking_Guide_Coalition_Releasable_v11.md) |

### EU / GDPR / NIS2

| Document | Reference |
|----------|-----------|
| GDPR (Regulation EU 2016/679) | [gdpr-info.eu](https://gdpr-info.eu/) |
| Council Decision 2013/488/EU (EUCI) | [EUR-Lex](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32013D0488) |
| NIS2 Directive (EU 2022/2555) | [nis2directive.eu](https://nis2directive.eu/nis2-requirements/) |
| EU Cyber Resilience Act (EU 2024/2847) | [digital-strategy.ec.europa.eu](https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act) |
| Regulation EU 2018/1725 (EU institutions data protection) | [EUR-Lex](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32018R1725) |
| NATO Personal Data Protection Framework (Sept 2024) | [nato.int](https://www.nato.int/content/dam/nato/webready/documents/publications-and-reports/20240901_NATO-personal-data-protection-f.pdf) |
| EU-US Data Privacy Framework | [dataprivacyframework.gov](https://www.dataprivacyframework.gov/Program-Overview) |

### Five Eyes National Frameworks

| Document | Nation | Reference |
|----------|--------|-----------|
| PSPF (Protective Security Policy Framework) | AUS | [protectivesecurity.gov.au](https://www.protectivesecurity.gov.au/) |
| ISM (Information Security Manual) | AUS | [cyber.gov.au](https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/ism) |
| TBS Appendix J (Security Categorization) | CAN | [tbs-sct.canada.ca](https://www.tbs-sct.canada.ca/pol/doc-eng.aspx?id=32614) |
| Government Security Classifications (GSC) | GBR | [gov.uk](https://www.gov.uk/government/publications/government-security-classifications/government-security-classifications-policy-html) |
| NZISM v3.7 (NZ Information Security Manual) | NZL | [nzism.gcsb.govt.nz](https://nzism.gcsb.govt.nz/) |

### Indo-Pacific Ally Frameworks

| Document | Nation | Reference |
|----------|--------|-----------|
| SDS Act (Act No. 108 of 2013) | JPN | [japaneselawtranslation.go.jp](https://www.japaneselawtranslation.go.jp/en/laws/view/2543/en) |
| Military Secret Protection Act (MSPA) | KOR | [elaw.klri.re.kr](https://elaw.klri.re.kr/eng_mobile/viewer.do?hseq=35867&type=part&key=13) |
| Personal Information Protection Act (PIPA) | KOR | [pipc.go.kr](https://www.pipc.go.kr/eng/index.do) |
| Data Privacy Act (Republic Act 10173) | PHL | [privacy.gov.ph](https://privacy.gov.ph/data-privacy-act/) |
| PDPA 2012 | SGP | [sso.agc.gov.sg](https://sso.agc.gov.sg/Act/PDPA2012) |
| IM8 OSCAL Adaptation | SGP | [GitHub: GovTechSG](https://github.com/GovTechSG/tech-standards) |

### European National Frameworks

| Document | Nation | Reference |
|----------|--------|-----------|
| VSA 2023 (Verschlusssachenanweisung) | DEU | BMI (restricted distribution) |
| BSI IT-Grundschutz (Grundschutz++ OSCAL) | DEU | [bsi.bund.de](https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/IT-Grundschutz/it-grundschutz_node.html) |
| IGI 1300 (2021) | FRA | [cyber.gouv.fr](https://cyber.gouv.fr/reglementation/cybersecurite-systemes-dinformation/protection-du-secret/instruction-generale-interministerielle-n1300/) |

### Cross-Border Data Sharing Frameworks

| Framework | Reference |
|-----------|-----------|
| Global Cross-Border Privacy Rules (GCBPR) | [globalcbpr.org](https://www.globalcbpr.org/) |
| APEC Privacy Framework | [apec.org](https://www.apec.org/groups/committee-on-trade-and-investment/digital-economy-steering-group) |
| OECD Privacy Guidelines (2013 update) | [oecd.org](https://www.oecd.org/sti/ieconomy/oecd_privacy_framework.pdf) |
| ROK EU Adequacy Decision (Dec 2023) | [ec.europa.eu](https://ec.europa.eu/commission/presscorner/detail/en/ip_23_6468) |

### DCS Design Research

| Document | Location |
|----------|----------|
| NIST SP 1800-35 ZTA Findings | [data/dcs/NIST-SP-1800-35-ZTA-Findings.md](../../data/dcs/NIST-SP-1800-35-ZTA-Findings.md) |
| NATO DCRA ACP 240 Findings | [data/dcs/NATO-DCRA-ACP240-Findings.md](../../data/dcs/NATO-DCRA-ACP240-Findings.md) |
| User Attributes DCS Architecture | [data/dcs/User-Attributes-DCS-Architecture-Findings.md](../../data/dcs/User-Attributes-DCS-Architecture-Findings.md) |
| DCS Roadmap | [data/dcs/README.md](../../data/dcs/README.md) |

---

## 31. AI-Simulated Auditor Review

### Purpose

This section simulates a formal review of the DCS Schema Migration design document
through two distinct evaluation lenses. Findings are structured as formal audit
observations with severity, affected sections, and recommended resolutions.

> **Methodology:** Each reviewer lens applies its domain-specific evaluation criteria
> to every section of the document. Findings are categorized as:
> - **CAT I (Critical)** — Must be resolved before authorization/approval
> - **CAT II (Significant)** — Must have a documented mitigation plan before approval
> - **CAT III (Moderate)** — Should be resolved; may proceed with documented risk acceptance
> - **Observation** — Noted for awareness; no action required before approval

---

### 31a. Review Lens 1: US DSAWG Member — CDS/DCS Package Evaluation

**Reviewer Role:** Defense Security Accreditation Working Group member evaluating
this design as part of a Cross Domain Solution / Data-Centric Security authorization
package per CNSSI 1253 and DoDI 8540.01.

**Evaluation Standard:** DoDI 8540.01 (Cross Domain Policy), CNSSP 24 (National
Policy on CDS in NSS), NIST SP 800-53 Rev 5 HIGH baseline, Committee on National
Security Systems (CNSS) guidelines.

#### DSAWG-F01: Accreditation Boundary Not Defined (CAT I)

| Field | Value |
|---|---|
| **Affected Sections** | §1 (Executive Summary), §28 (Security Considerations) |
| **Finding** | The document does not define the system's accreditation boundary. For a CDS/DCS authorization package, the DSAWG requires an explicit boundary diagram showing: (a) where classified data enters the system, (b) where it exits, (c) what components are within the boundary, and (d) what is external. The microservices architecture (gateway, parser, query, controls) is described in CLAUDE.md but not in this design document. |
| **Risk** | Without a defined boundary, security controls cannot be verified as complete. The DSAWG cannot determine whether the proposed RLS/Kyverno enforcement covers all data paths. |
| **Recommendation** | Add a §28c "System Accreditation Boundary" section with: (1) architecture diagram showing all microservices, database, and external interfaces; (2) classification of each interface (e.g., MCP STDIO = user-facing, PostgreSQL = internal); (3) trust boundaries between components; (4) data flow arrows with classification levels at each transition. |

#### DSAWG-F02: No Guard Architecture — RLS as Sole Cross-Domain Mechanism (~~CAT I~~ → RESOLVED by D44)

| Field | Value |
|---|---|
| **Affected Sections** | §28a (Platform Ceiling), §28b (User Sessions), §23 Phase C |
| **Original Finding** | Traditional CDS solutions use hardware or software **guards** at domain boundaries to inspect, filter, and validate data transfers between classification levels. This design relies on PostgreSQL Row-Level Security as the **sole data-level enforcement mechanism**. PostgreSQL RLS has NOT been evaluated by NSA as a cross-domain guard. RLS operates within a single database instance — it is an access control mechanism, not a cross-domain transfer mechanism. |
| **Resolution (D44 — MLS, Not CDS)** | **Resolved.** The system is explicitly scoped as a **Multi-Level Secure (MLS) data store**, NOT a Cross Domain Solution (CDS). It stores data at multiple classification levels and enforces access within a single domain using PostgreSQL RLS. Cross-domain data transfer is out of scope — any AI agents leveraging this capability reach through pre-existing Guards which are external to this system's accreditation boundary. The DSAWG evaluation follows MLS criteria per CNSSI 1253. See §28 "System Scope" section. |
| **Risk** | None — resolved by architectural scoping decision D44. |
| **Recommendation** | No action required. MLS scoping documented in §28. |

#### DSAWG-F03: Trusted Path from Authentication to RLS Not Verified (CAT I)

| Field | Value |
|---|---|
| **Affected Sections** | §28b (User Sessions) |
| **Finding** | The design uses `SET dcs.session_id = 'uuid'` at connection time to establish user context for RLS evaluation. This is a PostgreSQL session variable — it is set by the **application** (security-gateway), not by a trusted authentication mechanism integrated with PostgreSQL. A compromised or misconfigured gateway could set arbitrary session IDs, bypassing all RLS policies. There is no verification that the session_id in the PostgreSQL session matches a valid, authenticated session. |
| **Risk** | The entire RLS enforcement chain depends on the integrity of a single `SET` command. This is a **single point of failure** for the access control architecture. |
| **Recommendation** | (1) Document the trusted path from user authentication (CAC/PKI, Keycloak) through the gateway to the PostgreSQL session variable. (2) Implement a **session validation function** in PostgreSQL that verifies `session_id` against `dcs.user_sessions` (expiry, is_active) on every query — the current RLS policies already do this but it should be formalized as a security requirement, not an implementation detail. (3) Consider PostgreSQL connection pooling implications — PgBouncer/pgpool session variables may not persist correctly in transaction-mode pooling. (4) Add to Phase C requirements: gateway-to-database connection MUST use dedicated credentials per trust level, not a shared `mcp_app` account. |

#### DSAWG-F04: No Fail-Safe Default Documentation (CAT II)

| Field | Value |
|---|---|
| **Affected Sections** | §28b (RLS Policies) |
| **Finding** | The document does not explicitly state the fail-safe default when RLS policies cannot evaluate (e.g., `dcs.session_id` is not set, session has expired, user_sessions table is unavailable). PostgreSQL's default for `ENABLE ROW LEVEL SECURITY` is **deny all rows** when no policy matches — which IS fail-safe. However, this must be **explicitly documented and tested** as a security requirement, not assumed from database defaults. |
| **Risk** | If a future developer adds `FORCE ROW LEVEL SECURITY` incorrectly, or if table owners are misconfigured, the fail-safe default could be inverted. |
| **Recommendation** | (1) Add explicit fail-safe requirement: "When RLS policies cannot evaluate (missing session, expired session, database error), the default MUST be DENY ALL ROWS." (2) Document PostgreSQL table ownership strategy: RLS policies do NOT apply to table owners — the `mcp_app` role must NOT own the tables it queries through RLS. (3) Add a Phase C test requirement: verify fail-safe behavior under 5 conditions (no session set, expired session, revoked session, database connection loss, malformed session_id). |

#### DSAWG-F05: Data Spillage / Contamination Recovery Not Addressed (~~CAT II~~ → CAT III, partially resolved by D48)

| Field | Value |
|---|---|
| **Affected Sections** | §28 (Security Considerations), §24 (Migration SQL) |
| **Original Finding** | The document does not address data spillage — the scenario where classified data is erroneously loaded at a classification level below its actual classification. |
| **Partial Resolution (D48 — classification_confidence)** | The `classification_confidence` column (`'EXPLICIT'`, `'INFERRED'`, `'DEFAULT'`) is now added to data tables (§24), enabling spillage detection queries. The system will notify ISSM/ISSO when inferred or default classifications are detected. **Remaining:** A formal §28d "Data Spillage Detection and Response" section with containment/remediation procedures is still needed before Phase C. |
| **Risk** | Reduced — detection mechanism now exists. Containment and remediation procedures still need documentation before Phase C deployment. |
| **Recommendation** | (1) `classification_confidence` column resolves the detection gap. (2) Before Phase C: add §28d with containment procedures (emergency RLS lockdown), remediation (reclassification, audit notification), and UD reporting per DoDI 5200.01-V3. |

#### DSAWG-F06: Audit Log Integrity Chain Incomplete (~~CAT II~~ → RESOLVED by D45)

| Field | Value |
|---|---|
| **Affected Sections** | §28a (Audit Log) |
| **Original Finding** | The `log_hash VARCHAR(128)` column provides per-entry tamper detection (NIST AU-10), but there is no chaining mechanism — each hash is independent. |
| **Resolution (D45 — Hash Chaining)** | **Resolved.** The `dcs.audit_log` table now implements hash chaining: `log_hash = SHA-512(event_data \|\| previous_log_hash)` with a new `previous_log_hash VARCHAR(128)` column. Deleted entries break the chain (detectable). Hash chaining is configurable via Helm values for deployment flexibility (development may disable for performance). Periodic chain verification via cron job (proposed: daily at 0300). See updated §28a audit_log schema. |
| **Risk** | None — resolved by D45. |
| **Recommendation** | No action required. Hash chaining implemented in audit_log schema. External log shipping to SIEM remains a Phase C operational recommendation. |

#### DSAWG-F07: STANAG 4778 Digital Signature Key Management Not Addressed (CAT II)

| Field | Value |
|---|---|
| **Affected Sections** | §20 (Confidentiality Labels), §30 (References) |
| **Finding** | The `confidentiality_labels` table includes `digital_signature BYTEA` for STANAG 4778 cryptographic binding, but the design does not address: (a) what key management infrastructure supports these signatures, (b) what algorithms are authorized (RSA, ECDSA, post-quantum?), (c) how certificates are validated, (d) who the signing authority is, (e) how key compromise is handled. |
| **Risk** | Digital signatures without KMI documentation are security theater. The DSAWG will require a key management plan before authorizing any component that generates or validates cryptographic signatures. |
| **Recommendation** | (1) Add §28e "Cryptographic Key Management for STANAG 4778" addressing: algorithm selection (FIPS 140-3 validated), KMI integration (DoD PKI, NATO CIS), certificate validation chain, key rotation schedule, compromise recovery. (2) Note that this is a Phase C/D concern — Phase A/B do not generate signatures. (3) Reference the project's existing FIPS 140-3 compliance posture (OpenSSL FIPS Provider, CMVP Certificate #4282). |

#### DSAWG-F08: No Security Test Plan (CAT II)

| Field | Value |
|---|---|
| **Affected Sections** | Entire document |
| **Finding** | The design document contains no security test plan. For DSAWG authorization, the package must include: (a) functional security testing (do RLS policies enforce correctly?), (b) penetration testing scope, (c) negative testing (can policies be bypassed?), (d) covert channel analysis (can classification be inferred from timing, error messages, or row counts?), (e) regression testing after policy changes. |
| **Risk** | Without a test plan, the DSAWG cannot evaluate whether the security architecture will be validated before deployment. |
| **Recommendation** | Add a §28f "Security Test Plan" section with: (1) RLS policy unit tests (per-policy, per-role, per-classification level); (2) SAP no-acknowledgement verification (confirm invisible rows don't leak via COUNT, timing, or error messages); (3) Platform ceiling test matrix (every sanitization rule × every platform config); (4) Covert channel analysis plan (timing attacks on RLS evaluation, side-channel leakage via `rows_filtered_by_rls`); (5) Penetration testing scope for Phase C deployment. |

#### DSAWG-F09: Backup and Recovery Classification Inheritance (CAT III)

| Field | Value |
|---|---|
| **Affected Sections** | §28 (Security Considerations) |
| **Finding** | Database backups inherit the **highest classification level** of any data they contain. If the database holds TOP SECRET data, all backups are TOP SECRET — regardless of how much UNCLASSIFIED data the backup also contains. The design does not address backup classification, storage requirements, or destruction procedures. |
| **Risk** | Backup media at incorrect classification is a data spillage event. |
| **Recommendation** | Add a note to §28 documenting: (1) backup classification equals `MAX(classification_level)` across all rows; (2) backup storage must meet classification requirements of the platform ceiling; (3) backup media destruction per DoD 5220.22-M at the platform's classification level. |

#### DSAWG-F10: `rows_filtered_by_rls` as Potential Covert Channel (~~CAT III~~ → RESOLVED by D47)

| Field | Value |
|---|---|
| **Affected Sections** | §28a (Audit Log), §28b (SAP No-Acknowledgement) |
| **Original Finding** | The `rows_filtered_by_rls INTEGER` column in the audit log is a covert channel — users could infer SAP/SCI data existence from filter counts. |
| **Resolution (D47 — Separate Auditor-Only Table)** | **Resolved.** `rows_filtered_by_rls` is moved to a separate `dcs.audit_rls_details` table with `FORCE ROW LEVEL SECURITY` — ensuring even table owners cannot bypass RLS. Only auditors with clearance above all filtered classification levels AND access to any filtered compartments can query this table. No "God" privileges exist — system administrators and DBAs operate under the same RLS constraints. This eliminates the covert channel entirely. See updated §28a for the `dcs.audit_rls_details` table schema. |
| **Risk** | None — resolved by D47. |
| **Recommendation** | No action required. Covert channel eliminated by table separation with FORCE RLS. |

#### DSAWG Observations (No Action Required)

| # | Observation |
|---|---|
| DSAWG-O1 | The phased approach (A→B→C→D) is well-structured for incremental authorization. Phase A carries zero risk (informational columns with defaults). The DSAWG could authorize Phase A independently. |
| DSAWG-O2 | The 5-level ENUM validated against 14 international frameworks is thorough. No additional levels are needed. |
| DSAWG-O3 | The CUI-as-separate-concern decision (D2) correctly implements DoDI 5200.48 and avoids the common error of placing CUI in the classification hierarchy. |
| DSAWG-O4 | The CDSE source document catalog (§29) and authoritative references (§30) demonstrate strong policy grounding. Every design decision traces to an authoritative source. |
| DSAWG-O5 | The Kyverno + PostgreSQL RLS hybrid (D24) is architecturally sound. Kyverno for admission control, RLS for data — this avoids the complexity of OPA/Rego while maintaining defense in depth. |
| DSAWG-O6 | The platform classification ceiling concept (§28a) with audit sanitization is exactly what the DSAWG expects to see. The 4-rule sanitization logic is comprehensive. |

---

### 31b. Review Lens 2: EU Auditor — Government Cybersecurity Application Evaluation

**Reviewer Role:** EU Member State cybersecurity auditor evaluating this system for
incorporation into a government-managed cybersecurity compliance application, subject
to GDPR (Regulation 2016/679), NIS2 Directive (2022/2555), EU Cyber Resilience Act
(2024/2847), and Council Decision 2013/488/EU (EUCI).

**Evaluation Standard:** GDPR Articles 5, 6, 24-36, 44-49; NIS2 Articles 21, 23;
CRA Articles 10-14; ENISA technical guidance; EDPB Guidelines.

#### EU-F01: Data Protection Impact Assessment (DPIA) Scope — Reduced by Zero-PII (CAT III ↓ from CAT I)

| Field | Value |
|---|---|
| **Affected Sections** | §18 (GDPR Schema), §27 (Migration 000014 Preview), §28b (User Sessions) |
| **Original Finding** | GDPR Article 35 requires a DPIA before high-risk processing begins. The original design stored PII (user name, email, organization) in `dcs.user_sessions`, making the system a high-risk processor under Article 35(3). |
| **Updated Status (D28 — Zero-PII)** | The zero-PII architecture (§28b) eliminates all PII from the database. `dcs.user_sessions` now stores only an opaque `identity_hash` (irreversible without IdP access) and authorization attributes (nationality, clearance, compartments). The database is **not a system of records for personal data** under any privacy framework. A lightweight DPIA is still recommended for the authorization attribute processing and automated decision-making via RLS (Article 22), but the scope is dramatically reduced — this is no longer "high-risk processing of personal data." |
| **Risk** | Low — authorization attributes (clearance level, nationality code) are not personal data in isolation. The DPIA scope is limited to whether the *combination* of authorization attributes could re-identify individuals in small populations (e.g., "only one TOP SECRET//HCS-cleared KOR national in this deployment"). |
| **Recommendation** | (1) A lightweight DPIA covering authorization attribute processing and RLS automated decisions is still recommended for EU deployments. (2) The DPIA should document the zero-PII architecture as the primary privacy-by-design measure (Article 25). (3) Downgraded from CAT I to CAT III — no longer a deployment blocker. |

#### EU-F02: Controller/Processor Roles Not Defined (CAT I)

| Field | Value |
|---|---|
| **Affected Sections** | §18a (RoPA), §27 (GDPR Preview) |
| **Finding** | GDPR Article 26 (joint controllers) and Article 28 (processors) require clear definition of who is the **data controller** and who is the **data processor** for each processing activity. The `gdpr.processing_activities` table has `controller_name` and `joint_controllers` columns, but the design does not specify: (a) Is the project maintainer the controller or processor? (b) Is the deploying organization (e.g., a NATO member state ministry of defense) the controller? (c) In a CFC/USFK deployment, who is the controller for ROK national PII vs. EU national PII? (d) Does the open-source nature (Apache 2.0) create a situation where every deployer is an independent controller? |
| **Risk** | Without clear controller/processor determination, the RoPA is incomplete, data processing agreements (Article 28) cannot be executed, and liability for GDPR violations is indeterminate. |
| **Recommendation** | (1) Add a §18g "Controller and Processor Determination" section documenting: the project provides software (not a data processor); deploying organization is the controller (determines purposes and means of processing). (2) For the open-source scenario: each deploying organization is an independent controller; the project maintainer has no controller obligations for deployments they do not operate. (3) For joint controller scenarios (e.g., CFC/USFK with US and ROK data): document the Article 26 arrangement. (4) Prepare a template Data Processing Agreement (DPA) per Article 28 for commercial deployments. |

#### EU-F03: Legal Basis for User Session Processing — Reduced by Zero-PII (Observation ↓ from CAT I)

| Field | Value |
|---|---|
| **Affected Sections** | §28b (User Sessions) |
| **Original Finding** | The `dcs.user_sessions` table was designed to process personal data (user name, nationality, organization, clearance level). GDPR Article 6 requires a legal basis for every processing activity involving personal data. |
| **Updated Status (D28 — Zero-PII)** | The zero-PII architecture eliminates all personal data from `dcs.user_sessions`. The table now stores only: (a) an opaque `identity_hash` (not personal data — cannot be reversed without IdP access), (b) authorization attributes (nationality code, clearance level, compartments). **GDPR Article 6 legal basis analysis may not apply** — if no personal data is processed, GDPR processing rules do not engage. However, the `nationality` attribute merits analysis: a 3-letter country code (e.g., "KOR") is an authorization attribute, not personal data in isolation. It becomes personal data only when combined with identity — which this database does not hold. |
| **Residual Risk** | Minimal — an EU DPA might argue that authorization attribute *combinations* (nationality + clearance + compartments) could re-identify individuals in small populations. This is a deployment-specific risk, not a schema-level deficiency. |
| **Recommendation** | (1) Deploying organizations should assess whether their specific population size makes authorization attribute combinations re-identifiable. (2) For small-population deployments (< 50 users), consider additional pseudonymization of the `nationality` field. (3) Downgraded from CAT I to Observation — zero-PII architecture is the definitive mitigation. |

#### EU-F04: Phase C/D Sequencing — RESOLVED by Zero-PII (~~CAT I~~ → RESOLVED)

| Field | Value |
|---|---|
| **Affected Sections** | §23 (Migration Plan), §28b (User Sessions) |
| **Original Finding** | Phase C creates `dcs.user_sessions` before Phase D's GDPR tables exist, creating a compliance gap if Phase C processes PII in EU jurisdictions. |
| **Resolution (D28 — Zero-PII)** | **Fully resolved.** Phase C's `dcs.user_sessions` no longer processes any PII. The table stores only an opaque identity hash and authorization attributes. Since no personal data enters the database at Phase C, the GDPR compliance gap no longer exists. Phase D's GDPR tables remain valuable for organizations that need Article 30 RoPA documentation and breach notification infrastructure, but they are no longer a **prerequisite** for Phase C deployment in EU jurisdictions. The phased approach (A → B → C → D) is now sequencing-safe for all jurisdictions. |
| **Risk** | None — resolved by architectural decision D28. |
| **Recommendation** | No action required. Phase D remains recommended for organizations operating under GDPR, but is no longer a Phase C deployment dependency. |

#### EU-F05: Data Minimization — RESOLVED by Zero-PII (~~CAT II~~ → RESOLVED)

| Field | Value |
|---|---|
| **Affected Sections** | §28b (User Sessions) |
| **Original Finding** | The original `dcs.user_sessions` table stored 18 columns of user attributes including PII. An EU auditor would question whether all attributes are necessary for every deployment under GDPR Article 5(1)(c) data minimization. |
| **Resolution (D28 — Zero-PII)** | **Fully resolved.** The zero-PII redesign eliminated all PII columns (`user_principal`, `user_display_name`, `user_organization`, `clearance_granted_by`). The remaining columns are exclusively authorization attributes required for RLS policy evaluation — each column directly maps to a specific RLS policy (documented in the "What IS Stored" table in §28b). Nullable compartment arrays (`sap_access`, `sci_compartments`, etc.) contain NULL when not applicable, satisfying minimization in practice. The table now stores the **minimum set of attributes required for access control decisions** — nothing more. |
| **Risk** | None — resolved by architectural decision D28. |
| **Recommendation** | No action required. The zero-PII architecture is itself a data minimization measure per GDPR Article 25 (data protection by design and by default). |

#### EU-F06: GDPR Article 17 Erasure — RESOLVED by Zero-PII (~~CAT II~~ → RESOLVED)

| Field | Value |
|---|---|
| **Affected Sections** | §28b (User Sessions), Q20 |
| **Original Finding** | The tension between GDPR Article 17 (right to erasure) and audit log integrity (NIST AU-10) required a formal anonymization decision. |
| **Resolution (D28 — Zero-PII)** | **Fully resolved.** The database contains no PII to erase. `dcs.user_sessions` stores only an opaque `identity_hash` (SHA-512, irreversible without IdP) and authorization attributes. `dcs.audit_log` stores the same `identity_hash` for correlation. Since Article 17 applies to **personal data** and the database holds no personal data, erasure requests do not engage the database at all — they are handled exclusively by the external IdP (Keycloak, CAC/PKI infrastructure), which IS the system of records for PII. Session expiry and cleanup are operational housekeeping, not GDPR compliance obligations. Q20 is now RESOLVED. |
| **Risk** | None — resolved by architectural decision D28. |
| **Recommendation** | No action required for GDPR erasure. Deploying organizations should document that the IdP is the sole system of records for PII and handles all Article 17 requests. |

#### EU-F07: Cross-Border Transfer Mechanisms Incomplete (CAT II)

| Field | Value |
|---|---|
| **Affected Sections** | §18c (Transfer Authorizations), §17 (Privacy Frameworks) |
| **Finding** | The `gdpr.transfer_authorizations` table correctly models Article 44-49 transfer mechanisms (adequacy decisions, SCCs, BCRs, derogations). However, the design does not address: (a) **Schrems II implications** — supplementary measures required for SCC transfers to the US (even with EU-US DPF, non-DPF certified entities need SCCs + supplementary measures); (b) transfers to non-adequate countries not covered by the `data_privacy_frameworks` table (e.g., Philippines has no EU adequacy decision but IS a UNC member); (c) the specific scenario of EU military personnel data transiting through a US-operated system (CFC/USFK) — does the national security exemption (Article 23(1)(a)) apply? |
| **Risk** | Unauthorized cross-border data transfers are among the highest-fined GDPR violations (up to 4% of global turnover). |
| **Recommendation** | (1) Add a `supplementary_measures TEXT` column to `gdpr.transfer_authorizations` for Schrems II compliance. (2) Document the national security exemption analysis: Article 23(1)(a) and (d) may exempt military classification processing, but the exemption must be explicitly claimed and documented per EDPB Guidelines 10/2020. (3) For the CFC/USFK scenario: the ROK EU adequacy decision (December 2023) covers ROK-EU transfers; US-EU transfers require either EU-US DPF certification or SCCs. The system deployment location (ROK vs. US vs. EU) determines which mechanism applies. |

#### EU-F08: NIS2 Formal Mapping Not Provided (CAT II)

| Field | Value |
|---|---|
| **Affected Sections** | §18e (NIS2 Considerations) |
| **Finding** | Section 18e states that NIS2 requirements "largely overlap with NIST 800-53" and that ENISA maps NIS2 to ISO 27001 and NIST CSF 2.0. However, no **formal control mapping** is provided. An EU auditor evaluating a government cybersecurity application requires explicit evidence that each NIS2 Article 21 security measure is addressed — a general statement of overlap is insufficient. |
| **Risk** | NIS2 non-compliance carries fines up to €10M or 2% of worldwide turnover for essential entities. |
| **Recommendation** | (1) Add a NIS2 Article 21 compliance matrix mapping each of the 10 baseline security measures to specific NIST 800-53 controls already in the Security MCP database. (2) This is a documentation exercise — the controls likely already exist in the `oscal.catalog_controls` table — but the mapping must be explicit and auditable. (3) Consider creating an OSCAL profile that selects NIST 800-53 controls satisfying NIS2 requirements — this would be a unique differentiator for the MCP. |

#### EU-F09: CRA Exemption Claim Requires Analysis (CAT III)

| Field | Value |
|---|---|
| **Affected Sections** | §18f (CRA Considerations) |
| **Finding** | Section 18f claims the CRA "explicitly exempts non-monetized open-source software" and that Apache 2.0 licensing may qualify. The CRA's open-source exemption (Recital 18, Article 3(36)) is more nuanced than presented: it exempts **free and open-source software** that is not "supplied in the course of a commercial activity." If a commercial entity deploys this as part of a paid service, the exemption does not apply to that deployment. Furthermore, the CRA requires that even exempt open-source projects appoint a **security contact** and accept vulnerability reports — which this project does (security contact in CONTRIBUTING.md). |
| **Risk** | Incorrectly claiming the CRA exemption for a commercial deployment could result in non-compliance with CRA obligations (SBOM, vulnerability handling, security-by-design certification). |
| **Recommendation** | (1) Clarify: the open-source repository (Apache 2.0) is exempt. Commercial deployments are NOT exempt and must comply with CRA Articles 10-14. (2) Document this distinction explicitly: "Open-source distribution: CRA exempt per Article 3(36). Commercial deployment: CRA compliance required per Article 10 (cybersecurity requirements), Article 11 (reporting obligations), Article 13 (technical documentation)." (3) The existing SBOM generation (`make sbom`) partially satisfies CRA Article 13 — document this. |

#### EU-F10: Encryption Standards Reference EU Frameworks, Not Just FIPS (CAT III)

| Field | Value |
|---|---|
| **Affected Sections** | §28 (Security Considerations), §20 (STANAG 4778) |
| **Finding** | The document references FIPS 140-2/140-3 throughout (U.S. cryptographic standard). For EU deployment, the relevant standards are: **SOG-IS Crypto Evaluation Scheme** (European), **ENISA Recommended Cryptographic Algorithms** (2024), and **BSI Technical Guideline TR-02102** (German minimum key lengths). While FIPS 140-3 and SOG-IS are largely compatible, an EU auditor will expect EU-standard references. |
| **Risk** | Low — FIPS 140-3 validation is generally accepted in EU. However, a purely US-standard-referenced system may face procurement objections in EU member states. |
| **Recommendation** | (1) Add EU cryptographic standard references alongside FIPS: SOG-IS for module evaluation, ENISA for algorithm selection, BSI TR-02102 for key lengths. (2) Note that the OpenSSL FIPS Provider (CMVP #4282) uses algorithms that satisfy both FIPS 140-3 and SOG-IS requirements. (3) This is a documentation enhancement, not a technical change. |

#### EU-F11: Retention Periods Not Specified (CAT III)

| Field | Value |
|---|---|
| **Affected Sections** | §28a (Audit Log), §28b (User Sessions) |
| **Finding** | GDPR Article 5(1)(e) requires storage limitation — personal data must not be kept longer than necessary. The design creates `dcs.audit_log` and `dcs.user_sessions` tables but specifies no retention periods. The CLAUDE.md mentions "minimum 1 year (3 years for high-impact systems)" for logs per NIST AU-11, but this is not reflected in the DCS design document, and the GDPR retention schedule (`gdpr.retention_schedules` table) is Phase D. |
| **Risk** | Indefinite retention of personal data in audit logs violates storage limitation. |
| **Recommendation** | (1) Define default retention periods: audit log entries = 3 years (aligned with NIST AU-11 for high-impact systems); user sessions = 90 days active + 3 years archived (anonymized after active period). (2) Add a `retention_days INTEGER` column to `dcs.platform_configuration` for deployment-specific retention. (3) Document that EU deployments may require shorter retention per local DPA guidance. |

#### EU Auditor Observations (No Action Required)

| # | Observation |
|---|---|
| EU-O1 | The inclusion of 16 privacy frameworks (§17) with breach notification windows, special categories, and cross-border mechanisms demonstrates **privacy by design** awareness (Article 25). This is uncommonly thorough for a security-focused system. |
| EU-O2 | The ROK PIPA EU adequacy decision documentation (§27) and the ROK-EU transfer pathway are directly relevant for CFC/USFK deployments and show real-world operational awareness. |
| EU-O3 | **Updated (D28):** The zero-PII architecture (§28b) eliminates the Article 17 erasure tension entirely — no PII in the database means no erasure obligation. This is the strongest possible privacy-by-design measure: don't hold what you don't need. The IdP handles all PII obligations. |
| EU-O4 | The `gdpr_applies BOOLEAN` bridge column on **data tables** (STIG rules, etc.) is an elegant solution — it enables privacy scope identification without adding GDPR complexity to the core DCS schema. Note: the `gdpr_applies` column was removed from `dcs.user_sessions` as part of the zero-PII redesign (D28) since the table no longer holds personal data. |
| EU-O5 | The OSCAL gap analysis (§19) noting BSI Grundschutz++ as the first EU OSCAL adoption shows strategic awareness of the European compliance landscape. |
| EU-O6 | The EU bilingual marking abbreviations in the seed data (§16) correctly implement Council Decision 2013/488/EU requirements. This detail is frequently missed. |

---

### 31c. Combined Findings Summary

#### By Severity

| Severity | DSAWG | EU Auditor | Total |
|:--------:|:-----:|:----------:|:-----:|
| CAT I (Critical) | 2 | 1 | **3** |
| CAT II (Significant) | 3 | 2 | **5** |
| CAT III (Moderate) | 2 | 4 | **6** |
| Observation | 6 | 7 | **13** |
| RESOLVED (by D28 Zero-PII) | 0 | 3 | **3** |
| RESOLVED (by v3.4.0 decisions) | 3 | 0 | **3** |
| **Total** | **16** | **17** | **33** |

> **Impact of v3.4.0 Decisions (D44, D45, D47, D48):** In addition to the 3 EU findings
> resolved by D28, this version resolved 3 DSAWG findings:
>
> - **DSAWG-F02 (CAT I → RESOLVED)** by D44: System scoped as MLS, not CDS
> - **DSAWG-F06 (CAT II → RESOLVED)** by D45: Hash chaining implemented
> - **DSAWG-F10 (CAT III → RESOLVED)** by D47: Covert channel eliminated
> - **DSAWG-F05 (CAT II → CAT III)** by D48: classification_confidence column added
>
> Combined with D28, this reduces **open CAT I findings from 4 to 3** (DSAWG-F01,
> DSAWG-F03, EU-F02) and **open CAT II from 7 to 5**.
>
> **Previous Impact of Zero-PII Architecture (D28):** Resolved 3 EU findings outright
> (EU-F04, EU-F05, EU-F06), downgraded EU-F01 from CAT I to CAT III, and downgraded
> EU-F03 from CAT I to Observation.

#### By Phase Impact

| Phase | Findings That Must Be Resolved | Findings to Document Now, Implement Later |
|---|---|---|
| **Phase A (000012)** | None — Phase A carries zero risk | ~~DSAWG-F05~~ (D48: classification_confidence added), DSAWG-F09 (backup note) |
| **Phase B (000013)** | DSAWG-F07 (KMI plan needed before signatures) | EU-F08 (NIS2 mapping), EU-F10 (EU crypto refs) |
| **Phase C (RLS/Kyverno)** | DSAWG-F01, ~~F02 (D44)~~, F03, F04, F08 (MLS architectural issues) | EU-F01 (lightweight DPIA — reduced scope per D28) |
| **Phase D (GDPR)** | EU-F02 (controller/processor), EU-F07 (transfers) | EU-F09 (CRA), EU-F11 (retention) |

> **Phase C dramatically simplified by D28:** The zero-PII architecture resolved
> EU-F04 (Phase C/D sequencing), EU-F05 (data minimization), and reduced EU-F01
> (DPIA) and EU-F03 (legal basis) from deployment blockers to documentation items.
> Phase C is now safe to deploy in EU jurisdictions without Phase D as a prerequisite.

#### Cross-Cutting Findings (Affect Multiple Phases)

| Finding | Why Cross-Cutting |
|---|---|
| DSAWG-F01 (Accreditation Boundary) | Boundary definition affects ALL phases — what's in scope? |
| ~~DSAWG-F06 (Audit Hash Chain)~~ | ~~Audit integrity is a Phase A design decision that persists~~ — **RESOLVED (D45)** |
| EU-F02 (Controller/Processor) | Legal determination governs ALL data processing from Phase A |
| EU-F11 (Retention) | Retention policy applies to every table that stores time-series data |

---

### 31d. Recommended Resolution Priority

The following resolution order maximizes authorization velocity while maintaining
compliance:

1. **Immediate (before Phase A SQL is written):**
   - ~~Resolve DSAWG-F06: Add `previous_log_hash` to audit_log design~~ — **RESOLVED (D45)**
   - ~~Resolve DSAWG-F09: Add backup classification note to §28~~ — **RESOLVED (§28c added)**
   - ~~Resolve EU-F11: Define default retention periods~~ — **RESOLVED (§28d added, 60-day default, Helm-configurable)**

2. **Before Phase B:**
   - Resolve DSAWG-F07: Document KMI strategy for STANAG 4778
   - Resolve EU-F10: Add EU cryptographic standard references
   - Resolve EU-F08: Create NIS2 Article 21 compliance matrix

3. **Before Phase C (critical mass — most findings):**
   - Resolve DSAWG-F01: Define accreditation boundary
   - ~~Resolve DSAWG-F02: Clarify CDS vs. MLS scope~~ — **RESOLVED (D44)**
   - Resolve DSAWG-F03: Document trusted path and session validation
   - Resolve DSAWG-F04: Document fail-safe defaults and test cases
   - Resolve DSAWG-F08: Write security test plan
   - ~~Resolve DSAWG-F10: Restrict `rows_filtered_by_rls` visibility~~ — **RESOLVED (D47)**
   - Resolve EU-F01: Lightweight DPIA for authorization attribute processing (reduced scope per D28)
   - ~~Resolve EU-F03: Document legal basis~~ — **RESOLVED by D28** (downgraded to Observation)
   - ~~Resolve EU-F04: Re-sequence Phase C + Phase D~~ — **RESOLVED by D28** (zero-PII eliminates sequencing concern)
   - ~~Resolve EU-F05: Document data minimization~~ — **RESOLVED by D28** (only authorization attributes stored)

4. **Before Phase D:**
   - Resolve EU-F02: Document controller/processor determination
   - ~~Resolve EU-F06: Promote anonymization to formal decision~~ — **RESOLVED by D28** (no PII to erase)
   - Resolve EU-F07: Complete cross-border transfer analysis
   - ~~Resolve DSAWG-F05: Implement classification_confidence or equivalent~~ — **PARTIALLY RESOLVED (D48)** — detection added; containment procedures still needed

5. **Ongoing:**
   - Resolve EU-F09: Maintain CRA compliance analysis as licensing evolves

---

## 32. Decision Log

| # | Decision | Rationale | Alternatives Considered |
|---|----------|-----------|------------------------|
| D1 | 5-level ENUM (not 4) | Missing CONFIDENTIAL and RESTRICTED from original proposal; NATO/FGI/Philippines require RESTRICTED; RLS needs orderable hierarchy | 4-level ENUM with CUI as level 1 (rejected: breaks RLS, conflates classification with safeguarding) |
| D2 | CUI as separate columns, not in ENUM | CUI is a safeguarding category within UNCLASSIFIED per DoDI 5200.48, not a classification level per EO 13526; CUI has its own dissem control vocabulary | CUI in ENUM at ordinal 1 (rejected: breaks integer comparison for RLS) |
| D3 | GENC trigraphs as canonical codes | U.S. Government mandate via ODNI; profiles ISO 3166-1; used by CAPCO/ISMCAT | ISO 3166-1 directly (rejected: GENC is the mandated USG profile); STANAG 1059 (rejected: NATO-only, but aligns with GENC for real nations) |
| D4 | No negative dissemination field | U.S. marking system is purely inclusionary (positive authorization); REL TO inherently defines authorized set | `negative_dissem VARCHAR[]` (rejected: no CAPCO standard supports exclusionary markings in public documentation) |
| D5 | `handling_caveats TEXT` for non-standard markings | Real-world experience shows non-standard annotations exist (e.g., "NOT AUTHORIZED FOR ZAF"); informational only, not for ABAC | Reject non-standard markings (rejected: operational reality requires flexibility) |
| D6 | `label_id UUID` now, `confidentiality_labels` table later | Adding nullable UUID is nearly free; creating the table without consuming code is premature; establishes FK path for Migration 000013 | Create table now (rejected: premature complexity); Skip label_id entirely (rejected: expensive to add later) |
| D7 | Separate `display_only_nations` from `rel_to_nations` | DISPLAY ONLY and REL TO are legally distinct (viewing vs. retention); can co-exist on same document with different nation lists | Single `release_markings VARCHAR[]` (rejected: loses the DISPLAY ONLY vs. REL TO distinction documented in Classification Marking Guide v11 §9) |
| D8 | `owner_nations VARCHAR[]` not `originating_nation VARCHAR` | JOINT markings require multi-nation co-ownership; single VARCHAR cannot represent `//JOINT SECRET DEU GBR USA` | Single `originating_nation VARCHAR(3)` (rejected: cannot represent JOINT co-ownership) |
| D9 | Include `fgi_source_concealed BOOLEAN` | Classification Marking Guide v11 §3.4 requires protecting concealed FGI source identity; schema must distinguish "source is NULL because no FGI" from "source is NULL because concealed" | Rely on `document_type = 'FGI_CONCEALED'` alone (rejected: explicit boolean is clearer for queries) |
| D10 | Full 10-control CUI LDC vocabulary (not 4–5) | NARA CUI Registry and CUI Limited Dissemination Controls document define exactly 10 LDCs: NOFORN, FED ONLY, FEDCON, NOCON, DL ONLY, RELIDO, REL TO, DISPLAY ONLY, Attorney-Client, Attorney-WP. **Resolves Q8.** | Subset vocabulary matching Fortra DCS (rejected: we implement the standard, not the tool limitation) |
| D11 | CUI Designation Indicator Block as separate columns | CUI Markings Training Aid (Dec 2024) defines a 4-line DI block (Controlled by, Category, LDC, POC) that is structurally distinct from the Classification Authority Block. Both blocks required on classified docs with CUI. | Merge CUI DI fields into confidentiality_labels (rejected: DI block applies to CUI-only docs which don't have classification authority blocks) |
| D12 | Distribution Statement reference table (A–F) | DoDI 5230.24 defines 6 distribution statements required for export-controlled and CTI categories. A distribution statement is separate from and additive to LDCs. | Ignore distribution statements (rejected: required for two CUI categories; also used on classified technical info) |
| D13 | Portion marking abbreviations reference table | Banner markings and portion markings use different forms (NOFORN→NF, ORCON→OC, Attorney-Client→AC). Reference table enables bidirectional conversion and validation. | Hardcode abbreviations in application code (rejected: not maintainable; abbreviations are policy-defined, not code-defined) |
| D14 | Declassification exemption taxonomy (25X, 50X, 75X) + legacy conversion | ISOO Marking Booklet defines full exemption taxonomy and legacy marking conversion rules. Schema tracks both converted instruction and original legacy marking for audit trail. | Ignore exemptions (rejected: required for any classified document with duration beyond 25 years); Ignore legacy conversion (rejected: real-world documents still carry legacy markings) |
| D15 | Platinum Standard — implement full marking standard, not tool-constrained subset | Classification Marking Guide v11 documents Fortra DCS limitations (e.g., subject ≠ body classification). We implement the **authoritative policy** (DoDM 5200.01-V2), not the tool limitation. When tools catch up, our schema already supports the full standard. | Match Fortra DCS capabilities (rejected: we are the reference implementation, not the constrained one) |
| D16 | Atomic Energy, SAP, and Intelligence markings in Phase B | Marking National Security Information Job Aid and ISOO Booklet define RD/FRD/CNWDI, SAP nicknames/PIDs, and ORCON/PROPIN/IMCON. These are complex markings that belong on `confidentiality_labels` (Phase B), not on data table columns (Phase A). | Add all special markings to data tables now (rejected: premature — no consuming code exists; these are label-level concerns) |
| D17 | International classification systems registry as Phase A reference table | 14 national/multinational classification frameworks validated against the 5-level ENUM. Every framework maps without requiring a 6th level. Reference table enables `classification_system` column on labels (Phase B) to disambiguate identical ENUM values under different policies. | Defer to Phase B (rejected: reference table has no FK dependencies; low cost to include now; enables immediate documentation value) |
| D18 | Data privacy frameworks registry as Phase A reference table | 16 privacy laws (U.S. Privacy Act, GDPR, UK GDPR, ROK PIPA, Japan APPI, Brazil LGPD, etc.) tracked with breach notification windows, special categories support, and cross-border transfer mechanisms. Enables bridge columns on data tables. | Defer to Phase D/GDPR migration (rejected: the reference table itself is lightweight and provides immediate documentation value; bridge columns are nullable with no impact) |
| D19 | Platinum Standard expanded to international scope | The schema is not a "U.S. solution" — it must serve any nation's analyst using the MCP for AI-assisted compliance. The CFC/USFK operational context requires simultaneous handling of US, ROK, NATO, and EU frameworks on the same data. Design principle: "Any nation, any framework, any AI assistant. One schema." | U.S.-only scope (rejected: operational reality at CFC/USFK/UNC requires multi-framework support from day one) |
| D20 | GDPR compliance tables in Phase D (Migration 000014), not Phase A | GDPR Article 30 RoPA, data subject rights, breach register, cross-border transfers are mandatory when handling EU PII — but the Security MCP Server currently processes STIG rules, not personnel data. Phase D triggers when PII enters the system. | Include GDPR tables in Phase A (rejected: premature complexity; no consuming code; tables would be empty) |
| D21 | EU bilingual marking abbreviations in `marking_abbreviations` seed data | Council Decision 2013/488/EU requires bilingual (French/English) markings: RESTREINT UE/EU RESTRICTED, etc. Adding 4 rows to existing seed data enables EU marking validation from day one. | Defer EU markings to Phase B (rejected: 4 rows of seed data costs nothing and supports the international scope) |
| D22 | Privacy bridge columns (`gdpr_applies`, `privacy_framework`) on data tables in Phase A | Nullable columns with no defaults that enable future privacy framework tagging without schema migration. When STIG data has no PII, both remain NULL. When PII data arrives, they're ready. | Defer to Phase D (rejected: adding nullable columns to empty/small tables is nearly free; saves a schema migration later) |
| D23 | OSCAL gap analysis as living document section | OSCAL currently covers NIST 800-53 and FedRAMP only. BSI Grundschutz++ (Jan 2026) and Singapore IM8 are first non-US OSCAL adopters. Documenting gaps enables strategic planning for framework import capabilities. | Skip OSCAL analysis (rejected: understanding what OSCAL cannot do is as important as what it can do; guides our roadmap) |
| D24 | Hybrid Kyverno + PostgreSQL RLS (not OPA) | Three-layer enforcement: Kyverno for K8s admission control (Layer 1) and API gateway authorization (Layer 2) using YAML-native policies — no Rego, no new language, GitOps-friendly on RKE2. PostgreSQL RLS for data-level access control (Layer 3) using SQL — the policy engine for data IS the database. | OPA for everything (rejected: Rego is a new language with learning curve; OPA is not K8s-native; PostgreSQL RLS is more performant for row-level decisions than an external policy engine) |
| D25 | Platform Classification Ceiling with Audit Sanitization | Every deployment has a classification ceiling (ATO-defined). Audit logs MUST NEVER contain content above the platform ceiling. When sanitized: log shows `[SANITIZED — above platform ceiling]`, actual classification stored in RLS-protected column only visible to cleared auditors. `dcs.platform_configuration` table + `dcs.audit_log` table with sanitization columns. | Trust the application to not log classified data (rejected: defense in depth requires schema-level enforcement; NSA IMN evaluation requires verifiable proof); No audit logging of classified events (rejected: NIST AU-3 requires comprehensive logging) |
| D26 | User Session Attributes table (Option B) — zero-PII architecture | `dcs.user_sessions` table stores **only authorization attributes** (clearance, nationality, compartments) and an opaque `identity_hash` from external IdP. Enables PostgreSQL RLS to enforce SAP no-acknowledgement principle (invisible rows, not "access denied"). **Zero PII stored** — no user name, email, organization, or other identity data. `auth_source` and `auth_token_hash` provide provenance for NSA IMN evaluation. See D28 for zero-PII design principle. | Session variables only (rejected: no audit trail of what attributes were used; cannot answer "who has access to X?"; insufficient for NSA IMN verifiable proof); No user tracking in schema (rejected: RLS needs comparison context; audit log needs session correlation); PII in sessions (rejected: SORN/DPIA burden unacceptable for independent developer — see D28) |
| D27 | Opaque identity hash for audit correlation | `identity_hash = SHA-512(user_principal \|\| session_salt)` stored in `dcs.user_sessions` and `dcs.audit_log` for cross-session correlation. Irreversible without IdP access — the database cannot resolve hash to identity. Audit investigators query the IdP to resolve identity when needed. This satisfies NIST AU-3 (audit record content) while maintaining zero-PII in the database. | Store `user_principal` directly (rejected: creates PII, triggers SORN/GDPR obligations); No cross-session correlation (rejected: NSA IMN evaluation requires attributable audit trails); Per-session random ID only (rejected: cannot correlate same user across sessions for pattern analysis) |
| D28 | Zero-PII database architecture | The Security MCP Server database stores **zero Personally Identifiable Information**. The database knows WHAT a user is authorized to see (clearance, nationality, compartments) — it does NOT know WHO the user is. Identity resolution is the exclusive responsibility of the external IdP. This eliminates: U.S. Privacy Act SORN requirement, GDPR Article 17 erasure complexity, GDPR Article 35 DPIA scope, and all privacy framework obligations for the database. Resolved EU audit findings EU-F04, EU-F05, EU-F06; downgraded EU-F01, EU-F03. | Store PII with anonymization on erasure (rejected: still requires SORN, still triggers GDPR processing obligations, adds operational complexity); Store PII with encryption (rejected: encrypted PII is still PII under GDPR — encryption is a safeguard, not an exemption from processing rules) |
| D29 | Nation code seeding: allies for dev, all GENC for production | Development seed data limited to ~30 known allies for agility. Production release includes all ~249 GENC entities for completeness. **Resolves Q1.** | Seed all 249 from day one (rejected: unnecessary for development; adds noise to testing); Seed only allies forever (rejected: production must be complete for arbitrary nation code validation) |
| D30 | CUI categories as reference table, not free-text array | CUI categories stored in a `dcs.cui_categories` reference table enabling insert-time validation. Data source: DoD CUI Registry at dodcui.mil. **Resolves Q2 and Q12.** | Free-text VARCHAR[] (rejected: no validation, inconsistent values, typo-prone); Defer to Phase B (rejected: reference table is lightweight, enables validation from Phase A) |
| D31 | `classification_level` defaults to `'UNCLASSIFIED'` | Explicit is safer than implicit. Every row has a classification level; the default is the lowest level. No NULLs in classification — eliminates ambiguity for RLS comparisons. **Resolves Q4.** | Default to NULL (rejected: NULL is ambiguous — does it mean "unclassified" or "not yet assessed"?; forces COALESCE in every RLS policy) |
| D32 | Coalition membership: current state only, audit captures changes | The MCP is a Policy Enforcement Point making real-time access decisions. Historical membership is an audit concern, not an access control concern. When membership changes, audit records capture the transition. **Resolves Q6.** | Track historical membership with effective dates (rejected: adds temporal complexity to a simple lookup table; access decisions need current state, not history) |
| D33 | `marking_abbreviations` table in Phase A | Purely reference data with no FK dependencies. Including in Phase A enables early parsing work and banner line validation. Already included in Phase A table listing. **Resolves Q9.** | Defer to Phase B (rejected: no dependencies, low cost, immediate value) |
| D34 | `distribution_statements` table in Phase A | Purely reference data with 6 rows. Consistent with other Phase A reference tables. Already included in Phase A table listing. **Resolves Q10.** | Defer to Phase B (rejected: same rationale as D33) |
| D35 | Compilation flag on `confidentiality_labels` only (Phase B) | This MCP is NOT an Original Classification Authority (OCA) and does not make classification decisions. The `is_compilation` flag is an OCA determination about a document, not about individual STIG rules. Belongs on labels, not data tables. **Resolves Q11.** | Put on data tables in Phase A (rejected: MCP is not an OCA; compilation is a label-level concern) |
| D36 | `classification_system` column on data tables in Phase A | For CFC/multinational environments, knowing the classification system per-row is essential. A CFC analyst working with US, ROK, and NATO data simultaneously needs per-row system context without a JOIN to confidentiality_labels. Default `'US_DOD'` for existing data. Also supports future test data from coalition partner STIG equivalents. **Resolves Q13 and effectively resolves Q5.** | Defer to Phase B on labels only (rejected: CFC operational need is immediate; JOIN overhead unnecessary for a simple FK column) |
| D37 | GDPR-as-OSCAL is a stretch goal, late-stage proposal only | We are not an EU organization and it is not our responsibility to create standards. If we develop something meaningful, it would be a proposal submission only. Not a near-term priority. **Resolves Q14.** | Prioritize GDPR OSCAL catalog (rejected: premature; principles-based framework is the hardest OSCAL mapping; not our core mission) |
| D38 | Import BSI Grundschutz++ OSCAL content when available | Germany's BSI OSCAL/JSON catalogs (effective January 2026) will be imported as test data to validate persona-based responses. Test prompts must be updated to include focused German framework queries. **Resolves Q15.** | Wait for production need (rejected: test data validation is essential for multi-framework support; security-parser can consume with zero code changes) |
| D39 | Clean separation of privacy vs. classification frameworks | Classification systems (`dcs.classification_systems`) govern access control. Privacy frameworks (`dcs.data_privacy_frameworks`) govern PII handling. Different concerns, separate registries. Easier for long-term maintenance. **Resolves Q16.** | Unified registry (rejected: conflates access control with data protection; harder to maintain; conceptually muddled) |
| D40 | ROK PIPA dual breach notification windows: Phase D | ROK PIPA requires 72hr general / 24hr sensitive breach notification, distinct from GDPR 72hr. The `breach_notify_hours` single column captures the general window; the specific sensitive-data window is documented in `notes`. Full dual-window schema support deferred to Phase D breach workflow. **Resolves Q17.** | Implement dual-window now (rejected: Phase A reference table documents it; actual breach workflow is Phase D) |
| D41 | Single-tenant platform configuration; multi-tenancy is long-term | Helm chart provides ability to deploy multiple isolated environments via Kubernetes namespaces and clusters. Single-tenant `dcs.platform_configuration` is simpler and matches current deployment model. Multi-tenancy (with `tenant_id` on platform_configuration and audit_log) is a long-term evolution goal. **Resolves Q18.** | Multi-tenant from day one (rejected: adds `tenant_id` complexity to every table; Helm namespace isolation is sufficient for now) |
| D42 | User sessions: store audit history, determine partitioning approach | Audit trail requires historical session data. RLS only needs active sessions. Recommended approach: PostgreSQL table partitioning by `is_active` or a separate `dcs.session_history` table with automatic archival. Specific implementation to be designed in Phase C. **Resolves Q19.** | Active sessions only (rejected: NIST AU-3 requires attributable audit trails; cannot answer "what authorization did this hash hold 6 months ago?" without history) |
| D43 | Kyverno policies: GitOps only, not stored in database | Policy-as-Code standards-based approach. Kyverno policies live in Git and are applied to Kubernetes via GitOps (Flux/ArgoCD). The MCP can read policies from the K8s API via `kubectl` without DB storage. No `kyverno_policies` table needed. **Resolves Q21.** | Store in database (rejected: violates GitOps pattern; adds complexity; Git is the authoritative source for policy-as-code) |
| D44 | System is MLS data store, NOT a Cross Domain Solution (CDS) | The Security MCP Server is a Multi-Level Secure (MLS) data store: it stores data at multiple classification levels and enforces access within a single domain using PostgreSQL RLS. It is NOT a CDS — it does not transfer data between classification domains. Any AI agents leveraging this capability will reach through pre-existing Guards (e.g., ISSE Guard, Raise the Bar solutions) which are external to and outside the scope of this system. PostgreSQL RLS is the data-level enforcement mechanism; external CDS guards handle cross-domain transfer. **Resolves Q22. Resolves DSAWG-F02.** | Treat as CDS (rejected: PostgreSQL RLS is not an evaluated cross-domain guard; CDS scope would require NSA guard evaluation that is outside our boundary) |
| D45 | Tamper-evident audit trails with hash chaining; Helm-configurable | `dcs.audit_log` implements hash chaining: `log_hash = SHA-512(event_data \|\| previous_log_hash)`. New `previous_log_hash VARCHAR(128)` column enables chain verification and gap detection (deleted entries break the chain). Hash chaining can be enabled/disabled via Helm values for deployment flexibility (development may disable for performance). Allows deployment in higher classification environments out of the door. **Resolves Q23. Resolves DSAWG-F06.** | Per-entry hashing only (rejected: cannot detect deleted entries; insufficient for NSA IMN evaluation) |
| D46 | DPIA on Graduation Checklist; AI agent to develop DPIA | Lightweight DPIA added to the project's "Graduation Checklist" (pre-ATO requirements). Additionally, the Security MCP must enable an AI agent to develop the DPIA itself based on design documents provided as part of the effort — dogfooding the AI-assisted compliance capability. **Resolves Q25.** | Skip DPIA entirely (rejected: EU deployments benefit from the documentation even with zero-PII architecture) |
| D47 | `rows_filtered_by_rls` in separate auditor-only table — no covert channels | For MLS certification, NO covert channels are permitted. `rows_filtered_by_rls` is moved to a separate `dcs.audit_rls_details` table with its own RLS policies restricting visibility to cleared auditors only. This eliminates the covert channel where users could infer SAP/SCI data existence from filter counts. This extends to all platform roles including system and database administrators — no "God" privileges. **Resolves Q26. Resolves DSAWG-F10.** | Keep in main audit_log with RLS (rejected: even with RLS, the column's existence creates a query vector; SAP no-acknowledgement requires the information to not be in the same table at all) |
| D48 | `classification_confidence` column for data spillage detection | Add `classification_confidence VARCHAR(20)` to data tables with values: `'EXPLICIT'` (human-assigned), `'INFERRED'` (from DISA prefix), `'DEFAULT'` (schema default). Enables queries like "show all data classified by default, not by determination" for spillage reviews. System should notify ISSM/ISSO when inferred or default classifications are detected, as they may not always have visibility into information being ingested and stored. **Resolves Q27. Resolves DSAWG-F05.** | Skip classification confidence (rejected: DEFAULT classification on imported data is a data spillage vector; detection is mandatory for MLS environments) |
| D49 | Migration 000002: `classification_level_rank()` function for ABAC | Created `dcs.classification_level_rank()` as IMMUTABLE PARALLEL SAFE SQL function mapping ENUM → integer (0–4) for application-level WHERE clause comparisons. Separate migration (000002) rather than modifying consolidated baseline (000001) because: (a) baseline is immutable once deployed, (b) function is consumed by ABAC middleware, not by schema structure. Deployed 2026-02-11. | Include in 000001 baseline (rejected: baseline already deployed in production; modifying it would require data wipe) |
| D50 | Application-level ABAC before PostgreSQL RLS | ABAC enforcement implemented as Go middleware in security-query (Layer 2) before PostgreSQL RLS (Layer 3). Gateway propagates JWT claims as HTTP headers (`X-User-Clearance`, `X-User-Nationality`). Query service applies WHERE clauses using `classification_level_rank()`. This provides immediate enforcement while RLS policies are designed. Defense-in-depth: application layer filters first, RLS will provide database-level guarantee. Deployed v0.9.0, 2026-02-10. | Wait for PostgreSQL RLS (rejected: delays enforcement until Phase C; application-level filtering is sufficient for current UNCLASSIFIED-only data); OPA sidecar (rejected per D24: Kyverno + RLS replaces OPA) |
| D51 | Zero-PII audit identity via `X-Identity-Hash` header propagation | Gateway computes SHA-512 identity hash from JWT claims and propagates via `X-Identity-Hash` header to all downstream services. Downstream services log the hash for correlated audit trails without storing PII. Implements NIST AU-3 (audit record content) while maintaining zero-PII architecture (D28). Deployed v0.9.0, 2026-02-10. | Pass user principal in headers (rejected per D28: creates PII in transit and in downstream logs); Per-service independent hashing (rejected: would produce different hashes for same user across services, breaking correlation) |

---

## 33. Open Questions

| # | Question | Who Decides | Impact if Deferred | Status | 
|---|----------|------------|-------------------|--------|
| Q1 | Should we seed `nation_codes` with ALL GENC entries (~249 codes) or just known allies (~30 codes)? | DevSecOps team | Low — can add nations later; starting with allies is pragmatic | **ANSWER**: Seed data during development can be limited to known allies; Production release includes all entities |
| Q2 | Should CUI categories be a reference table or free-text array? | InfoSec team | Medium — reference table enables validation but requires CUI Registry import | **ANSWER**: Let's go with a reference table; need to identify where to import data from |
| Q3 | What is the correct CAPCO tetragraph for AUKUS? Is it publicly assigned? | Security Officer | Low — can add when confirmed | Open | TBD |
| Q4 | Should `classification_level` default to `'UNCLASSIFIED'` or `NULL`? | DevSecOps team | Low — `'UNCLASSIFIED'` is safer (explicit > implicit) | **ANSWER**: Default to `UNCLASSIFIED` |
| Q5 | Do we need `classification_system VARCHAR` on data tables or only on `confidentiality_labels`? | All three perspectives | Medium — adding to data tables means every row carries its policy context; adding only to labels means a JOIN is required | **RESOLVED via Q13/D36** — Include as column on data tables. MLS DCS compliance discussion captured in D36 and D44 (MLS architecture). Deeper MLS compliance analysis to be conducted as part of Phase C DSAWG package preparation. |
| Q6 | Should the coalition_members table track historical membership changes (e.g., Germany joined UNCK in 2024)? | Security Officer | Low — current membership is sufficient for access control; history is audit concern | **ANSWER**: This is an MCP where PEP decisions are real time; current membership only. Audit records can capture when that changes |
| Q7 | How should we handle the Japan dual-track classification (traditional SDF vs. SDS vs. GSOMIA)? | InfoSec team + Japan bilateral SME | Low for now — all map to same ENUM values; `classification_system` on the label distinguishes | Open |
| Q8 | ~~Are there additional CUI dissemination controls beyond FEDCON, FED ONLY, NOCON, DL ONLY?~~ | ~~InfoSec team~~ | ~~Medium~~ | **RESOLVED** — See D10. NARA CUI Registry defines 10 LDCs: NOFORN, FED ONLY, FEDCON, NOCON, DL ONLY, RELIDO, REL TO, DISPLAY ONLY, Attorney-Client, Attorney-WP. Schema updated in §5. |
| Q9 | Should `marking_abbreviations` reference table be in Phase A (000012) or Phase B (000013)? | DevSecOps team | Low — the table is purely reference data with no FK dependencies. Including in Phase A means it's available for any early parsing work. | **ANSWER**: Include in Phase A |
| Q10 | Should the `distribution_statements` reference table be in Phase A or Phase B? | DevSecOps team | Low — similar to Q9, purely reference data. Including in Phase A alongside other reference tables (nation_codes, tetragraphs) is consistent. | **ANSWER**: Include in Phase A |
| Q11 | For classification by compilation (`is_compilation`), should this flag go on data tables (Phase A) or only on `confidentiality_labels` (Phase B)? | DevSecOps team | Low — compilation is an OCA decision about a *document*, not about individual data records like STIG rules. Likely belongs on labels only. | **ANSWER**: We're not an OCA nor are we making classification decisions; this is a MCP |
| Q12 | Should we import the full NARA CUI Category Registry as a reference table? Per the CUI Markings Training Aid, the DoD CUI Registry at dodcui.mil has the authoritative list. | InfoSec team | Medium — enables validation of `cui_category` values at insert time. Related to Q2. | **ANSWER**: See Q2 response |
| Q13 | Should `classification_system` be a column on data tables (Phase A) or only on `confidentiality_labels` (Phase B)? With the `classification_systems` reference table in Phase A, we could add a FK column to data tables now. But most data is US_DOD and the column would be redundant with `document_type`. | DevSecOps team | Medium — for CFC/multinational environments, knowing the classification system per-row is valuable; for STIG-only use, it's overhead. See also Q5. | **ANSWER**: Include it as a Column. Queried Gemini to determine coalition partner equivants to STIGs to include as Test Data during the reload |
| Q14 | Should we create an OSCAL catalog for GDPR requirements? GDPR is principles-based, not controls-based, making it the hardest framework to express in OSCAL. However, commercial GRC tools attempt this mapping. Could be a major differentiator. | DevSecOps team + Legal | High for EU market — a GDPR-as-OSCAL catalog would be unprecedented in open source. Low for immediate STIG use. |**ANSWER**: Stretch goal to add for Late Stage development. We're not an EU organization and it's not our responsibility to create Standards. Proposal only if we do come up with something. |
| Q15 | When should we import BSI Grundschutz++ OSCAL content? Germany's BSI is publishing OSCAL/JSON catalogs effective January 2026. Our security-parser can consume these with zero code changes. Timing question only. | DevSecOps team | Low — import capability exists; just need the published content. Monitor BSI publication schedule. | **ANSWER**: ABSOLUTELY! Let's get the test data in and be able to validate persona-based responses when we have the IdP established. Also need to update test Prompts to include focused queries to ensure we return proper results |
| Q16 | Should the `data_privacy_frameworks` table include non-privacy data protection laws (e.g., ROK Military Secret Protection Act, Japan SDS Act)? Currently these are in `classification_systems`. Clean separation or unified registry? | DevSecOps team | Low — current separation (classification vs. privacy) is conceptually clean. Military classification governs access; privacy law governs PII handling. Different concerns. | **ANSWER**: Clean separation. Easier for long-term mx |
| Q17 | For CFC/USFK operations: should the schema support ROK PIPA breach notification (72hr general, 24hr sensitive) as distinct from GDPR breach notification (72hr)? The `breach_notify_hours` column on `data_privacy_frameworks` currently stores a single value. | DevSecOps team + ROK legal SME | Low for Phase A — the reference table documents it; actual breach workflow is Phase D. | **ANSWER**: Yes. Phase D is fine. |
| Q18 | Should `dcs.platform_configuration` allow multiple active configurations (e.g., for multi-tenant deployments where different tenants have different ceilings)? Current design assumes one active platform config per deployment. | DevSecOps team | Medium — multi-tenancy would require `tenant_id` on platform_configuration and audit_log. Single-tenant is simpler and matches current deployment model. | **ANSWER**: Single-Tenant now. Helm provides ability to deploy multiple environments to the same platform (namespaces, clusters, etc.). Long term goal: mutli-tenancy |
| Q19 | Should `dcs.user_sessions` store historical sessions (for audit trail) or only active sessions (for performance)? Could partition by `is_active` or use a separate `session_history` table. | DevSecOps team | Medium — audit trail requires history; RLS only needs active sessions. Partitioning is the cleanest solution. | **ANSWER**: We need audit history; determine best approach given our technical solutions |
| Q20 | ~~For GDPR Article 17 erasure of `dcs.user_sessions`: should we anonymize or delete?~~ | ~~DevSecOps team + Legal~~ | ~~High~~ | **RESOLVED (D28)** — Zero-PII architecture eliminates the question entirely. The database holds no PII, so GDPR Article 17 erasure does not apply to the database. All erasure requests are handled by the external IdP. See EU-F06 resolution. |
| Q21 | Should Kyverno policies be stored in the database (for MCP tool management) or only in Git/K8s (GitOps pattern)? Storing in DB enables MCP tools like `list_policies` and `validate_policy`. Git-only is cleaner for GitOps. | DevSecOps team | Low — GitOps pattern is standard; MCP could read from K8s API via `kubectl` without DB storage. | **ANSWER**: GitOps only. Policy As Code standards-based approach |
| Q22 | Is this system a **Cross Domain Solution (CDS)** or a **Multi-Level Secure (MLS) data store**? CDS transfers data between classification domains via guards; MLS stores multi-level data with access enforcement within a single domain. The answer determines DSAWG evaluation criteria and whether an external guard component is required. (See §31a DSAWG-F02) | ISSM + DSAWG | **Critical** — determines accreditation pathway and whether PostgreSQL RLS alone is sufficient. | **Audit §31** **ANSWER**: Multi-Level Secure (MLS) data store. Any AI agents that leverage this capability will reach through pre-existing Guards which are outside of the scope of our effort. |
| Q23 | Should `dcs.audit_log` implement hash chaining (`previous_log_hash`) for tamper-evident audit trails, or is per-entry hashing (`log_hash`) sufficient? Hash chaining enables gap detection (deleted entries break the chain). Per-entry hashing only detects modification of existing entries. (See §31a DSAWG-F06) | DevSecOps team + ISSM | **High** — NSA IMN evaluation and DSAWG authorization require tamper-evident logging. Hash chaining is the stronger posture. | **Audit §31** **ANSWER**: I would like tamper-evident audit trails. Allows us to potentially be deployed in higher classification environments and meet those requirements out of the door. Can this be a deployment option via Helm values setting? |
| Q24 | ~~Should Phase D be re-sequenced to deploy concurrently with Phase C for EU deployments?~~ | ~~DevSecOps team + Legal~~ | ~~High for EU~~ | **RESOLVED (D28)** — Zero-PII architecture eliminates the Phase C/D sequencing concern. Phase C no longer processes PII, so GDPR infrastructure (Phase D) is not a prerequisite for Phase C deployment in EU jurisdictions. See EU-F04 resolution. |
| Q25 | Should a lightweight DPIA be prepared for the authorization attribute processing in `dcs.user_sessions`? The zero-PII architecture (D28) eliminated high-risk PII processing, but a lightweight DPIA covering automated decision-making via RLS and re-identification risk in small populations may still be prudent for EU deployments. (See updated EU-F01) | DevSecOps team + DPO | **Low** (downgraded from High) — no longer a deployment blocker. A lightweight DPIA documenting zero-PII as a privacy-by-design measure would strengthen compliance posture. Recommend separate companion document if pursued. | **UPDATED — Scope reduced by D28** **ANSWER**: Add to the "Graduation Checklist". In addition to the ATO the Security MCP must allow an AI agent to also develop the DPIA based on design documents that would be provided as part of the effort. |
| Q26 | Should `rows_filtered_by_rls` be moved to a separate auditor-only table (not visible via normal audit log queries) to prevent covert channel leakage of SAP/SCI data existence? (See §31a DSAWG-F10) | ISSM + Security Architect | **Medium** — affects SAP no-acknowledgement principle. Current RLS on audit_log may be sufficient if properly configured. | **Audit §31** **ANSWER**: No Covert Channels allowed. If we want MLS-certification, we CANNOT have exposures. This even includes Platform and System Administrators who would not have true "God" privileges as they typically do. |
| Q27 | Should `dcs.audit_log` include a `classification_confidence` indicator ('EXPLICIT', 'INFERRED', 'DEFAULT') to support data spillage detection? Records classified by schema default (UNCLASSIFIED) vs. explicit human/parser determination have different assurance levels. (See §31a DSAWG-F05) | DevSecOps team | **Medium** — enables queries like "show all data classified by default, not by determination" for spillage reviews. | **Audit §31** **ANSWER**: Sounds GREAT! Let the system notify the ISSM/ISSO there may be an issue to address as they may not always have visibility into the information being ingested and stored. |
| Q28 | Where should we import the full CUI category reference data from? The DoD CUI Registry at dodcui.mil is authoritative but does not appear to offer a machine-readable export. Options: (a) manual curation from dodcui.mil web pages, (b) scrape/parse the registry, (c) use NARA CUI Registry as supplementary source. | DevSecOps team | Medium — reference table enables validation; incomplete data means some valid categories would be rejected on import. | **ANSWER**: Scrape the registry and use NARA CUI registry as supplementary source (b & c) |
| Q29 | What is the BSI Grundschutz++ OSCAL catalog publication URL and timeline? Germany's BSI committed to OSCAL/JSON catalogs effective January 2026 with a transition through 2029. Need to monitor for publication and validate our security-parser can consume the format. | DevSecOps team | Low — import capability exists; just need the published content. | **NEW — Flows from Q15/D38** |
| Q30 | What are the coalition partner equivalents to STIGs for test data? Mentioned in Q13 answer: "Queried Gemini to determine coalition partner equivalents to STIGs to include as Test Data during the reload." Need to identify specific frameworks (e.g., BSI IT-Grundschutz, UK Cyber Essentials, AUS ISM controls) and their import formats. | DevSecOps team | Medium — multi-framework test data is essential for validating `classification_system` column and persona-based queries. | **ANSWERED**: View new folders in ./data — "au-ism-oscal" (Australian ISM OSCAL), "ca-itsg-33" (Canadian ITSG-33), "uk-device-security-guidance" (UK NCSC), and "uk-zta" (UK Zero Trust Architecture). Each folder contains a README with links to source documents/downloads. |
| Q31 | What test prompts need to be created/updated for persona-based queries against multi-framework data? E.g., a German analyst querying BSI controls, a ROK analyst at CFC querying Korean security requirements, a NATO staff officer querying EUCI-marked data. | DevSecOps team | Medium — validates that the multi-framework schema actually works for real-world query patterns. | **NEW — Flows from Q15/D38** |
| Q32 | What is the best approach for session history archival? Options: (a) PostgreSQL table partitioning by `is_active`, (b) separate `dcs.session_history` table with automatic trigger-based archival, (c) PostgreSQL pg_partman extension for time-based partitioning. Must balance audit query performance with active session RLS performance. | DevSecOps team | Medium — affects Phase C implementation. Active session lookup is in the hot path for every RLS evaluation. | **NEW — Flows from Q19/D42** |
| Q33 | How should Helm values configure hash chaining behavior? Proposed: `auditLog.hashChaining.enabled: true` (default), `auditLog.hashChaining.algorithm: SHA-512`, `auditLog.hashChaining.verificationSchedule: "0 3 * * *"` (daily 3am chain verification cron). Development environments may set `enabled: false` for performance. | DevSecOps team | Low — implementation detail for Phase C; documenting the Helm interface now ensures consistency. | **NEW — Flows from Q23/D45** |

---

**End of Design Document**

*Design developed for the Security MCP Server project.*
*Author: Alex Ackerman*
*Security Contact: security@securitymcp.io*
