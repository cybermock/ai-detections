# Architecture

This document describes the system architecture of the Splunk ES AI RBA Starter Pack, including data flow, component relationships, and design decisions.

## System Overview

The AI RBA Starter Pack is a Splunk ES content pack that detects unsanctioned AI usage using Risk-Based Alerting (RBA). Instead of generating individual alerts for every AI-related event, the pack assigns risk scores to users and systems. Only when cumulative risk exceeds a threshold does the system generate a notable event for SOC review.

### Design Principles

1. **Risk over alerts:** Individual detections contribute risk, not notables. This reduces alert fatigue.
2. **Defense in depth:** Multiple detection layers (web, DNS, process, network, DLP) ensure coverage even when one data source is unavailable.
3. **Signal stacking:** Overlapping detections for the same activity are intentional. A user browsing an AI site generates web, DNS, and potentially first-seen detections, building a composite risk picture.
4. **Configurable thresholds:** All numeric thresholds are externalized to `ai_detection_config.csv` for environment-specific tuning.
5. **Allowlist-first filtering:** The `ai_unsanctioned_filter` macro is the last step in every detection, ensuring sanctioned users/systems are excluded consistently.

## Data Flow

```mermaid
flowchart TD
    subgraph "Data Sources"
        PROXY["Proxy / Web Gateway<br/>(pan:traffic, bluecoat, zscaler)"]
        EDR["EDR / Sysmon<br/>(crowdstrike, sysmon, cb)"]
        DNS["DNS Server<br/>(infoblox, umbrella, bind)"]
        FW["Firewall / Network<br/>(pan:traffic, cisco:asa)"]
        DLP["DLP System<br/>(symantec, forcepoint, mcafee)"]
        IDENTITY["Identity Provider<br/>(AD, Okta, Azure AD)"]
    end

    subgraph "CIM Data Models"
        WEB["Web Data Model"]
        PROC["Endpoint.Processes<br/>Data Model"]
        NRES["Network_Resolution<br/>Data Model"]
        NTRAF["Network_Traffic<br/>Data Model"]
        DLPM["Data_Loss_Prevention<br/>Data Model"]
        IDENT["identity_lookup_expanded"]
    end

    subgraph "Enrichment Layer"
        MACRO1["`ai_domains_filter` macro<br/>Domain -> Provider mapping"]
        MACRO2["`ai_process_filter` macro<br/>Process -> Tool mapping"]
        MACRO3["`ai_unsanctioned_filter` macro<br/>Allowlist evaluation"]
        LKP1["ai_provider_domains.csv"]
        LKP2["ai_tool_processes.csv"]
        LKP3["ai_sanctioned_entities.csv"]
        LKP4["ai_detection_config.csv"]
    end

    subgraph "Detection Layer"
        WEB_DET["Web Detections<br/>AI-006, AI-007, AI-009,<br/>AI-010, AI-015, AI-016,<br/>AI-017, AI-018, AI-020,<br/>AI-021, AI-022 thru AI-028,<br/>AI-031, AI-032, AI-036,<br/>AI-040 thru AI-044"]
        PROC_DET["Process Detections<br/>AI-004, AI-005,<br/>AI-008, AI-011"]
        DNS_DET["DNS Detection<br/>AI-012"]
        NET_DET["Network Detections<br/>AI-014, AI-019"]
        DLP_DET["DLP Detection<br/>AI-020"]
    end

    subgraph "Risk Framework"
        RISK["risk index<br/>(user + system scores)"]
        AGG["Aggregate Correlation Rules<br/>AI-RISK-001 (medium, 60 pts)<br/>AI-RISK-002 (high, 90 pts)"]
        NOTABLE["Notable Events<br/>(Incident Review queue)"]
    end

    PROXY --> WEB
    EDR --> PROC
    DNS --> NRES
    FW --> NTRAF
    DLP --> DLPM
    IDENTITY --> IDENT

    WEB --> MACRO1
    PROC --> MACRO2
    MACRO1 --> WEB_DET
    MACRO2 --> PROC_DET
    NRES --> DNS_DET
    NTRAF --> NET_DET
    DLPM --> DLP_DET
    IDENT --> WEB_DET

    LKP1 --> MACRO1
    LKP2 --> MACRO2
    LKP3 --> MACRO3
    LKP4 --> WEB_DET
    LKP4 --> PROC_DET

    MACRO3 --> WEB_DET
    MACRO3 --> PROC_DET
    MACRO3 --> DNS_DET
    MACRO3 --> NET_DET
    MACRO3 --> DLP_DET

    WEB_DET --> RISK
    PROC_DET --> RISK
    DNS_DET --> RISK
    NET_DET --> RISK
    DLP_DET --> RISK

    RISK --> AGG
    AGG --> NOTABLE
```

## Risk Aggregation Pipeline

```mermaid
flowchart LR
    subgraph "Individual Detections (every 5 min)"
        D1["AI-028: Web Access<br/>user: 15, system: 10"]
        D2["AI-007: Upload Volume<br/>user: 20-80, system: 20"]
        D3["AI-016: Privileged<br/>user: 40, system: 20"]
        D4["AI-020: DLP<br/>user: 60, system: 30"]
        DN["...other detections..."]
    end

    subgraph "Risk Index"
        RI["Per-user risk accumulation<br/>over rolling 24-hour window"]
    end

    subgraph "Threshold Evaluation (every 15 min)"
        T1["total_risk >= 60?<br/>-> Medium Notable"]
        T2["total_risk >= 90?<br/>-> High Notable"]
    end

    D1 --> RI
    D2 --> RI
    D3 --> RI
    D4 --> RI
    DN --> RI
    RI --> T1
    RI --> T2
```

## Lookup Relationship Diagram

```mermaid
flowchart TD
    subgraph "Lookup Files"
        L1["ai_provider_domains.csv<br/>52 domains<br/>Fields: provider, domain, usage_type,<br/>severity_weight, enabled"]
        L2["ai_tool_processes.csv<br/>80+ processes<br/>Fields: tool, provider, process_name_lc,<br/>platform, usage_type, enabled"]
        L3["ai_sanctioned_entities.csv<br/>Fields: entity_type, entity, provider,<br/>scope, expires, enabled, allow_key"]
        L4["ai_detection_config.csv<br/>25 controls<br/>Fields: control_name, value, notes"]
        L5["ai_mitre_mapping.csv<br/>38 mappings<br/>Fields: detection_id, mitre_technique_id,<br/>mitre_technique_name, mitre_tactic"]
    end

    subgraph "Macros"
        M1["`ai_domains_filter`<br/>Domain enrichment"]
        M2["`ai_process_filter`<br/>Process enrichment"]
        M3["`ai_unsanctioned_filter(3)`<br/>Allowlist evaluation"]
    end

    subgraph "Detection Categories"
        WD["Web Detections"]
        PD["Process Detections"]
        DD["DNS Detections"]
        ND["Network Detections"]
    end

    L1 --> M1
    L2 --> M2
    L3 --> M3
    L4 --> WD
    L4 --> PD

    M1 --> WD
    M1 --> DD
    M2 --> PD
    M3 --> WD
    M3 --> PD
    M3 --> DD
    M3 --> ND
```

## Allowlist Evaluation Flow

```mermaid
flowchart TD
    START["Detection fires with<br/>user, src, provider fields"]

    U1["Lookup: user|provider<br/>e.g., alice@corp.com|openai"]
    U2["Lookup: user|*<br/>e.g., alice@corp.com|*"]
    S1["Lookup: system|provider<br/>e.g., 10.20.30.40|openai"]
    S2["Lookup: system|*<br/>e.g., 10.20.30.40|*"]
    G1["Lookup: group|provider<br/>e.g., engineering|openai"]
    G2["Lookup: group|*<br/>e.g., engineering|*"]

    CHECK_EN["Check: enabled=1?"]
    CHECK_EXP["Check: not expired?<br/>(expires >= today OR empty)"]

    ALLOW["ALLOWED<br/>Event is filtered out<br/>(no risk generated)"]
    DENY["NOT ALLOWED<br/>Event proceeds to risk action"]

    START --> U1
    START --> U2
    START --> S1
    START --> S2
    START --> G1
    START --> G2

    U1 --> CHECK_EN
    U2 --> CHECK_EN
    S1 --> CHECK_EN
    S2 --> CHECK_EN
    G1 --> CHECK_EN
    G2 --> CHECK_EN

    CHECK_EN -->|"enabled=1"| CHECK_EXP
    CHECK_EN -->|"not found or enabled=0"| DENY

    CHECK_EXP -->|"not expired"| ALLOW
    CHECK_EXP -->|"expired"| DENY
```

The `ai_unsanctioned_filter` macro performs six parallel lookups against `ai_sanctioned_entities.csv`. If **any** lookup returns an active, non-expired match, the event is filtered out. All six lookups must fail for the event to proceed and generate risk.

## Component Descriptions

### Macros (`default/macros.conf`)

| Macro | Arguments | Purpose |
|---|---|---|
| `ai_domains_filter` | None | Normalizes domain fields and enriches against `ai_provider_domains.csv`. Extracts provider, usage_type, severity_weight, and enabled status. |
| `ai_unsanctioned_filter(3)` | user_field, system_field, provider_field | Six-way allowlist evaluation against `ai_sanctioned_entities.csv`. Checks user, system, and group entries with provider-specific and wildcard matching. Enforces enabled status and expiration dates. |
| `ai_process_filter` | None | Enriches process names against `ai_tool_processes.csv` to resolve tool name, provider, usage type, and enabled status. |
| `ai_risk_defaults(1)` | control_name | Retrieves a single configuration value from `ai_detection_config.csv`. Used for threshold lookups. |

### Lookups (`lookups/`)

| File | Records | Purpose |
|---|---|---|
| `ai_provider_domains.csv` | 52 domains | Maps AI domains to providers, usage types (web/api/ide/cli/local_llm), severity weights, and enabled flags. |
| `ai_tool_processes.csv` | 80+ processes | Maps process names and original file names to AI tools, providers, platforms, and usage types. |
| `ai_sanctioned_entities.csv` | Variable | Allowlist entries for users, systems, and groups. Supports provider-specific and wildcard scoping with expiration dates. |
| `ai_detection_config.csv` | 25 controls | Tunable thresholds for all configurable detections. Centralized configuration avoids editing savedsearches.conf. |
| `ai_mitre_mapping.csv` | 38 mappings | Maps detection IDs to MITRE ATT&CK technique IDs, names, and tactics. |

### Detection Categories

| Category | IDs | Data Model | Description |
|---|---|---|---|
| Web Access | AI-028 | Web | Direct browsing to AI web properties |
| CLI Execution | AI-004, AI-008 | Endpoint.Processes | AI CLI tools launched from terminal or scripts |
| Desktop Apps | AI-005 | Endpoint.Processes | AI desktop applications (ChatGPT, Cursor, etc.) |
| API Access | AI-006 | Web | AI API calls from non-development endpoints |
| Data Upload | AI-007 | Web | High-volume data uploads to AI services |
| First-Seen | AI-009 | Web | New AI provider usage per user |
| Burst Activity | AI-010 | Web | Rapid request volume to AI services |
| Local LLM | AI-011, AI-014 | Endpoint.Processes, Network_Traffic | Local LLM framework execution and server ports |
| DNS | AI-012 | Network_Resolution | DNS resolution of AI domains |
| Model Download | AI-013 | Web | Download of LLM model files |
| After-Hours | AI-015 | Web | AI usage outside business hours |
| Privileged | AI-016 | Web + Identity | AI usage by privileged accounts |
| Volume Anomaly | AI-017 | Web | Statistical z-score anomaly detection |
| Multi-Service | AI-018 | Web | Multiple AI providers in one session |
| Code Assistant | AI-019 | Network_Traffic | IDE network connections to AI backends |
| DLP Correlation | AI-020 | Data_Loss_Prevention | DLP violations targeting AI services |
| Browser Extension | AI-021 | Web | AI browser extension activity |
| Risk Aggregation | AI-RISK-001, AI-RISK-002 | risk index | Cumulative risk threshold notables |

## Data Model Dependencies

| Data Model | Required By | Fields Used | Acceleration |
|---|---|---|---|
| Web | AI-006, AI-007, AI-009, AI-010, AI-013, AI-015-018, AI-020-024, AI-026-028, AI-031-032, AI-036, AI-040-042, AI-044, AI-DISCOVERY-001 | url_domain, user, src, dest, bytes_out, bytes_in, url, http_user_agent, http_method | Recommended |
| Endpoint.Processes | AI-004, AI-005, AI-008, AI-011, AI-034-036 | user, dest, process_name, parent_process_name, process, parent_process, process_path, original_file_name | Recommended |
| Network_Resolution | AI-012 | src, query, record_type | Recommended |
| Network_Traffic | AI-014, AI-019 | src, dest, dest_port, transport, app, src_ip, dest_ip | Recommended |
| Data_Loss_Prevention | AI-020, AI-025, AI-030 | user, src, dest, file_name, dlp_type, file_content | Recommended |
| risk (index) | AI-RISK-001, AI-RISK-002 | search_name, risk_object, risk_object_type, risk_score | N/A |
| identity_lookup_expanded | AI-016, AI-026, AI-040 | identity, category, priority, department | N/A (ES managed) |
| asset_lookup_by_str | AI-006, AI-022, AI-023, AI-032 | ip, category, asset_id, is_expected | N/A (ES managed) |

## Scheduling Architecture

The detection scheduling is tiered by resource impact and urgency:

| Tier | Schedule | Detections | Rationale |
|---|---|---|---|
| Real-time (5 min) | `*/5 * * * *` | Most detections (AI-004 through AI-036, AI-043) | Near-real-time detection for active threats |
| Frequent (15 min) | `*/15 * * * *` | AI-009, AI-RISK-001/002/003/004/005 | Longer lookback or aggregation windows |
| Daily | `30 3 * * *`, `30 4 * * *`, `45 4 * * *`, `0 5 * * *`, `0 6 * * *` | AI-017, AI-040, AI-041, AI-042, AI-044 | Resource-intensive baseline computations run off-peak |

All detections use `alert.suppress` to prevent alert flooding within their respective suppress periods (1h for most, 2-4h for risk thresholds, 24h for first-seen and anomaly).
