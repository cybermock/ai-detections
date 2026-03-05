# HDSI AI RBA Detection Pack for Splunk ES

50 correlation searches detecting unsanctioned and adversarial AI usage across shadow AI browsing, desktop apps, CLI tools, API access, local LLMs, data uploads, agentic AI, MCP servers, and behavioral anomalies. Every detection writes dual risk events (user + system risk objects) and uses RBA signal stacking — no single low-signal detection fires a notable on its own. Risk threshold searches aggregate signals so only genuinely concerning patterns surface as notables. Validated: 50/50 SPL parse, 50/50 P2R conformance (10-check audit).

## Quick start

1. **Deploy `hdsi_ai_rba_common` first** — contains 7 shared macros required by all detection packages.
2. **Deploy detection packages** — `hdsi_ai_*` and `hdsi_rba_ai_*` packages from `p2r/packages/`.
3. **Install lookups** — copy all 9 CSVs from `lookups/` into the same app context (e.g., `HurricaneLabsContentUpdates`).
4. **Validate CIM mappings** — confirm your proxy, DNS, endpoint, network, DLP, and email sources map correctly to the required data models.
5. **Configure allowlists and thresholds:**
   - `lookups/ai_sanctioned_entities.csv` — sanctioned users, systems, and groups.
   - `lookups/ai_detection_config.csv` — tunable thresholds (upload tiers, risk thresholds, z-scores, time windows).
   - `lookups/ai_department_sensitivity.csv` — department-level risk multipliers.

### Optional data source setup

- **Identity-aware detections** (AI-016, AI-026, AI-040): Requires `identity_lookup_expanded` with `bunit` field in ES.
- **DLP detections** (AI-020, AI-025, AI-030, AI-038): Requires `Data_Loss_Prevention` data model populated.
- **Email detection** (AI-031): Requires `Email` data model with `action="send"` events.
- **Filesystem detection** (AI-043): Requires `Endpoint.Filesystem` data model with file access events.

## Repository structure

```
default/                           # Monolithic Splunk app
  savedsearches.conf               #   All 50 searches (single file)
  macros.conf                      #   All macros
  transforms.conf                  #   Lookup definitions
  data/ui/views/                   #   4 dashboards
p2r/                               # Modular P2R format
  packages/
    hdsi_ai_rba_common/            #   Shared macros (prerequisite)
    hdsi_ai_<name>/                #   Detection package
    hdsi_rba_ai_<name>/            #   RBA correlation package
  tools/                           #   Conformance audit, SPL validation, fix scripts
  reports/                         #   Audit results (JSON + Markdown)
lookups/                           # 9 CSV lookup files
docs/                              # Architecture, tuning, runbooks, reviews
tests/                             # 6 test modules (pytest)
```

## P2R package format

P2R (Package-to-Release) structures each detection as an independently deployable, versioned package. Each package contains:

```
hdsi_ai_<name>/
  package.yml               # Metadata: version, author, description, dependencies, data prereqs
  confs/savedsearches.conf   # The correlation search
  confs/macros.conf          # Per-package extension macros
  README.md                  # Package-specific documentation
```

### Per-package extension macros

Every detection package ships two local macros:

- **`hdsi_ai_<name>_filter`** — empty `()` placeholder. Add `WHERE` clauses to exclude specific users, hosts, or patterns without modifying the search itself.
- **`hdsi_ai_<name>_customizations`** — passthrough `search *`. Append post-processing logic (field overrides, enrichments) without touching the base SPL.

### Common prerequisite

`hdsi_ai_rba_common` must be deployed first. All detection packages declare it in `prereq_packages` and reference its shared macros via `common_dependencies` in `package.yml`.

### Conformance audit

`p2r/tools/audit_savedsearch_conformance.sh` validates all 50 packages against 10 checks:

| Check | Validates |
|---|---|
| `action.notable = 1` | Notable event creation enabled |
| `action.risk = 1` | Risk event creation enabled |
| Notable description present | `rule_description` populated |
| Risk message present | `_risk_message` populated |
| Risk object present | `_risk` JSON array defined |
| Drilldown searches present | Drilldown searches configured |
| Drilldown dashboards present | Empty dashboards array set |
| Drilldown key schema | Uses `earliest_offset`/`latest_offset` (not legacy `earliest`/`latest`) |
| Enabled by default | `disabled = 0` |
| Risk object type schema | `risk_object_type` restricted to `user` or `system` |

Current result: **50/50 fully conformant**.

### Convention compliance fixes

`p2r/tools/apply_audit_fixes.py` enforces packaging conventions across all packages:

- Cron offset staggering (anti-thundering-herd across `*/5` and `*/15` schedules)
- Risk score normalization (string → integer in `_risk` JSON)
- Multi-line SPL reformatting (pipe-delimited line breaks with `\` continuation)
- Suppress period conversion (human-readable → seconds)
- Dynamic field tokens in `rule_title` (e.g., `($user$)`)
- `common_dependencies` injection based on macro usage detection

## Shared macros

7 macros defined in `hdsi_ai_rba_common`:

| Macro | Args | Purpose |
|---|---|---|
| `ai_domains_filter` | — | Normalizes domain fields, joins `ai_provider_domains` lookup, resolves cloud AI endpoints (Bedrock, Vertex, Azure OpenAI), filters `enabled=1` |
| `ai_unsanctioned_filter(3)` | `user_field`, `system_field`, `provider_field` | Multi-tier allowlist check against `ai_sanctioned_entities.csv` — matches by user, system, and group with provider-specific and wildcard scopes; enforces `enabled` and `expires` |
| `ai_process_filter` | — | Joins `ai_tool_processes` lookup by lowercase process name, filters `enabled=1` |
| `ai_risk_multiplier` | — | Enriches with department sensitivity from `ai_department_sensitivity.csv`, applies 1.5x multiplier for privileged/critical accounts via `identity_lookup_expanded` |
| `ai_risk_defaults(1)` | `control_name` | Returns threshold value from `ai_detection_config.csv` for the given control name |
| `ai_prompt_injection_patterns_enabled` | — | Returns enabled prompt injection regex patterns from `ai_prompt_injection_patterns.csv` |
| `ai_api_key_patterns_enabled` | — | Returns enabled API key regex patterns from `ai_api_key_patterns.csv` |

## Detection inventory

### Core Detections (AI-004 to AI-021)

| ID | Detection | Risk | MITRE | Data Source |
|---|---|---|---|---|
| AI-004 | Unsanctioned AI CLI execution | 25+15 | T1059.001 | Endpoint |
| AI-005 | Unsanctioned AI desktop app execution | 20+12 | T1204.002 | Endpoint |
| AI-006 | AI API access from non-dev endpoint | 24+14 | T1071.001 | Web |
| AI-007 | High volume upload to AI service (tiered) | 20-80+20 | T1567.002 | Web |
| AI-008 | Scripted AI CLI invocation | 32+18 | T1059.004 | Endpoint |
| AI-009 | First-seen AI provider for user | 15+8 | T1071.001 | Web |
| AI-010 | Repeated unsanctioned AI access burst | 18+10 | T1071.001 | Web |
| AI-011 | Local LLM framework execution | 20+15 | T1204.002 | Endpoint |
| AI-012 | DNS queries to AI domains | 12 | T1071.004 | DNS |
| AI-013 | LLM model file download | 30+18 | T1105 | Web |
| AI-014 | Local LLM listening port detected | 30 | T1571 | Network |
| AI-015 | After-hours AI service usage | 15+8 | T1567.002 | Web |
| AI-016 | Privileged account AI service usage | 40+20 | T1078.004 | Web + Identity |
| AI-017 | AI usage volume anomaly (z-score) | 35 | T1567.002 | Web |
| AI-018 | Multiple AI services in single session | 15+8 | T1567.002 | Web |
| AI-019 | Code assistant network connection | 15 | T1071.001 | Network |
| AI-020 | DLP violation on AI service upload | 60+30 | T1567.002 | DLP |
| AI-021 | AI browser extension activity | 12+8 | T1176 | Web |

### Shadow AI & Policy Bypass (AI-022 to AI-028)

| ID | Detection | Risk | MITRE | Data Source |
|---|---|---|---|---|
| AI-022 | AI access via VPN/proxy evasion | 35+20 | T1090.003 | Web |
| AI-023 | AI access from unmanaged device | 30+25 | T1078.004 | Web + Asset |
| AI-024 | Browser extension high-volume data transmission | 30+15 | T1176 | Web |
| AI-025 | Copy-paste correlation to AI service | 25+12 | T1115 | DLP + Web |
| AI-026 | AI usage from personal account / OAuth mismatch | 28+12 | T1078.004 | Web + Identity |
| AI-027 | Personal email to AI service upload correlation | 30+15 | T1048.002 | Web |
| AI-028 | Unsanctioned AI web access (consolidated) | 15+10 | T1071.001 | Web |

### Adversarial AI Threats (AI-030 to AI-036)

| ID | Detection | Risk | MITRE | Data Source |
|---|---|---|---|---|
| AI-030 | Prompt injection indicators in web uploads | 45+25 | T1190 | DLP |
| AI-031 | AI-generated phishing indicators | 40+20 | T1566.001 | Web + Email |
| AI-032 | Suspicious model file exfiltration from ML infra | 50+30 | T1567.002 | Web |
| AI-033 | AI API key exposure in code/DLP | 55+25 | T1552.001 | Code/DLP |
| AI-034 | Deepfake tool execution/access | 50+30 | T1588.005 | Endpoint |
| AI-035 | AI-assisted lateral movement | 45+25 | T1059.001 | Endpoint |
| AI-036 | Compromised AI plugin/extension installation | 35+20 | T1195.002 | Endpoint + Web |

### Agentic AI & MCP (AI-037 to AI-039, AI-046)

| ID | Detection | Risk | MITRE | Data Source |
|---|---|---|---|---|
| AI-037 | AI agent framework execution | 35+20 | T1059 | Endpoint |
| AI-038 | Sanctioned AI DLP violation | 40+20 | T1567.002 | DLP |
| AI-039 | AI agent autonomous action detection | 40+20 | T1059 | Endpoint |
| AI-046 | MCP server execution | 35+20 | T1059 | Endpoint |

### UEBA Behavioral Baselines (AI-040 to AI-045)

| ID | Detection | Risk | MITRE | Data Source |
|---|---|---|---|---|
| AI-040 | User peer group AI usage anomaly | 30 | T1567.002 | Web + Identity |
| AI-041 | Time-of-day usage pattern anomaly | 25 | T1567.002 | Web |
| AI-042 | New AI provider adoption velocity | 20+10 | T1071.001 | Web |
| AI-043 | AI usage following data access spike | 40+20 | T1567.002 | Endpoint + Web |
| AI-044 | Gradual low-and-slow data exfiltration via AI | 45+20 | T1567.002 | Web |
| AI-045 | Voice cloning API access | 40+20 | T1588.005 | Web |

### RBA Correlation Rules

| ID | Detection | Risk | Data Source |
|---|---|---|---|
| AI-RISK-001 | User risk threshold exceeded — medium | notable | risk index |
| AI-RISK-002 | User risk threshold exceeded — critical | notable | risk index |
| AI-RISK-003 | Data collection to AI upload kill chain | 60 + notable | risk index |
| AI-RISK-004 | Privilege escalation plus AI usage correlation | 70 + notable | risk index |
| AI-RISK-005 | Multi-vector AI risk (3+ categories in 24h) | 55 + notable | risk index |

### Threat Intelligence & Health

| ID | Detection | Data Source |
|---|---|---|
| AI-DISCOVERY-001 | Unknown high-volume external API discovery (disabled) | Web |
| Health — Lookup Staleness | Weekly stale lookup file check | REST API |
| Health — Data Model Availability | Hourly data model event check | Data Models |

Risk column shows `user_score+system_score` for dual-risk detections.

### Deprecated

| ID | Replacement | Notes |
|---|---|---|
| AI-001 | AI-028 | ChatGPT web access merged into consolidated detection |
| AI-002 | AI-028 | Claude web access merged into consolidated detection |
| AI-003 | AI-028 | Gemini web access merged into consolidated detection |

## Risk scoring model

### Dual-risk pattern

Every detection emits two risk events via the `_risk` JSON array: one for the **user** risk object and one for the **system** (host/src) risk object. This ensures risk accumulates on both the person and the machine, enabling correlation from either pivot.

### Dynamic scoring

Some detections use variable risk scores based on severity tiers. AI-007 (high volume upload) scores 20/40/60/80 based on upload size thresholds (1/5/10/50 MB). Detections enriched via `ai_domains_filter` inherit `severity_weight` from the provider lookup, allowing higher-risk providers to score proportionally higher.

### Risk multipliers

The `ai_risk_multiplier` macro applies two multipliers to the base risk score:

- **Department sensitivity** — looked up from `ai_department_sensitivity.csv` (e.g., finance, legal, executive may carry higher multipliers).
- **Privileged account** — 1.5x multiplier for accounts where `category=privileged` or `priority=critical` in `identity_lookup_expanded`.

These multiply together: a privileged user in a sensitive department gets `department_multiplier * 1.5`.

### Threshold-based notables

Risk threshold searches aggregate all AI risk events per user over a rolling 24-hour window:

- **AI-RISK-001**: Notable at **60 points** (medium).
- **AI-RISK-002**: Notable at **90 points** (critical).

Both thresholds are configurable via `ai_detection_config.csv`.

### Kill chain correlation

AI-RISK-003 correlates data collection activity (file access spikes) with subsequent AI service uploads within a configurable window (default: 4 hours), detecting the staging-to-exfiltration pattern.

## Detection overlap & stacking

Multiple detections are expected to fire for the same activity. This is by design — overlapping RBA signals build composite risk scores:

- **Browsing claude.ai** → AI-028 (Web) + AI-012 (DNS) + AI-009 (First-Seen) + AI-018 (Multi-Service)
- **Using Cursor IDE** → AI-005 (Desktop App) + AI-019 (Code Assistant Network) + AI-012 (DNS)
- **Running `ollama run`** → AI-011 (Local LLM) + AI-014 (Listening Port) + AI-012 (DNS)
- **Large upload by privileged user after hours** → AI-028 + AI-007 + AI-015 + AI-016 + AI-012
- **MCP server with filesystem access** → AI-046 (MCP) + AI-039 (Autonomous Actions)
- **Insider data staging** → AI-043 (Data Access Spike) + AI-007 (Upload) + AI-RISK-003 (Kill Chain)

No single low-scoring detection generates a notable. Risk threshold searches (AI-RISK-001/002) aggregate signals so only genuinely concerning patterns surface.

## Scheduling & performance

### Cron schedules

Detections run on `*/5` or `*/15` minute intervals with **staggered offsets** to prevent thundering-herd load spikes. Offsets are distributed by `apply_audit_fixes.py` (e.g., `0-59/5`, `1-59/5`, `2-59/5` for `*/5` searches; `0-59/15`, `3-59/15`, `6-59/15` for `*/15` searches).

### Dispatch windows

- `*/5` searches: `dispatch.earliest_time = -5m@m`
- `*/15` searches: `dispatch.earliest_time = -15m@m`

### Suppression periods

| Period | Applies To |
|---|---|
| 3600s (1h) | Most detection searches |
| 14400s (4h) | RBA correlation rules |
| 86400s (24h) | UEBA behavioral baselines |
| 604800s (7d) | Health checks |

### Scheduling flags

All searches set `allow_skew = 5m` and `realtime_schedule = 0` to reduce search head contention.

## Lookups

| File | Purpose | Entries |
|---|---|---|
| `ai_provider_domains.csv` | Provider/domain catalog | 112 domains |
| `ai_tool_processes.csv` | CLI, desktop, local LLM process catalog | 88 processes |
| `ai_sanctioned_entities.csv` | User/system allowlist with expiration | configurable |
| `ai_detection_config.csv` | Tunable thresholds | 26 controls |
| `ai_mitre_mapping.csv` | MITRE ATT&CK mapping per detection ID | 42 mappings |
| `ai_department_sensitivity.csv` | Department risk multipliers | 11 departments |
| `ai_prompt_injection_patterns.csv` | Prompt injection pattern library | 25 patterns |
| `ai_deepfake_tools.csv` | Deepfake/synthetic media tools | 30 tools |
| `ai_api_key_patterns.csv` | API key regex patterns | 20 patterns |

## Allowlist model

`ai_sanctioned_entities.csv` supports provider-specific and provider-agnostic entries:

```
allow_key = "<entity>|<provider>"    # provider-specific exception
allow_key = "<entity>|*"             # all AI providers
```

CSV schema: `entity_type`, `entity`, `provider`, `scope`, `expires`, `owner`, `reason`, `enabled`, `allow_key`

The `ai_unsanctioned_filter` macro enforces `enabled` and `expires` fields. Group-based allowlisting is supported via `user_group`, `user_category`, `category`, or `bunit` fields.

## Tuning

All thresholds are configurable via `lookups/ai_detection_config.csv`. See [`docs/TUNING_GUIDE.md`](docs/TUNING_GUIDE.md) for detailed guidance.

| Control | Default | Detection |
|---|---|---|
| Upload tier 1/2/3/4 | 1 / 5 / 10 / 50 MB | AI-007 |
| Request burst count | 10 requests / 15m | AI-010 |
| Medium risk threshold | 60 points / 24h | AI-RISK-001 |
| High risk threshold | 90 points / 24h | AI-RISK-002 |
| After-hours window | 8 PM – 6 AM | AI-015 |
| Multi-service threshold | 3 providers / 1h | AI-018 |
| Volume anomaly z-score | 3.0 | AI-017 |
| Model download threshold | 500 MB | AI-013 |
| Extension data threshold | 10 MB | AI-024 |
| New provider velocity | 3 providers / 7 days | AI-042 |
| Low-and-slow threshold | 50 MB / 7 days | AI-044 |
| Peer group z-score | 2.5 | AI-040 |
| Time anomaly z-score | 3.0 | AI-041 |
| Data access spike | 100 files | AI-043 |
| Kill chain window | 4 hours | AI-RISK-003 |
| Multi-vector categories | 3 categories | AI-RISK-005 |

## Data model requirements

| Data Model | Required By |
|---|---|
| `Web` | Most web-based detections |
| `Endpoint.Processes` | AI-004, AI-005, AI-008, AI-011, AI-034–AI-039, AI-046 |
| `Network_Traffic` | AI-014, AI-019 |
| `Network_Resolution` | AI-012 |
| `Data_Loss_Prevention` | AI-020, AI-025, AI-030, AI-038 |
| `Endpoint.Filesystem` | AI-043 |
| `Email` | AI-031 |
| `risk` index | AI-RISK-001 through AI-RISK-005 |
| `identity_lookup_expanded` | AI-016, AI-026, AI-040 |
| `asset_lookup_by_str` | AI-006, AI-022, AI-023, AI-032 |

## MITRE ATT&CK coverage

| Technique | ID | Detections |
|---|---|---|
| Application Layer Protocol: Web | T1071.001 | AI-006, AI-009, AI-010, AI-019, AI-028, AI-042 |
| Application Layer Protocol: DNS | T1071.004 | AI-012 |
| Exfiltration Over Web Service | T1567.002 | AI-007, AI-015, AI-017, AI-018, AI-020, AI-032, AI-038, AI-040, AI-041, AI-043, AI-044 |
| Exfiltration Over Alternative Protocol | T1048.002 | AI-027 |
| User Execution: Malicious File | T1204.002 | AI-005, AI-011 |
| Command and Scripting Interpreter | T1059 | AI-004, AI-008, AI-035, AI-037, AI-039, AI-046 |
| Ingress Tool Transfer | T1105 | AI-013 |
| Non-Standard Port | T1571 | AI-014 |
| Valid Accounts: Cloud Accounts | T1078.004 | AI-016, AI-023, AI-026 |
| Browser Extensions | T1176 | AI-021, AI-024 |
| Clipboard Data | T1115 | AI-025 |
| Proxy: Multi-hop Proxy | T1090.003 | AI-022 |
| Exploit Public-Facing Application | T1190 | AI-030 |
| Phishing: Spearphishing Attachment | T1566.001 | AI-031 |
| Unsecured Credentials: Credentials In Files | T1552.001 | AI-033 |
| Obtain Capabilities: Exploits | T1588.005 | AI-034, AI-045 |
| Supply Chain Compromise: Software | T1195.002 | AI-036 |

## Kill chain phases

Every detection includes an `ai_kill_chain_phase` field. AI-RISK-003 specifically correlates across phases, detecting the collection → exfiltration transition.

| Phase | Detections |
|---|---|
| recon | AI-009, AI-012, AI-028, AI-042 |
| staging | AI-013, AI-030, AI-031, AI-033, AI-034, AI-045 |
| execution | AI-004, AI-005, AI-008, AI-011, AI-037, AI-039, AI-046 |
| collection | AI-006, AI-010, AI-019, AI-022, AI-023, AI-025, AI-026, AI-035, AI-043 |
| exfiltration | AI-007, AI-015, AI-017, AI-018, AI-020, AI-024, AI-027, AI-032, AI-038, AI-040, AI-041, AI-044 |
| persistence | AI-014, AI-021, AI-036 |

## Dashboards

| Dashboard | Purpose |
|---|---|
| `ai_rba_analytics` | Detection hit rates, risk score trends, top users/providers, stacking analysis |
| `ai_rba_fp_tracker` | False positive tracking and tuning feedback loop |
| `ai_rba_health` | Search execution health, skipped/failed searches, data model availability |
| `ai_rba_lookup_health` | Lookup staleness, row counts, last-modified timestamps |

## Tests

6 pytest modules in `tests/`:

| Module | Purpose |
|---|---|
| `test_spl_syntax.py` | SPL parse validation for all savedsearches.conf |
| `test_csv_schema.py` | CSV lookup schemas, value constraints, uniqueness rules |
| `test_detection_metadata.py` | Required fields, naming conventions, risk/notable config |
| `test_mitre_coverage.py` | MITRE ATT&CK coverage and cross-references |
| `test_runbook_coverage.py` | Runbook existence for every detection |
| `test_sample_events.py` | Sample event matching against detection logic |

## Additional documentation

| Document | Description |
|---|---|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | System design, data flow, macro architecture |
| [`docs/TUNING_GUIDE.md`](docs/TUNING_GUIDE.md) | Threshold tuning, FP reduction, environment-specific guidance |
| [`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md) | Adding new detections, P2R packaging, review process |
| [`docs/DETECTION_TEMPLATE.md`](docs/DETECTION_TEMPLATE.md) | Template for new detection development |
| [`docs/runbooks/`](docs/runbooks/) | 49 investigation runbooks (one per detection/correlation) |
| [`docs/reviews/`](docs/reviews/) | Architecture and code reviews |
