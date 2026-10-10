# Changelog

All notable changes to the Splunk ES AI RBA Starter Pack are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-10-09

This is the first release in which the packages under `saved_searches/packages/` are the only deployable artifact. It contains 47 packages: 1 common, 38 risk detections, 1 hunting search, 2 health checks and 5 risk aggregators. Three packages are `deployment_type: adhoc` (the hunting search and two detections), and the other 44 are `global`. Each package is at `version: 1.1.0`. Every saved search was run read-only against 4 production Splunk ES tenants (Tenants A-D: Splunk Cloud 10.4-10.5, ES 8.5-8.7). All 46 searches and their 128 drilldowns parse on all 4 tenants. Four further detections are held back, unreleased, in `saved_searches/incubating/` (see **Incubating** below). Per-package results are in each package README under **Validation**.

### Fixed
- **Parse-blocking defects that stopped every 1.0.0 search from running.**
  - Piped empty filter macro, in all 50 searches. `` | `<pkg>_filter` `` expanded to `| ()`, which is a fatal parse error. The filter macro (ships as `()`) now goes inline in the first `tstats` `where` clause or base search, using data-model field names.
  - Invalid Risk drilldown syntax. `| from datamodel:"Risk.All_Risk" where ...` is fatal. Risk drilldowns now use `| from datamodel:"Risk.All_Risk" | search risk_object=...`.
  - Wrong DLP data model name. `Data_Loss_Prevention` does not exist. The CIM model is `DLP` and its dataset is `DLP_Incidents`. Both the searches and `package.yml` `data_prereqs` are corrected.
  - ES identity `department` field. ES `identity_lookup_expanded` has no `department` field in any validated tenant, so lookups that output it failed or were always empty. Identity sensitivity now uses `bunit`.
- **`unknown` risk objects.** No detection writes risk to a literal `unknown`, `-` or empty user or system any more. Such rows are dropped, or that risk object is not emitted. Machine (`$`), service and built-in accounts are also excluded where a rule scores people.
- **Web data without `url_domain`.** Proxies and SSE platforms often fill CIM `Web.site` but not `Web.url_domain`. Web searches now match on `(Web.url_domain=* OR Web.site=*)`, group by both fields with `fillnull_value="unknown"`, and resolve `coalesce(url_domain, site)`. Web drilldowns follow the same pattern.
- **Subsearch truncation.** Rules that merged data models through `append [...]` subsearches were capped at 50,000 rows or auto-finalized at 60 s on large tenants. They now use chained `tstats prestats=t append=t` in the main pipeline, or a bounded `append` only for a light branch.

### Changed
- **Risk-only RBA policy.**
  - Detections (`hdsi_ai_*`) set `action.notable = 0` and `action.risk = 1`. They keep their `action.notable.param.*` lines (drilldowns, rule title and description, security domain, severity) so the risk events carry analyst context.
  - Only the risk aggregators (`hdsi_rba_ai_*`) raise notables: `action.notable = 1`, `action.risk = 0`.
  - The health checks raise audit-domain notables. They write no risk and send no email: `action.email = 0`, and `alert_email_to` ships empty.
  - The hunting search `hdsi_ai_unknown_high_volume_external_api_discovery` writes neither risk nor notables.
  - Every package ships `enable_alerting: false`.
- **Risk scoring policy (ES 8.x).**
  - Every `action.risk.param._risk` entry carries a literal integer `risk_score` (1-100). `$token$` scores are not supported by ES.
  - Dynamic scoring computes a numeric field named `risk_score` in SPL. It is capped per rule with `min(<cap>, ...)`; caps are 30-80, so no single event dominates a user's total. The aggregators make the escalation decision.
  - Analyst text (`_risk_message`, `rule_title`, `rule_description`) no longer uses underscore tokens (`$_x$`). ES drops fields that start with `_`. Those fields are renamed, for example `_final_multiplier` to `risk_multiplier`.
  - Each risk-writing search ends with `` | `<pkg>_risk_score` `` (ships as `search *`) as its last pipe, after `` | `<pkg>_customizations` ``.
- **Search names.** Every saved search is named `<Domain> - HDSI AI <Title> - Rule`, and the aggregators are named `Threat - HDSI RBA AI <Title> - Rule`. The `AI RBA - AI-0xx` names are gone. Each search sets `detection_id` to its package name, and the aggregators select HDSI AI risk by `source="* - HDSI AI * - Rule"` or `detection_id="hdsi_ai_*"`. Health checks are excluded.
- **Conventions applied to every package.**
  - `version: 1.1.0`.
  - Search `description` starts with `v1.1.0`, and macro descriptions start with `v1.1`.
  - `alert.suppress.fields` is set to the risk object, with `alert.suppress.period` in seconds.
  - Paired cron and dispatch windows: 5-min, 15-min, hourly and daily `@d` windows.
  - MITRE `action.correlationsearch.annotations` is valid JSON with 1-4 current ATT&CK IDs and matches the in-SPL `mitre_attack` value. AI tooling acquisition maps to T1588.007.
  - `data_prereqs` describe what each search really reads, and `tags` come from `saved_searches/package_tags.csv`.
- **Common package (`hdsi_ai_rba_common`).**
  - **Domain normalisation in `ai_domains_filter`.** The macro lowercases its input and strips URL schemes and paths, a leading `*.`, `:port`, trailing dots (DNS answers such as `chatgpt.com.`) and a leading `www.`. It then rewrites `ai_domain` to that normalised form. URLs, hostnames, DNS answers and app names all resolve through one macro.
  - **New `ai_provider_apps` lookup** (105 rows). It maps SSE/CASB application names (`Web.site` values such as `ChatGPT` or `Google Gemini`), Palo Alto App-IDs and IdP application labels to providers. Single-word names match only when the value comes from the row's own `site` or `app` field, or when the caller sets `ai_input_type="app"`. This keeps DNS search-suffix queries such as `claude.` from counting as AI use.
  - **`match_subdomains` column in `ai_provider_domains`.** A parent domain covers its subdomains only when this flag is set (115 of 200 rows). Multi-purpose SaaS bases no longer pull in unrelated hosts.
  - **New `traffic_class` column** (`interactive`, `background`, `site`). Volume and first-seen rules can now ignore telemetry and updater hosts.
  - **Cloud endpoint patterns.** Azure AI Foundry and Azure AI Services (`*.cognitiveservices.azure.com`, medium confidence, weight 0.8) are added to the Bedrock, Vertex AI, Azure OpenAI and SageMaker patterns.
  - **Refreshed provider registry.** It has 200 domain rows across 96 providers, with source, `first_seen`, `last_verified` and `confidence` provenance columns.
  - **Microsoft 365 Copilot is opt-in.** Microsoft notice MC1462915 turns `copilot.cloud.microsoft` into the Microsoft 365 home page during September-November 2026. The Microsoft 365 Copilot domain and app rows therefore ship `enabled=0`, tagged `OPT_IN_M365_COPILOT`. Copilot Studio, Security Copilot and consumer Copilot stay enabled.
  - **`ai_risk_multiplier`.** It reads the identity `bunit`, matching it against `ai_department_sensitivity` by the whole value and then by its last and first path segments. It falls back to the bare account name (`DOMAIN\` and `@suffix` removed). It multiplies by 1.25 for a whole-word privileged category or `priority=critical`, caps at 2.0, and outputs a plain `risk_multiplier` field. `_final_multiplier` remains as a legacy alias.
  - **`ai_unsanctioned_filter(3)`.** It adds an organisation-wide `*|<provider>` allow key. It looks up the user's identity `bunit` itself, so group keys work, and it honours `expires`. It drops its `_allow_*` working fields.
  - **`ai_process_filter`.** It outputs `requires_context` for generic process names such as `fabric.exe`, `lms.exe` and `chat.exe`. The new `ai_process_enrich` macro does the same lookup without dropping rows.
  - **Config and reference lookups.** In `ai_detection_config`, only `medium_risk_threshold` (60) and `high_risk_threshold` (90) are read now. The other numeric rows are marked `DEPRECATED v1.1` and replaced by package macros. `ai_mitre_mapping` is keyed by package name and was regenerated from the annotations.
- **Per-detection reworks.** Each package README documents the logic, scoring, thresholds and live results. Highlights:
  - **DNS** (`dns_queries_to_ai_domains`, `access_from_unmanaged_device`, `code_assistant_network_connection`). These are now the most portable signal. Changes include a provider pre-filter generated from the registry, a shared-source (resolver/NAT) guard, a guard for roaming DNS-security home-router addresses, background-name handling, and no double counting of coding-assistant DNS.
  - **Web and SSE** (`unsanctioned_web_access`, `high_volume_upload_to_ai_service`, `first_seen_provider_for_user`, `repeated_unsanctioned_access_burst`, `multiple_services_in_single_session`, `time_of_day_usage_pattern_anomaly`, `usage_volume_anomaly`, `user_peer_group_usage_anomaly`, `new_provider_adoption_velocity`, `voice_cloning_api_access`, `llm_model_file_download` and others). Changes include app-name and `site` support, inbound server-log exclusion, guards against shared addresses and NAT, blocked-only traffic weighted down, and drilldowns that handle `DOMAIN\user` values.
  - **Endpoint** (`agent_framework_execution`, `agent_autonomous_action_detection`, `assisted_lateral_movement`, `mcp_server_execution`, `scripted_cli_invocation`, `unsanctioned_cli_execution`, `unsanctioned_desktop_app_execution`, `local_llm_framework_execution`, `local_llm_listening_port_detected`, `deepfake_tool_execution_access`, `compromised_plugin_extension_installation`). These now match on command line and path as well as process name. They cover macOS and Linux installs, add corroboration for generic names, and exclude non-human accounts.
  - **Data protection and email** (`api_key_exposure_in_code_dlp`, `sanctioned_dlp_violation`, `dlp_violation_on_service_upload`, `prompt_injection_indicators_in_web_uploads`, `generated_phishing_indicators`). Changes include token-boundary key matching with per-key roll-up, a content-evidence gate for DLP incidents, weak injection patterns that now need a second marker, and broader lure and payload coverage.
  - **Aggregators.**
    - `user_risk_threshold_exceeded` is now the medium band: 60 to below 90, with at least 2 distinct detections in 24 h.
    - `user_critical_risk_threshold_exceeded` is the high band: 90 or more.
    - `data_collection_kill_chain` requires a collection detection followed by an upload detection for the same person within 4 h.
    - `multi_vector_risk` requires 3 or more vectors, at least 1 of them high impact.
    - `privilege_escalation_correlation` counts only AI activity that is proven to come after the privilege change.
    - All five merge `DOMAIN\user`, UPN and bare names into one person key and exclude placeholder, machine and service accounts.
  - **Health checks.** `health_data_model_availability` and `health_lookup_staleness_alert` now find dependent rules. The REST `search=` filter returned nothing on Splunk Cloud, so they read the saved-search list unfiltered and match titles with an anchored `HDSI (RBA )?AI ` regex.
- **Demoted to `deployment_type: adhoc`.** These rules need data or setup that a typical tenant lacks, and each produced real results on at least one validation tenant once that was in place. Each README states the exact requirement.
  - `hdsi_ai_after_hours_service_usage`: a business-hours clock must be configured per tenant.
  - `hdsi_ai_copy_paste_correlation_to_ai_service`: browser paste audit or DLP data.
  - `hdsi_ai_unknown_high_volume_external_api_discovery`: now a hunting search with no risk and no notables.
- **Incubating (not released).** These four moved from `saved_searches/packages/` to `saved_searches/incubating/`, together with their runbooks (formerly `docs/runbooks/AI-020`, `AI-023`, `AI-024` and `AI-026`). Their logic passed synthetic tests run live in Splunk, but no validation tenant had the data they need, so none has fired on real activity. They are kept, not deleted, and are promoted once a customer environment proves them. Their `ai_mitre_mapping` rows were removed from the common lookup; the aggregator macros still list their detection IDs, which has no effect while they are not deployed.
  - `hdsi_ai_access_from_unmanaged_device`: on-network DNS plus an asset inventory of client IPs or guest/BYOD blocks.
  - `hdsi_ai_browser_extension_high_volume_data_transmission`: a proxy that logs destination host and request bytes.
  - `hdsi_ai_dlp_violation_on_service_upload`: an egress DLP/CASB incident feed in the `DLP` model.
  - `hdsi_ai_usage_from_personal_account_oauth_mismatch`: AI traffic attributed to users plus corporate SSO sign-ins.

### Added
- `saved_searches/reports/live_validation.md`: read-only live validation of all 50 searches (46 released, 4 incubating) on 4 production ES tenants (parse 189/189 searches and drilldowns per tenant; 200/200 real runs without errors), with per-search results, expected risk volumes and performance notes.
- `saved_searches/incubating/`: unreleased detections with a promotion checklist. `tools/render_live_spl.py` renders them for read-only tests; `tests/test_incubating.py` keeps them renderable and stops released packages from depending on them.
- **`tests/` validates the packages.**
  - Package layout and `package.yml` conventions.
  - Saved-search policy: hook macros, notable/risk role, literal risk scores, no underscore tokens, drilldown and annotation JSON, and Web `site` grouping.
  - Macros and lookups resolve within each package's prerequisite closure.
  - Lookup CSV schemas, and sync between hard-coded `tstats` lists and lookups.
  - MITRE mapping coverage.
  - Sample-event matching.
  - Repository hygiene: no customer identifiers, and no resurrected legacy app.
- **`saved_searches/tools/render_live_spl.py`.** Renders a package's search and drilldowns into self-contained SPL, with repo macros expanded and repo lookups inlined, for read-only testing on any ES search head without deploying.
- **`saved_searches/tools/audit_savedsearch_conformance.sh` rewritten.** It applies the release policy by package role across 12 checks: role-aware notable/risk, filter never piped, `risk_score` hook as last pipe, drilldown key schema, and more. It falls back to `grep -E` when `rg` is absent and takes an output directory argument.
- **CI.** It now runs `saved_searches/validate.py`, `pytest tests/` and `ruff check tests/`.

### Removed
- **The legacy monolithic app is retired.** `saved_searches/packages/` is the single source of truth. Removed:
  - `default/`:
    - `savedsearches.conf`, `macros.conf` and `transforms.conf`.
    - The KV store collections (`collections.conf`).
    - `eventtypes.conf` and `tags.conf`.
    - The 4 dashboards: `ai_rba_analytics`, `ai_rba_fp_tracker`, `ai_rba_health` and `ai_rba_lookup_health`.
  - The top-level `lookups/` directory (9 CSVs). The maintained copies live in `saved_searches/packages/hdsi_ai_rba_common/lookups/`.
  - `build/` and its `.spl` packaging output.

## [1.0.0] - 2026-02-13

### Added
- 20+ new detections across Shadow AI, Adversarial AI, and UEBA categories
- Consolidated web access detection (AI-028) replacing AI-001/002/003
- 3 new aggregate risk correlation rules (AI-RISK-003/004/005)
- UEBA behavioral baseline detections (AI-040 to AI-044)
- 4 new CSV lookups for expanded threat coverage
- Python test suite with 5 test modules
- CI/CD pipelines (GitHub Actions)
- 4 Splunk dashboards for health monitoring and analytics
- 23+ analyst runbooks
- Architecture documentation with Mermaid diagrams
- Tuning guide with per-threshold calibration
- Contributing guide for detection engineers
- Build/packaging system for .spl generation
- Health monitoring searches for lookup staleness and data model availability
- Kill chain phase tagging on all detections
- Risk multiplier macro for contextual scoring

### Changed
- Refined MITRE ATT&CK sub-technique mappings
- Enhanced ai_provider_domains.csv with threat intelligence columns
- Updated app.conf for Splunkbase readiness
- Improved risk scoring with contextual multipliers

### Deprecated
- AI-001, AI-002, AI-003 (consolidated into AI-028)

## [0.1.0] - Initial Release

### Added
- 21 individual AI usage detections
- 2 aggregate risk threshold searches
- 5 CSV lookup files
- 4 reusable macros
- README documentation
