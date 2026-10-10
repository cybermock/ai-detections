# Contributing Guide

**Author:** Trevor Mock, Hurricane Labs LLC. Security Operations Architect

This guide covers how to add or change HDSI AI RBA content. Each detection is a package under `saved_searches/packages/`, built to the soc-search-repo gold package conventions. This guide is written for detection engineers who build and tune ES correlation searches. Read [ARCHITECTURE.md](ARCHITECTURE.md) for how the parts fit together, and use [DETECTION_TEMPLATE.md](DETECTION_TEMPLATE.md) as the copy-paste starting point.

## Setup

- Python 3.11 or later. `validate.py` and `tools/render_live_spl.py` are `uv` inline-metadata scripts and declare `>=3.11`. CI uses 3.12.
- [`uv`](https://docs.astral.sh/uv/) (recommended), or `pip`.
- Read-only search access to at least one Splunk ES 8 search head, for live testing.

```bash
cd splunk-es-ai-rba
pip install -r requirements.txt -r saved_searches/requirements.txt   # pytest, pyyaml, ruff, validate.py deps
```

### Repository layout

```
splunk-es-ai-rba/
├── saved_searches/
│   ├── packages/                  # THE deployable content: 47 packages
│   │   ├── hdsi_ai_rba_common/    #   shared macros, lookups/ (10 CSVs), transforms.conf
│   │   ├── hdsi_ai_<name>/        #   38 detections, 2 health checks (hdsi_ai_health_*), 1 hunting search
│   │   └── hdsi_rba_ai_<name>/    #   5 risk aggregators
│   ├── templates/template_package/  # upstream soc-search-repo skeleton
│   ├── tools/
│   │   ├── render_live_spl.py     # render a package into self-contained SPL for read-only live tests
│   │   ├── audit_savedsearch_conformance.sh  # release-convention audit -> reports/
│   │   ├── collect_tags.py, check_repo_bones.py, apply_audit_fixes.py, delete_splunk_package.py
│   ├── validate.py                # soc-search-repo package validator (schema, tags, deps, conf syntax)
│   ├── package-schema.yml         # package.yml JSON schema
│   ├── package_tags.csv           # allowed package tags
│   └── deploy.py, to_hec.py, extract_risk_params.py   # soc-search-repo pipeline scripts
├── tests/                         # pytest suite that validates the packages
├── docs/                          # ARCHITECTURE, TUNING_GUIDE, this file, DETECTION_TEMPLATE, runbooks/
├── CHANGELOG.md
└── README.md
```

Packages are the single source of truth. The legacy monolithic app was retired in 1.1.0 (see the [CHANGELOG](../CHANGELOG.md)). Do not recreate it: `tests/test_repo_hygiene.py::test_legacy_app_retired` fails if top-level app directories come back.

## Adding a detection

### 1. Prove the data path first

Before writing logic, measure what the target data really looks like in the validation tenants. Use read-only `tstats` counts and field fill rates over a short window. The four validation tenants differ a lot (see [ARCHITECTURE.md](ARCHITECTURE.md#data-realities-that-shaped-the-design)). Typical surprises:

- `Web.url_domain` is empty while `Web.site` carries an SSE application name.
- Web data is inbound server traffic, not user egress.
- DNS answers carry a trailing dot (`chatgpt.com.`).
- Roaming DNS-security clients report home-router addresses as `src`.
- `identity_lookup_expanded` has no `department` field.
- No tenant has DLP data.

Where a detection lands depends on what the live tests proved:

- **`global`**: it ran on real data on at least one validation tenant, and its data is common.
- **`adhoc`**: it produced real results on at least one tenant, but needs data or setup most tenants lack. The README states the exact requirement.
- **Incubating** (`saved_searches/incubating/<package>/`, not released): no tenant had its data, so it is proven only with synthetic test events. Keep its runbook beside it as `RUNBOOK.md`. Promote it to `packages/` once a customer environment produces real results; see `saved_searches/incubating/README.md`.

Never delete a weak rule.

### 2. Create the package

Copy the skeleton from [DETECTION_TEMPLATE.md](DETECTION_TEMPLATE.md). Naming:

| Thing | Convention | Example |
|---|---|---|
| Package / `detection_id` | `hdsi_ai_<snake_case_title>`; aggregators `hdsi_rba_ai_<...>` | `hdsi_ai_mcp_server_execution` |
| Stanza | `[<Domain> - HDSI AI <Title> - Rule]`; aggregators `[Threat - HDSI RBA AI <Title> - Rule]` | `[Endpoint - HDSI AI MCP Server Execution - Rule]` |
| Label | Stanza without the domain and ` - Rule` | `HDSI AI MCP Server Execution` |
| `rule_title` | `HDSI AI <Title> (<$token$ ...>)` | `HDSI AI DNS Queries To AI Domains ($src$)` |
| Macros | `<package>_<purpose>` | `hdsi_ai_mcp_server_execution_filter` |
| Fields | CIM names (`user`, `src`, `dest`, `process_name`); AI fields `provider`, `usage_type`, `severity_weight`, `risk_multiplier`, `ai_activity`, `ai_kill_chain_phase`, `detection_id`, `mitre_attack` | |

Use only the current `HDSI AI` names in searches, macros, risk sources and drilldowns. The 1.0 saved-search names are retired. The `AI-0xx` numbers survive only as analyst runbook IDs under `docs/runbooks/`; never put them in a stanza, label or `detection_id`.

### 3. Write the search to the gold conventions

The template lists every rule. These are the ones that break searches or mislead analysts when they are missed:

| Convention | Requirement | Enforced by |
|---|---|---|
| **Filter inline** | `` `<pkg>_filter` `` (ships `()`) goes inside the first `tstats ... where` clause or base search, with data model field names. Never piped: `\| ()` is fatal. | `test_filter_macro_inline_not_piped`, audit script |
| **Customizations** | `` \| `<pkg>_customizations` `` (ships `search *`) piped after normalisation and scoring. | `test_customizations_macro_piped` |
| **`risk_score` last** | `` \| `<pkg>_risk_score` `` (ships `search *`) is the last pipe of every search with `action.risk = 1`. | `test_risk_score_macro_is_last_pipe`, audit script |
| **Notable/risk policy** | Detections `action.notable = 0`, `action.risk = 1`, all `action.notable.param.*` lines kept. Aggregators `1`/`0`. Health checks: audit-domain notable, no risk, `action.email = 0`. Hunting (adhoc, no risk): exempt. | `test_notable_risk_policy`, audit script |
| **Risk JSON** | `_risk` entries carry a literal integer `risk_score` from 1 to 100 and `risk_object_type` `user`/`system`. Dynamic scoring means a numeric SPL field named `risk_score`, capped with `min()`. | `test_risk_action_params` |
| **No `_` tokens** | No `$_field$` in `_risk_message`, `rule_title`, `rule_description` or drilldowns. ES drops fields that start with `_`. | `test_no_underscore_tokens_in_analyst_text` |
| **`detection_id`** | `detection_id="<package name>"` in the SPL. | `test_detection_id_matches_package` |
| **Version prefix** | `package.yml` `version: 1.1.0`; saved-search `description = v1.1.0 ...`; macro `description = v1.1 ...`. | `test_package_version`, `test_description_starts_with_version` |
| **Web fields** | Group `by ... Web.url_domain Web.site`, in drilldowns too; `fillnull_value="unknown"`; resolve `coalesce(url_domain, site)`. | `test_web_search_groups_by_site`, `test_web_drilldowns_group_by_site` |
| **Risk drilldowns** | `\| from datamodel:"Risk.All_Risk" \| search ...`, never `from ... where`. Drilldown JSON has `name`, `search`, `earliest_offset`, `latest_offset`. | `test_drilldown_schema` |
| **MITRE** | `action.correlationsearch.annotations = {"mitre_attack": [...]}`, valid JSON, 1-4 current IDs, matching the SPL `mitre_attack` eval and `ai_mitre_mapping.csv`. | `test_annotations`, `tests/test_mitre_coverage.py` |
| **CIM names** | `datamodel=Endpoint.Processes`, never bare `Endpoint`; `DLP.DLP_Incidents`, never `Data_Loss_Prevention`. | `test_search_datamodels_are_cim`, `test_data_prereq_datamodels_are_cim` |
| **References resolve** | Every macro and lookup resolves within the package and its `prereq_packages`. Lookup key and OUTPUT fields exist in the CSV. No `\| \|` after macro expansion. | `tests/test_spl_references.py` |
| **Pre-filter lists in sync** | Hard-coded tstats `IN (...)` lists contain only enabled lookup values. | `tests/test_lookup_sync.py` |

#### Risk scoring

- Score per event, not per verdict. The user aggregators raise a medium notable from 60 points (with at least 2 detections) and a high notable from 90 points in 24 hours, so one detection should not reach 90 alone.
- `risk_score = min(<cap>, max(<floor>, round(<base> x severity_weight x risk_multiplier)))`. The dynamic score applies to **every** risk object in the row. If the user and the host need different scores, keep static `_risk` integers.
- Never emit a risk object that is `unknown`, empty, a placeholder or a shared address (resolver, NAT egress, proxy, shared jump host). Drop the row, or leave that field null.

| Evidence class | Typical base (user) | Cap | Examples |
|---|---|---|---|
| Presence (DNS, web visit, first-seen, timing) | 10-20 | 30-40 | `dns_queries_to_ai_domains` 10/30, `unsanctioned_web_access` 15/30, `first_seen_provider_for_user` 20/40 |
| Tool execution or API use | 20-40 | 50-60 | `unsanctioned_desktop_app_execution` 20/50, `mcp_server_execution` 30/60, `api_access_from_non_dev_endpoint` 24/50 |
| Data movement | 20-60 | 60-80 | `high_volume_upload_to_ai_service` 20/80, `suspicious_model_file_exfiltration` 40/70, `gradual_data_exfiltration_via_ai` 25/60 |
| Adversarial or credential exposure | 40-60 | 70-80 | `api_key_exposure_in_code_dlp` 50/80, `deepfake_tool_execution_access` 40/80, `assisted_lateral_movement` 50 (70 with offensive tooling) |

#### Performance

- `tstats summariesonly=t allow_old_summaries=t` on accelerated models. Use `summariesonly=false` only for models that are rarely accelerated (DLP), and only with narrow `where` clauses.
- Scope the `where` clause. On Tenant A a 1-hour Web `tstats` grouped by domain took 73 s unscoped and 4 s with a 7-host `IN (...)` scope. Generate scope lists from the common registries and keep them wide (wildcards). The common macros make the exact match.
- Resolve DNS on distinct `query` values, not on `src x query` rows. On the tenant with about 1.1B DNS queries a day, resolving a `src x query` table for 4 hours took 250-270 s, close to the scheduler cap. Resolving distinct queries for 1 hour took 25 s.
- Give every `append` subsearch `maxtime` and `maxout`, or use chained `tstats prestats=t append=t`.
- Baselines longer than 7 days with `summariesonly=t` are cut short where a tenant accelerates only one week.

### 4. Live-test it (read-only)

`saved_searches/tools/render_live_spl.py` turns a package into one self-contained search that runs on any ES search head **without deploying anything**:

- Macros from the package and its `prereq_packages` are expanded, including argument macros. `cim_*` and ES macros are left for the search head.
- Every repo lookup (any CSV under a package's `lookups/`) is inlined as a case-insensitive `makeresults format=csv` join. ES lookups (`identity_lookup_expanded`, `asset_lookup_by_*`) are left as they are.

```bash
cd saved_searches
python3 tools/render_live_spl.py hdsi_ai_<name>                  # the rule, ready to paste into Search
python3 tools/render_live_spl.py hdsi_ai_<name> --drilldowns     # plus every drilldown search
python3 tools/render_live_spl.py --all --json --earliest -4h@m --latest -5m@m > batch.json   # batch for a scripted runner
```

A scripted runner can submit the JSON batch through the read-only search jobs API (`/services/search/jobs/export`). Test protocol:

1. **Parse everything first,** the rule and every drilldown, on every tenant. A parse failure on one tenant (a missing ES lookup field, a macro the tenant lacks) is a deployment blocker for that tenant.
2. **Run the rule over its own window,** widened for short-cadence rules: 5-, 15- and 60-minute rules over the last 4 hours (`-4h@m` to `-5m@m`) so there is signal; daily rules over one `-1d@d` to `@d` day. Keep each job under about 120-300 s, and avoid multi-week backtests on production tenants.
3. **Judge the output,** not just the row count. Are the risk objects real people or hosts (no placeholders, resolvers or shared addresses)? Do the scores stay inside the cap? Are the fields used in `_risk_message` filled? Run the drilldowns with values from a real row.
4. **Derive thresholds** from the tenant's own distribution (for example p95/p99 per entity per window) with a copy-paste SPL that applies the same scope and exclusions as the rule. Put it in the README under **Threshold**.

Live-test rules:

- **Read-only.** Never `outputlookup`, `collect`, `sendalert`, `| delete`, REST POST or anything else that writes.
- **Anonymise.** Refer to environments only as "Tenant A-D" (or "4 production ES tenants"). Never copy customer names, hostnames, usernames, internal domains, IP addresses or sample rows into the repo. Aggregate counts, field fill rates, runtimes and public AI provider names are fine. `tests/test_repo_hygiene.py` scans `saved_searches/`, `docs/` and `README.md` for known identifiers.

### 5. Write the README

Every package README follows the gold structure in [DETECTION_TEMPLATE.md](DETECTION_TEMPLATE.md#readmemd-gold-structure):

1. `## Architect Notes`, `---`, then the author line `**Author:** Trevor Mock, Hurricane Labs LLC. Security Operations Architect`.
2. A 2-4 sentence summary: what it detects, why it matters, what it emits.
3. `### Prerequisites`
4. `### How it works`
5. `### Tuning macros` (table: Macro, Ships as, Purpose)
6. `### Threshold` (if any)
7. `### Known false positives / Limitations`
8. `### Validation` (dated table of the Tenant A-D results)
9. `### Deployment`

Keep claims evidence-based. Every number in the README should come from a live test or from the confs.

### 6. Wire it into the rest of the content

- **Multi-vector aggregator.** Add the package to the right vector in `hdsi_rba_ai_multi_vector_risk_vector_map` (`shadow_usage`, `usage_anomaly`, `local_tooling`, `risky_access`, `data_exposure`, `adversarial`). Otherwise it falls back to its `ai_kill_chain_phase`.
- **Kill-chain aggregator.** If the detection is evidence of data collection or of upload, add it to `hdsi_rba_ai_data_collection_kill_chain_collection_detections` or `_exfil_detections`.
- **Privilege-escalation aggregator.** This one reads `ai_kill_chain_phase`. Exclude the detection in `_ai_excluded_detections` if it is itself about privilege (as `hdsi_ai_privileged_account_service_usage` is).
- **`ai_mitre_mapping.csv`** (common package). Add one row per technique, keyed by package name.
- **Runbook.** Add or update an analyst runbook under `docs/runbooks/` (start from `_runbook_template.md`) that names the package, stanza or label.
- **Top-level `README.md`** detection inventory and **`CHANGELOG.md`**.

### 7. Validate and test

```bash
cd saved_searches
uv run --offline --no-project --script validate.py      # exit 0 and no output = pass
bash tools/audit_savedsearch_conformance.sh              # writes reports/savedsearch_conformance.{json,md}; exit 0 = all conform
cd ..
python -m pytest tests/                                  # or: uv run --with pytest --with pyyaml python -m pytest tests
ruff check tests/
```

CI (`.github/workflows/ci.yml`) runs `validate.py`, `pytest tests/` and `ruff check tests/` on every push and pull request to `main`.

| Test module | What it checks |
|---|---|
| `test_package_structure.py` | Required files, one saved search per package, release version and description prefix, metadata, `prereq_packages` (must include the common package), registered tags, resolvable `common_dependencies`, CIM data model names, name prefixes |
| `test_savedsearch_policy.py` | Hook macro placement, notable/risk policy by role, scheduling fields and cron syntax, risk JSON, `detection_id`, `_` tokens, drilldown schema, Web `site` grouping, MITRE annotations, health-check email token |
| `test_spl_references.py` | Macros and lookups resolve in the package closure, lookup fields exist, rendered SPL is clean, balanced delimiters, no `\| \|`, no bare `Endpoint` model |
| `test_csv_schema.py` | Every common CSV has a `transforms.conf` stanza, is well formed, has its core columns and valid `enabled` values |
| `test_lookup_sync.py` | Hard-coded tstats pre-filter lists match enabled lookup rows; pattern detections stay lookup-driven |
| `test_mitre_coverage.py` | `ai_mitre_mapping.csv` keys are packages, every detection is mapped, mappings agree with the annotations |
| `test_sample_events.py` | Sample domains, processes, API keys, prompt injections and deepfake tools match the lookups and macros |
| `test_runbook_coverage.py` | Every detection, hunting search and aggregator is named in a runbook (currently `xfail` while the runbooks are rewritten) |
| `test_repo_hygiene.py` | No customer identifiers; the legacy app stays retired |

## Changing the common package

`hdsi_ai_rba_common` changes what **every** dependent detection reports. Treat a lookup edit like a detection change.

- **Provider names are join keys.** `ai_sanctioned_entities`, `provider IN (...)` exclusion macros and risk messages all compare the `provider` string. Rename a provider only together with every reference to it.
- **`usage_type` vocabulary** (`web`, `api`, `ide`, `cli`, `local_llm`, `model_registry`; processes also use `desktop_app`) is fixed. Detections filter on these values.
- **After adding registry rows,** regenerate the detections' pre-filter lists (the DNS query pre-filter, Web scope macros, process `IN` lists). Rows that a pre-filter does not cover are never seen. `tests/test_lookup_sync.py` catches the reverse case, a list value that is not in the lookup.
- **New lookup:** add the CSV under `hdsi_ai_rba_common/lookups/` (lowercase snake_case name with the `ai_` prefix, UTF-8, header row, an `enabled` 0/1 column for toggleable rows, a `last_verified` column for curated lists) and its `transforms.conf` stanza (`case_sensitive_match = false`). Add core columns to `tests/test_csv_schema.py`, and add the lookup to the staleness health check's curated list if it needs review.
- **New shared macro:** a `v1.1` description that states the input and output contract, and a section in the common README. Callers list it in `common_dependencies`.
- Update the common README's **Lookups** and **Validation** sections.

## Pull request checklist

- [ ] The data path was measured on the validation tenants; `deployment_type` and `data_prereqs` match what was found. A rule that never ran on real data goes to `saved_searches/incubating/`, not `packages/`.
- [ ] Stanza, label, `rule_title`, macros and `detection_id` follow the naming conventions; no `AI-0xx` names.
- [ ] `_filter` inline, `_customizations` piped, `_risk_score` the last pipe.
- [ ] `action.notable = 0`, `action.risk = 1`, all `action.notable.param.*` lines kept, `enable_alerting: false`.
- [ ] Literal integer `_risk` scores; dynamic `risk_score` capped; no placeholder or shared risk objects; no `$_x$` tokens.
- [ ] Version `1.1.0`, `v1.1.0` description prefix, `v1.1` macro descriptions that state why each default was chosen.
- [ ] MITRE annotation valid and consistent with the SPL `mitre_attack` value and `ai_mitre_mapping.csv`.
- [ ] Rendered with `render_live_spl.py`. The rule and every drilldown parse on Tenants A-D, a real run was reviewed, and the threshold was derived from tenant data.
- [ ] README in the gold structure with a dated, anonymised Validation table.
- [ ] Aggregator mappings, runbook, top-level README and CHANGELOG updated.
- [ ] `validate.py` exits 0; the conformance audit exits 0; `pytest tests/` and `ruff check tests/` pass.
- [ ] No customer identifiers anywhere in the diff.
