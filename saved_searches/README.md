# HDSI AI RBA Packages

**Author:** Trevor Mock, Hurricane Labs LLC. Security Operations Architect

Every detection here is shipped as an independently deployable, versioned package in the soc-search-repo layout. `saved_searches/packages/` is the single source of truth. The old monolithic app was retired in 1.1.0 (see the [CHANGELOG](../CHANGELOG.md)). Nothing is generated from it, and the tests fail if it comes back.

The pack follows the risk-based alerting (RBA) model. Detections write risk events only. Five risk aggregators read the ES Risk data model and raise the notables analysts work.

## Package inventory

47 packages, all at `version: 1.1.0`, with 46 saved searches (the common package has none). Four more detections are held back in `saved_searches/incubating/` (see [Incubating packages](#incubating-packages)).

| Role | Name pattern | Count | `action.notable` | `action.risk` | Notes |
|---|---|---:|---:|---:|---|
| Common | `hdsi_ai_rba_common` | 1 | n/a | n/a | Shared macros (8) and lookups (10). No saved search. Deploy first. |
| Detection | `hdsi_ai_*` | 38 | 0 | 1 | Risk on `user` and/or `system`. 36 `global`, 2 `adhoc`. |
| Hunting | `hdsi_ai_unknown_high_volume_external_api_discovery` | 1 | 0 | 0 | `adhoc` review list for lookup gaps. Writes no risk and raises no notables. |
| Health | `hdsi_ai_health_*` | 2 | 1 | 0 | Audit-domain notables only. `action.email = 0`. |
| Risk aggregator | `hdsi_rba_ai_*` | 5 | 1 | 0 | The only packages that raise threat notables. |

Every package ships `enable_alerting: false`. Enabling a search in a customer tenant is a separate, approved change.

### Ad hoc packages

`deployment_type: adhoc` marks a rule that parses and runs everywhere but needs data most tenants do not have. Deploy it only where the README's prerequisite check passes.

| Package | Data it needs |
|---|---|
| `hdsi_ai_after_hours_service_usage` | A per-tenant business-hours clock (`_utc_offset`). It emits nothing until that is set. |
| `hdsi_ai_copy_paste_correlation_to_ai_service` | Browser paste audit events (enterprise browser) or DLP incidents. |
| `hdsi_ai_unknown_high_volume_external_api_discovery` | DNS or Web data and an analyst who owns the review. It is a hunting list, not RBA. |

All three produced real results on at least one validation tenant once their data or setting was in place.

### Incubating packages

`saved_searches/incubating/` holds detections that are **not released**. Their logic passed synthetic tests run through the real search in Splunk, but none of the four validation tenants had the data they need, so none has fired on real activity. They are kept, not deleted. Nothing in `packages/` depends on them, `validate.py` and `deploy.py` do not see them, and `tools/render_live_spl.py <package>` can still render them for a read-only test. Promote one by moving its folder into `packages/` once it produces real results in a customer environment; [incubating/README.md](incubating/README.md) has the checklist.

| Package | Data it needs |
|---|---|
| `hdsi_ai_access_from_unmanaged_device` | On-network DNS (resolvers or sensors, not cloud roaming agents) plus an asset inventory of client IPs or registered guest/BYOD address blocks. |
| `hdsi_ai_browser_extension_high_volume_data_transmission` | A forward proxy, SWG or SSE that writes destination host and request bytes to CIM Web. |
| `hdsi_ai_dlp_violation_on_service_upload` | An egress DLP/CASB incident feed in the CIM `DLP` model (`DLP_Incidents`) that names the destination. |
| `hdsi_ai_usage_from_personal_account_oauth_mismatch` | AI traffic attributed to users plus corporate SSO sign-ins to the provider, in the same tenant. |

## Package layout

```
saved_searches/
  packages/
    hdsi_ai_rba_common/              # DEPLOY FIRST
      confs/macros.conf              #   8 shared macros (ai_domains_filter, ai_unsanctioned_filter(3), ai_risk_multiplier, ...)
      confs/transforms.conf          #   10 lookup definitions
      lookups/                       #   10 CSVs (ai_provider_domains, ai_provider_apps, ai_sanctioned_entities, ...)
      package.yml
      README.md                      #   resolver contract and calling patterns for detection authors

    hdsi_ai_<name>/                  # detection, hunting or health package
      confs/savedsearches.conf       #   one saved search
      confs/macros.conf              #   _filter, _customizations, _risk_score + named thresholds
      package.yml                    #   version, deployment_type, tags, prereq_packages, data_prereqs
      README.md                      #   architect notes, tuning, live validation

    hdsi_rba_ai_<name>/              # risk aggregator over the Risk data model
      (same files)

  incubating/                        # unreleased detections (same layout, plus RUNBOOK.md); not deployed
  templates/template_package/        # starting point for a new package
  tools/                             # audit, renderer and maintenance scripts (below)
  validate.py  deploy.py  to_hec.py  extract_risk_params.py
  package-schema.yml  package_tags.csv  requirements.txt  .gitlab-ci.yml
```

`package.yml` declares the package's dependencies:

- `prereq_packages`: every package lists `hdsi_ai_rba_common`.
- `common_dependencies`: the shared macros and lookups the package uses.
- `data_prereqs`: the CIM data models, or copy-paste `tstats` checks, that the search needs. The CIM DLP model is `DLP` with dataset `DLP_Incidents`.

## Deployment order

1. **`hdsi_ai_rba_common`**. Every other package expands its macros. A `| lookup` on an undefined lookup is a fatal search error, so deploy every CSV with its `transforms.conf` stanza.
2. **Detections** (`hdsi_ai_*`) in any order. Deploy the `global` ones whose `data_prereqs` the tenant meets. Deploy `adhoc` ones only after their README check passes.
3. **Health checks** (`hdsi_ai_health_*`). These report missing or unaccelerated data models and stale or missing lookups for the AI-RBA rules that are enabled.
4. **Risk aggregators** (`hdsi_rba_ai_*`), once detections are writing risk events. Thresholds come from `ai_detection_config` (`medium_risk_threshold` 60, `high_risk_threshold` 90) and package macros.

> [!WARNING]
> A detection deployed without `hdsi_ai_rba_common` fails to expand its macros. All but one of them (`hdsi_ai_compromised_plugin_extension_installation`) call at least one of `ai_domains_filter`, `ai_unsanctioned_filter(3)`, `ai_process_filter` or `ai_risk_multiplier`.

## Conventions

These conventions apply to every package and are enforced by `validate.py`, the conformance audit and `tests/`.

### Naming

- Stanza: `[<Domain> - HDSI AI <Title> - Rule]`. Domain is one of `Network`, `Endpoint`, `Identity`, `Threat` or `Audit`. Aggregators are named `[Threat - HDSI RBA AI <Title> - Rule]`.
- `action.correlationsearch.label` is the stanza name without the domain and ` - Rule`.
- Each search sets `detection_id` to its package name. The aggregators select HDSI AI risk by `source="* - HDSI AI * - Rule"` or `detection_id="hdsi_ai_*"` and exclude the health checks.

### Search structure and hook macros

Every package ships these per-package hooks, so tenants can tune without editing `savedsearches.conf`:

| Macro | Ships as | Where it goes |
|---|---|---|
| `<pkg>_filter` | `()` | **Inline** in the first `tstats` `where` clause or base search, using data-model field names (`DNS.src`, `Web.user`, `Processes.dest`). Never piped: `| ()` is a fatal parse error, and it broke all 50 searches in 1.0.0. |
| `<pkg>_customizations` | `search *` | Piped after normalisation and aggregation. Used for tenant exclusions on output fields and enrichment. |
| `<pkg>_risk_score` | `search *` | The **last pipe** of every risk-writing search. Adjusts or overrides `risk_score` (integer, at most 100). Not present on aggregators or health checks. |

Most packages also ship named threshold and scope macros (`_min_queries`, `_upload_mb`, `_excluded_accounts`, ...). The package README's **Tuning macros** table lists them with the shipped value and how to derive a tenant value.

Example: exclude the DNS forwarders from the DNS detection. Because the filter is inline in `tstats`, it uses `DNS.*` field names.

```
[hdsi_ai_dns_queries_to_ai_domains_filter]
definition = NOT DNS.src IN ("10.1.1.10","10.1.1.11")
```

### Risk and notables

- Detections: `action.notable = 0` and `action.risk = 1`. They keep all `action.notable.param.*` lines (`rule_title`, `rule_description`, `security_domain`, `severity`, drilldowns) so each risk event carries analyst context.
- Aggregators: `action.notable = 1` and `action.risk = 0`. Health checks: an audit-domain notable, no risk and no email.
- Every `action.risk.param._risk` entry has a **literal integer** `risk_score`. ES does not support `$token$` scores there. The literal is the fallback score.
- Dynamic scoring sets a numeric field named `risk_score` in SPL, capped with `min(<cap>, ...)`. It applies to every risk object in the row. Per-event caps are 30-80, so a single event does not escalate a user on its own; the aggregators decide that.
- Context multipliers come from `ai_risk_multiplier`, which outputs `risk_multiplier`. It applies identity `bunit` sensitivity, × 1.25 for privileged identities, and is capped at 2.0. Provider `severity_weight` comes from the registry.
- No risk object may be `unknown`, `-` or empty. Rules that score people null out machine (`$`), service and built-in accounts.
- `_risk_message`, `rule_title` and `rule_description` never use `$_field$` tokens, because ES drops fields that start with `_`.

### Drilldowns, scheduling and metadata

- Drilldowns use `earliest_offset`/`latest_offset` keys and `drilldown_dashboards = []`.
  - Risk drilldowns: `| from datamodel:"Risk.All_Risk" | search risk_object=...`. The 1.0.0 `from ... where` form was fatal.
  - Web drilldowns: `where (Web.url_domain=* OR Web.site=*) ... by ... Web.url_domain Web.site`, followed by `eval url_domain=coalesce(url_domain,site)`.
- Cron and dispatch windows are paired:

  | Schedule | Dispatch window |
  |---|---|
  | Every 5 min | `-15m@m` to `-5m@m` |
  | Every 15 min | `-20m@m` to `-5m@m` |
  | Hourly | `-65m@m` to `-5m@m` |
  | Daily or weekly | `@d` windows |

  Cron minutes are offset to spread load.
- `alert.suppress.fields` names the risk object fields. `alert.suppress.period` uses the seconds form (for example `86400s`).
- `action.correlationsearch.annotations` is valid JSON with 1-4 current MITRE ATT&CK IDs, and it matches the `mitre_attack` value set in the SPL. Acquisition of AI tooling maps to T1588.007.
- Versioning:
  - `package.yml`: `version: 1.1.0`.
  - Saved search `description`: starts with `v1.1.0 `.
  - Macro `description`: starts with `v1.1 `, followed by why the macro exists.
- `tags` must exist in `package_tags.csv`.

### Package README structure

Each package README follows the same outline:

1. **Architect Notes**, with the author line.
2. Prerequisites.
3. How it works.
4. Tuning macros.
5. Threshold, with copy-paste SPL to derive a tenant value.
6. Known false positives / Limitations.
7. Validation (Tenant A-D results).
8. Deployment.

## Validation tooling

Run these from the repository root unless noted.

| Tool | What it checks | Run |
|---|---|---|
| `saved_searches/validate.py` | `package.yml` against `package-schema.yml`. Tags are registered, conf files parse, prerequisite packages exist, and stanzas have no stray spaces or trailing backslashes. Exit 0 with no output = pass. | `cd saved_searches && uv run --offline --no-project --script validate.py` |
| `saved_searches/tools/audit_savedsearch_conformance.sh` | Role-aware release policy for every saved search, 12 checks (table below). Writes `savedsearch_conformance.{json,md}`. Exit 0 = every search conforms. | `saved_searches/tools/audit_savedsearch_conformance.sh [OUT_DIR]` (default `saved_searches/reports/`) |
| `tests/` (pytest) | Package layout and metadata; saved-search policy (hooks, notable/risk role, literal scores, no underscore tokens, drilldown and annotation JSON, Web `site` grouping). Also: macros and lookups resolve within each package's prerequisite closure and render cleanly; lookup CSV schemas; hard-coded `tstats` lists stay in sync with lookups; MITRE mapping coverage; sample-event matching; no customer identifiers; legacy app stays retired. | `pytest tests/` |
| `saved_searches/tools/render_live_spl.py` | Renders a package's search (and `--drilldowns`) into self-contained SPL. Repo macros are expanded and repo lookups inlined as `makeresults`, so the SPL can be pasted into any ES search head for a read-only test without deploying. ES lookups and `cim_*` macros are left for the search head. | `python3 saved_searches/tools/render_live_spl.py <package> [--drilldowns]` or `--all --json --earliest -24h` |
| `saved_searches/tools/check_repo_bones.py` | The soc-search-repo scaffolding files are present. | `cd saved_searches && uv run tools/check_repo_bones.py` |

GitHub CI (`.github/workflows/ci.yml`) runs `validate.py`, `pytest tests/` and `ruff check tests/`. `saved_searches/.gitlab-ci.yml` runs the repo-bones check and `validate.py`, then deploys with `deploy.py`.

The runbook-coverage test (`tests/test_runbook_coverage.py`) checks that every detection, hunting search and aggregator package is named in a runbook under `docs/runbooks/`; all 44 cases pass. Runbook file names keep the `AI-0xx` runbook IDs; each runbook header names its package and search. Incubating packages keep their runbook beside them as `RUNBOOK.md`, and `tests/test_incubating.py` checks that they still render and that no released package depends on them.

### Conformance audit

Audit run of 2026-10-10: 46 searches audited, 46 fully conformant.

| Check | Passed |
|---|---:|
| `action.notable` matches role (detection 0, aggregator 1, health/hunting exempt) | 46/46 |
| `action.risk` matches role (detection 1, aggregator 0, health/hunting exempt) | 46/46 |
| Notable `rule_description` present | 46/46 |
| Risk message present (when `action.risk = 1`) | 46/46 |
| Risk objects present (when `action.risk = 1`) | 46/46 |
| Drilldown searches present | 46/46 |
| `drilldown_dashboards` line present | 46/46 |
| Drilldown keys use `earliest_offset`/`latest_offset` | 46/46 |
| Search enabled by default (`disabled = 0`) | 46/46 |
| `risk_object_type` in {`user`, `system`} | 46/46 |
| `<pkg>_filter` referenced inline, never piped | 46/46 |
| `<pkg>_risk_score` is the last pipe (when `action.risk = 1`) | 46/46 |

The roles are assigned by package name and `package.yml`: `hdsi_ai_health_*` is health and `hdsi_rba_ai_*` is aggregator. An `adhoc` package with `action.risk = 0` is hunting. Everything else is a detection.

## Live validation

Each package was tested read-only against 4 production Splunk ES tenants (Splunk Cloud 10.4-10.5, ES 8.5-8.7), referred to only as Tenants A-D. The tests used ordinary search jobs; no configuration was written. On 2026-10-09, all 50 searches of that build (the 46 released here plus the 4 now incubating) and all 139 drilldowns, rendered with `render_live_spl.py`, parsed on all four tenants. Each package README's **Validation** table records its real-run results: rows in the scheduled window, runtime and field fill.

What the tenants showed, and what it means for deployment:

| Data | What was seen | Impact |
|---|---|---|
| DNS (`Network_Resolution`) | AI queries present on all 4 tenants, sparse on one. One tenant logs names with a trailing dot (`chatgpt.com.`). | The most portable AI-usage signal. The resolver strips trailing dots. |
| Web | Varied by tenant: firewall URL logs with `url_domain` but no `site`; SSE logs with an app name in `site` and no `url_domain`; mostly inbound load-balancer/WAF or IIS logs on two tenants. | Web rules group by `url_domain` and `site`, resolve app names through `ai_provider_apps`, and exclude inbound server logs. They cannot fire where no user egress is logged. |
| Endpoint | Processes on all tenants (small on two). Filesystem and Ports sparse. | Process rules deploy fine. Port and file rules are low-yield where those datasets are thin. |
| DLP | No `DLP` model data on any tenant. | DLP rules are `adhoc` or rely on vendor-specific sources. Each README gives the exact feed. |
| Identity | ES identities have no `department` field. `bunit` is often sparse. | `ai_risk_multiplier` keys on `bunit` and falls back to 1.0. |

## Related documentation

- [Common package README](packages/hdsi_ai_rba_common/README.md): provider resolver contract, allowlist keys, lookups and calling patterns.
- [Template package](templates/template_package/): starting point for a new detection.
- [Changelog](../CHANGELOG.md): 1.1.0 release notes.
- [Main README](../README.md): project overview.
- [Architecture](../docs/ARCHITECTURE.md), [Tuning Guide](../docs/TUNING_GUIDE.md) and [Contributing](../docs/CONTRIBUTING.md).
