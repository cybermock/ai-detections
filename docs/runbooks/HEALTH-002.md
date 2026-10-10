# HEALTH-002 - AI Health Lookup Staleness Alert

> **Detection ID:** HEALTH-002 (health check; no `AI-0xx` detection ID)
> **Package:** `hdsi_ai_health_lookup_staleness_alert` (v1.1.0, deployment type `global`, ships `enable_alerting: false`)
> **Search name:** `Audit - HDSI AI Health Lookup Staleness Alert - Rule`
> **Status:** Active (audit notable: `action.notable = 1`, `security_domain = audit`; `action.risk = 0`; `action.email = 0`)
> **Risk Score:** none. Notable severity by status: high (`MISSING_DEFINITION`, `MISSING_FILE`, `EMPTY`, `INVALID_CONTROLS`), medium (`STALE`, `EXPIRED_ENTRIES`), low (`MISSING_CONTROLS`, `EXPIRING_ENTRIES`)
> **MITRE ATT&CK:** none (content health, no annotation)
> **Data Model:** none. Splunk REST (`data/transforms/lookups`, `data/lookup-table-files`, `saved/searches`) and `inputlookup`
> **Schedule:** `15 9 * * *` (daily at 09:15)
> **Lookback Window:** `-1d@d` to `@d` (not time-dependent: REST and lookups)
> **Suppression:** 6 days (`518400s`) on `lookup_name,status`
> **Kill Chain Phase:** N/A (excluded from every AI risk aggregator)
> **Last Updated:** 2026-10-09

---

## Overview

This daily audit health check watches the lookups that the HDSI AI-RBA detections read. Those lookups ship in the common package `hdsi_ai_rba_common`. It raises one audit notable per lookup and status when:

- a lookup is **missing** (definition or file). Every detection that reads it stops with a FATAL `lookup` error and writes no risk;
- a curated list (provider domains, provider apps, AI tool processes, API-key patterns, prompt-injection patterns) is **empty**, or has **not been reviewed for 90 days**, so detections miss new AI domains, apps or tools;
- the two `ai_detection_config` rows the user risk aggregators read (`medium_risk_threshold`, `high_risk_threshold`) leave the medium band **empty or start at zero**, or are **missing or not numeric**, so the aggregators silently fall back to their defaults (60 and 90);
- an approved exemption in `ai_sanctioned_entities` has **expired** or expires within 14 days.

A notable is created only when at least one HDSI AI-RBA detection or aggregator is enabled and scheduled on the search head. The check creates no risk and sends no email. The audience is the content owner or Splunk/ES engineer, not a Tier 1 analyst: every finding is a configuration task.

---

## MITRE ATT&CK Mapping

| Field | Value |
|---|---|
| Technique ID | N/A |
| Technique Name | N/A (detection content health) |
| Tactic | N/A |
| Sub-technique | N/A |

`action.correlationsearch.annotations = {}`. Health checks map to no aggregator vector and are excluded from every `HDSI RBA AI` aggregator.

---

## Detection Logic

### Plain English

1. Build the expected lookup list from two macros. **Curated** (`_curated_lookups`): `ai_provider_domains`, `ai_provider_apps`, `ai_tool_processes`, `ai_api_key_patterns`, `ai_prompt_injection_patterns`, checked for presence, content and age. **Config** (`_config_lookups`): `ai_sanctioned_entities`, `ai_department_sensitivity`, `ai_detection_config`, checked for presence, plus expiry for `ai_sanctioned_entities` and the threshold controls for `ai_detection_config`.
2. Read lookup definitions from REST `data/transforms/lookups` (titles starting `ai_`).
3. Run `content_stats(<lookup>)` on each lookup: row count, enabled rows, newest `last_verified`, rows unverified for 90 days, and expired or expiring `expires` entries.
4. Join each definition to its file from REST `data/lookup-table-files`. The file `updated` time is parsed with its UTC offset; an epoch-0 time means "not reported" and is ignored.
5. For `ai_detection_config`, compute the effective `medium_risk_threshold` and `high_risk_threshold` (row value, or default 60/90).
6. Count enabled, scheduled saved searches whose title matches the case-sensitive regex `HDSI (RBA )?AI ` (health checks excluded). REST is read unfiltered and filtered with `where match()`, because REST's `search="title=*...*"` argument returns nothing on Splunk Cloud.
7. Set `status` in priority order: `MISSING_DEFINITION` → `MISSING_FILE` → `EMPTY` → `INVALID_CONTROLS` → `MISSING_CONTROLS` → `STALE` → `EXPIRED_ENTRIES` → `EXPIRING_ENTRIES` → `AGE_UNKNOWN` → `OK`.
8. Raise a notable (`alert=1`) when the status is not `OK` or `AGE_UNKNOWN` and `enabled_ai_rules > 0`.

### Key Fields

| Field | Description | Example Value |
|---|---|---|
| `lookup_name` | Lookup the finding is about (suppression key) | `ai_tool_processes` |
| `status`, `severity`, `reason` | Finding, notable severity and a readable explanation | `STALE`, `medium`, `the newest review date is ...` |
| `age_days`, `last_reviewed_date`, `review_source` | Age of the newest review and where it came from | `12`, `2026-09-28`, `last_verified column` |
| `newest_verified_date`, `last_file_update` | Newest `last_verified`; file time or "not reported" | `2026-09-28`, `not reported` |
| `content_rows`, `enabled_rows`, `verified_rows`, `stale_rows` | Content facts | `109`, `109`, `109`, `55` |
| `expired_enabled`, `expiring_enabled` | Sanctioned entries past or near `expires` | `1`, `0` |
| `missing_controls_count`, `missing_controls`, `medium_risk_threshold`, `high_risk_threshold` | Threshold control facts (`ai_detection_config` only) | `0`, -, `60`, `90` |
| `def_app`, `file_app`, `file_key` | Apps holding the definition and file | `HurricaneLabsContentUpdates` |
| `enabled_ai_rules` | Enabled, scheduled HDSI AI-RBA rules (alert gate) | `14` |
| `max_age_days`, `stale_row_pct` | Thresholds in force | `90`, `50` |

### Thresholds

| Parameter | Default | Macro | Notes |
|---|---|---|---|
| Review age | 90 days | `hdsi_ai_health_lookup_staleness_alert_max_age_days` | Newest review date of a curated lookup |
| Stale share | 50% | `hdsi_ai_health_lookup_staleness_alert_stale_row_pct` | STALE when more than this % of enabled rows are older than the limit |
| Expiry warning | 14 days | `hdsi_ai_health_lookup_staleness_alert_expiry_warn_days` | `EXPIRING_ENTRIES` window |
| Required controls | `medium_risk_threshold,high_risk_threshold` | `hdsi_ai_health_lookup_staleness_alert_required_controls` | Rows that shipped searches read |
| Alert gate | `"HDSI (RBA )?AI "` | `hdsi_ai_health_lookup_staleness_alert_rule_title_regex` | Case-sensitive title regex |

---

## Triage Steps

> **Estimated triage time:** 5-15 minutes. Replace `$lookup_name$` with the value from the notable.

### Step 1: Read the notable

```spl
`notable`
| search source="Audit - HDSI AI Health Lookup Staleness Alert - Rule"
| table _time lookup_name status severity reason age_days last_reviewed_date enabled_rows stale_rows expired_enabled expiring_enabled missing_controls medium_risk_threshold high_risk_threshold enabled_ai_rules
| sort - _time
```

- `reason` states the problem and its effect on the detections. Several notables on the same day (one per lookup) usually share one cause, for example the common package missing or not shared to the app.

### Step 2: Check lookup definitions, files and file times

```spl
| rest /servicesNS/-/-/data/transforms/lookups splunk_server=local count=0
| where match(title,"^ai_")
| eval lookup_name=title, file_key=lower(filename), def_app='eai:acl.app', sharing='eai:acl.sharing'
| fields lookup_name def_app sharing file_key collection
| join type=left max=1 file_key
    [| rest /servicesNS/-/-/data/lookup-table-files splunk_server=local count=0
     | where match(title,"^ai_")
     | eval file_key=lower(title), file_app='eai:acl.app', file_epoch=strptime(updated,"%Y-%m-%dT%H:%M:%S%:z")
     | eval last_file_update=if(file_epoch>86400, strftime(file_epoch,"%Y-%m-%d %H:%M:%S %z"), "not reported (app-shipped file)")
     | stats values(file_app) as file_app values(last_file_update) as last_file_update by file_key]
| table lookup_name def_app sharing file_key file_app last_file_update collection
| sort lookup_name
```

- `MISSING_DEFINITION`: no row for the lookup. Deploy or repair `hdsi_ai_rba_common`, and check the definition is shared globally (or to the app the detections run in).
- `MISSING_FILE`: the definition exists but `file_app` is empty. The CSV was deleted or never shipped.

### Step 3: Review the lookup rows

```spl
| inputlookup $lookup_name$
| eval enabled=coalesce(enabled,"1 (no enabled column)"), last_verified=coalesce(last_verified,"(no last_verified column)"), expires=coalesce(expires,"-")
| sort 0 last_verified
| head 1000
```

- `STALE`: the oldest `last_verified` rows come first. Review them against current vendor documentation and set `last_verified` to the review date.
- `EMPTY`: every row has `enabled=0`, or the file has only a header.
- `EXPIRED_ENTRIES` / `EXPIRING_ENTRIES`: check `expires` on enabled `ai_sanctioned_entities` rows.

### Step 4: Check the threshold controls (`INVALID_CONTROLS`, `MISSING_CONTROLS`)

```spl
| inputlookup ai_detection_config
| search control_name IN ("medium_risk_threshold","high_risk_threshold")
| eval numeric=if(isnum(tonumber(value)),"yes","no")
| table control_name value numeric description
```

- Valid: both rows present, numeric, `0 < medium_risk_threshold < high_risk_threshold` (shipped 60 / 90).
- A duplicated `control_name` row makes the aggregators' `lookup` return a multivalue, which they treat as non-numeric (default used). This check does not detect duplicates, so look for them here.

### Step 5: See which enabled detections depend on the lookup

```spl
| rest /servicesNS/-/-/saved/searches splunk_server=local count=0 f=title f=disabled f=is_scheduled f=search f=cron_schedule f=next_scheduled_time f=eai:acl
| where match(title,"HDSI (RBA )?AI ") AND NOT match(title,"HDSI AI Health ") AND disabled=0 AND is_scheduled=1
| eval reads=mvappend(if(match(search,"ai_domains_filter|ai_provider_domains"),"ai_provider_domains",null()), if(match(search,"ai_domains_filter|ai_provider_apps"),"ai_provider_apps",null()), if(match(search,"ai_process_filter|ai_process_enrich|ai_tool_processes"),"ai_tool_processes",null()), if(match(search,"ai_api_key_patterns"),"ai_api_key_patterns",null()), if(match(search,"ai_prompt_injection_patterns"),"ai_prompt_injection_patterns",null()), if(match(search,"ai_unsanctioned_filter|ai_sanctioned_entities"),"ai_sanctioned_entities",null()), if(match(search,"ai_risk_multiplier|ai_department_sensitivity"),"ai_department_sensitivity",null()), if(match(search,"ai_detection_config"),"ai_detection_config",null()))
| search reads="$lookup_name$"
| eval app='eai:acl.app'
| table title app cron_schedule next_scheduled_time
```

- This lists rules that reference the lookup or its common macro directly. Some packages wrap common lookups in their own macros, so the list can be incomplete; the alert gate itself only counts enabled AI-RBA rules.
- For a missing lookup, confirm the impact in the scheduler log:

```spl
index=_internal sourcetype=scheduler savedsearch_name="* - HDSI AI * - Rule" status=* earliest=-24h
| stats count by savedsearch_name status
```

### Step 6: Make a determination

- **Actionable:** the lookup really is missing, empty, unreviewed, misconfigured or has lapsed exemptions. Fix it (Response Actions) and close the notable once the next daily run is clean.
- **Expected:** `STALE` on day one for lookups the common package shipped with partly unverified rows (see Known Conditions). Assign the review and close.
- **Not applicable:** the tenant deliberately does not use a lookup or renamed the rules. Tune the macros.

---

## True Positive Indicators

- `MISSING_DEFINITION` or `MISSING_FILE` while AI-RBA rules are enabled: those rules are failing every run.
- `INVALID_CONTROLS`: the medium user aggregator either fires for every user with any AI risk (`medium_risk_threshold` ≤ 0) or can never fire (medium ≥ high).
- `STALE` with many enabled rows older than 90 days: new AI domains, apps and tools are probably missing.
- `EXPIRED_ENTRIES`: approved users or hosts have started accumulating AI risk again.

---

## Known Conditions and False Positive Scenarios

| Scenario | Likelihood | Mitigation |
|---|---|---|
| `STALE` on day one: with the common package as shipped, `ai_tool_processes` (55 of 109 enabled rows), `ai_api_key_patterns` (14 of 22) and `ai_prompt_injection_patterns` (23 of 25) have more than 50% of rows last verified on 2026-03-04 | Certain until reviewed | Review the rows and update `last_verified`, or agree the review owner before enabling. Do not raise `max_age_days` to hide it |
| App-shipped lookup files report `updated = 1970-01-01` through REST (27-96% of files per tenant in validation) | High | Handled: epoch 0 is "unknown" and the `last_verified` column is the primary age signal. `AGE_UNKNOWN` (no alert) only if a tenant replaces a curated lookup with one that has no `last_verified` column |
| Editing any row resets the file time, which can make an unreviewed list look fresh | Medium | `last_verified` and `stale_row_pct` still report the unreviewed rows |
| Tenant renamed the AI-RBA rules, so the gate never opens | Low | Update `_rule_title_regex`. Never make it case-insensitive: `title=*HDSI*AI*` also matches unrelated HDSI rules with words such as "Chain" or "Email" |
| `inputlookup` of a missing lookup adds non-fatal `requires a .csv or KV store lookup definition` ERROR messages to the job | Certain when a lookup is missing | Expected; it is the condition being reported |

---

## Response Actions

### By status

| Status | Action |
|---|---|
| `MISSING_DEFINITION` / `MISSING_FILE` | Deploy or redeploy `hdsi_ai_rba_common`; check the lookup definition's permissions (global sharing or the detections' app) and that the CSV exists in the app's `lookups/` directory. Re-run an affected detection to confirm the FATAL error is gone |
| `EMPTY` | Restore the lookup from the common package, or re-enable rows (`enabled=1`) |
| `INVALID_CONTROLS` | Fix `ai_detection_config`: both rows numeric, `0 < medium_risk_threshold < high_risk_threshold` |
| `MISSING_CONTROLS` | Add the missing row with a numeric `value` (shipped 60 / 90) or accept the aggregator default deliberately |
| `STALE` | Review the oldest rows against vendor documentation, fix or disable obsolete entries, add new providers/apps/tools, and set `last_verified` to today. Prefer updating through the common package so the change is versioned |
| `EXPIRED_ENTRIES` / `EXPIRING_ENTRIES` | Ask the entry `owner` to renew (new `expires`) or disable it (`enabled=0`) |

Then:

1. **Verify:** re-run the check; the fixed lookup must no longer appear:
   ```spl
   | savedsearch "Audit - HDSI AI Health Lookup Staleness Alert - Rule"
   ```
2. **Document:** record the lookup, the change and who reviewed it. Close the notable.

---

## Tuning Guidance

- `hdsi_ai_health_lookup_staleness_alert_filter` (`()`): inline exclusion after the status is computed, for example `(NOT (lookup_name="ai_api_key_patterns" status="AGE_UNKNOWN"))`.
- `hdsi_ai_health_lookup_staleness_alert_customizations` (`search *`): piped before `where alert=1`; can override `alert`, `severity` or `status`, for example `eval alert=if(status="AGE_UNKNOWN",1,alert)` to be reminded about lookups without a review date.
- Shorten `_max_age_days` if AI governance reviews the lists monthly; lengthen it only to match a documented slower cycle.
- Add a lookup to `_curated_lookups` only if a detection reads it and it ages; add a control to `_required_controls` only when a shipped search starts reading it. `ai_deepfake_tools` and `ai_mitre_mapping` are not checked because no shipped detection reads them.

### Measuring how current each curated list is

```spl
| inputlookup ai_provider_domains | eval lookup_name="ai_provider_domains"
| append [| inputlookup ai_provider_apps | eval lookup_name="ai_provider_apps"]
| append [| inputlookup ai_tool_processes | eval lookup_name="ai_tool_processes"]
| append [| inputlookup ai_api_key_patterns | eval lookup_name="ai_api_key_patterns"]
| append [| inputlookup ai_prompt_injection_patterns | eval lookup_name="ai_prompt_injection_patterns"]
| where coalesce(tonumber(enabled),1)=1
| eval age_days=floor((now()-strptime(last_verified,"%Y-%m-%d"))/86400)
| stats count as enabled_rows min(age_days) as newest_age_days perc50(age_days) as median_age_days count(eval(age_days>90)) as rows_older_than_90d by lookup_name
| eval pct_older_than_90d=round(100*rows_older_than_90d/enabled_rows,1)
```

### Before enablement

Deploy `hdsi_ai_rba_common` first. Run the search once with the gate opened (put `eval alert=1` in `_customizations` temporarily, or run the search body without `| where alert=1`) and confirm every expected lookup is present and `enabled_ai_rules` counts the AI-RBA rules you enabled.

---

## Related Detections

| Detection ID | Name | Relationship |
|---|---|---|
| HEALTH-001 | AI Health Data Model Availability (`Audit - HDSI AI Health Data Model Availability - Rule`) | The other health check: data models the detections read |
| AI-RISK-001 / AI-RISK-002 | User Risk Threshold Exceeded (medium) / User Critical Risk Threshold Exceeded | Read `medium_risk_threshold` and `high_risk_threshold`, which this check validates |
| All `AI-0xx` detections | `<Domain> - HDSI AI <Title> - Rule` | Read the curated lookups (`ai_domains_filter`, `ai_process_filter`), the allow-list (`ai_unsanctioned_filter`) and the multiplier table (`ai_risk_multiplier`) |

---

## Data Requirements

| Requirement | Details |
|---|---|
| Data Model | None |
| Required Access | Read access for the scheduling role to REST `data/transforms/lookups`, `data/lookup-table-files`, `saved/searches` on the local search head, and to the app that holds the lookups |
| Required Columns | Curated lookups: `enabled`, `last_verified` (YYYY-MM-DD). `ai_sanctioned_entities`: `enabled`, `expires`. `ai_detection_config`: `control_name`, `value` |
| Acceleration | N/A |
| Lookups | Common package `hdsi_ai_rba_common`: `ai_provider_domains`, `ai_provider_apps`, `ai_tool_processes`, `ai_api_key_patterns`, `ai_prompt_injection_patterns`, `ai_sanctioned_entities`, `ai_department_sensitivity`, `ai_detection_config` |

### Validation evidence (2026-10-09, 4 production ES tenants)

No tenant had the common package deployed (0 `ai_*` lookup definitions) and no `HDSI AI`/`HDSI RBA AI` rule existed yet, so the scheduled run correctly returned 0 rows on A-D (about 3-8 s). With the title regex widened to every enabled HDSI rule (114-322 per tenant), the gate opened and each tenant produced 8 high-severity `MISSING_DEFINITION` notables, proving the alert path. With the repo CSVs inlined, the shipped content gave `OK` for `ai_provider_domains`, `ai_provider_apps`, the config lookups and `ai_detection_config` (effective 60 / 90), and `STALE` for `ai_tool_processes`, `ai_api_key_patterns` and `ai_prompt_injection_patterns`. Threshold-control scenarios (pruned deprecated rows, 50/80, missing high row, 95/90, 0/non-numeric) produced `OK`, `OK`, `MISSING_CONTROLS`, `INVALID_CONTROLS` and `INVALID_CONTROLS` as designed. The search and 3 drilldowns parse on all tenants.

---

## Revision History

| Date | Author | Change |
|---|---|---|
| 2026-10-09 | Trevor Mock, Hurricane Labs | 1.1.0: first runbook, for the released package `hdsi_ai_health_lookup_staleness_alert` (`Audit - HDSI AI Health Lookup Staleness Alert - Rule`). Audit notable per lookup and status, 6-day suppression; REST-based presence checks, `last_verified`-based staleness, threshold-control validation, sanctioned-entry expiry; alert gate on enabled `HDSI AI`/`HDSI RBA AI` rules via unfiltered REST and a case-sensitive title regex |
