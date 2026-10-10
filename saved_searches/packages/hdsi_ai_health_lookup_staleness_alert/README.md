## Architect Notes
---
**Author:** Trevor Mock, Hurricane Labs LLC. Security Operations Architect

This daily audit health check watches the lookups that the HDSI AI-RBA detections read. It raises an audit notable when a lookup is missing, since every detection that reads a missing lookup stops with a FATAL error and produces no risk. It also raises one when a curated list is empty or has not been reviewed for 90 days, so the detections are missing new AI domains, apps or tools; when the two `ai_detection_config` rows that the user risk aggregators still read (`medium_risk_threshold`, `high_risk_threshold`) leave the medium band empty or start at zero, or are missing so the aggregators silently fall back to their defaults; and when an approved exemption in the sanctioned-use allowlist has expired or is about to. It creates one notable per lookup and status in the `audit` security domain. It creates no risk and sends no email.

### Prerequisites
- **No data model or index.** The search reads Splunk REST endpoints on the local search head (`data/transforms/lookups`, `data/lookup-table-files`, `saved/searches`) and the lookups themselves with `inputlookup`. The scheduling role needs read access to these endpoints and to the app that holds the lookups.
- **`hdsi_ai_rba_common`** (declared in `prereq_packages`): this package provides the lookups being checked. If it is not deployed, every lookup reports `MISSING_DEFINITION`, and each scheduled run also logs non-fatal `ERROR: The lookup table 'ai_...' requires a .csv or KV store lookup definition` messages from its `inputlookup` subsearches (the job still completes). Deploy the common package first. No notable is created until an HDSI AI-RBA detection is enabled and scheduled.
- **Review dates:** all five curated lookups carry a `last_verified` (YYYY-MM-DD) column, and `ai_sanctioned_entities` has an `expires` column. Rows the common package has not re-verified keep the package date (2026-03-04), so their staleness is reported honestly. The file modification time is used as well when REST reports it; on Splunk Cloud it is usually not reported for files that ship inside an app (see Limitations).

### How it works
- Builds the list of expected lookups from two macros. **Curated** lookups are checked for presence, content and age. **Config** lookups are checked for presence only, plus expiry for `ai_sanctioned_entities`.
- Appends the lookup definitions (REST `transforms/lookups`) and runs `content_stats(<lookup>)` on each shipped lookup. That macro is an `inputlookup` that returns the row count, the enabled row count, the newest `last_verified` date, the number of enabled rows verified more than 90 days ago, and the number of enabled `expires` entries that have passed or fall within 14 days.
- Joins each definition to its file (REST `lookup-table-files`, matched on the definition's `filename`). The file's `updated` time is parsed with its UTC offset (`%Y-%m-%dT%H:%M:%S%:z`). An epoch-0 value means "not reported" and is treated as unknown, not as 56 years old.
- For `ai_detection_config`, compares the rows that hold a numeric `value` with the `required_controls` macro. Only two controls are still read by shipped searches: `medium_risk_threshold` (by `hdsi_rba_ai_user_risk_threshold_exceeded`) and `high_risk_threshold` (by that rule and `hdsi_rba_ai_user_critical_risk_threshold_exceeded`). Both aggregators `coalesce` a missing or non-numeric value to a built-in default (60 and 90), so a missing row does not break them; it only means tenant tuning is ignored. The other 23 rows are marked `DEPRECATED v1.1` in the common package and have no reader, so pruning them raises nothing. The search computes the effective thresholds (row value or default) into `medium_risk_threshold` and `high_risk_threshold`.
- Counts the enabled, scheduled HDSI AI-RBA rules on the search head: it reads REST `saved/searches` without a server-side filter (only the `title`, `disabled` and `is_scheduled` fields) and keeps titles that match the case-sensitive regex `HDSI (RBA )?AI ` (the `rule_title_regex` macro), excluding the `HDSI AI Health` checks. REST's own `search="title=*...*"` argument is not used because it returns no rows for wildcard title expressions on Splunk Cloud (see Validation).
- Sets the status in this order: `MISSING_DEFINITION` → `MISSING_FILE` (file-based definition whose file is missing) → `EMPTY` (curated, no enabled rows) → `INVALID_CONTROLS` (effective `medium_risk_threshold` ≤ 0 or ≥ `high_risk_threshold`: the medium aggregator either fires for every user with any AI risk or can never fire) → `MISSING_CONTROLS` (a required control row is missing or not numeric, so its default is used) → `STALE` (curated, newest review date older than `max_age_days`, or more than `stale_row_pct`% of enabled rows unverified for `max_age_days`) → `EXPIRED_ENTRIES` → `EXPIRING_ENTRIES` → `AGE_UNKNOWN` (curated, no review date available) → `OK`.
- Sets `severity` to high for missing, empty or invalid controls, medium for stale or expired, and low otherwise (including `MISSING_CONTROLS` and `EXPIRING_ENTRIES`). A notable is created (`alert=1`) only when the status is not `OK` or `AGE_UNKNOWN` **and** at least one HDSI AI-RBA detection is enabled. Suppression is on `lookup_name,status` for 6 days, so an unresolved condition comes back about once a week, and a new status for the same lookup alerts at once.

### Tuning macros
| Macro | Ships as | Purpose |
|---|---|---|
| `hdsi_ai_health_lookup_staleness_alert_filter` | `()` | Inline exclusion, applied after status is computed, e.g. `(NOT (lookup_name="ai_api_key_patterns" status="AGE_UNKNOWN"))` |
| `hdsi_ai_health_lookup_staleness_alert_customizations` | `search *` | Piped before `where alert=1`; can override `alert`, `severity` or `status` (e.g. `eval alert=if(status="AGE_UNKNOWN",1,alert)`) |
| `hdsi_ai_health_lookup_staleness_alert_curated_lookups` | the 5 matching lookups | Lookups checked for content and age |
| `hdsi_ai_health_lookup_staleness_alert_config_lookups` | `ai_sanctioned_entities`, `ai_department_sensitivity`, `ai_detection_config` | Lookups checked for presence (and expiry) only |
| `hdsi_ai_health_lookup_staleness_alert_rule_title_regex` | `"HDSI (RBA )?AI "` | Case-sensitive title regex of the AI-RBA rules that open the alert gate. Change it only if the tenant renames the rules |
| `hdsi_ai_health_lookup_staleness_alert_required_controls` | `"medium_risk_threshold,high_risk_threshold"` | `ai_detection_config` rows that shipped searches read. A missing or non-numeric one is `MISSING_CONTROLS` (low). Add a name only when a search starts reading a new control; the band check (`INVALID_CONTROLS`) is specific to these two rows |
| `hdsi_ai_health_lookup_staleness_alert_max_age_days` | `90` | Maximum age of the newest review date of a curated lookup |
| `hdsi_ai_health_lookup_staleness_alert_stale_row_pct` | `50` | STALE when more than this % of enabled rows were last verified before the limit |
| `hdsi_ai_health_lookup_staleness_alert_expiry_warn_days` | `14` | Warn window for sanctioned-use entries that are about to expire |
| `hdsi_ai_health_lookup_staleness_alert_content_stats(1)` | `inputlookup` + `stats` | Per-lookup content facts. Change it only to add a date column |

`ai_deepfake_tools` and `ai_mitre_mapping` are not checked. No shipped detection reads them, so their age cannot affect detection.

### Threshold
`max_age_days` = 90 matches how fast AI providers add domains, apps and API endpoints. Shorten it if the tenant's AI governance reviews the lists monthly, and lengthen it only to match a slower review cycle that is documented. To see how current each list is before you choose a value:

```text
| inputlookup ai_provider_domains | eval lookup_name="ai_provider_domains"
| append [| inputlookup ai_provider_apps | eval lookup_name="ai_provider_apps"]
| append [| inputlookup ai_tool_processes | eval lookup_name="ai_tool_processes"]
| append [| inputlookup ai_api_key_patterns | eval lookup_name="ai_api_key_patterns"]
| append [| inputlookup ai_prompt_injection_patterns | eval lookup_name="ai_prompt_injection_patterns"]
| where coalesce(tonumber(enabled),1)=1
| eval age_days=floor((now()-strptime(last_verified,"%Y-%m-%d"))/86400)
| stats count as enabled_rows, min(age_days) as newest_age_days, perc50(age_days) as median_age_days,
        count(eval(age_days>90)) as rows_older_than_90d by lookup_name
| eval pct_older_than_90d=round(100*rows_older_than_90d/enabled_rows,1)
```

After you review rows, update their `last_verified` values (or refresh the common package). That clears `STALE` on the next daily run.

### Known false positives / Limitations
- **The shipped common lookups are partly unverified, so expect `STALE` on day one.** With the common package as shipped, `ai_tool_processes` (55 of 109 enabled rows), `ai_api_key_patterns` (14 of 22) and `ai_prompt_injection_patterns` (23 of 25) have more than 50% of enabled rows last verified on 2026-03-04, more than 90 days ago. They report `STALE` (medium) until the rows are reviewed and their `last_verified` updated. This is accurate: the common package deferred that re-verification.
- **The file modification time is often not reported for app-shipped lookups.** In all four validation tenants, most lookup files report `updated = 1970-01-01` (epoch 0) through REST: 27–96% per tenant, including every shipped file of a content app in three of them. The search treats epoch 0 as "unknown" and relies on the `last_verified` column, which every curated lookup now has. `AGE_UNKNOWN` (no alert by default) only occurs if a tenant replaces a curated lookup with one that has no `last_verified` column.
- **The file modification time measures edits, not review.** Editing any row resets the file date. The `last_verified` column and `stale_row_pct` are the real review signals.
- **Detection dependency is coarse.** The alert gate counts enabled HDSI AI-RBA rules. It does not check which rule reads which lookup, because several packages wrap common lookups in their own macros. The third drilldown lists rules that reference a lookup or its common macro directly.
- **The gate depends on rule titles.** It matches `HDSI AI ` or `HDSI RBA AI ` case-sensitively. A case-insensitive `search title=*HDSI*AI*` would also count unrelated HDSI rules whose titles contain words such as "Chain", "CloudTrail" or "Email". If the tenant renames the AI-RBA rules, update `rule_title_regex`.
- **The control checks cover only the user risk thresholds.** `INVALID_CONTROLS` catches an empty or zero-based medium band; any other numeric pair (for example 50/80) is accepted even if it is unsuitable for the tenant. A duplicated `control_name` row makes the aggregators' `lookup` return a multivalue, which they treat as non-numeric (default used); this search does not detect duplicates. The `hdsi_rba_ai_*` packages' own macros (window, vector count, minimum detections) are not checked.
- **The rows drilldown reads only the notable's lookup.** For a `MISSING_DEFINITION` notable it shows the same "requires a .csv or KV store lookup definition" error, which confirms the finding; for every other notable it shows that lookup's rows (oldest `last_verified` first), including `ai_department_sensitivity` and `ai_detection_config`.
- **One copy per file name.** If a lookup file exists in more than one app, the newest modification time wins and every app is listed in `file_app`.
- `inputlookup` of a missing lookup adds a non-fatal ERROR message to the job (one per missing lookup, plus one from the controls subsearch for `ai_detection_config`). The REST checks still report the lookup as missing, and the search completes. In production this only happens when the common package is absent or a lookup was deleted, which is exactly what the search reports.

### Validation
Read-only live runs on 2026-10-09 against 4 production ES tenants. No tenant has the common package deployed: `| rest .../data/transforms/lookups | where match(title,"^ai_")` returns 0 definitions in all four. Every result about lookup content below therefore comes from the repo CSVs, inlined into the search by the test harness, with the REST definition and file checks replaced by stubs for the 8 expected lookups (app-shipped files, no modification time). Rule counts use enabled, scheduled saved searches whose title contains `HDSI ` (with a trailing space); counting titles that contain `HDSI` anywhere gives 342/132/191/114.

| Tenant | Common lookups deployed? | HDSI AI-RBA rules enabled (shipped gate) | Enabled HDSI rules (title contains `HDSI `) | Parses (search + 3 drilldowns) | Scheduled run (repo lookups inlined) | Gate opened (title regex widened to `HDSI `) |
|---|---|---|---|---|---|---|
| A | No | 0 | 322 | OK | 200, 0 rows, ~7 s | 8 notables, all `MISSING_DEFINITION` (high) |
| B | No | 0 | 132 | OK | 200, 0 rows, ~3 s | same |
| C | No | 0 | 175 | OK | 200, 0 rows, ~5 s | same |
| D | No | 0 | 114 | OK | 200, 0 rows, ~3 s | same |

The 0-row scheduled run is correct: no rule titled `HDSI AI ...` or `HDSI RBA AI ...` exists in any tenant yet. Widening the title regex to every enabled HDSI rule proves the alert path end to end: the gate counts the rules and every missing lookup produces a high-severity audit notable.

Simulation with the common package's CSVs as shipped and stub definitions (gate widened, `where alert=1` removed), identical in A–D:

| Lookup | Status | Why |
|---|---|---|
| `ai_provider_domains` | `OK` | 40 of 192 enabled rows older than 90 days (21%, below 50%) |
| `ai_provider_apps` | `OK` | all enabled rows verified 2026-10-09 |
| `ai_tool_processes` | `STALE` (medium) | 55 of 109 enabled rows older than 90 days (50.5%) |
| `ai_api_key_patterns` | `STALE` (medium) | 14 of 22 |
| `ai_prompt_injection_patterns` | `STALE` (medium) | 23 of 25 |
| `ai_sanctioned_entities`, `ai_department_sensitivity` | `OK` | present; the sanctioned-entity examples are disabled |
| `ai_detection_config` | `OK` | effective thresholds 60 / 90 |

`ai_detection_config` scenarios (rows replaced in the controls subsearch, run in A and D, same result in both):

| Rows | Result |
|---|---|
| only `medium_risk_threshold=60`, `high_risk_threshold=90` (all 23 deprecated rows pruned) | `OK` |
| 50 / 80 (tuned) | `OK` |
| `medium=70`, high row removed | `MISSING_CONTROLS` (low), effective 70 / 90 |
| `medium=95`, `high=90` | `INVALID_CONTROLS` (high): medium band empty |
| `medium=95`, high row removed | `INVALID_CONTROLS` (high): 95 / default 90 |
| `medium=0`, `high=ninety` | `INVALID_CONTROLS` (high): medium threshold 0 |

Other findings:
- **REST title filter.** `| rest .../saved/searches search="title=*HDSI*"` returned 0 rows in all four tenants, although 114–322 enabled rules with `HDSI ` in the title exist; `search="title=*Rule*"` also returned 0. The search therefore filters with `where match(title, ...)` after an unfiltered read.
- **REST `f=` field filter.** `f=eai:acl.app` returns nothing; `f=eai:acl` returns `eai:acl.app`. The third drilldown uses `f=eai:acl`, and its `app` column was filled in all four tenants.
- **Age logic on real files.** Run against tenant lookup files (not AI-RBA lookups), the file-time branch returned `STALE` for old files (199–3,789 days) and `OK` for recently edited ones.
- **Epoch-0 file times.** 27–96% of lookup files per tenant report `updated = 1970-01-01` through REST, which is why the `last_verified` column is the primary age signal.
- **UTC offset.** `updated` carries the search head's offset (`+00:00` to `-06:00`); parsing it without the offset was 4–6 hours off on non-UTC search heads.
- **Production form without the common package** (macros expanded, lookups not inlined): 200, 0 rows, 3–8 s, with the non-fatal `requires a .csv or KV store lookup definition` ERROR messages described under Limitations.
- A synthetic test of `content_stats` with 5 rows returned 4 enabled, 1 stale, 1 expired and 1 expiring, all correct. A header-only lookup returns `content_rows=0`, which the search reports as `EMPTY`.

### Deployment
The package ships with `enable_alerting: false`. Before enablement, deploy `hdsi_ai_rba_common`, run the search once with `| where alert=1` removed and confirm that every expected lookup is present and that `enabled_ai_rules` counts the AI-RBA rules you enabled. Expect `STALE` for `ai_tool_processes`, `ai_api_key_patterns` and `ai_prompt_injection_patterns` until their rows are reviewed (see Limitations): review them, or agree who owns the lookup review cycle, before enabling, so the first notables are not noise. Enabling it is a separately approved change. It creates audit notables only: no risk, no email, no adaptive response.
