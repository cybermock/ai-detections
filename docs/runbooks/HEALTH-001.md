# HEALTH-001 - HDSI AI Health Data Model Availability

> **Detection ID:** HEALTH-001 (`package hdsi_ai_health_data_model_availability`; health check, no `detection_id`)
> **Search name:** `Audit - HDSI AI Health Data Model Availability - Rule`
> **Package:** `saved_searches/packages/hdsi_ai_health_data_model_availability` (version 1.1.0, `deployment_type: global`, ships `enable_alerting: false`)
> **Status:** Active health check. **Audit-domain notable, no risk, no email** (`action.notable = 1`, `action.risk = 0`, `action.email = 0`), severity medium.
> **Risk Score:** none (health checks never write risk and are excluded from the user threshold aggregators)
> **MITRE ATT&CK:** T1562.006 - Impair Defenses: Indicator Blocking (Defense Evasion)
> **Data Model:** `Web`, `Network_Resolution`, `Network_Traffic`, `Endpoint.Processes`, `Endpoint.Filesystem`, `Endpoint.Ports`, `Email`, `DLP` (`DLP.DLP_Incidents`), `Authentication`; plus REST (`datamodel/model`, `admin/summarization`, `saved/searches`)
> **Schedule:** `20 * * * *` (hourly at :20)
> **Lookback Window:** `-7d@h` to `-1h@h` (7-day hourly baseline; "recent" = the last 2 complete hours)
> **Suppression:** `data_model` for 86400 s (one notable per model per day)
> **Kill Chain Phase:** N/A (operational health; Defense Evasion if adversary-induced)
> **Last Updated:** 2026-10-09

---

## Overview

This health check tells you when an HDSI AI-RBA detection has **gone blind**. The AI-RBA detections read CIM data models with `tstats summariesonly=t`. When a model's acceleration summary stops filling, slows down, was never populated, or has acceleration disabled, those detections still run and still return zero rows, and nothing about that looks like a failure.

Every hour the search classifies each data model that AI-RBA detections read as `OK`, `DEGRADED`, `STOPPED`, `ABSENT` or `NOT_ACCELERATED`. It raises **one audit-domain notable per unhealthy model per day**, and only when an enabled AI-RBA detection depends on that model (or the model is listed in `hdsi_ai_health_data_model_availability_required_models`). Models the tenant does not collect, and models no enabled AI-RBA detection reads, never alert.

Most notables are operational: a broken forwarder, input, API pull, CIM mapping or acceleration. MITRE T1562.006 is noted because a telemetry gap can also be adversary-induced (a disabled agent, a blocked log pipeline).

Before 1.1.0 the rule referenced a non-existent `Data_Loss_Prevention` model (a FATAL error on every tenant) and its dependency discovery could never find a dependent rule.

---

## MITRE ATT&CK Mapping

| Field | Value |
|---|---|
| Technique ID | T1562.006 |
| Technique Name | Impair Defenses: Indicator Blocking |
| Tactic | Defense Evasion |
| Sub-technique | T1562.006 |

The SPL sets `mitre_attack="T1562.006"`, matching the annotation.

---

## Detection Logic

### Plain English

1. One `tstats summariesonly=t allow_old_summaries=t count ... by _time span=1h` per model (9 in total), the same summaries the detections read. A model with raw data but no summary therefore correctly shows as unavailable. Each `append` carries `maxtime=300`.
2. `timechart` and `fillnull` build a zero-filled hourly series per model.
3. **Recent** = the last 2 complete hours. **Expected** = the sum, over those 2 hours, of the median count for the same hour of day across the prior 6 days.
4. **Long-silence test:** `silence_hours` since the last hour with events, `prior_expected` (average events per 2 hours while the model was sending), and `continuous` (events in at least half of its hours, and either sending at the window start or for at least `max_silence_hours`). This catches outages older than about 4 days, after which the same-hour median has decayed to 0.
5. REST adds the acceleration flag (`datamodel/model`), summary completeness (`admin/summarization`) and the enabled AI-RBA rules (`saved/searches`, titles containing ` - HDSI AI ` or ` - HDSI RBA AI `, excluding ` - HDSI AI Health `), with each rule's `datamodel=` references parsed from its SPL. A legacy `datamodel=Data_Loss_Prevention` reference counts as `DLP`.
6. **Status**, first match wins:

| Status | Condition |
|---|---|
| `NOT_ACCELERATED` | Acceleration is disabled for the model |
| `ABSENT` | Accelerated, but no events in the whole 7-day window |
| `STOPPED` | 0 recent events while expected >= `min_expected` (100) |
| `STOPPED` (long silence) | 0 recent events, silent >= `max_silence_hours` (24), `continuous`, and `prior_expected` >= `min_expected` |
| `DEGRADED` | Recent events below `degraded_pct` (10%) of expected, with expected >= `min_expected` |
| `OK` | Anything else (sparse feeds under `min_expected` land here) |

7. **Alert** when the model is required (at least one enabled AI-RBA rule reads it, or it is in `required_models`) **and** its status is not `OK`.

### Key Fields (notable)

| Field | Description | Example Value |
|---|---|---|
| `data_model` | Catalog label | `Network_Resolution` |
| `status` | Health status | `STOPPED` |
| `reason` | Plain-language explanation with the numbers | `no events in the last 2 complete hours, where the same hours of day over the prior 6 days had a median of 41230 events (last data 2026-10-09 14:00 CDT).` |
| `impact` | How many enabled AI-RBA detections are blind, or that it alerts only because of `required_models` | `2 enabled AI-RBA detection(s) read this data model ...` |
| `recent_events` / `expected_recent` | Last 2 complete hours / same-hour median expectation | `0` / `41230` |
| `prior_expected` / `silence_hours` | Earlier 2-hour rate / complete hours since the last data | `40877` / `3` |
| `baseline_events` / `baseline_coverage_pct` | Baseline volume / share of baseline hours with data | `3.2e6` / `100.0` |
| `last_data` | Last hour with events | `2026-10-09 14:00 CDT` |
| `accelerated` / `summary_complete_pct` | Acceleration flag / lowest summary completeness | `1` / `99.8` |
| `dependent_rule_count` / `dependent_rules` | Enabled AI-RBA rules reading the model (up to 5 listed) | `2` / `Network - HDSI AI DNS Queries To AI Domains - Rule` |
| `required` / `dm_root` | Alert eligibility / root model name for the acceleration drilldown | `1` / `Network_Resolution` |

### Thresholds

| Parameter | Default | Macro | Notes |
|---|---|---|---|
| Minimum expected events (2 h) | 100 | `hdsi_ai_health_data_model_availability_min_expected` | Stops sparse feeds from flapping |
| Degraded percentage | 10 | `hdsi_ai_health_data_model_availability_degraded_pct` | Weekend hours fall to 0.17 to 0.25 of expected; never raise it |
| Long-silence hours | 24 | `hdsi_ai_health_data_model_availability_max_silence_hours` | Raise (e.g. 66) only for a business-hours-only feed |
| Always-alert models | `"__none__"` | `hdsi_ai_health_data_model_availability_required_models` | Quoted labels, e.g. `"Web","Email"` |

---

## Triage Steps

> **Estimated triage time:** 10 to 20 minutes. The goal is to find which feed or acceleration broke and get it fixed; the notable is a ticket, not an incident, unless the gap looks deliberate.

### Step 1: Read the notable

- `status` and `reason` say what is wrong and by how much; `impact` and `dependent_rules` say which AI-RBA detections are blind.
- `NOT_ACCELERATED` and `ABSENT` are configuration or onboarding problems. `STOPPED` and `DEGRADED` are feed or summary problems that started recently.

### Step 2: Look at the hourly series

Set the time range to the last 7 days and change `datamodel=` to the notable's model (use `DLP.DLP_Incidents` for `DLP`). This is a one-model version of the first drilldown.

```spl
| tstats summariesonly=t allow_old_summaries=t count from datamodel=Network_Resolution by _time span=1h
| timechart span=1h sum(count) as events
| fillnull value=0 events
```

- A clean drop to zero at a specific hour points to a single event (forwarder down, token expired, input disabled, change window).
- A gradual decline or a step down to a lower level points to one of several sources dropping out.

### Step 3: Check acceleration status

The second drilldown, with the notable's `dm_root`:

```spl
| rest /services/admin/summarization by_tstats=t splunk_server=local count=0
| where match('summary.id', "_Network_Resolution(\.|$)")
| eval complete_pct=round(tonumber('summary.complete')*100, 1)
| table summary.id, complete_pct, summary.is_inprogress, summary.earliest_time, summary.latest_time, summary.time_range, summary.size, summary.mod_time, summary.last_error
```

- `summary.last_error` set, `complete_pct` far below 100, or `summary.latest_time` hours behind now: the summary is not keeping up (skipped acceleration searches, a rebuild in progress, a constraint change in CIM setup).
- `summary.time_range` below 604800 (7 days) breaks the baseline; keep acceleration at 7 days or more.

Acceleration searches that are skipped or failing. CIM accelerations are named `_ACCELERATE_DM_Splunk_SA_CIM_<data_model>_ACCELERATE_`, with the dataset for Endpoint (for example `_ACCELERATE_DM_Splunk_SA_CIM_Endpoint.Processes_ACCELERATE_`). Healthy models run about every 5 minutes with `status=success`.

```spl
index=_internal sourcetype=scheduler savedsearch_name="_ACCELERATE_DM_Splunk_SA_CIM_Network_Resolution_ACCELERATE_" earliest=-24h
| fillnull value="-" reason
| stats count min(_time) as first max(_time) as last by status, reason
| convert ctime(first) ctime(last)
| sort - count
```

- No rows at all: the acceleration search is not running (acceleration disabled, or the model is defined in another app).
- `status=skipped` with a concurrency reason: the search head is overloaded and summaries fall behind.

### Step 4: Is the raw data still arriving?

Find the sourcetypes that feed the model (7 days of summaries), then check their raw arrival over the last few hours with index-time `tstats` (cheap, no raw scan):

```spl
| tstats summariesonly=t allow_old_summaries=t count from datamodel=Network_Resolution by index sourcetype
| sort - count
```

```spl
| tstats count where index=* sourcetype IN ("<sourcetype 1>","<sourcetype 2>") earliest=-6h@h latest=now by sourcetype host _time span=1h
| timechart span=1h sum(count) by sourcetype
```

- Raw data arriving but the summary empty: acceleration or CIM tags/eventtypes problem (Step 3), or a sourcetype rename that no longer matches the CIM constraints.
- Raw data missing too: an ingestion problem (forwarder, syslog relay, HEC token, cloud API input, licence block). Look at the sending hosts' last-seen times and the input's own error logs.

### Step 5: Confirm which detections are affected

The third drilldown lists enabled AI-RBA rules that read the model:

```spl
| rest /servicesNS/-/-/saved/searches splunk_server=local count=0 search="HDSI"
| fields title search disabled is_scheduled cron_schedule dispatch.earliest_time eai:acl.app
| search disabled=0 is_scheduled=1 title="*HDSI*AI*"
| where match(title, " - HDSI (RBA )?AI ") AND NOT match(title, " - HDSI AI Health ")
| rex field=search max_match=0 "datamodel[=:]\s*\"?(?<dep_dm>[A-Za-z_]+(?:\.[A-Za-z_]+)?)"
| mvexpand dep_dm
| eval dep_dm=replace(dep_dm, "^Data_Loss_Prevention", "DLP"), data_model=if(match(dep_dm, "^Endpoint\."), dep_dm, mvindex(split(dep_dm, "."), 0))
| search data_model="Network_Resolution"
| dedup title
| table title, eai:acl.app, cron_schedule, dispatch.earliest_time
```

- The listed rules produced no or partial risk for the outage window. Note the window so analysts know the risk timeline has a gap.

### Step 6: Rule out adversary activity

- Did the gap start on specific hosts only (one site, one sensor, one EDR group)? A targeted gap around an incident, or agents stopped by a user with admin rights, warrants a security investigation (T1562.006).
- Check for related notables (EDR tamper, service stops, audit-policy changes) for the affected hosts in the same period.

### Step 7: Make a determination

- **True Positive (operational):** a real feed or acceleration failure. Open a ticket with the platform or data-source owner and track it to recovery.
- **True Positive (security):** the gap was caused deliberately. Escalate as an incident.
- **False Positive:** a known maintenance window, a holiday-level volume drop, or a peer/subsearch error that cleared on the next run.

---

## True Positive Indicators

- `STOPPED` with `silence_hours` growing on consecutive daily notables.
- `summary.last_error` or skipped `_ACCELERATE_DM_*` searches for the model.
- Raw sourcetypes for the model missing from index-time `tstats`.
- `NOT_ACCELERATED` for a model that an enabled AI-RBA rule reads (for example `DLP`, which no validation tenant accelerates).
- A gap limited to hosts involved in an ongoing investigation.

---

## False Positive Scenarios

Evidence from read-only tests on 4 production ES tenants (2026-10-09), including a 14-day out-of-sample backtest that found **0 STOPPED and 0 DEGRADED hours** with the defaults.

| Scenario | Likelihood | Mitigation |
|---|---|---|
| Weekend or holiday volume for user-driven feeds (Web, Email, DNS) falls to 0.17 to 0.25 of the weekday-dominated median | Medium on holidays | `degraded_pct` 10 leaves 1.7x to 2.5x headroom at weekends; lower it to 5 if holidays drop further. Never raise it |
| Business-hours-only feed shows `STOPPED` on weekend daytime hours | Low (no validation tenant has one) | Add a `..._filter` exclusion for the model/status, or raise `max_silence_hours` |
| Indexer or peer errors, subsearch truncation during the run | Low | 24 h suppression and the next hourly run limit the impact; recheck before escalating |
| Acceleration rebuild leaves recent hours empty until it catches up | Low | Check `summary_complete_pct` and Step 3 before escalating |
| Planned maintenance on a source | Situational | `eval alert=if(data_model="Email", 0, alert)` in `..._customizations` for the window |

### Known limits

- A sustained partial drop becomes the new normal after about 4 days (the median follows it); a total stop stays `STOPPED` through the long-silence test. Fix the feed when the first `DEGRADED` notable arrives.
- Dependency discovery is textual: a renamed rule, or one that hides `tstats` inside a macro, is not counted. Add its model to `required_models`.
- Availability is not fitness: on two validation tenants the `Web` model is mostly inbound server or WAF logs, healthy here but useless to user-egress AI detections.

---

## Response Actions

### If confirmed True Positive

| Status | Typical cause | Action |
|---|---|---|
| `NOT_ACCELERATED` | Acceleration disabled in CIM setup, or never enabled (for example `DLP`) | Enable acceleration with a summary range of at least 7 days, or disable the AI-RBA rules that read the model |
| `ABSENT` | No source mapped to the model, or acceleration constraints exclude the data | Onboard and CIM-map a source, fix the CIM index constraints, or disable the dependent rules |
| `STOPPED` | Forwarder, syslog relay, HEC token, cloud API input, licence or acceleration failure | Restore the input; confirm raw arrival (Step 4) and summary progress (Step 3) |
| `DEGRADED` | One of several sources stopped, a sensor or site offline, partial acceleration | Find the missing sourcetype or host from Step 4 and restore it |

1. **Notify:** the data-source owner and the Splunk platform team; tell the SOC which AI-RBA detections were blind and for how long.
2. **Verify recovery:** the next hourly run returns the model to `OK`; while it stays down it raises one notable per day (`STOPPED` while earlier data remains in the 7-day window, then `ABSENT`).
3. **Document:** record the outage window, cause and fix in the case.

### If the gap is expected

1. Suppress temporarily with `..._customizations` (`eval alert=if(data_model="<model>", 0, alert)`) and remove it after the maintenance.
2. If the tenant will never collect the model, disable the AI-RBA rules that read it rather than silencing this check.

---

## Tuning Guidance

### Reducing false positives

- `hdsi_ai_health_data_model_availability_filter` (inline search terms after status is computed), e.g. `NOT (data_model="Endpoint.Ports" status="DEGRADED")`.
- `hdsi_ai_health_data_model_availability_customizations` can override `alert` per model.
- If an hourly run (117 to 141 s on the largest validation tenant) is too heavy, change `cron_schedule` to `20 */4 * * *` and keep the `-1h@h` latest time.

### Adjusting thresholds

Replay the rule's 6-value same-hour median for one model over `-15d@h` to `-1h@h` (change `datamodel=`):

```spl
| tstats summariesonly=t allow_old_summaries=t count from datamodel=Email by _time span=1h
| timechart span=1h sum(count) as ev
| fillnull value=0 ev
| eval hod=strftime(_time, "%H")
| streamstats current=f global=f window=6 median(ev) as hod_median count(ev) as nb by hod
| streamstats window=2 sum(ev) as recent2 sum(hod_median) as expected2 min(nb) as nb2
| where nb2>=6 AND expected2>=100
| eval weekend=if(in(strftime(_time, "%a"), "Sat", "Sun"), 1, 0), ratio=recent2/expected2
| stats count as hours min(ratio) as min_ratio p5(ratio) as p5_ratio median(ratio) as median_ratio sum(eval(if(recent2*100<expected2*10, 1, 0))) as degraded_hours by weekend
```

Aim for `degraded_pct` at or below `50 x min_ratio` from the weekend row and never above `100 x min_ratio`.

### Report mode

To see every model's status, copy the rule's `search`, remove the `| where alert=1` line, and run it over `-7d@h` to `-1h@h`. Do this before enabling the check and after enabling any new AI-RBA detection.

---

## Related Detections

| Detection ID | Name | Relationship |
|---|---|---|
| HEALTH-002 | `Audit - HDSI AI Health Lookup Staleness Alert - Rule` | Companion health check for the common AI lookups the detections depend on |
| AI-012 | `Network - HDSI AI DNS Queries To AI Domains - Rule` | Example dependent: blind when `Network_Resolution` is not OK |
| AI-020 / AI-038 | DLP-based AI detections (AI-020 is incubating: not released; see [`saved_searches/incubating/hdsi_ai_dlp_violation_on_service_upload/`](../../saved_searches/incubating/hdsi_ai_dlp_violation_on_service_upload/RUNBOOK.md)) | Raise `DLP NOT_ACCELERATED` when enabled on a tenant without DLP acceleration |
| AI-RISK-001 / AI-RISK-002 | User risk threshold aggregators | Exclude health checks (`- HDSI AI Health -`) from their totals |

---

## Data Requirements

| Requirement | Details |
|---|---|
| Data Model | All 9 catalog models must be **defined** (Splunk_SA_CIM): `Web`, `Network_Resolution`, `Network_Traffic`, `Endpoint` (`Processes`, `Filesystem`, `Ports`), `Email`, `DLP` (dataset `DLP_Incidents`; not `Data_Loss_Prevention`), `Authentication`. They need not contain data |
| Undefined model | A `tstats` against an undefined model is a FATAL error that aborts the whole search, even inside an `append`. On an old CIM version, remove that model's `append` line and its label from the catalog `makeresults` |
| REST access | Search owner must read `/servicesNS/-/-/datamodel/model`, `/services/admin/summarization` and `/servicesNS/-/-/saved/searches`, and see the AI-RBA rules' app context |
| Acceleration | Summary range of at least 7 days for the baseline |
| Lookups | None; no common macros |
| Common package | Listed as `prereq_packages: hdsi_ai_rba_common` only so it deploys with the detections it monitors |

### Validation (2026-10-09)

| Tenant | Parses (rule + 3 drilldowns) | Scheduled run | Report-mode status |
|---|---|---|---|
| A | OK | 0 rows, 117 to 118 s | All OK except DLP `NOT_ACCELERATED` |
| B | OK | 0 rows, 88 to 96 s | Email and Endpoint.Filesystem `ABSENT`; Ports OK (sparse); DLP `NOT_ACCELERATED` |
| C | OK | 0 rows, 29 s | All OK except DLP `NOT_ACCELERATED` |
| D | OK | 0 rows, 21 to 24 s | All OK except DLP `NOT_ACCELERATED` |

The scheduled runs return 0 rows because no AI-RBA rule is enabled yet on any tenant and `required_models` ships empty. With four synthetic enabled rules injected, every tenant returned exactly one notable (`DLP NOT_ACCELERATED`); `Email`, `ABSENT` on Tenant B, did not alert because only a non-AI rule read it. Synthetic outage feeds were classified `STOPPED` (stopped 1 to 6.9 days ago), `DEGRADED` (dropped to 5% 1 or 4 days ago) and `OK` (sparse, bursty and daytime-only healthy feeds) in all four tenants.

---

## Revision History

| Date | Author | Change |
|---|---|---|
| 2026-10-09 | Trevor Mock, Hurricane Labs | 1.1.0: initial runbook for the released health check. Hourly status per CIM data model (OK, DEGRADED, STOPPED, ABSENT, NOT_ACCELERATED) with same-hour median and long-silence tests; audit notable only for models that enabled AI-RBA detections read; DLP model name corrected to `DLP.DLP_Incidents`; no risk, no email |
