## Architect Notes
---
**Author:** Trevor Mock, Hurricane Labs LLC. Security Operations Architect

This audit health check tells you when an HDSI AI-RBA detection has gone blind. AI-RBA detections read CIM data models with `tstats summariesonly=t`. When a model's acceleration summary stops filling, slows down, was never populated, or has acceleration disabled, the detection still runs and still returns zero rows. Nothing about that looks like a failure. Every hour this search classifies each data model that AI-RBA detections read as `OK`, `DEGRADED`, `STOPPED`, `ABSENT` or `NOT_ACCELERATED`. It creates one audit-domain notable per unhealthy model, and only when an enabled AI-RBA detection depends on that model (or you list it in `required_models`). It creates no risk and sends no email.

### Prerequisites
- **CIM data models must be defined** (Splunk_SA_CIM, shipped with ES): `Web`, `Network_Resolution`, `Network_Traffic`, `Endpoint` (`Processes`, `Filesystem`, `Ports`), `Email`, `DLP` (dataset `DLP_Incidents`; the model is named `DLP`, not `Data_Loss_Prevention`) and `Authentication`. These are every model that an AI-RBA detection reads with `summariesonly=t`. `Authentication` is read by `hdsi_ai_privileged_account_service_usage` (SSO branch) and the incubating (not released) `hdsi_ai_usage_from_personal_account_oauth_mismatch` (corporate SSO lookback). A `tstats` against an undefined model is a FATAL error. That error aborts the whole search even inside an `append` subsearch (verified live). If an old CIM version lacks a model, remove that model's `append` line and its label from the catalog `makeresults`.
- None of the models needs to contain data. Showing which ones are empty is the point of the search. `data_prereqs` therefore lists them with `op: OR`.
- REST read access for the search owner: `/servicesNS/-/-/datamodel/model` (acceleration flag), `/services/admin/summarization` (summary completeness) and `/servicesNS/-/-/saved/searches` (which AI-RBA rules are enabled). The saved-search owner must be able to see the AI-RBA rules' app context, or dependency discovery silently finds none.
- No ES lookups and no common macros are used. The package stays in the `hdsi_ai_rba_common` suite only so that it deploys together with the detections it monitors.

### How it works
- One `tstats summariesonly=t allow_old_summaries=t count ... by _time span=1h` per model (9 in total) over `-7d@h` to `-1h@h`. These are the same summaries the detections read, so a model with raw data but no summary correctly shows as unavailable. Every `append` (the 8 extra `tstats`, the catalog and the 3 REST calls) carries `maxtime=300`, so a slow subsearch is not cut off at the default 60 s limit.
- `timechart` and `fillnull` produce a zero-filled hourly series per model, so hours with no data count as zero instead of disappearing.
- **Recent** is the last 2 complete hours, `[-3h@h, -1h@h)`. The scheduled run at :20 therefore leaves at least 80 minutes for acceleration lag. Live tests saw up to 18 minutes of DNS summary lag.
- **Expected** is the sum, over those 2 hours, of the median count for the same hour of day across the **prior 6 days**. Day -7 is not included for the recent hours because the window starts at `-7d@h`, which is after them (165 baseline hours in total). The baseline absorbs day/night cycles. Weekends are not modelled separately: the median is dominated by weekdays, so weekend hours run at a fraction of expected (live: as low as 0.17 of expected). They stay above the default `degraded_pct` of 10 only because that threshold is deliberately low. See **Threshold**.
- **Long-silence test.** A same-hour median decays once an outage covers most of the window: after about 4 days of zeros, 4 of the 6 same-hour values are 0, the median is 0 and the first `STOPPED` test can no longer fire. A second test therefore looks at the model's own earlier rate. `silence_hours` is the number of complete hours since the last hour with events. `prior_expected` is the model's average events per 2 hours between its first and last event in the window. The model is `continuous` when it had events in at least half of those hours, and either was already sending at the start of the window or sent for at least `max_silence_hours` hours. A single burst or a sparse feed is therefore never `continuous`.
- Status, first match wins:
  - `NOT_ACCELERATED`: the model's acceleration is disabled. Every `summariesonly=t` search against it returns nothing.
  - `ABSENT`: accelerated, but no events in the whole 7-day window.
  - `STOPPED`: 0 recent events while expected ≥ `min_expected`.
  - `STOPPED` (long silence): 0 recent events, silent for ≥ `max_silence_hours` (24), `continuous`, and `prior_expected` ≥ `min_expected`.
  - `DEGRADED`: recent events are below `degraded_pct`% of expected while expected ≥ `min_expected`.
  - `OK`: anything else. Sparse feeds whose expected volume is under `min_expected` land here. If an `OK` model has 0 recent events, the `reason` field says so and explains why it is not treated as an outage.
- **Required:** the model is listed in `required_models`, or at least one enabled, scheduled AI-RBA rule reads it. AI-RBA rules come from `| rest /servicesNS/-/-/saved/searches search="HDSI"`. The `search="HDSI"` argument is only a free-text pre-filter that reduces the rows returned (live: 5493 to 502 rows in Tenant A, with every `HDSI` title kept in all four tenants). The rows are then filtered in SPL: `disabled=0 is_scheduled=1`, then the title must contain ` - HDSI AI ` or ` - HDSI RBA AI ` (a case-sensitive substring match on the `<Domain> - HDSI AI <Title> - Rule` naming pattern, not an anchored one), and ` - HDSI AI Health ` rules are excluded. Other HDSI rules such as `Threat - HDSI High Volume Email ...` therefore do not count, even though a case-insensitive `*HDSI*AI*` glob matches them. A `title=*wildcard*` expression in the REST `search=` argument returns 0 entries (verified live), so the title test stays in SPL. The data model comes from parsing `datamodel=`/`datamodel:` in each rule's own SPL. A legacy `datamodel=Data_Loss_Prevention` reference is counted as `DLP`. Data models outside the catalog (for example `Risk`, which the RBA aggregators read through `index=risk` and the drilldowns through `| from datamodel:`) are ignored.
- A notable is created only when the model is required **and** its status is not `OK`. Models the tenant does not collect, and models no enabled AI-RBA detection reads, show up in report mode but never alert. The notable description says how many enabled AI-RBA detections read the model, or that it alerts only because of `required_models`.
- `alert.suppress.fields = data_model` for 86400 s caps the output at one notable per model per day. A required model that stays down keeps alerting once per day: `STOPPED` for as long as any of its earlier data is still in the 7-day window (verified with synthetic feeds stopped 1, 2, 3, 4, 5, 6 and 6.9 days ago), then `ABSENT`. The alerts stop when the feed recovers, when you remove the model from `required_models`, or when you disable the AI-RBA detections that read it.
- **Deviations from the package conventions:** the schedule is `20 * * * *` over `-7d@h` to `-1h@h`, not the usual hourly `-65m@m` to `-5m@m` pair, because the check needs a 7-day baseline and complete hours. The `_filter` macro (ships as `()`) sits inline in `| search data_model=* <filter>` after the status is computed, instead of in the first `tstats` `where` clause, because the search has 9 `tstats` over different data models and the filter is meant to act on `data_model`/`status`. The SPL sets `mitre_attack="T1562.006"` to match the annotation. `tools/audit_savedsearch_conformance.sh` flags `action.notable = 1` / `action.risk = 0`; that is the owner-approved health-check pattern (audit notable, no risk).
- MITRE `T1562.006` (Indicator Blocking) is noted because a telemetry gap can be adversary-induced. Most hits will be operational: a broken forwarder, input, CIM mapping or acceleration.

### Tuning macros
| Macro | Ships as | Purpose |
|---|---|---|
| `hdsi_ai_health_data_model_availability_required_models` | `"__none__"` | Quoted, comma-separated labels that must alert whenever not `OK`, even with no enabled AI-RBA rule reading them. Labels: `"Web","Network_Resolution","Network_Traffic","Endpoint.Processes","Endpoint.Filesystem","Endpoint.Ports","Email","DLP","Authentication"`. |
| `hdsi_ai_health_data_model_availability_min_expected` | `100` | Minimum expected events in the 2-hour window before `STOPPED`/`DEGRADED` is evaluated, and the minimum `prior_expected` for the long-silence test. Stops sparse feeds from flapping. |
| `hdsi_ai_health_data_model_availability_degraded_pct` | `10` | `DEGRADED` when recent volume is below this percentage of expected. |
| `hdsi_ai_health_data_model_availability_max_silence_hours` | `24` | Hours of silence after which a `continuous` model is `STOPPED` even when its same-hour median has decayed to 0. Raise it (for example to 66) only for a business-hours-only feed that is legitimately silent over a weekend. |
| `hdsi_ai_health_data_model_availability_filter` | `()` | Search terms inline in `search data_model=* <filter>` after status is computed (fields `data_model`, `status`, `required`, `silence_hours`, ...). Example: `NOT (data_model="Endpoint.Ports" status="DEGRADED")`. |
| `hdsi_ai_health_data_model_availability_customizations` | `search *` | Piped before the final `where alert=1`, so it can override `alert`. Example: `eval alert=if(data_model="Email", 0, alert)` during planned maintenance. |

### Threshold
A 14-day backtest ran on 2026-10-09 in all four validation tenants. Each hour was compared with the median of the same hour of day over the days before it. That backtest used 7 prior values per hour; the rule uses 6, so the backtest is a close approximation, not an exact replay. With the defaults it found **0 `STOPPED` and 0 `DEGRADED` hours**, on weekdays and on the 2026-10-03/04 weekend:

| | Weekday lowest recent/expected ratio | Weekend lowest recent/expected ratio |
|---|---|---|
| Tenant A | 0.89 (Email) | not measurable: the summaries do not reach back far enough to give the weekend a full baseline |
| Tenant B | 0.56 (Network_Traffic) | 0.24 (Network_Resolution) |
| Tenant C | 0.73 (Email) | 0.17 (Web) |
| Tenant D | 0.27 (Endpoint.Ports) | 0.19 (Web) |

Weekend volume is the tightest case. Weekend hours for user-driven feeds (Web, Email, DNS) fall to 0.17–0.25 of the weekday-dominated median. Headroom is `100 * min_ratio / degraded_pct`, so the default `degraded_pct` of 10 leaves 1.7x (Tenant C Web) to 2.5x of headroom at weekends. That was enough for zero false `DEGRADED` hours, but it is thin. If a tenant's feed drops further at weekends or on holidays, lower `degraded_pct` to 5. Do not raise it. To size the thresholds for one model in your tenant, run the following over `-15d@h` to `-1h@h` (change `datamodel=`). It replays the rule's 6-value same-hour median out of sample:

```text
| tstats summariesonly=t allow_old_summaries=t count from datamodel=Email by _time span=1h
| timechart span=1h sum(count) as ev | fillnull value=0 ev
| eval hod=strftime(_time,"%H")
| streamstats current=f global=f window=6 median(ev) as hod_median count(ev) as nb by hod
| streamstats window=2 sum(ev) as recent2 sum(hod_median) as expected2 min(nb) as nb2
| where nb2>=6 AND expected2>=100
| eval weekend=if(in(strftime(_time,"%a"),"Sat","Sun"),1,0), ratio=recent2/expected2
| stats count as hours min(ratio) as min_ratio p5(ratio) as p5_ratio median(ratio) as median_ratio sum(eval(if(recent2*100<expected2*10,1,0))) as degraded_hours by weekend
```

Aim for `degraded_pct` at or below `50 * min_ratio` from the weekend row (2x headroom under the quietest hour). Never set it above `100 * min_ratio`. `global=f` matters: without it, `streamstats window=6 ... by hod` uses one shared window and returns no baseline. If `expected2` is often below the default `min_expected` of 100, the feed is too sparse for `STOPPED`/`DEGRADED` during quiet hours. That is intended. Lower `min_expected` only if a 2-hour gap in that feed matters.

`max_silence_hours`: in report mode on 2026-10-09, every model with `prior_expected` ≥ 100 in all four tenants was `continuous` with a longest gap of 0 hours in the 7-day window. The only model with gaps (Tenant B `Endpoint.Ports`, longest gap 44 hours, `prior_expected` 2) is excluded by both `continuous` and `min_expected`. The default of 24 therefore has no live false positives. To check a model's longest silent stretch, run the sizing SPL's first two lines, then `| eval nz=if(ev>0,_time,null()) | streamstats max(nz) as prev | eval gap_h=round((_time-prev)/3600,0) | stats max(gap_h)`. Keep `max_silence_hours` above that value.

To see every model's status at once, copy the rule's `search`, remove the `| where alert=1` line, and run it over `-7d@h` to `-1h@h`.

### Known false positives / Limitations
- **A sustained partial drop becomes the new normal after about 4 days.** A feed that falls to 5% of its usual volume is `DEGRADED` (one notable per day) for about 4 days. After that, 4 of the 6 same-hour values are low, the median follows them and the status returns to `OK` (verified with synthetic feeds: `DEGRADED` after 1 and 4 days, `OK` after 5 and 6 days). This is the nature of a rolling 7-day baseline. A total stop is not affected: it stays `STOPPED` through the long-silence test. Treat a `DEGRADED` notable as a ticket to fix the feed, not as something that will keep reminding you.
- **Business-hours-only feeds.** A feed that only sends on weekday business hours is not `continuous` (it has events in fewer than half of its hours), so the long-silence test never fires for it, and a dead feed of this shape alerts only for the first ~4 days. During weekend daytime hours such a feed can also show `STOPPED` from the first test, because its same-hour median comes from weekdays. No validation tenant has a model like this.
- **Indexer or peer errors during the run.** A run hit by peer read errors or subsearch truncation returns partial counts, and that can briefly look like `DEGRADED`. The 24 h suppression and the next hourly run limit the impact. Partial-result warnings were seen once on Tenant A during a wider 10-day backtest; the scheduled 7-day search ran clean.
- **Acceleration backfill.** After a summary rebuild, `allow_old_summaries=t` reads the old summaries, but a fresh rebuild can leave recent hours empty until it catches up. Check `summary_complete_pct` and the acceleration drilldown before escalating.
- **Dependency discovery is textual.** A rule counts as a dependent only when its title contains ` - HDSI AI ` or ` - HDSI RBA AI ` (case-sensitive) and its own `search` string contains `datamodel=<Model>`. A rule that you renamed, or one that hides `tstats` inside a macro, is not counted. Add its model to `required_models` instead.
- **Legacy DLP model name.** A rule that still references `datamodel=Data_Loss_Prevention` (not a CIM model) fails with a FATAL error until it is moved to `DLP.DLP_Incidents`. This check still counts it as a DLP dependent, so enabling it raises `DLP NOT_ACCELERATED` (or `ABSENT`).
- **Inbound-only data still counts as "available".** On two validation tenants the Web model is mostly inbound server or WAF logs. That is healthy here but useless to user-egress AI detections. This check measures availability, not fitness. Each detection's README covers its data fitness.
- **DLP is not accelerated in any validation tenant.** If you enable a DLP-based AI detection, this check will raise `NOT_ACCELERATED` for `DLP` once per day until you accelerate the model or disable the rule. That is the intended signal.
- **7-day summary range.** The baseline needs 7 days of acceleration summaries. In Tenant A the CIM summaries keep exactly 7 days (`summary.time_range` 604800), so the oldest baseline hours can be partly aged out. With 6 values per hour of day, the median tolerates up to 2 low values. Do not shorten a model's acceleration range below 7 days.
- **Cost.** Measured on 2026-10-09 with all 9 models: 117–141 s per run on Tenant A, 88–122 s on Tenant B, 29–45 s on Tenant C and 21–29 s on Tenant D. If that is too heavy hourly, change `cron_schedule` to `20 */4 * * *`. Keep the `-1h@h` latest time.

### Validation
Live read-only tests on 2026-10-09 across 4 production ES tenants:

| Tenant | Before (v1.1.0 original) | Parses (rule + 3 drilldowns) | Scheduled run (`-7d@h`→`-1h@h`) | Report mode: model status | Dependency discovery | 14-day backtest |
|---|---|---|---|---|---|---|
| A | FATAL: data model `Data_Loss_Prevention` not found; old drilldown showed every model `MISSING` | OK | 0 rows, no errors, 117–118 s | Web, DNS, Traffic, Processes, Filesystem, Ports, Email, Authentication OK; DLP NOT_ACCELERATED | 446 saved searches with `HDSI` in the title, 0 AI-RBA rules | 0 STOPPED / 0 DEGRADED (weekdays only) |
| B | Same FATAL | OK | 0 rows, no errors, 88–96 s | Web, DNS, Traffic, Processes, Authentication OK; Ports OK (sparse); Email and Filesystem ABSENT; DLP NOT_ACCELERATED | 136 `HDSI` titles, 0 AI-RBA | 0 / 0 |
| C | Same FATAL | OK | 0 rows, no errors, 29 s | All OK including Authentication; DLP NOT_ACCELERATED | 211 `HDSI` titles, 0 AI-RBA | 0 / 0 |
| D | Same FATAL | OK | 0 rows, no errors, 21–24 s | All OK including Authentication; DLP NOT_ACCELERATED | 115 `HDSI` titles, 0 AI-RBA | 0 / 0 |

The scheduled runs return 0 rows because no AI-RBA rule is enabled in any of the four tenants, and `required_models` ships empty. That is the correct, quiet outcome. The `search="HDSI"` REST pre-filter returned every `HDSI` title that the unfiltered call returned, in all four tenants.

**Dependency gate.** In an earlier round the full rule was run with the REST rows replaced by four synthetic enabled rules (an AI DNS rule reading `Network_Resolution`, an AI DLP rule reading the legacy `Data_Loss_Prevention`, a non-AI HDSI Email rule, and an RBA AI aggregator reading `Risk`). In every tenant it returned exactly one notable, `DLP NOT_ACCELERATED`, with "1 enabled AI-RBA detection(s) read this data model...". `Network_Resolution` was required but `OK`. `Email`, which is `ABSENT` in Tenant B, did not alert, because only a non-AI rule reads it.

**Outage logic.** The rule's own status SPL was run in all four tenants on synthetic hourly feeds (1000 events per hour) over the scheduled window. Results were identical in every tenant:

| Synthetic feed | Status |
|---|---|
| Stopped 1, 2, 3 or 4 days ago | `STOPPED` (same-hour median test) |
| Stopped 5, 6 or 6.9 days ago | `STOPPED` (long-silence test; the median was already 0) |
| Dropped to 5% 1 or 4 days ago | `DEGRADED` |
| Dropped to 5% 5 or 6 days ago | `OK` (see Limitations) |
| Daytime only (08:00–18:00), 5 events every 6 hours, one 500-event burst 3 days ago, healthy | `OK` |

### Deployment
The package ships with `enable_alerting: false`. Before enabling it:
1. Run the report-mode variant to confirm that every model your enabled AI-RBA detections read is `OK`.
2. Decide whether any model belongs in `required_models`.
3. Confirm that the hourly runtime is acceptable.

The rule creates audit-domain notables only (`action.risk = 0`, `action.email = 0`). Enabling it is a separately approved change and should be made alongside enabling the AI-RBA detections it monitors.
