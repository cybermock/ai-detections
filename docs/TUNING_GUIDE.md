# Tuning Guide

Threshold calibration, allowlist management, false positive reduction, and performance tuning for the AI RBA Detection Pack.

## Day 1 Quick Start

Don't tune anything on day one. Seriously.

1. **Deploy with defaults.** The pack ships with conservative thresholds that work across most environments.
2. **Observe for 1-2 weeks.** Let detections fire and risk accumulate. Watch what patterns emerge.
3. **Allowlist first.** The single biggest win is populating `ai_sanctioned_entities.csv` with known-approved users and teams. This eliminates most false positives without weakening detection.
4. **Then calibrate.** Use the queries in this guide to set thresholds that match your environment's actual usage patterns.
5. **Tighten gradually.** Adjust one threshold at a time. Monitor notable volume after each change.

> [!TIP]
> **Target notable volume:** 1-5 high-severity notables/day, 5-15 medium-severity notables/day. More than this means thresholds are too low or allowlists need expansion. Fewer means thresholds are too high or data sources are missing.

## Per-Threshold Calibration

All thresholds live in `lookups/ai_detection_config.csv`. Changes take effect on the next detection run (within 5-15 minutes for most detections).

## Per-Threshold Calibration

All thresholds are configured in `lookups/ai_detection_config.csv`. Changes take effect on the next detection run (within 5-15 minutes for most detections).

### Health Monitoring Email Recipient

Health searches now read the alert destination from `ai_detection_config.csv` using control `alert_email_to`.

**Default:** `soc-alerts@company.com`

Update this value to your SOC distribution list so these searches alert the correct recipients:
- `AI RBA - Health - Lookup Staleness Alert`
- `AI RBA - Health - Data Model Availability`

### AI-007: Upload Volume Tiers

**What it controls:** The data volume thresholds (in MB) for tiered risk scoring on uploads to AI services.

**Defaults:** 1 MB (low/20 risk), 5 MB (medium/40 risk), 10 MB (high/60 risk), 50 MB (critical/80 risk).

**How to calibrate:**

```spl
| tstats summariesonly=t sum(Web.bytes_out) as bytes_out
  from datamodel=Web where Web.url_domain=* earliest=-7d latest=now
  by Web.user Web.url_domain _time span=15m
| rename Web.* as *
| eval ai_domain=lower(url_domain)
| lookup ai_provider_domains domain as ai_domain OUTPUTNEW provider enabled
| where enabled=1
| stats sum(bytes_out) as window_bytes by user provider _time
| eval window_mb=round(window_bytes/1024/1024,2)
| where window_mb > 0
| stats
    perc50(window_mb) as p50_mb
    perc75(window_mb) as p75_mb
    perc90(window_mb) as p90_mb
    perc95(window_mb) as p95_mb
    perc99(window_mb) as p99_mb
    max(window_mb)    as max_mb
    count             as total_windows
```

> [!TIP]
> Set tier 1 above p90 (most normal usage won't fire), tier 2 at p95, tier 3 at p99, and tier 4 well above observed max during normal operations.

**Example adjustment for a development-heavy organization:**

```csv
control_name,value,notes
upload_tier1_mb,5,Raised from 1: developers upload code context regularly
upload_tier2_mb,15,Raised from 5: large codebases generate more data
upload_tier3_mb,50,Raised from 10: repository-level uploads
upload_tier4_mb,200,Raised from 50: only full database exports should hit this
```

### AI-010: Burst Request Count

**What it controls:** The number of requests to AI providers in a 15-minute window that triggers the burst detection.

**Default:** 10 requests.

**How to calibrate:**

```spl
| tstats summariesonly=t count
  from datamodel=Web where Web.url_domain=* earliest=-7d latest=now
  by Web.user Web.url_domain _time span=15m
| rename Web.* as *
| eval ai_domain=lower(url_domain)
| lookup ai_provider_domains domain as ai_domain OUTPUTNEW provider enabled
| where enabled=1
| stats sum(count) as window_requests by user _time
| stats
    perc50(window_requests) as p50
    perc75(window_requests) as p75
    perc90(window_requests) as p90
    perc95(window_requests) as p95
    perc99(window_requests) as p99
    max(window_requests)    as max
```

> [!TIP]
> Modern AI chat interfaces generate 5-20 subrequests per user interaction (XHR, WebSocket, polling). API users generate far more. Set at p90-p95 for your environment. Typical adjustment: 10 -> 25 for heavy AI API usage.

### AI-015: After-Hours Window

**What it controls:** The hours (24-hour format) that define "after hours" for AI usage detection.

**Default:** Start = 20 (8 PM), End = 6 (6 AM). Weekends are always flagged.

**How to calibrate:**

```spl
| tstats summariesonly=t count
  from datamodel=Web where Web.url_domain=* earliest=-30d latest=now
  by Web.user _time span=1h
| rename Web.* as *
| eval ai_domain=lower(url_domain)
| lookup ai_provider_domains domain as ai_domain OUTPUTNEW provider enabled
| where enabled=1
| eval hour=tonumber(strftime(_time,"%H")), dow=tonumber(strftime(_time,"%u"))
| where dow<=5
| stats sum(count) as requests by hour
| sort hour
```

> [!TIP]
> Set after-hours start after the last hour with significant activity, and end before the first. For global organizations, consider timezone-specific configurations or user-level timezone data.

**Example for a company with developers working until 10 PM:**

```csv
control_name,value,notes
after_hours_start,22,Adjusted from 20: developers regularly work until 10 PM
after_hours_end,5,Adjusted from 6: early arrivals start at 5 AM
```

### AI-RISK-001/002: Risk Thresholds

**What it controls:** The cumulative risk score (over 24 hours) that triggers medium and high notable events.

**Defaults:** Medium = 60, High = 90.

**How to calibrate:**

```spl
index=risk search_name="AI RBA - *" risk_object_type="user" earliest=-30d
| bin _time span=24h
| stats sum(risk_score) as daily_risk dc(search_name) as unique_detections by risk_object _time
| where daily_risk > 0
| stats
    perc50(daily_risk)  as p50
    perc75(daily_risk)  as p75
    perc90(daily_risk)  as p90
    perc95(daily_risk)  as p95
    perc99(daily_risk)  as p99
    max(daily_risk)     as max
    count               as user_days
```

> [!TIP]
> Medium threshold: above p90 of daily user risk scores (background noise stays below). High threshold: above p95-p99 (only genuinely concerning accumulations fire). Too many notables? Raise both. Too few? Lower thresholds or check if detections are generating risk correctly.

### AI-017: Volume Anomaly Z-Score

**What it controls:** The number of standard deviations above the user's historical mean that triggers the anomaly detection.

**Default:** Z-score = 3.0 (approximately 0.13% probability under normal distribution).

**How to calibrate:**

```spl
| tstats summariesonly=t count from datamodel=Web
  where Web.url_domain=* earliest=-30d by Web.user Web.url_domain _time span=1d
| rename Web.* as *
| eval ai_domain=lower(url_domain)
| lookup ai_provider_domains domain as ai_domain OUTPUTNEW provider enabled
| where enabled=1
| stats sum(count) as daily_requests by _time user
| eventstats avg(daily_requests) as mean stdev(daily_requests) as stdev count as days by user
| where days >= 14
| eval z=if(stdev>0, round((daily_requests-mean)/stdev, 2), 0)
| stats perc90(z) as p90 perc95(z) as p95 perc99(z) as p99 max(z) as max
```

> [!TIP]
> Z-score 2.0 = flags ~2.3% of days (sensitive). Z-score 3.0 = flags ~0.13% (default, balanced). Z-score 4.0 = extreme outliers only. Also adjust `volume_anomaly_min_days` if users have sparse baseline data.

## Allowlist Management

The `ai_sanctioned_entities.csv` lookup serves as the centralized allowlist. All detections pass through the `ai_unsanctioned_filter` macro, which checks this lookup before generating risk.

### Adding User Allowlist Entries

**Provider-specific (recommended):**
```csv
entity_type,entity,provider,scope,expires,owner,reason,enabled,allow_key
user,alice@corp.com,OpenAI,provider,2026-06-30,security_lead,approved_chatgpt_for_research,1,alice@corp.com|openai
```

**All providers (use sparingly):**
```csv
user,alice@corp.com,*,global,2026-06-30,ciso,approved_all_ai_access,1,alice@corp.com|*
```

### Adding System/IP Allowlist Entries

```csv
entity_type,entity,provider,scope,expires,owner,reason,enabled,allow_key
system,10.20.30.40,*,subnet,2026-12-31,soc_lead,approved_dev_jumpbox,1,10.20.30.40|*
system,BUILD-SRV-01,OpenAI,global,2026-12-31,devops,cicd_openai_integration,1,build-srv-01|openai
```

### Group-Based Allowlisting

Group-based entries match against the `user_group`, `user_category`, `category`, or `bunit` fields in your events. These fields must be populated by your identity framework or data enrichment.

```csv
entity_type,entity,provider,scope,expires,owner,reason,enabled,allow_key
group,engineering,*,group,2026-12-31,ciso,approved_ai_for_all_engineers,1,engineering|*
group,data_science,OpenAI,group,2026-06-30,ds_lead,approved_openai_for_ds_team,1,data_science|openai
```

### Setting Expiration Dates

All allowlist entries should have an expiration date in `YYYY-MM-DD` format. This ensures periodic review of approved access.

- **Short-term (30-90 days):** Individual user exceptions, trial access, project-based access.
- **Medium-term (6-12 months):** Team-level approvals, established workflows.
- **Long-term (2099-12-31):** Infrastructure entries (build servers, security tools) that should persist indefinitely.

To find expired entries:

```spl
| inputlookup ai_sanctioned_entities.csv
| where expires!="" AND strptime(expires,"%Y-%m-%d") < now()
| table entity_type entity provider expires owner reason
```

### Bulk Import Guidance

For large-scale allowlisting (e.g., onboarding a department):

1. Export the current CSV: `| inputlookup ai_sanctioned_entities.csv | outputcsv ai_sanctioned_entities_backup.csv`
2. Prepare new entries in a spreadsheet following the CSV schema.
3. Ensure each entry has a unique `allow_key` (format: `entity_lowercase|provider_lowercase`).
4. Append new entries to the CSV and upload to `lookups/ai_sanctioned_entities.csv`.
5. Verify the import: `| inputlookup ai_sanctioned_entities.csv | stats count by entity_type`

## False Positive Reduction Strategies

> [!NOTE]
> **Target volume:** If you're seeing more than 5 high-severity or 15 medium-severity notables per day, work through these strategies in order. Strategy 1 alone resolves most FP issues.

### Strategy 1: Allowlist sanctioned users first

The single most effective tuning action. Populate the allowlist with known-approved users and teams. This eliminates the vast majority of false positives without reducing detection sensitivity for unsanctioned users.

### Strategy 2: Adjust thresholds for your environment

Use the calibration queries above to set thresholds that match your organization's baseline. A threshold set at the p90 of normal usage means only 10% of legitimate activity exceeds it.

### Strategy 3: Filter by data source accuracy

If a specific data source (proxy, EDR) generates inaccurate fields (e.g., incorrect user attribution, inflated bytes_out), address the data quality issue at the source rather than weakening the detection.

### Strategy 4: Tune detection overlap

If the same user action consistently triggers 3+ low-scoring detections and pushes them over the risk threshold, consider:
- Lowering individual detection risk scores (edit `action.risk.param._risk` in savedsearches.conf).
- Raising the risk thresholds.
- Adding more granular allowlist entries.

### Strategy 5: Leverage suppression

All detections use `alert.suppress` to prevent repeat alerting. If a detection fires too frequently for the same user:
- Add them to the allowlist (preferred).
- Increase the suppress period (last resort).

## Performance Tuning

### Scheduling Optimization

| Issue | Recommendation |
|---|---|
| High search concurrency during peak hours | Stagger detection start times by 30-60 seconds to avoid search queue saturation |
| AI-017 (volume anomaly) runs slowly | Ensure it runs during off-peak hours (default: 3:30 AM). Consider narrowing to 14-day lookback instead of 30. |
| AI-009 (first-seen) uses 30-day lookback | Ensure Web data model acceleration covers 30+ days |

### Data Model Acceleration

Accelerating the relevant data models significantly improves detection performance:

```
[Web]
acceleration = true
acceleration.earliest_time = -30d

[Endpoint.Processes]
acceleration = true
acceleration.earliest_time = -7d

[Network_Resolution]
acceleration = true
acceleration.earliest_time = -7d

[Network_Traffic]
acceleration = true
acceleration.earliest_time = -7d
```

Verify acceleration status:

```spl
| rest /services/datamodel/acceleration
| search title IN ("Web","Endpoint","Network_Resolution","Network_Traffic","Data_Loss_Prevention")
| table title acceleration.is_done acceleration.last_duration_secs
```

### Search Time Windows

Most detections use a 15-minute lookback (`-15m@m` to `now`) with a 5-minute schedule. This creates a 10-minute overlap between runs, ensuring events are not missed if a search run is delayed. If search performance is a concern:

- **Do not reduce the lookback window** below the schedule interval (e.g., do not use `-5m` with a `*/5` schedule, as you risk missing events).
- Consider extending the schedule interval to `*/10` or `*/15` for lower-priority detections while keeping the lookback proportionally larger.

### Lookup Performance

If lookup performance degrades as `ai_sanctioned_entities.csv` grows large (1000+ entries):

1. Ensure the lookup is configured with `case_sensitive_match = false` in transforms.conf (already set).
2. Consider splitting allowlists by entity_type if the file exceeds 5000 entries.
3. Use the KV Store instead of CSV for very large allowlists (requires modifying the macro).
