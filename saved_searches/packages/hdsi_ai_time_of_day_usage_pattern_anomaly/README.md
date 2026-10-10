## Architect Notes
---
**Author:** Trevor Mock, Hurricane Labs LLC. Security Operations Architect

This rule finds **identified users who made sustained use of AI web services at an hour of the day that is new for them**. Each user is compared with their own hourly histogram, not with a fixed business-hours clock. Night-shift staff who always work at 02:00 stay quiet, while a day worker whose account suddenly drives 60 ChatGPT requests at 03:00 is flagged. A new hour is not malicious by itself. It can point to a shared or compromised account, an unattended script using a person's session, or data being moved when nobody is watching, so it adds context to a user who is already collecting risk. The rule runs once a day for the previous day and creates low risk on `user` (15, scaled, capped at 40). It creates no notable.

v1.0 returned 0 rows on all four validation tenants, and its design had these defects:

- **Zero-activity hours were left out of the baseline (AI-041).** It built `stats ... by user hour day`, so an hour in which the user did nothing on a given day was not a data point. Mean and stdev were computed only over days on which the user was already active at that hour, and `datapoints>=7` required at least 7 such days. An hour the user had never used therefore could never be scored, which is exactly the anomaly the rule is meant to find. What it measured was a per-hour volume spike, not a time-of-day change.
- The evaluated day was part of its own baseline, and "today" meant a partial day up to 04:40.
- It split `tstats` by `Web.url_domain` and `Web.site` without `fillnull_value`. Most proxies fill only one of those fields, so every row was dropped on the SSE tenant (`url_domain` empty).
- It read 30 days of the whole Web data model at 1-hour resolution with no pre-filter. That hit the 300 s test cap on two tenants (6.8 billion events scanned on one).
- It set `src="unknown"` and `provider="Multiple"`, so per-provider approvals in `ai_sanctioned_entities` could never match. It also counted IDE plugins and background calls from idle browser tabs, which run at any hour.
- The MITRE mapping was T1567.002 (Exfiltration to Cloud Storage). AI chat services are not cloud storage.

### Prerequisites
| Data | Fields used | If absent |
|---|---|---|
| `Web` data model (accelerated) from an **egress** web proxy, firewall URL log, SWG or SSE/CASB | `user`, `url_domain` and/or `site`, `_time` | No `Web` data, or only inbound server logs (load balancer, WAF, IIS): no rows. Inbound logs never resolve to an AI provider |
| `Web.user` populated | `user` | Rows without a user are dropped. A time-of-day pattern only means something for a person, so the rule never scores an IP address |
| `Web` acceleration summary range of at least the dispatch window (15 days) | `summariesonly=t` | The baseline is shorter than intended. With a 7-day summary range (one validation tenant) the baseline is 6 days. Check it with the REST search under Threshold |

- `site` may be a hostname or an SSE application name (for example Netskope `site` = "Microsoft Copilot Studio"). When `url_domain` is empty, the rule sets `ai_input_type=app`, so application names resolve through `ai_provider_apps`.
- **Common package** (`hdsi_ai_rba_common`, required): `ai_domains_filter` (the `ai_provider_domains` and `ai_provider_apps` lookups), `ai_unsanctioned_filter(3)` (`ai_sanctioned_entities` approvals) and `ai_risk_multiplier` (ES `identity_lookup_expanded` `bunit` with `ai_department_sensitivity`).
- ES `identity_lookup_expanded` supplies `bunit` for group approvals and the multiplier. Users without an identity keep a multiplier of 1.0.
- This rule no longer reads `time_anomaly_zscore` from `ai_detection_config`. Every threshold is now a named macro.

### How it works
- **Collection:** one daily `tstats` over `Web`, from `-15d@d` to `@d`, in 1-hour buckets by `user`, `url_domain` and `site`, with `fillnull_value="unknown"` and `Web.user!="unknown"`. The inline `..._prefilter` macro limits `tstats` to exact AI web hostnames and SSE application names from the common lookups, which is what makes a multi-week hourly read affordable. Placeholder users (`-`, `n/a`, empty) are dropped.
- **Provider resolution:** `ai_domains_filter` resolves each `user`/`ai_domain`/hour row. Only `usage_type` values in `..._usage_types` (default `"web"`) are kept, and hostnames matching `..._background_hosts` (`ab.chatgpt.com`, `bzrcdn.openai.com`, `gemini.gstatic.com`, `sentry-*` and similar) are removed before the histogram is built. Approved user, group or provider pairs are removed with `ai_unsanctioned_filter(user,src,provider)`, after an identity `bunit` lookup.
- **Evaluated day and baseline:** the last whole day of the window (yesterday) is the evaluated day. All earlier days form the baseline (14 days by default). `baseline_days` counts the days on which the user used AI web services at all.
- **Zero-filled hourly histogram (fix for AI-041):** each baseline hour is counted for its own hour and for the hours either side of it (plus or minus one hour), which absorbs daylight-saving shifts and slightly early or late sessions. For each user and hour of the day, mean and stdev are computed over **all** `baseline_days`, so a day with no activity at that hour counts as 0. `usual_days` is the number of baseline days with activity within an hour of that time.
- **New-hour test:** an hour on the evaluated day is anomalous when all of these hold: the user has `baseline_days >= ..._min_baseline_days` (5), made `>= ..._min_requests` (20) foreground requests in that hour, was active near that hour on `<= ..._max_usual_days` (1) baseline days, and the hour's z-score against the zero-filled baseline (stdev floored at 1 request) is `>= ..._zscore` (3). The z-score test removes hours where a single earlier day already had heavy use.
- **Aggregation:** one row per user with `anomalous_hours` (search time zone), `anomalous_hour_count`, `anomalous_requests`, `z_score` (highest), `usual_days`, `baseline_days`, `usual_hours` (hours active on at least 25% of baseline days, for the analyst), `provider_list`, `ai_domains` and `eval_day`.
- **Scoring:** base 15 x the highest provider `severity_weight` (0.3 to 1.2) x `risk_multiplier` (1.0 to 2.0). `risk_score = min(40, max(1, round(...)))` applies to `user`, the only risk object. The literal `_risk` fallback is 15.
- **Time zone:** hours are read in the time zone of the saved-search owner. Because each user is compared with their own history in the same clock, the result does not depend on that zone. Only the hour labels in the risk message do, and the message says "search time zone".
- **Suppression:** 23 h per `user` (`82800s`), which allows one risk event per user per daily run.

### Tuning macros
| Macro | Ships as | Purpose |
|---|---|---|
| `hdsi_ai_time_of_day_usage_pattern_anomaly_filter` | `()` | Exclusions inside the `tstats` where clause (`Web.*` names), e.g. `NOT Web.user IN ("svc_*")` for service or shared accounts |
| `hdsi_ai_time_of_day_usage_pattern_anomaly_prefilter` | exact AI web names and app names | Inline `tstats` pre-filter generated from the enabled `web` rows of the common lookups. Regenerate it with the SPL below when web rows are added or `..._usage_types` is widened |
| `hdsi_ai_time_of_day_usage_pattern_anomaly_usage_types` | `"web"` | `usage_type` values that count as personal use. IDE assistants, API endpoints and model registries are called by tools that run unattended |
| `hdsi_ai_time_of_day_usage_pattern_anomaly_background_hosts` | regex | AI hostnames that idle tabs and apps call (experiment flags, static assets, telemetry, sign-in). Removed before the histogram is built |
| `hdsi_ai_time_of_day_usage_pattern_anomaly_min_baseline_days` | `5` | AI-active baseline days a user needs before being scored. Raise to about 10 with a 28-day window |
| `hdsi_ai_time_of_day_usage_pattern_anomaly_max_usual_days` | `1` | Baseline days with activity within an hour of the time that still count as "new". Use `0` for never-seen hours only |
| `hdsi_ai_time_of_day_usage_pattern_anomaly_min_requests` | `20` | Foreground AI web requests in one new hour (see Threshold). Use about `3` on SSE connection logs |
| `hdsi_ai_time_of_day_usage_pattern_anomaly_zscore` | `3` | Minimum z-score of the hour against the zero-filled baseline |
| `hdsi_ai_time_of_day_usage_pattern_anomaly_customizations` | `search *` | Post-aggregation hook (`user`, `provider`, `provider_list`, `ai_domains`, `eval_day`, `anomalous_hours`, `anomalous_hour_count`, `anomalous_requests`, `z_score`, `usual_days`, `baseline_days`, `usual_hours`, `bunit`, `severity_weight`, `risk_multiplier`, `base_score`, `risk_score`) |
| `hdsi_ai_time_of_day_usage_pattern_anomaly_risk_score` | `search *` | Last pipe. Override `risk_score` (1 to 100) here |

The baseline length is set by `dispatch.earliest_time` (`-15d@d` = 14 baseline days plus the evaluated day). Widen it to `-29d@d` where the Web acceleration summary covers 29 days and the cost is acceptable, and raise `..._min_baseline_days` to match. Per-user or per-group approvals (for example a sanctioned enterprise assistant) go in `ai_sanctioned_entities` in the common package, keyed `<user or bunit>|<provider>` or `<entity>|*`.

**Regenerating the pre-filter.** Run this and paste the `search` value as the macro definition:

```spl
| inputlookup ai_provider_domains | where enabled=1 AND usage_type="web"
| eval d=lower(trim(domain)), t=mvappend(d, if(match(d,"^www\."), null(), "www.".d))
| stats values(t) as t
| eval dom=mvjoin(mvmap(t, "\"".t."\""), ",")
| appendcols [| inputlookup ai_provider_apps | where enabled=1 AND usage_type="web" | eval a="\"".lower(trim(app_name))."\"" | stats values(a) as a | eval app=mvjoin(a, ",")]
| eval search="(Web.url_domain IN (".dom.") OR Web.site IN (".dom.",".app."))"
| fields search
```

Exact terms are used on purpose. A version with leading-wildcard terms (`*.chatgpt.com`) took 233 s for one day on a tenant with high-cardinality inbound Web data, slower than no filter. Exact terms took 11 to 19 s per day. The cost is that subdomains that are not their own lookup row (for example `ws.chatgpt.com`) are not counted. The main hosts carry the interactive use.

### Threshold
`..._min_requests` is counted in Web data model events, so the right value depends on how verbose the proxy is. On the validation tenant with firewall URL logs, a user's AI web requests per active hour were 3 at the median, 17 at p90, 69 at p98 and 134 at p99 over 7 days (27,730 user-hours, about 9,900 users). 20 is about p92. On the SSE tenant, connection logs record about one event per session, and a user's busiest hour never exceeded 9 events (p99 6), so 20 can never fire there. Use about 3 on that kind of source. Derive the tenant value from the user-hour distribution, and check the summary range:

```spl
| tstats summariesonly=t allow_old_summaries=t fillnull_value="unknown" count from datamodel=Web
    where `hdsi_ai_time_of_day_usage_pattern_anomaly_prefilter` Web.user!="unknown" by Web.user Web.url_domain Web.site _time span=1h
| rename Web.* as *
| eval ai_domain=lower(coalesce(nullif(url_domain,"unknown"),nullif(site,"unknown"))), ai_input_type=if(isnull(nullif(url_domain,"unknown")),"app","host")
| `ai_domains_filter`
| search usage_type IN (`hdsi_ai_time_of_day_usage_pattern_anomaly_usage_types`)
| where NOT match(ai_domain, `hdsi_ai_time_of_day_usage_pattern_anomaly_background_hosts`)
| stats sum(count) as req by user _time
| eval day=strftime(_time,"%F") | eventstats dc(day) as active_days by user
| stats count as user_hours dc(user) as users dc(eval(if(active_days>=5,user,null()))) as users_5_days perc50(req) as p50 perc90(req) as p90 perc98(req) as p98 perc99(req) as p99
```

```spl
| rest /services/admin/summarization by_tstats=t splunk_server=local count=0
| search summary.id=*Web*
| eval summary_days=round('summary.time_range'/86400,0)
| table summary.id summary.complete summary_days
```

Run the first search over 7 days. Set `..._min_requests` near p90 to p95. A lower value finds more users and more noise.

### Known false positives / Limitations
- **Evening and weekend use by day workers.** Most rows in validation were ChatGPT or Gemini use late in the evening or after midnight in the search time zone, by users whose usual hours were daytime. That is the intended signal, but it is often benign (working from home, travel). The score is kept low for that reason.
- **Travel and time-zone changes.** A user working from another time zone shifts their whole pattern for a few days. Expect a row on the first day.
- **Thin history.** The rule needs `..._min_baseline_days` AI-active days. New AI users and occasional users are never scored. On the busiest tenant, 224 of 2,866 daily AI users met the default of 5, with a 6-day effective baseline.
- **Short acceleration ranges.** A tenant whose Web summary covers only 7 days gets a 6-day baseline whatever the dispatch window. The REST search under Threshold shows the range.
- **No user, no risk.** On the firewall-URL tenant, about 80% of AI web events had no `user`. Those events cannot raise risk here.
- **Exact-name pre-filter.** Subdomains that are not their own lookup rows are not counted (see Tuning). Regenerate the pre-filter when the common lookups change.
- **IDE and API traffic is excluded on purpose.** IDE assistants (GitHub Copilot was the densest AI signal on the SSE tenant: 242 users, about 4,000 user-hours a week) keep calling home while the IDE is open, at any hour.
- **Cost.** One run read 14 days in about 90 s on the largest proxy tenant and about 170 s on a tenant whose Web model is dominated by inbound load-balancer logs. Most of that is the pre-filtered `tstats`. On such tenants, consider excluding inbound sourcetypes in `..._filter`.

### Validation
Read-only tests on 4 production ES tenants, 2026-10-09. The v1.1 runs use the shipped dispatch window (`-15d@d` to `@d`, evaluated day 2026-10-08).

| Tenant | Web data reality | Parses (search + 2 drilldowns) | v1.0 run (30 days) | v1.1 real run | Notes |
|---|---|---|---|---|---|
| A | Firewall URL/threat logs, `url_domain` set, `site` empty, about 20% of AI events carry a user. Web summary range 7 days | OK | Not completed: the test harness timed out waiting for this tenant (no pre-filter, 30 days at 1-hour resolution) | 4 rows, 86-91 s. Scores 15 | 2,866 users with AI web use on the evaluated day, 224 with 5+ baseline days, 44 of those over 20 requests in some hour, 5 of them in a new hour, 4 after the z-score test. Rows: ChatGPT at 02:00 to 03:00 or 23:00 and Gemini at 00:00 for users whose usual hours were daytime |
| B | Inbound load-balancer/WAF logs plus a small cloud proxy, no `user` on any AI row | OK | 0 rows, hit the 300 s cap (6.8 billion events scanned) | 0 rows, 168-177 s | Expected silence. No user-attributed AI web use |
| C | SSE/CASB connection logs, `site` = application name, `url_domain` empty, `user` 100% | OK | 0 rows, 5 s (every row dropped by the `url_domain`/`site` split) | 0 rows, 4 s | 43 AI web users a day, 1 to 9 events per user-hour. With `..._min_requests` = 3, 1 user qualified. GitHub Copilot (IDE) excluded by `..._usage_types` |
| D | Inbound IIS logs only | OK | 0 rows, 4 s | 0 rows, 3 s | No data path |

No FATAL or ERROR messages on any tenant. The `user` drilldown reads only AI web names through the pre-filter and returns the user's hourly AI activity per day and hour (baseline and evaluated day).

Expected daily volume at one run a day: tenant A about 4 risk events a day at about 15 points, B none, C none at the default (about 1 a day with `..._min_requests` = 3), D none.

### Deployment
The package ships with `enable_alerting: false`. Before enablement:

1. Confirm that `Web` holds egress proxy or SSE data with `user` populated for AI hostnames or applications, and check the Web acceleration summary range.
2. Derive `..._min_requests` with the Threshold search (about 3 for SSE connection logs).
3. Decide the baseline length (`dispatch.earliest_time`) and set `..._min_baseline_days` to match.
4. Load approvals for shift workers, service accounts and sanctioned enterprise assistants into `ai_sanctioned_entities`, or exclude them in `..._filter`.
5. Run the search for several days and confirm the daily risk volume and the runtime.

The rule is risk-only (no notable) and is meant to strengthen other AI-RBA signals, not to stand alone. Enabling it, and disabling any rule it replaces, is one separately approved change.
