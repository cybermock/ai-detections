## Architect Notes
---
**Author:** Trevor Mock, Hurricane Labs LLC. Security Operations Architect

This rule finds **identified users who use AI web services repeatedly, or send them a lot of data, outside business hours**. The default after-hours window is before 06:00, from 20:00, and all of Saturday and Sunday, on a business-hours clock that the tenant must set. Only requests the proxy **allowed** count: blocked attempts never reached the provider, so they are reported in the message but never qualify a user. After-hours use is not malicious by itself. It is a context signal: data sent to an AI service at 02:00 or on a Sunday is less likely to be seen and less likely to be for an approved purpose, so it adds a little weight to a user who is already collecting risk. The rule creates low risk on `user`, normalised to the bare account name so it adds to the same risk object as other detections (10, or 20 when 5 MB or more was sent, scaled, capped at 40). It emits at most one request event and one upload event per user per day, and no notable.

**The rule emits nothing until `hdsi_ai_after_hours_service_usage_utc_offset` is set**, and it ships as `deployment_type: adhoc` for that reason (see Deployment). Without a configured clock it cannot tell after hours from working hours. Splunk Cloud runs scheduled searches in UTC by default, and on a US tenant UTC 20:00 is mid-afternoon.

v1.0 returned 0 rows on all four validation tenants, and its design had four defects:

- It split `tstats` by `Web.url_domain` and `Web.site` without `fillnull_value`. Rows lacking either field were dropped, and most proxies fill only one of them.
- It read the hour from the search head's time zone. That is UTC on two of the tenants, so "20:00" was mid-afternoon for their users.
- It counted every AI hostname and every action, including IDE plugins, the background calls of idle browser tabs and requests the proxy blocked.
- It put `$token$` values in `risk_score`, which ES does not support, and it raised risk on `unknown` users and sources.

### Prerequisites
| Data | Fields used | If absent |
|---|---|---|
| `Web` data model (accelerated) from an **egress** web proxy, SWG or SSE/CASB | `user`, `src`, `url_domain` and/or `site`, `action`, `bytes_out` | No `Web` data, or only inbound server logs (load balancer, WAF, IIS): no rows. Inbound logs never match AI provider hostnames |
| `Web.user` populated by the proxy | `user` | Rows without a user are dropped. This rule raises user risk only, because an after-hours IP address is not a useful risk object. On a proxy without user identity the rule stays silent |
| `Web.action` (CIM `allowed` / `blocked`) | `action` | Without it every request counts as allowed (`fillnull_value="unknown"`). A proxy that blocks AI services but does not map `action` would then raise risk for traffic that never reached the provider |
| `Web.bytes_out` | `bytes_out` | Only the request-count path works. The upload path (5 MB and score 20) never fires. This was the case for PAN-OS URL logs in validation |

- `site` may be a hostname or an SSE application name (Netskope `site` = "Microsoft 365 Copilot"). The rule sets `ai_input_type=app` when `url_domain` is empty, so application names resolve through `ai_provider_apps`.
- **Common package** (`hdsi_ai_rba_common`, required): `ai_domains_filter` (the `ai_provider_domains` and `ai_provider_apps` lookups, including the `traffic_class` flag), `ai_unsanctioned_filter(3)` (`ai_sanctioned_entities` approvals; it looks up the identity `bunit` itself) and `ai_risk_multiplier` (ES `identity_lookup_expanded` `bunit` with `ai_department_sensitivity`, bare-name fallback).
- Users without an identity keep a multiplier of 1.0 and can only be approved per user, per host or organisation-wide.
- Splunk 8.0 or later (`mvmap`, `mvsort`). ES 8 meets this.
- This rule does not read `after_hours_start` and `after_hours_end` from `ai_detection_config`. The window is the `..._after_hours` macro.

### How it works
- **Collection:** hourly `tstats` over `Web`, `-65m@m` to `-5m@m`. It uses `fillnull_value="unknown"` and `Web.user!="unknown"` inside the where clause, and splits by `user`, `src`, `url_domain`, `site`, `action` and 10-minute `_time` periods (up to 7 per window). Placeholder users (`-`, `n/a`, empty) are dropped.
- **User normalisation:** the proxy value is kept as `user_raw`, and `user` becomes the account name with any `DOMAIN\` prefix removed (UPNs are kept as they are). On Tenant A, where the proxy logs `DOMAIN\user`, the risk index holds about 12,000 bare-name user objects and 2 `DOMAIN\user` objects in 24 h, so the raw form would build risk on an object nothing else uses. The bare `user` is the risk object, the approval key and the identity key; `user_raw` is only used for the web drilldown.
- **Business-hours clock first:** `..._local_clock` gives every period a `local_hour`, `local_dow` and `local_tz`. They come from `..._utc_offset` (standard-time offset in hours) plus `..._dst_rule` (`us`, `eu` or `none`), or from the saved-search owner's time zone when the offset is `"owner"`. While the offset is unset (`null()`, the shipped value) the clock is empty and `..._after_hours` drops every row. During business hours the search also drops every row here, before any lookup runs.
- **Blocked requests:** an `action` in `..._blocked_actions` (CIM `blocked`, plus vendor values such as `deny`, `drop`, `reset-both`) marks the request as blocked. Blocked requests and their bytes never count toward any threshold. They appear only as `blocked_requests` in the risk message, and only for users who also qualified on allowed traffic. Other values (`allowed`, PAN-OS `Reported`, Netskope `isolate`, `unknown`) count as allowed.
- **Provider resolution:** rows are collapsed per `user`, `src` and `ai_domain` and resolved with `ai_domains_filter`, using `url_domain`, or `site` when `url_domain` is empty. Only `usage_type` values in `..._usage_types` (default `"web"`) are kept. That excludes IDE assistants, raw API endpoints and model registries, which call home whenever a tool is running.
- **Background hosts:** a host is background when the common registry marks it `ai_traffic_class="background"` (`ab.chatgpt.com`, `bzr.openai.com`, `bzrcdn.openai.com`, `gemini.gstatic.com`, the QuillBot extension streams, Copilot telemetry) or when it matches `..._background_hosts` (static and CDN assets, `sentry-*`, streaming and sign-in hosts not in the registry). Its requests count in `total_requests` and `mb_out` but not toward `min_requests` or `min_buckets`.
- **Approvals:** `ai_unsanctioned_filter(user,src,provider)` removes per-user, per-host, per-group (identity `bunit`, looked up by the common macro) and organisation-wide (`*|<provider>`) approvals.
- **Aggregation:** one row per user per window. Fields: `request_count` (allowed requests to foreground hosts), `active_buckets` (10-minute periods with allowed foreground requests), `total_requests` (allowed, including background), `blocked_requests`, `action` (allowed action values seen), `mb_out` (allowed requests only), `provider_list` and `ai_domains` (up to 10, providers with allowed traffic only), `src` (up to 3), `local_start`, `local_end` and `local_tz`, and `after_hours_reason` (`weekend` or `outside business hours`).
- **Threshold:** a row is kept when `request_count >= ..._min_requests` (default 50) **and** `active_buckets >= ..._min_buckets` (default 2), **or** when `mb_out >= ..._upload_mb` (default 5). The bucket condition stops a single page load from qualifying: PAN-OS logs 50 to 60 events for one page in about 15 seconds. `signal_type` is `upload` when the upload threshold is met, otherwise `requests`.
- **Scoring:** base 10, or 20 for `upload`. The base is multiplied by the highest `severity_weight` (0.3 to 1.2) of the providers with allowed traffic and by `risk_multiplier` (1.0 to 2.0). `risk_score = min(40, max(1, round(base x weight x multiplier)))`, and it applies to `user`, the only risk object. The literal `_risk` fallback is 10. Low-weight providers score below 10 (QuillBot at 0.5 gives 5, a Microsoft Copilot plus OpenAI row gives 8).
- **Suppression:** 24 h per `user` and `signal_type` (`86400s`). A user raises at most one request event and one upload event a day, so a low-value request event in the evening cannot hide a later 5 MB upload by the same user.
- **Drilldowns:** the risk drilldown filters on the normalised `user`. The web drilldown filters on `drilldown_user`, which is the first `user_raw` value with `\` and `"` replaced by `*`, because a raw `DOMAIN\user` token in a quoted SPL string loses its backslash and matches nothing. It lists every action, so blocked attempts are visible to the analyst.

### Tuning macros
| Macro | Ships as | Purpose |
|---|---|---|
| `hdsi_ai_after_hours_service_usage_utc_offset` | `null()` | **Required.** Business-hours time zone as the standard (winter) UTC offset in hours: `-5` US Eastern, `-6` US Central, `-8` US Pacific, `0` UK, `1` Central Europe, `5.5` India. `"owner"` uses the saved-search owner's time zone instead. `null()` keeps the rule silent |
| `hdsi_ai_after_hours_service_usage_dst_rule` | `"none"` | Daylight saving rule for a numeric offset: `"us"` (second Sunday of March to first Sunday of November, 02:00 local), `"eu"` (last Sunday of March to last Sunday of October, 01:00 UTC), `"none"` |
| `hdsi_ai_after_hours_service_usage_after_hours` | `(local_hour<6 OR local_hour>=20 OR local_dow=0 OR local_dow=6)` | After-hours definition. `local_dow` 0 is Sunday and 6 is Saturday. For a Sunday-to-Thursday week, replace the weekend terms with `local_dow=5 OR local_dow=6` |
| `hdsi_ai_after_hours_service_usage_local_clock` | `eval` | Computes `local_hour`, `local_minute`, `local_dow`, `local_day`, `local_slot`, `local_tz`. Not normally edited |
| `hdsi_ai_after_hours_service_usage_filter` | `()` | Exclusions inside the `tstats` where clause, on raw `Web.*` values (so `DOMAIN\user` here, not the normalised name). Examples: service accounts (`NOT Web.user IN ("svc_*", "*svc_*")`), or the performance pre-filter below |
| `hdsi_ai_after_hours_service_usage_usage_types` | `"web"` | `usage_type` values that count. Add `"cli"` or `"api"` only if background agents and jobs are not expected after hours |
| `hdsi_ai_after_hours_service_usage_background_hosts` | regex | Extra background hostnames on top of the registry's `ai_traffic_class="background"`: static and CDN assets, error reporting, streaming channels, sign-in |
| `hdsi_ai_after_hours_service_usage_blocked_actions` | `"blocked","block","denied","deny","dropped","drop","reset","rejected","block-url","reset-both","reset-client","reset-server","quarantined"` | Lower-case `Web.action` values that mean the request did not reach the provider. Add a vendor value if the proxy passes its own blocking verdict through |
| `hdsi_ai_after_hours_service_usage_min_requests` | `50` | Allowed foreground AI web requests by one user in the window (see Threshold) |
| `hdsi_ai_after_hours_service_usage_min_buckets` | `2` | 10-minute periods with allowed foreground requests that the request path also needs. `1` turns the check off |
| `hdsi_ai_after_hours_service_usage_upload_mb` | `5` | MB sent by allowed requests in the window that qualifies the user on its own and doubles the base score |
| `hdsi_ai_after_hours_service_usage_customizations` | `search *` | Post-aggregation hook (`user`, `user_raw`, `drilldown_user`, `src`, `provider`, `provider_list`, `ai_domains`, `action`, `signal_type`, `request_count`, `active_buckets`, `total_requests`, `blocked_requests`, `mb_out`, `upload_flag`, `local_start`, `local_end`, `local_tz`, `after_hours_reason`, `severity_weight`, `risk_multiplier`, `sensitivity_level`, `base_score`, `risk_score`) |
| `hdsi_ai_after_hours_service_usage_risk_score` | `search *` | Last pipe. Override `risk_score` (1 to 100) here |

**Approvals** go in `ai_sanctioned_entities` in the common package. The `allow_key` is lower case:

- `<user>|<provider>` or `<user>|*`, where `<user>` is the **normalised** name (`DOMAIN\jdoe` becomes `jdoe`; a UPN stays a UPN).
- `<src>|<provider>` or `<src>|*` for a host.
- `<bunit>|<provider>` or `<bunit>|*` for a night-shift group. The common macro looks up the identity `bunit` of the user itself; this only works for users that resolve in `identity_lookup_expanded` with a `bunit`.
- `*|<provider>` to approve a provider for the whole organisation, for example a licensed enterprise assistant (`*|microsoft 365 copilot`).

**Performance pre-filter (recommended on large proxy tenants).** Without it, every hourly run aggregates every user-attributed Web event in the window, including runs during business hours that return nothing. On the largest validation tenant a run cost 107 to 150 s (about 40 M events scanned per hour), and a 4-hour window cost 235 s. That is real scheduler load for a low-score context rule. Pasting the subsearch below into `..._filter` makes `tstats` return only rows whose `url_domain` or `site` could be an AI provider. In validation an hourly window then ran in 15 to 24 s on that tenant and returned the same rows as the unfiltered search. It returns a superset, and `ai_domains_filter` still decides the provider. It does not ship enabled because subsearches cannot be syntax-checked with `parse_only`, and because a `url_domain` logged with a port or a trailing dot would not match it. Check that the rule still returns the same rows after you paste it.

```spl
[| inputlookup ai_provider_domains | eval d=lower(trim(domain)) | where d!="" | eval term="Web.url_domain=\"".d."\" OR Web.url_domain=\"*.".d."\" OR Web.site=\"".d."\" OR Web.site=\"*.".d."\"" | append [| inputlookup ai_provider_apps | eval a=lower(trim(app_name)) | where a!="" | eval term="Web.site=\"".a."\""] | stats values(term) as term | eval search="(".mvjoin(term," OR ")." OR Web.url_domain=\"bedrock*.amazonaws.com\" OR Web.url_domain=\"*aiplatform.googleapis.com\" OR Web.url_domain=\"*.openai.azure.com\" OR Web.url_domain=\"*.services.ai.azure.com\" OR Web.url_domain=\"*.cognitiveservices.azure.com\" OR Web.url_domain=\"*sagemaker.*.amazonaws.com\")" | fields search]
```

### Threshold
`..._min_requests` defaults to 50 allowed foreground AI web requests per user per hourly window. "Requests" means Web data model events, so the number measures proxy verbosity as much as human activity. PAN-OS URL logs record many entries per page, while an SSE connection log records about one per session. That is why the request path also needs `min_buckets` periods.

On the validation tenant with PAN-OS URL logs, with the search below (allowed requests only, `:12` windows, pre-filter on): over the after-hours part of a weekday morning (00:07 to 06:07 local), 42 users had allowed foreground AI web use in at least 2 periods of a window. Their busiest window had 11.5 requests at the median, 44 at the 90th percentile, 68 at the 95th and 75 at the 98th; 4 users reached 50, so 50 sat at about the 90th percentile. On a whole Saturday, 153 users had p50 9, p90 27, p95 39 and p98 124, and 7 reached 50 (about the 95th percentile). On that Saturday the shipped search flagged exactly the same 7 users. Derive the tenant value with the search below over 1 to 7 days, using the pre-filter on large tenants, and aim for a percentile that gives a daily volume the SOC accepts.

```spl
| tstats summariesonly=t allow_old_summaries=t fillnull_value="unknown" count from datamodel=Web
    where (Web.url_domain=* OR Web.site=*) Web.user!="unknown" `hdsi_ai_after_hours_service_usage_filter` by Web.user Web.url_domain Web.site Web.action _time span=10m
| rename Web.* as *
| where NOT in(lower(action), `hdsi_ai_after_hours_service_usage_blocked_actions`) AND NOT in(lower(user),"-","n/a","none","null")
| eval user=replace(user,"^.*[\\\\]","")
| `hdsi_ai_after_hours_service_usage_local_clock`
| where `hdsi_ai_after_hours_service_usage_after_hours`
| eval ai_domain=lower(coalesce(nullif(url_domain,"unknown"),nullif(site,"unknown"))), ai_input_type=if(isnull(nullif(url_domain,"unknown")),"app","host"), win=floor((_time-420)/3600)
| stats sum(count) as count values(_time) as bk by user ai_domain ai_input_type win
| `ai_domains_filter`
| search usage_type IN (`hdsi_ai_after_hours_service_usage_usage_types`)
| where NOT (ai_traffic_class="background" OR match(ai_domain, `hdsi_ai_after_hours_service_usage_background_hosts`))
| stats sum(count) as req values(bk) as bk by user win
| where mvcount(bk)>=`hdsi_ai_after_hours_service_usage_min_buckets`
| stats max(req) as busiest_window by user
| stats count as users perc50(busiest_window) as p50 perc90(busiest_window) as p90 perc95(busiest_window) as p95 perc98(busiest_window) as p98 count(eval(busiest_window>=50)) as users_ge_50
```

`win` approximates the scheduled `:12` windows (`-65m@m` to `-5m@m`) to the 10-minute period. Set `..._utc_offset` first, because the search uses the same clock. On an SSE tenant where `request_count` stays in single digits, the request path never fires and the upload path does the work (users had 2 to 3 requests in their busiest hour on the SSE validation tenant). That is the intended behaviour.

### Known false positives / Limitations
- **People who legitimately work late.** Shift workers, other time zones and on-call staff are the main source of rows. Approve them by `bunit` or user in `ai_sanctioned_entities`, or exclude them in `..._filter`. One business-hours clock per tenant cannot represent offices in several time zones. Split the rule per region with `..._filter` if needed.
- **Idle tabs and extensions.** An open ChatGPT, Gemini or Claude tab, or a writing extension, keeps calling the provider all night. The background hosts remove the telemetry, asset and streaming calls seen in validation, but a tab that keeps polling the foreground host can still qualify. On Tenant A one Gemini user qualified in two consecutive Friday-night windows with 54 to 60 allowed requests over 4 to 5 periods, and one Saturday user qualified in 24 windows of the day (up to 394 requests). Suppression turns either into a single score-10 event that day. v1.1 briefly dropped "steady" rows (5 or more periods, busiest period at most 30% of requests). That test was removed: the same continuous activity was steady in one window and bursty in the next, so with daily suppression it only delayed the event, and it dropped genuine sessions of 50 minutes or more.
- **Blocked attempts are not scored here.** A user whose AI traffic is blocked all night creates no risk from this rule. Most of Tenant A's user-attributed blocked AI traffic came from a few dozen users retrying blocked pages (in one sample hour, 11,869 blocked events from 36 users against 17,283 allowed from 8,343). Blocked attempts are context for the analyst (`blocked_requests` and the web drilldown), not after-hours use.
- **No user, no risk.** On the PAN-OS tenant only about 10% of AI web events carried a `user` (81k of 804k events to the main AI hosts in 24 h; User-ID gaps). The rest cannot raise risk here. Improve User-ID coverage rather than scoring IP addresses.
- **User forms.** Only the `DOMAIN\` prefix is removed. A proxy that logs UPNs keeps UPNs, which match other detections only if they also use UPNs. A user seen in several raw forms in one window is one risk object; the web drilldown uses the first raw form.
- **IDE and API traffic is excluded on purpose.** GitHub Copilot (an SSE app with `usage_type=ide`) appeared after hours for 122 distinct users over 7 days on the SSE tenant, mostly because IDEs were left open. Agentic CLIs and jobs that call AI APIs at night are also excluded by default.
- **Sanctioned enterprise assistants.** In the previous validation round, Microsoft 365 Copilot Studio uploads of 5 MB or more were the only rows on the SSE tenant (2 to 4 users a day). The common registry now ships the Netskope "microsoft copilot studio" application name as opt-in (disabled), so those rows no longer appear by default (on Tenant C, 3 users sent 134 MB to that application on the replayed Saturday and the rule returned nothing). Where Copilot is licensed and enabled in the registry, approve it organisation-wide (`*|microsoft 365 copilot`), per group or per user, or raise `..._upload_mb`.
- **Time zone.** Set `..._dst_rule` with a numeric offset, or use `"owner"` with an owner account whose time zone is correct. The risk message shows `local_start`, `local_end` and `local_tz` on the clock that was used, so an analyst can see a mis-set clock at once.
- **Upload volume depends on `bytes_out`.** PAN-OS URL logs in validation carried no byte counts, so the upload path is silent there.
- **Cost.** See the performance pre-filter. Without it the rule scans all user-attributed Web events every hour, including business hours.

### Validation
Read-only tests on 4 production ES tenants, 2026-10-09 and 2026-10-10. "Configured" means the shipped search with `..._utc_offset` = `-5`, `..._dst_rule` = `"us"` (US Eastern, `UTC-4` on these dates) and the performance pre-filter. "Replay" means the configured search grouped by approximate `:12` window (`floor((_time-420)/3600)`) over a time range, which approximates the scheduled runs before suppression; "events" counts distinct `user` and `signal_type` pairs, the number of risk events after suppression.

| Tenant | Web data reality | Parses (search + 2 drilldowns) | Shipped defaults, last 4 h | Replay (local time): Fri 2026-10-09 00:07-06:07 / Fri 19:07-00:07 / Sat 2026-10-03 full day, events (user windows) | Notes |
|---|---|---|---|---|---|
| A | PAN-OS URL/threat logs, `url_domain` set, `site` empty; about 10% of AI events carry a user | OK | 0 rows (offset unset), 97 s | 4 (10) / 3 (3) / 7 (41); scores 7 to 10 | Gemini, OpenAI and Anthropic web; every qualifying row had `blocked_requests` = 0. A single configured hourly window ran in 15 to 24 s with the pre-filter. No `bytes_out`, so no upload rows |
| B | Inbound load-balancer/WAF logs plus a small cloud proxy; no `user` on any AI row | OK | 0 rows, 7 s | not run | Expected silence. Inbound logs never resolve to an AI provider as a user |
| C | SSE/CASB connection logs, `site` = application name, `url_domain` empty, `user` 100%; action `isolate` | OK | 0 rows, 2 s | 0 / 0 / 0 (2 to 3 s each) | The previous round's Copilot Studio upload rows are gone because the common registry made that app name opt-in |
| D | Inbound IIS logs only | OK | 0 rows, 2 s | not run | No data path |

Further checks:

- **Rows without a source address:** the first replay of the Saturday found 3 users while the Threshold search found 7. The cause was a defect carried over from the previous round: `src` was set to null before a `stats ... by src`, which silently dropped every row whose source was unknown. `src` now stays `unknown` until the end. After the fix the shipped search and the Threshold search flagged the same 7 users.
- **Blocked traffic:** in the previous round the only Tenant A row of a night hour was an OpenAI user with 152 requests, all of them `blocked` (`chatgpt.com` and `ab.chatgpt.com`). No blocked-only user qualifies now. In one hour of Tenant A's AI-host traffic with a user, 11,869 events from 36 users were `blocked` and 17,283 from 8,343 users were `allowed`.
- **User normalisation:** in the replays, 11 of 13 qualifying user windows had a `DOMAIN\user` raw value, and none of the emitted `user` values kept a backslash.
- **Clock:** `local_clock` was unit-tested live with fixed timestamps on both sides of each daylight-saving change. US Eastern gave 01:59 EST then 03:00 EDT on 2026-03-08, and 01:59 EDT then 01:00 EST on 2026-11-01. EU (`1`, `"eu"`) switched at 01:00 UTC on 2026-03-29 and 2026-10-25. `5.5` gave `UTC+5:30`. `null()` gave no clock, so no row passed. `"owner"` used the owner's time zone.
- **Drilldowns:** on Tenant A, with the raw `DOMAIN\user` token the web drilldown returned 0 rows; with `drilldown_user` it returned the user's AI activity. The risk drilldown now uses the bare `user`, the form other detections write to the risk index.
- No FATAL or ERROR messages on any tenant.

Expected daily volume once configured (one request event and at most one upload event per user per day): Tenant A about 5 to 8 events a day at 7 to 10 points (4 users in the early-morning hours plus 3 in the evening of the replayed Friday, 7 on the Saturday), B none, C none with the shipped registry, D none.

### Deployment
The package ships with `enable_alerting: false` and `deployment_type: adhoc`: it needs a per-tenant business-hours clock before it can emit anything, and an unconfigured copy would still spend 100 s or more of search time every hour on a large proxy tenant. Deploy it per tenant, and before enablement:

1. Confirm that `Web` holds egress proxy or SSE data with `user` and `action` populated for AI hostnames or applications.
2. Set `..._utc_offset` to the standard-time offset of the business-hours time zone and `..._dst_rule` to `"us"` or `"eu"` (or set the offset to `"owner"` and give the owning account the right time zone). Adjust `..._after_hours` to the organisation's working week.
3. On large proxy tenants, paste the performance pre-filter into `..._filter` and confirm the rows match an unfiltered run.
4. Check `..._blocked_actions` against the tenant's `Web.action` values, then derive `..._min_requests` with the Threshold search.
5. Load approvals for night-shift groups and sanctioned enterprise assistants into `ai_sanctioned_entities`.
6. Run the search over several night hours and a weekend day, and confirm the daily risk volume.

The rule is risk-only (no notable) and is meant to strengthen other AI-RBA signals, not to stand alone. Enabling it is a separately approved change.
