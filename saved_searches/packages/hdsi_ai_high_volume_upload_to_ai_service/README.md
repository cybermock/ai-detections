## Architect Notes
---
**Author:** Trevor Mock, Hurricane Labs LLC. Security Operations Architect

This rule finds a host, and the user where the log source knows it, that **uploads a large volume of data to an AI service in one hour**. Examples are ChatGPT, Gemini, Claude, Perplexity, DeepSeek, AI APIs and Hugging Face. A large upload to a chat or API service usually means files, documents or bulk text are being pasted or attached, which is a direct data-exposure path outside the organisation. The rule measures `bytes_out` from firewall App-ID sessions (`Network_Traffic`) or from proxy/SSE logs with byte counts (`Web`). It applies four volume tiers and creates risk on `src` (system) and, when known, on `user`. It creates no notable.

v1.0 read only the `Web` data model, ran every 5 minutes over overlapping 10-minute windows, and started scoring at 1 MB. It returned 0 rows on all four validation tenants, because none of them has proxy logs with byte counts for AI traffic. Where the volume is visible (firewall App-ID on Tenant A), a 1 MB threshold would have fired about 7,100 times a day. v1.0 also placed a `$risk_score$` token in `_risk`, which ES does not support, and its score could exceed 100. v1.1 adds the firewall App-ID path, measures hourly, starts at 50 MB and caps the score at 80.

### Prerequisites
Either data path is enough. The `Web` branch is joined with `append`, and a missing data model only empties its own branch (`data_prereqs` op `OR`).

| Data | Fields used | What it adds | If absent |
|---|---|---|---|
| `Network_Traffic` (accelerated) from an NGFW with application identification (PAN-OS App-ID or equivalent) and byte counts | `app`, `src`, `user`, `bytes_out`, `bytes_in`, `action` | Upload volume per session to each AI application. Firewall User-ID supplies the user | Firewalls that put only protocol or port in `app` (ASA, FortiGate without application control) contribute nothing: the destination is an IP address and cannot be resolved to a provider |
| `Web` (accelerated) from an egress proxy or SSE/CASB that logs request bytes | `url_domain` or `site` (hostname or SSE app name), `src`, `user`, `bytes_out`, `bytes_in`, `action` | Upload volume per AI domain or SSE application, usually with the user | PAN-OS URL logs carry no byte counts and add nothing. Inbound server logs (load balancer, WAF, IIS) never resolve to an AI provider, but they make the branch slower. Exclude them by sourcetype in `..._web_filter` (see Tuning macros) |

- `ai_domains_filter` (common) resolves the App-ID, hostname or SSE app name to `provider`, `usage_type` and `severity_weight` through `ai_provider_apps` and `ai_provider_domains`. Only enabled rows count.
- `ai_unsanctioned_filter(3)` removes approved user, host or group (`bunit`) and provider pairs from `ai_sanctioned_entities`.
- `ai_risk_multiplier` uses the ES `identity_lookup_expanded` `bunit` (via `ai_department_sensitivity`) and privileged status. A row with no user gets multiplier 1.0.
- Requires the prerequisite package `hdsi_ai_rba_common`. No `ai_detection_config` values are read. The tier thresholds are macros in this package.

### How it works
- **App-ID branch:** `tstats` over `Network_Traffic` sums `bytes_out` and `bytes_in` by `src`, `user` and `app`. It is pre-filtered inline by `..._app_ids` (candidate AI App-IDs), `bytes_out>0`, not `blocked`, and `..._filter`. Then `ai_domains_filter` runs with `ai_input_type="app"`.
- **Web branch (`append`):** `tstats` over `Web` sums bytes by `src`, `user`, `url_domain` and `site`, with `bytes_out>0` and not `blocked`, plus `..._web_filter`. `ai_domain` is `url_domain`, or `site` when the proxy only gives an SSE app name. Providers are resolved inside the subsearch, so only AI rows leave it and the 50,000-row subsearch limit is never reached.
- **Scope:** only `usage_type` values in `..._usage_types` are kept. These ship as web, api, cli and model registry. IDE coding assistants are excluded because they upload source context all day by design (GitHub Copilot via SSE: about 1 GB a day on Tenant C). Providers in `..._excluded_providers` are dropped. This ships as Microsoft 365 Copilot (see Known false positives).
- **Normalisation:** placeholder users (`unknown`, `-`, empty) become null. Rows without a usable `src` are dropped. Approved entities are removed.
- **Aggregation (one row per `src`):** bytes are summed per `src` and evidence type (firewall or proxy) across all users, and the larger evidence total is used. A flow logged by both the firewall and the proxy is therefore counted once, even when only one of them carries the user, and traffic from the same `src` with and without a user is added together before the threshold is applied.
- **User attribution:** the attributed user with the most upload on that `src` becomes `user` only if that user alone uploaded at least `..._low_mb`, so a user is never scored for a NAT or shared host total. If that user has more than `..._max_user_sessions` (1000) sessions in the window, the login is named in `user_display` but gets no risk, because one login carrying that many sessions is a terminal, VDI or proxy server mapped to a single User-ID. `user_out_mb`, `user_sessions` and `attributed_users` are kept on the row.
- **Tiers (MB uploaded in the hour):** low ≥ `..._low_mb` (50), medium ≥ `..._medium_mb` (100), high ≥ `..._high_mb` (500), critical ≥ `..._critical_mb` (2000). Base scores are 20, 30, 45 and 60.
- **Scoring:** `risk_score = min(80, round(base x risk_multiplier x severity_weight))`. `severity_weight` is the highest provider weight in the row (0.3 to 1.2). The score applies to `src` and, when attributed, to `user`. The `_risk` literal fallback is 20 for each object. No risk object is ever `unknown`. When no user is known, only `src` receives risk.
- **Cadence:** hourly at minute 7 over `-65m@m` to `-5m@m`. Suppression is 4 h per `src` (the row key), so a sustained uploader yields at most 6 events a day and the risk aggregators decide.

### Tuning macros
| Macro | Ships as | Purpose |
|---|---|---|
| `hdsi_ai_high_volume_upload_to_ai_service_filter` | `()` | Exclusions inside the `Network_Traffic` where clause (`All_Traffic.*` names), e.g. `NOT All_Traffic.src IN ("10.20.0.0/24")` for a NAT pool, VDI subnet or an approved AI integration server |
| `hdsi_ai_high_volume_upload_to_ai_service_web_filter` | `()` | Exclusions inside the `Web` where clause. Data model fields take the `Web.` prefix (`NOT Web.src IN (...)`), but `sourcetype` is inherited and takes none. Exclude inbound server logs with `NOT sourcetype IN ("aws:elb:accesslogs","aws:waf","ms:iis:auto")`. `NOT Web.sourcetype=...` matches nothing in `tstats` and silently excludes nothing |
| `hdsi_ai_high_volume_upload_to_ai_service_app_ids` | `All_Traffic.app IN ("openai*","chatgpt*","claude*","anthropic*","google-gemini*", ...)` | Pre-filter of candidate App-IDs. It only narrows the search. A value counts only if `ai_provider_apps` has an enabled row for it. When you add an App-ID to that lookup, make sure a pattern here covers it. App-IDs containing a dot (for example `otter.ai-base`) cannot be resolved by `ai_domains_filter` today and are not listed |
| `hdsi_ai_high_volume_upload_to_ai_service_usage_types` | `"web","api","cli","model_registry"` | Which `usage_type` values count. Add `"ide"` to include coding assistants |
| `hdsi_ai_high_volume_upload_to_ai_service_excluded_providers` | `"Microsoft 365 Copilot"` | Providers whose uploads are not counted. Use `"__none__"` to count all |
| `hdsi_ai_high_volume_upload_to_ai_service_low_mb` | `50` | Minimum MB per hour to raise risk (tier low) |
| `hdsi_ai_high_volume_upload_to_ai_service_medium_mb` | `100` | Tier medium |
| `hdsi_ai_high_volume_upload_to_ai_service_high_mb` | `500` | Tier high |
| `hdsi_ai_high_volume_upload_to_ai_service_critical_mb` | `2000` | Tier critical |
| `hdsi_ai_high_volume_upload_to_ai_service_max_user_sessions` | `1000` | Most sessions the top user on a `src` may have in the window and still receive user risk (shared-server guard) |
| `hdsi_ai_high_volume_upload_to_ai_service_customizations` | `search *` | Post-scoring hook (fields: `src`, `user`, `user_display`, `user_out_mb`, `user_sessions`, `attributed_users`, `provider`, `ai_endpoint_sample`, `evidence`, `bytes_out_mb`, `bytes_in_mb`, `session_count`, `upload_tier`, `base_score`, `severity_weight`, `risk_multiplier`, `risk_score`) |
| `hdsi_ai_high_volume_upload_to_ai_service_risk_score` | `search *` | Last pipe. Override `risk_score` (1 to 100) here |

Per-user, per-host or per-group approvals go in `ai_sanctioned_entities` (common package), keyed `<user, src or bunit>|<provider>`, for example an approved data-science workstation `ds-ws-07|openai`.

### Threshold
The defaults (50/100/500/2000 MB per hour) come from one day of App-ID data on the largest tenant. Measure your own tenant over at least a full day. The SPL below reproduces the rule's per-`src` hourly total and prints the high percentiles and the number of source-hours at each candidate threshold. Pick `..._low_mb` from the `ge*` columns so that the count per day is a volume your analysts will review (it is the upper bound of risk events per day before the 4 h suppression). It usually lands at or above the 99.99th percentile (`p99_99`). Never go below about 25 MB: the 99th percentile is around 1 MB and would fire thousands of times a day.

```spl
| tstats summariesonly=t allow_old_summaries=t sum(All_Traffic.bytes_out) as bytes_out
    from datamodel=Network_Traffic
    where All_Traffic.bytes_out>0 NOT All_Traffic.action="blocked" `hdsi_ai_high_volume_upload_to_ai_service_app_ids` `hdsi_ai_high_volume_upload_to_ai_service_filter`
    by _time span=1h All_Traffic.src All_Traffic.user All_Traffic.app
| rename All_Traffic.* as *
| eval ai_domain=app, ai_input_type="app"
| `ai_domains_filter`
| search usage_type IN (`hdsi_ai_high_volume_upload_to_ai_service_usage_types`) NOT provider IN (`hdsi_ai_high_volume_upload_to_ai_service_excluded_providers`)
| stats sum(bytes_out) as bytes_out by _time src
| eval mb=bytes_out/1048576
| stats count as src_hours exactperc99.9(mb) as p99_9 exactperc99.99(mb) as p99_99 max(mb) as max_mb
    count(eval(mb>=10)) as ge10 count(eval(mb>=25)) as ge25 count(eval(mb>=50)) as ge50
    count(eval(mb>=100)) as ge100 count(eval(mb>=500)) as ge500 count(eval(mb>=2000)) as ge2000
```

On Tenant A (about 731,000 source-hours of AI App-ID traffic in 24 h) the 99th percentile was 0.98 MB per hour, the 99.9th 6.4 MB and the 99.99th 26 MB. There were 7,093 source-hours at 1 MB or more, 78 at 25 MB, 36 at 50 MB (17 sources), 31 at 100 MB, 11 at 500 MB and 4 at 2,000 MB. For a proxy-only tenant, run the same calculation on the `Web` branch.

### Known false positives / Limitations
- **Bytes are not file content.** `bytes_out` includes TLS, HTTP and streaming overhead. Voice or screen-sharing modes in chat assistants upload continuously, so treat tier low as "look at it", not as proof of document exfiltration.
- **Shared egress.** When the firewall or proxy sees a NAT, VDI or terminal-server address as `src` and has no user, the uploads of many people add up on one system. On Tenant A, most sources above 50 MB per hour had no firewall user. The heaviest was one client address (a single host with about 20 applications and one Zoom meeting in the same hours) uploading about 5 to 9 GB per hour to ChatGPT. That is a real lead, not a NAT artefact. Exclude proven shared addresses with `..._filter` or `..._web_filter`.
- **One User-ID login on a shared server.** A terminal, VDI or proxy server can be mapped to the single user who logged in to it, so every session from that host is attributed to that person. On Tenant A one internal source carried about 17,700 OpenAI and Gemini sessions in 4 h under one login, while a normal user has at most a few dozen sessions an hour (24 h p99.9: 36). Above `..._max_user_sessions` the rule names the login in `user_display` but scores only the `src`. Lower the macro if your users are lighter, or exclude the server in `..._filter`.
- **Long-lived SSE connections.** Some SSE products (for example Netskope connection events) log a whole connection once, with all its bytes, when it closes. A long session can therefore land in one hour. On Tenant C, the SSE app name "Microsoft Copilot Studio" produced one connection of 55 to 67 MB a day for 18 of 21 users, with less than 0.3 MB returned. This looks like client background behaviour inside the Microsoft 365 boundary, so `Microsoft 365 Copilot` ships in `..._excluded_providers`. Remove it if Copilot uploads matter for you. In the common lookups most Microsoft 365 Copilot domains and App-IDs ship disabled (opt-in), but the Netskope app name `microsoft copilot studio` ships enabled with provider Microsoft 365 Copilot, which is why this package excludes the provider itself.
- **App-ID coverage, and expected volume growth.** Only App-IDs with an enabled `ai_provider_apps` row count. On Tenant A, the PAN-OS IDs `openai-base` (about 260 MB per hour fleet-wide), `anthropic-api-base`, `claude-base`, `claude-post`, `deepseek-api`, `google-gemini-posting` and `google-gemini-downloading` carried real upload volume but are not yet in the common lookup, so they are not counted (requested from the common package). Expect volume to rise when they are added: re-running the 24 h measurement with them counted raised Tenant A from 36 to 111 source-hours at 50 MB or more (17 to 42 sources, about 24 to about 66 risk events a day). 72 of those 111 source-hours were dominated by API traffic (`anthropic-api-base`, `deepseek-api`), which normally comes from integration servers and build hosts. Before or right after that lookup change, add those servers to `ai_sanctioned_entities` or `..._filter`, and re-run the Threshold SPL.
- **IDE assistants are out of scope by default.** Copilot, Cursor and Windsurf upload code context continuously. Add `"ide"` to `..._usage_types` only with a much higher `..._low_mb`.
- **User attribution.** Only 8 of 43 source and user pairs above 50 MB in a day on Tenant A carried a firewall user. Expect mostly system risk unless User-ID or the proxy supplies users. The user is lower-cased. A `DOMAIN\user` value may not match an ES identity, in which case the multiplier stays 1.0.
- **No DNS path.** DNS logs have no byte counts, so DNS-only tenants (and firewalls without App-ID) get no coverage from this rule. The suite's DNS rules cover AI usage there.
- **Inbound web logs** (load balancers, WAFs, IIS) never match an AI provider. On Tenant B they made the hourly `Web` branch take about 14 to 25 s, and a 24 h test hit the 240 s subsearch limit, after which `append` silently keeps the partial result. Exclude them by sourcetype: `NOT sourcetype IN ("aws:elb:accesslogs","aws:waf")` in `..._web_filter` cut the hourly `Web` branch on Tenant B from 14 s to 3 s with the same result. Do not write `Web.sourcetype`: it matches nothing in `tstats`, so the exclusion silently does nothing.

### Validation
Read-only tests on 4 production ES tenants, 2026-10-09. "Scheduled window" is `-65m@m` to `-5m@m`. The "4 h test window" is `-4h@m` to `-5m@m`, used to get signal from an hourly rule. The daily estimate re-ran the per-`src` hourly totals over the previous 24 h and counted one event per source per 4 h block as an approximation of the 4 h suppression.

| Tenant | Data paths present | Parses (search + 3 drilldowns) | v1.0 rows (24 h) | v1.1 rows (scheduled window) | v1.1 rows (4 h test window) | Estimated risk events per day | Notes |
|---|---|---|---|---|---|---|---|
| A | NGFW App-ID with bytes (Network_Traffic); Web is PAN-OS URL logs with no bytes | OK | 0 | 2 (about 24 s) | 9 (about 60 s) | about 24 (36 source-hours at 50 MB or more from 17 sources, 4 h suppression) | All App-ID evidence: OpenAI, Google Gemini, Perplexity. Over 24 h: 5 low, 20 medium, 7 high, 4 critical source-hours. Scores 20 to 60, multiplier 1.0 (no `bunit`). In the 4 h test, 3 of 9 rows carried a user risk object; one shared-server login (about 17,700 sessions) was named but not scored |
| B | Web = inbound load balancer/WAF plus a small DNS-security proxy whose AI rows carry no bytes; firewall has no AI App-IDs | OK | 0 | 0 (about 20 s) | 0 | 0 | No byte-count data path for AI traffic. Excluding the inbound sourcetypes by `sourcetype` cut the `Web` branch from 14 s to 3 s |
| C | SSE (Web, app names in `site`) with bytes on about 6% of events, plus small App-ID | OK | 0 | 0 (about 6 s) | 0 | 0 to 1 | Highest per-source hour in 24 h was 15 MB. Before the Microsoft 365 Copilot exclusion, 6 rows in 4 h were the Copilot Studio pattern described above. GitHub Copilot (IDE) volume is excluded by default |
| D | Inbound IIS only; no App-ID | OK | 0 | 0 (about 5 s) | 0 | 0 | No data path. Expected silence |

There were no FATAL or ERROR messages on any tenant. With a concrete `src`, the firewall drilldown returns in about 30 s and the web drilldown in about 11 s on the largest tenant.

### Deployment
The package ships with `enable_alerting: false`. Before enablement:

1. Confirm that a byte-count data path exists. Either `Network_Traffic.app` carries AI App-IDs with `bytes_out` (run the `..._app_ids` filter alone), or `Web` has `bytes_out` on AI domains or SSE app names.
2. Derive `..._low_mb` and the higher tiers from the Threshold SPL. Add NAT pools and VDI or terminal servers to `..._filter` (`All_Traffic.src`). Add inbound sourcetypes to `..._web_filter` as `NOT sourcetype IN (...)`, without the `Web.` prefix. Load approved users, hosts or groups into `ai_sanctioned_entities`.
3. Run the search once over the scheduled window and once in hourly buckets over a day, and confirm the expected risk volume.

The rule is risk-only (no notable). Enabling it is a separately approved change.
