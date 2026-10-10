## Architect Notes
---
**Author:** Trevor Mock, Hurricane Labs LLC. Security Operations Architect

This rule finds a user who uploads attachment-sized data to **personal (consumer) webmail** and then, in the same hourly window, uploads file-sized data to an **AI web service**. Mailing work files to a personal Gmail, Yahoo or Outlook.com account and then pushing them into ChatGPT, Claude or Gemini moves corporate data through two uncontrolled hops, and the second hop usually escapes DLP. The rule creates risk on `user` (35) and on `src` (15). It creates no notable.

v1.0 matched the personal-email half on `url_domain` only, so it missed SSE/CASB data where the destination is an app name in `site`. It required `bytes_out` on both halves without saying so. It allowlist-checked only the first AI provider of a user, and it did not check that the email upload came before the AI upload. It ran every 5 minutes over 10 minutes of data while describing a 1-hour correlation, and it could emit the risk object `unknown`. v1.0 returned 0 rows on all four validation tenants.

### Prerequisites
| Requirement | Why | If absent |
|---|---|---|
| `Web` data model, accelerated, from a **forward proxy, SWG or SSE/CASB** (user egress) | Both halves come from one `tstats` over `Web` | Inbound web server, WAF or load-balancer logs never contain user uploads to webmail or AI. The rule stays silent on them |
| `Web.bytes_out` populated per request or connection | Upload size is the only evidence that something was sent. `http_method` alone is not enough: every webmail action is a `POST` | No results. PAN-OS URL-filtering logs (`pan:threat`) carry no byte counts. Use PAN traffic logs or an SSE feed in `Web` instead |
| `Web.user` populated | The correlation is per user | Rows without a user are dropped. No row carries an `unknown` user |
| `Web.url_domain` (hostname) **or** `Web.site` (SSE app name such as "Google Gmail") | Identifies the destination | The rule handles either. Netskope-style data with `site` only is fully supported |
| `Web.src` | System risk object | Optional. When it is missing, only the user receives risk |

- `http_method` is optional. When it is present, `GET`, `HEAD` and `OPTIONS` are excluded inside `tstats`.
- Depends on `hdsi_ai_rba_common`. `ai_domains_filter` resolves hostnames and SSE app names to a provider through `ai_provider_domains` and `ai_provider_apps`, and drops disabled rows. `ai_unsanctioned_filter(3)` applies `ai_sanctioned_entities` approvals per user, per host and per provider. The rule uses no ES asset or identity lookup.

### How it works
- **One `tstats`** over `Web` in 5-minute buckets by `user`, `src`, `url_domain` and `site`, prefiltered to rows with a user and `bytes_out>0`, minus the `..._filter` exclusions. Placeholder users (`unknown`, `-`, empty, `anonymous`) are dropped.
- **Personal-email half:** `lower(url_domain)` without a leading `www.`, or else the `site` app name, is matched exactly against `..._personal_email_names` (consumer webmail hosts and SSE app names). Corporate Outlook hosts are not in the list.
- **Corporate-platform guard:** a personal-email destination that at least `..._corporate_mail_users` (25) distinct users reach in the window is the company's own mail platform (for example Gmail at a Google Workspace tenant) and is ignored.
- **AI half:** only for users who had personal-email traffic. Other destinations go through `ai_domains_filter` (hostnames as `host`, SSE app names as `app`). Only providers whose `usage_type` is in `..._ai_usage_types` (`web`) count. Approved user, host or group plus provider pairs are removed by `ai_unsanctioned_filter` **per provider, before aggregation**, so one approved provider no longer hides or admits the others.
- **Upload thresholds per 5-minute bucket:** personal email at least `..._min_email_bytes` (5 MB), AI at least `..._min_ai_bytes` (1 MB).
- **Ordering:** only AI buckets at or after the first qualifying email bucket count. The rule fires when at least one remains. `gap_minutes` is the time from the email upload to the first AI upload, at 5-minute granularity.
- **Output:** one row per `user` and `src` with `personal_email_list`, `personal_mb`, `provider_list`, `ai_domains`, `ai_mb`, `email_upload_time`, `ai_upload_time` and `gap_minutes`. A `src` of `unknown` is nulled, so no system risk is created for it.
- **Scoring:** static, 35 on the user and 15 on the system. The correlation is a staging pattern, not proof of a leak, and the aggregator decides on escalation.
- **Cadence:** hourly at :05 over `-65m@m` to `-5m@m`, suppressed for 24 hours per `user` and `src`.

### Tuning macros
| Macro | Ships as | Purpose |
|---|---|---|
| `hdsi_ai_personal_email_to_ai_service_upload_correlation_filter` | `()` | Exclusions inside the `tstats` where clause (`Web.*` names), e.g. `NOT Web.src IN ("10.1.2.0/24")` for VDI or explicit-proxy egress |
| `hdsi_ai_personal_email_to_ai_service_upload_correlation_personal_email_names` | Consumer webmail hosts (`mail.google.com`, `outlook.live.com`, `mail.yahoo.com`, `mail.proton.me`, `mail.aol.com`, GMX, Yandex, Tuta, 163, QQ, mail.ru) and SSE app names (`google gmail`, `yahoo mail`, `microsoft live outlook`, `protonmail`, `comcastmail`, `tempmail`...) | Personal-email destinations, lowercase, exact match. **Remove `mail.google.com` and `google gmail`/`gmail` if Google Workspace is the corporate mail platform.** Add ISP or regional webmail seen in your data |
| `hdsi_ai_personal_email_to_ai_service_upload_correlation_corporate_mail_users` | `25` | Distinct users per window above which a destination is treated as the corporate mail platform |
| `hdsi_ai_personal_email_to_ai_service_upload_correlation_min_email_bytes` | `5242880` (5 MB) | Personal-email upload threshold per user, source and 5-minute bucket |
| `hdsi_ai_personal_email_to_ai_service_upload_correlation_min_ai_bytes` | `1048576` (1 MB) | AI upload threshold per user, source and 5-minute bucket |
| `hdsi_ai_personal_email_to_ai_service_upload_correlation_ai_usage_types` | `"web"` | Provider usage types that count as the AI half. Add `"api"` for direct API uploads from user endpoints. IDE assistants (`ide`) upload code context continuously and are excluded |
| `hdsi_ai_personal_email_to_ai_service_upload_correlation_customizations` | `search *` | Post-correlation hook (fields listed in the macro description) |
| `hdsi_ai_personal_email_to_ai_service_upload_correlation_risk_score` | `search *` | Last pipe. A numeric `risk_score` set here overrides both static scores |

Per-user, per-host and per-group approvals go in `ai_sanctioned_entities` (common package), keyed `<user, src or bunit>|<provider>` or `<entity>|*`.

### Threshold
The byte thresholds decide whether ordinary webmail and chat use count as an upload. On the validated SSE tenant, consumer webmail buckets with traffic were 0.1 to 0.2 MB at p50 (1.8 MB for one ISP webmail) and about 2 to 10 MB at p90 (a connection-level SSE log reports bytes when the connection closes, so long sessions add up). AI web buckets were a few KB at p50 for chat. Derive tenant values from the same buckets the rule uses:

```spl
| tstats summariesonly=t allow_old_summaries=t fillnull_value="unknown" sum(Web.bytes_out) as bytes_out
    from datamodel=Web where Web.user=* Web.bytes_out>0 NOT Web.http_method IN ("GET","HEAD","OPTIONS")
    by _time span=5m Web.user Web.url_domain Web.site
| rename Web.* as *
| eval dest_name=replace(lower(coalesce(nullif(url_domain,"unknown"),site)),"^www\d*\.","")
| where in(dest_name, `hdsi_ai_personal_email_to_ai_service_upload_correlation_personal_email_names`)
| eval mb=bytes_out/1048576
| stats count as buckets dc(user) as users p50(mb) as p50_mb p90(mb) as p90_mb p99(mb) as p99_mb by dest_name
```

Run it over 7 days. Keep `..._min_email_bytes` at or above the p90 of the busiest consumer webmail destination. Use the same SPL with `ai_domains_filter` in place of the `where in(...)` to size `..._min_ai_bytes`. Check the corporate-platform guard with `dc(user)` per destination per hour: a destination that crosses 25 users an hour is almost certainly the corporate platform and belongs out of `..._personal_email_names`.

### Known false positives / Limitations
- **Gmail at Google Workspace tenants.** `mail.google.com` serves both personal and Workspace mail. On Tenant A it was reached by about 43,000 users a day. The corporate-platform guard removes it, but a small Workspace tenant can stay under 25 users an hour. Remove it from `..._personal_email_names` there.
- **SSE connection logs are coarse.** On Tenant C (`netskope:connection`), `bytes_out` is per connection and reported when it closes, so a long-lived webmail session can cross 5 MB without an attachment. The time order is then accurate to the connection, not the upload. SSE application or upload events with an activity field are more precise, but are not in the CIM `Web` model.
- **AI half coverage depends on `ai_provider_apps`.** On Tenant C the AI web apps with upload volume were Microsoft Copilot Studio, Lovable and Adobe Firefly. Copilot Studio showed about 67 MB per bucket for 24 users, which looks like sanctioned enterprise use. Approve it in `ai_sanctioned_entities` if so. Microsoft 365 Copilot web traffic is opt-in in the common package and is not counted by default.
- **Byte-less proxies cannot be supported.** PAN-OS URL logs (Tenant A) have methods and users but no `bytes_out`. Typed prompts, webmail reads and attachment uploads look the same there, so the rule returns nothing rather than guess.
- **The rule is per hourly window.** An email upload in one hour and an AI upload in the next hour are not correlated. That is a deliberate trade-off against a longer, costlier search. The `ai_*` aggregators see both halves through other AI rules.
- **Personal cloud storage and messaging** (personal Drive, Dropbox, WhatsApp Web) are not personal email and are out of scope here.

### Validation
Read-only tests on 4 production ES tenants, 2026-10-09. The search and both drilldowns parse on all four.

| Tenant | Web data reality | v1.0 rows (4 h) | v1.1 rows (4 h) | v1.1 rows (24 h / 7 d) | Notes |
|---|---|---|---|---|---|
| A | PAN-OS URL logs: user on about 55 %, method on about 40 %, `bytes_out` 0 % | 0 | 0 | 0 / 0 | No data path (no byte counts). `mail.google.com` is the corporate platform there (about 43,000 users a day) |
| B | Mostly inbound load-balancer and WAF logs, plus a small user proxy feed with bytes | 0 | 0 | 0 / 0 (7 d run stopped at the 300 s test limit) | Proxy feed showed a handful of sub-KB webmail requests and no AI web uploads in 7 days |
| C | SSE connection logs: `site` = app name, `url_domain` 0 %, user and `bytes_out` populated, no method | 0 | 0 | 0 / 0 | 16 users crossed 5 MB to personal webmail in 7 days (Google Gmail, Yahoo Mail, Microsoft Live Outlook, comcastmail). None of them had any AI web traffic in the same window, even with no AI threshold |
| D | Inbound IIS logs only | 0 | 0 | 0 / 0 | No data path. Expected silence |

A synthetic test (`makeresults` fed through the full post-`tstats` pipeline, on Tenant C) confirmed the logic. A Gmail SSE app upload of 6 MB followed 10 minutes later by 2 MB to `chatgpt.com` fired, with the provider resolved to OpenAI. An AI upload that came before the email upload did not fire. A 0.5 MB AI upload stayed below the threshold. A `www.mail.google.com` host and a `ChatGPT` app name were both normalised and resolved. No FATAL or ERROR messages on any tenant. The search took 1 to 34 s over 4 hours (the hourly schedule scans a quarter of that) and 2 to 106 s over 7 days on Tenants A, C and D. The `Web.user=*` and `Web.bytes_out>0` prefilters keep inbound-only and byte-less tenants cheap.

Expected daily volume at the defaults: 0 on all four validation tenants. On a tenant with a byte-accurate user proxy and active consumer AI use, expect a few users a day at most (24-hour suppression per user and source).

### Deployment
The package ships with `enable_alerting: false`. Before enablement:

1. Confirm that `Web` contains user egress with `user` and `bytes_out` (run the Threshold SPL over a day). If it does not, leave the rule disabled.
2. Decide whether Gmail is a corporate platform and edit `..._personal_email_names`. Add any ISP or regional webmail that the Threshold SPL surfaces.
3. Derive `..._min_email_bytes` and `..._min_ai_bytes`, and add sanctioned AI services or users to `ai_sanctioned_entities`.
4. Run the search over its scheduled window several times and confirm the expected daily risk volume.

The rule is risk-only (no notable). Enabling it is a separately approved change.
