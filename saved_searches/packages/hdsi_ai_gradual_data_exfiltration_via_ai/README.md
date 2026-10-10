## Architect Notes
---
**Author:** Trevor Mock, Hurricane Labs LLC. Security Operations Architect

This rule finds a user who keeps uploading data to AI services across a week. It also covers a known, inventoried host with no user attribution. It looks for a large total spread over several days, not one burst. That is the low-and-slow pattern that stays under per-hour upload thresholds, such as the 50 MB/h default in `hdsi_ai_high_volume_upload_to_ai_service`. The rule runs once a week, early on Saturday, over the 7 complete days from Saturday to Friday. Each qualifying entity produces one risk event, on the user, or on `src` when no user is known. No notable is created.

MITRE ATT&CK: T1567 (Exfiltration Over Web Service) and T1030 (Data Transfer Size Limits).

### Prerequisites

- **Network_Traffic** (preferred) with firewall App-ID in `All_Traffic.app`, for example Palo Alto `pan:traffic`. It also needs `bytes_out`, `src` and, ideally, `user` (User-ID). Without `user`, only inventoried hosts can be scored (see How it works).
- **Web** (optional second source): proxy or SSE logs with `bytes_out` and either `url_domain` or `site`. An SSE app name in `site`, as Netskope writes it, also works. Inbound web-server and load-balancer logs never match the AI terms, so they add cost but no results.
- If neither model has byte counts for AI traffic, the rule returns nothing. DNS-only tenants cannot use it.
- Both data models need an acceleration summary range of at least 7 days. A range of exactly 7 days misses the first 80 minutes of the oldest day. That is acceptable. A shorter range is not.
- ES lookups:
  - `identity_lookup_expanded` provides `bunit`. The common macros look it up themselves (raw user name, then the bare name without `DOMAIN\` or `@suffix`) for the group allowlist and the risk multiplier. The rule does not look it up separately.
  - `asset_lookup_by_str` (match on `ip`) decides whether a host-only `src` is a known host.
- Common package `hdsi_ai_rba_common`:
  - `ai_domains_filter` resolves App-IDs, domains and SSE app names to a provider. It uses `ai_provider_apps` and `ai_provider_domains`.
  - `ai_unsanctioned_filter(user,src,provider)` applies the allowlist in `ai_sanctioned_entities`.
  - `ai_risk_multiplier` applies the identity sensitivity.

### How it works

- **Firewall branch:** a `tstats` over Network_Traffic, pre-filtered inline to exact AI App-IDs (`_app_ids`) and excluding blocked sessions. It sums `bytes_out` per user, src, App-ID and day.
- **App-ID aliases:** some Palo Alto App-ID variants have no `ai_provider_apps` row yet. `_app_id_aliases` maps each one to its provider's canonical domain before resolution, for example `anthropic-api-base` to `api.anthropic.com` (usage `api`) and `claude-base` to `claude.ai`. An App-ID that has a row in the common lookup always uses that row, so a row added or disabled there wins.
- **Web branch (`append`):** the same daily sum from the Web model, pre-filtered inline to exact AI domains and SSE app names (`_web_ai_terms`). Inside the subsearch, rows are resolved, filtered and summed to one row per user, src, provider and day before they are returned. `append` returns at most 50,000 rows and stops after 1,200 s, so the rows are reduced first. On Tenant C, 7 days of SSE data gave 908 resolved rows, and 31 rows after the reduction.
- **Provider resolution:** `ai_domains_filter` resolves the provider for both branches. Only the counted `usage_type` values are kept: web, api, cli and model_registry. IDE assistants and Microsoft 365 Copilot are left out by default. Rows that the registry marks as `background` traffic (telemetry and CDN hosts such as `bzr.openai.com` or `gemini.gstatic.com`) or `site` traffic (download sites such as `ollama.com`) are dropped, because their volume is not user content. Firewall App-ID matches are always `interactive`.
- **Cleanup:** placeholder users and sources (`unknown`, `-`, empty) become null. Allowlisted user, host or group rows are removed.
- **Entity key:** the user when known, otherwise `src`.
- **Daily totals:** for each entity, day and evidence source, the bytes are summed. Across evidence sources, the larger daily total is kept, together with that source's request count. A session seen by both the firewall and the proxy is therefore not counted twice.
- **Weekly totals:**
  - `window_mb`: total MB uploaded in the window.
  - `active_days`: days with at least `_active_day_mb` uploaded.
  - `max_day_mb` and `max_day_share`: the largest single day, in MB and as a share of the total. The share is compared unrounded.
  - `last_day_mb`: MB uploaded on Friday, the last day of the window. It is for context only and is not a firing condition.
  - `src_count`: number of distinct source addresses.
  - `daily_mb`: the per-day MB, for example `2026-10-05=120.4, 2026-10-06=98.0`. It is in the risk event, so the daily pattern can be read without running a drilldown.
- **Firing conditions:** all of the following must hold.
  - `window_mb` is at least `_cumulative_mb`.
  - `active_days` is at least `_min_active_days`.
  - `max_day_share` is no more than `_max_day_share`.
  - The pattern does not have to be active on the last day. An earlier version required activity on Friday. On a weekly schedule, that check meant a drip with no upload on Friday was never scored, for example someone who does not work Fridays. It was removed. In a relaxed run on Tenant C (20 MB, 2 days), it dropped 1 of 3 qualifying entities.
  - **User guard:** a user seen on more than `_max_user_srcs` hosts is dropped as a shared or placeholder identity.
  - **Host guard:** a host-only `src` is scored only when it resolves in `asset_lookup_by_str` (`_host_requires_asset`). Its largest day must also be no more than `_host_max_day_mb`. DHCP, VPN and CGNAT pool addresses, NAT egress, terminal servers and VDI are handed to different people across the week, so their weekly total is not one entity's behaviour. The matched asset name and category are output as `src_asset` and `src_category`.
- **Scoring:**
  - The base is 25, 35 or 45 at 1x, 2x or 4x `_cumulative_mb`.
  - It is multiplied by `risk_multiplier` (identity bunit sensitivity, x1.25 for privileged identities) and by the highest provider `severity_weight`. Provider API usage weighs 1.2.
  - The result is capped at 60 and written to `risk_score`.
  - Each row carries exactly one risk object, so the dynamic score never spills onto a second object. The literal `_risk` fallback is 25.
- **Suppression:** 6 days on `user,src`, so an entity fires at most once per weekly run.
- **Drilldowns:** they show the daily AI App-ID volume and the daily AI web volume for the entity, limited to the same AI terms as the rule, over the rule's window. The risk-event drilldown runs from the start of the window to now. The rule writes its own risk event at run time, about 01:20 on Saturday, after the window ends. If the drilldown stopped at the end of the window, it would show only the entity's other HDSI AI risk events. They use `entity_search`, which is the entity with backslashes doubled. A `DOMAIN\user` value pasted into SPL unescaped matches nothing (verified live).

### Tuning macros

| Macro | Ships as | Purpose |
|---|---|---|
| `hdsi_ai_gradual_data_exfiltration_via_ai_filter` | `()` | Exclusions inside the firewall `tstats` (datamodel names), such as approved AI integration servers. |
| `hdsi_ai_gradual_data_exfiltration_via_ai_web_filter` | `()` | Exclusions inside the Web `tstats`. |
| `hdsi_ai_gradual_data_exfiltration_via_ai_app_ids` | exact App-ID list | Firewall pre-filter: every enabled `ai_provider_apps` App-ID with a counted usage type, plus `kimi`. Download and delete variants and the Microsoft 365 Copilot App-IDs are left out. When you enable or add an App-ID in `ai_provider_apps`, add it here as well. |
| `hdsi_ai_gradual_data_exfiltration_via_ai_app_id_aliases` | `case(app="kimi","kimi.com")` | Counts App-IDs that have no `ai_provider_apps` row by mapping each one to its provider's domain. A row in the common lookup always wins. Replace it with `null()` to rely on the common lookup only. |
| `hdsi_ai_gradual_data_exfiltration_via_ai_web_ai_terms` | exact domain and app-name list | Web pre-filter. Exact terms only (see Limitations). Keep it in step with the common lookups. |
| `hdsi_ai_gradual_data_exfiltration_via_ai_usage_types` | `"web","api","cli","model_registry"` | Which `usage_type` values count. Add `"ide"` to include coding assistants. |
| `hdsi_ai_gradual_data_exfiltration_via_ai_excluded_providers` | `"Microsoft 365 Copilot"` | Providers whose volume is not counted. Use `"__none__"` to count every provider. |
| `hdsi_ai_gradual_data_exfiltration_via_ai_cumulative_mb` | `250` | Weekly MB threshold. Also sets the medium (2x) and high (4x) tiers. |
| `hdsi_ai_gradual_data_exfiltration_via_ai_min_active_days` | `3` | Minimum number of active days in the window. |
| `hdsi_ai_gradual_data_exfiltration_via_ai_active_day_mb` | `1` | MB a day must reach to count as active. |
| `hdsi_ai_gradual_data_exfiltration_via_ai_max_day_share` | `0.5` | Largest share of the weekly total that one day may carry. Set it to 1 to also score burst-dominated weeks. |
| `hdsi_ai_gradual_data_exfiltration_via_ai_max_user_srcs` | `20` | A user seen on more hosts than this counts as a shared or generic identity and is dropped. |
| `hdsi_ai_gradual_data_exfiltration_via_ai_host_requires_asset` | `1` | 1 scores a host-only `src` only when it is in the ES asset inventory. 0 scores every host-only `src`. Use 0 only on firewalls without User-ID that have stable workstation addressing. |
| `hdsi_ai_gradual_data_exfiltration_via_ai_host_max_day_mb` | `1024` | A host-only `src` whose largest day is above this many MB is treated as shared egress or an integration, and is not scored. 0 means no ceiling. |
| `hdsi_ai_gradual_data_exfiltration_via_ai_customizations` | `search *` | Post-scoring hook. For example, `search NOT src_category="*session host*"` drops multi-user hosts, and `search entity_type="user"` scores users only. |
| `hdsi_ai_gradual_data_exfiltration_via_ai_risk_score` | `search *` | Last pipe. Override `risk_score` here, keeping it between 1 and 100. |

The `low_slow_cumulative_mb` and `low_slow_days` rows in `ai_detection_config` are no longer read by this rule. Use the macros above instead.

### Threshold

The default is 250 MB per 7 days. It was set on the largest validation tenant (Tenant A), which had about 75,000 users of AI App-IDs a day. With every other default condition and guard applied, a 7-day reconstruction qualified:
- 48 entities at 100 MB
- 23 at 250 MB
- 16 at 500 MB

All of them were users. These are the only threshold counts for this rule; earlier draft counts were from older logic and were dropped. The reconstruction was made before two later changes, and both can only add entities:
- the Friday activity check was removed
- the App-ID list was extended (`kimi`, `google-gemini-models`, `bing-ai-base` and others)

In one day on Tenant A, the added App-IDs carried 115 MB through `kimi` from one source, 82 MB across 8 `google-gemini-models` users and 92 MB across 324 `bing-ai-base` users. On Tenant C, the SPL below found 3 users who met the day and share conditions: 1 at 100 MB or more, none at 250 MB.

To derive a tenant value:

1. Run the SPL below over the same window as the rule, `-7d@d` to `@d`. It is the rule's own pipeline, with every condition except the weekly MB threshold, and it reports the distribution.
2. Pick the lowest threshold that gives a reviewable weekly count, for example 10 to 25 entities. Do not go below 100 MB.
3. On a very large firewall data model, the run takes as long as the rule itself (see Limitations), so schedule it rather than running it ad hoc.

```spl
| tstats summariesonly=t allow_old_summaries=t fillnull_value="unknown" sum(All_Traffic.bytes_out) as bytes_out count from datamodel=Network_Traffic where All_Traffic.bytes_out>0 NOT All_Traffic.action="blocked" `hdsi_ai_gradual_data_exfiltration_via_ai_app_ids` `hdsi_ai_gradual_data_exfiltration_via_ai_filter` by All_Traffic.user All_Traffic.src All_Traffic.app _time span=1d
| rename All_Traffic.* as *
| lookup ai_provider_apps app_name as app OUTPUT enabled as app_row
| eval ai_domain=if(isnull(app_row),coalesce(`hdsi_ai_gradual_data_exfiltration_via_ai_app_id_aliases`,app),app), ai_input_type=if(ai_domain=app,"app","host"), evidence="firewall App-ID"
| `ai_domains_filter`
| append maxtime=1200 maxout=50000 [| tstats summariesonly=t allow_old_summaries=t fillnull_value="unknown" sum(Web.bytes_out) as bytes_out count from datamodel=Web where Web.bytes_out>0 NOT Web.action="blocked" `hdsi_ai_gradual_data_exfiltration_via_ai_web_ai_terms` `hdsi_ai_gradual_data_exfiltration_via_ai_web_filter` by Web.user Web.src Web.url_domain Web.site _time span=1d | rename Web.* as * | eval ai_domain=lower(coalesce(nullif(url_domain,"unknown"),nullif(site,"unknown"))), ai_input_type=if(isnull(nullif(url_domain,"unknown")),"app","host"), evidence="web proxy" | `ai_domains_filter` | search usage_type IN (`hdsi_ai_gradual_data_exfiltration_via_ai_usage_types`) NOT provider IN (`hdsi_ai_gradual_data_exfiltration_via_ai_excluded_providers`) NOT ai_traffic_class IN ("background","site") | stats sum(bytes_out) as bytes_out sum(count) as count max(severity_weight) as severity_weight by user src provider usage_type evidence _time]
| search usage_type IN (`hdsi_ai_gradual_data_exfiltration_via_ai_usage_types`) NOT provider IN (`hdsi_ai_gradual_data_exfiltration_via_ai_excluded_providers`) NOT ai_traffic_class IN ("background","site")
| eval user=if(isnull(user) OR match(lower(user),"^(unknown|-|n/a|null|none|)$"),null(),lower(user)), src=if(isnull(src) OR match(lower(src),"^(unknown|-|n/a|null|none|0\.0\.0\.0|::|)$"),null(),src), severity_weight=coalesce(tonumber(severity_weight),1.0)
| where isnotnull(user) OR isnotnull(src)
| `ai_unsanctioned_filter(user,src,provider)`
| eval entity_type=if(isnotnull(user),"user","system"), entity=coalesce(user,src)
| stats sum(bytes_out) as bytes_out sum(count) as requests values(provider) as providers values(src) as srcs max(severity_weight) as severity_weight by entity entity_type evidence _time
| eventstats max(bytes_out) as day_bytes by entity entity_type _time
| eval requests_at_max=if(bytes_out=day_bytes,requests,null())
| stats max(day_bytes) as day_bytes max(requests_at_max) as day_requests values(providers) as providers values(srcs) as srcs values(evidence) as evidence max(severity_weight) as severity_weight by entity entity_type _time
| eval day_mb=day_bytes/1048576
| stats sum(day_bytes) as window_bytes max(day_mb) as max_day_mb count(eval(day_mb>=`hdsi_ai_gradual_data_exfiltration_via_ai_active_day_mb`)) as active_days values(srcs) as srcs by entity entity_type
| eval window_mb=window_bytes/1048576, max_day_share=max_day_mb/window_mb, src_count=mvcount(srcs)
| where active_days>=`hdsi_ai_gradual_data_exfiltration_via_ai_min_active_days` AND max_day_share<=`hdsi_ai_gradual_data_exfiltration_via_ai_max_day_share` AND (entity_type="system" OR src_count<=`hdsi_ai_gradual_data_exfiltration_via_ai_max_user_srcs`)
| lookup asset_lookup_by_str ip as entity OUTPUT nt_host as asset_nt_host dns as asset_dns asset as asset_id
| eval src_asset=if(entity_type="system",mvindex(coalesce(asset_nt_host,asset_dns,asset_id),0),null())
| where entity_type="user" OR ((`hdsi_ai_gradual_data_exfiltration_via_ai_host_requires_asset`=0 OR isnotnull(src_asset)) AND (`hdsi_ai_gradual_data_exfiltration_via_ai_host_max_day_mb`=0 OR max_day_mb<=`hdsi_ai_gradual_data_exfiltration_via_ai_host_max_day_mb`))
| stats count as entities perc50(window_mb) as p50_mb perc90(window_mb) as p90_mb count(eval(window_mb>=100)) as ge100 count(eval(window_mb>=250)) as ge250 count(eval(window_mb>=500)) as ge500 count(eval(window_mb>=1000)) as ge1000 by entity_type
```

### Known false positives / Limitations

- **Developers using AI APIs.** On the largest tenant, most qualifying users uploaded through the Anthropic or OpenAI API App-IDs, at 0.3 to 3.6 GB a week each. That traffic is typical of agentic coding tools and API scripts, which send file and repository context with every request. It is real data leaving the organisation, but it is often approved. Sanction approved users or groups in `ai_sanctioned_entities`, or raise `_cumulative_mb`. The score stays modest (25 to 60) so that the risk aggregators decide.
- **Heavy chat users.** People who upload files or screenshots to a chat assistant every day will reach the threshold. Handle them the same way.
- **Host-only coverage is narrow by design.** Firewalls without User-ID produce host-only rows. On the largest tenant, 73 of 76 host-only addresses above the daily pace did not resolve in the asset inventory. They were VPN/CGNAT pool, DHCP or NAT addresses, at up to 17 GB a day. The 3 that did resolve included an RDS session host at 7.5 GB a day, which the 1 GB host ceiling drops. A tenant whose workstations are not in the asset inventory therefore scores no hosts. Set `_host_requires_asset` to 0 only when workstation addresses are stable for a week.
- **App-ID coverage.** The variant App-IDs that carry most of the volume on Tenant A now have `ai_provider_apps` rows. These include `claude-base`, `anthropic-api-base`, `openai-base`, `openai-chatgpt-uploading`, `xai-grok`, `deepseek-api`, `google-gemini-posting`, `google-gemini-models` and `google-notebooklm`. Before those rows existed, they would have missed 17 of the 23 qualifying users. `kimi` (Moonshot Kimi) still has no row, so `_app_id_aliases` maps it to `kimi.com`. On Tenant A it carried about 3.1 GB over 5 days, and 115 MB from one source in a single day. A new App-ID that is not in `_app_ids` is not counted at all, so review the firewall's AI App-ID list now and then. `openai-codex` and `codeium` are coding tools and count only when `ide` is added to `_usage_types`.
- **Web branch uses exact terms only.** Leading-wildcard subdomain terms cost about 200 s per day of data on a large Web data model, against 30 s for exact terms. A proxy that logs only subdomains, such as `files.oaiusercontent.com`, is therefore not counted by the Web branch. The firewall branch does not depend on hostnames.
- **Two entities for the same activity.** When the firewall has no user but the proxy does, the same traffic can appear twice: once as an inventoried host from the firewall and once as a user from the proxy.
- **Byte semantics differ by source.** Netskope connection events carry several MB each over few requests. `window_requests` is taken from whichever source carried the larger volume that day, so compare it within one evidence source.
- **Cost.**
  - The weekly run reads 7 days of accelerated data. On Tenant A (about 7.4 billion firewall sessions a day, 2.6 million of them AI App-ID sessions), the full 7-day run has never been measured in one piece, because it exceeds the 300 s test cap.
  - Seven separate one-day runs of the same pipeline took 67 to 293 s each. A later one-day re-run took 204 s. That puts one weekly run at roughly 20 to 30 minutes. This is an estimate, not a measurement. Measure it on the target tenant before enabling, and schedule it at a quiet time; the shipped Saturday 01:20 run is one.
  - That cost comes from reading `user` and `src` for every AI session. The same filter grouped only by App-ID takes 45 s a day, and a count alone takes 19 s.
  - A daily schedule would repeat 6 of the 7 days on every run, which is why the rule runs weekly on large tenants.
  - The smaller tenants finished the full 7-day run in 7 to 198 s.
  - The Web branch is an `append` subsearch, limited to 50,000 rows and 1,200 s. It reduces its rows to one per user, src, provider and day before returning them, which gave 31 rows a week on Tenant C. If an SSE tenant still reaches either limit, the Web branch is cut short without a warning in the risk event. In that case, narrow `_web_filter` or run the Web source as a separate copy of the rule.
- **Firewall drilldown cost on very large tenants.** The 7-day firewall drilldown for one entity takes more than 5 minutes on the largest tenant. Use `daily_mb` in the risk event first, or narrow the drilldown time range.
- **Detection latency.** The rule fires up to a week after the pattern starts. Same-day bursts are covered by `hdsi_ai_high_volume_upload_to_ai_service`.
- **Fixed weekly windows split drips.** The windows do not overlap, Saturday to Friday each week. A drip that crosses the Saturday boundary is split between two runs. For example, 150 MB on Wednesday to Friday and 150 MB on Saturday to Monday gives two weeks of 150 MB, and neither week reaches 250 MB. On a tenant where one 7-day run is cheap (Tenants B to D took 7 to 198 s), you can run the rule daily with `cron_schedule = 20 1 * * *` and keep the same `-7d@d` to `@d` window. That gives a rolling window. The 6-day suppression still limits an entity to about one risk event a week, though it can fire again on day 7 from the same days. On a very large tenant a daily run costs 7 times as much, so keep the weekly schedule there, or lower `_cumulative_mb` to make up for the split.

### Validation

These were read-only live tests on 4 production ES tenants on 2026-10-09. Rows are at the shipped defaults over `-7d@d` to `@d` unless noted. The rule, its 3 drilldowns and the Threshold SPL parse on all 4 tenants.

| Tenant | AI data with byte counts | Run (shipped rule) | Rows | Notes |
|---|---|---|---|---|
| A | Firewall App-ID: about 2.6 M AI sessions a day from about 75 k users. Web: IDS/URL logs without bytes. | Capped at 120 s: auto-finalized with partial results at 151 s, no errors. The full 7-day run is longer than the test cap. It is estimated from one-day runs (see Cost). | 0 in the capped run. 7-day reconstruction: 23 | All 23 are users, mostly API uploads. A relaxed 1-day run (50 MB, 1 day, any share) returned 28 user rows scored 25 to 54, with no host rows. The added App-IDs all resolve to a provider: 13 checked over 1 day, in 79 s. |
| B | None in the firewall data. Web is mostly inbound load-balancer and WAF logs, plus a small proxy share with about 0.2 MB a day of AI traffic, on subdomains only. | 198 s, no errors | 0 | Relaxed (20 MB, 2 days): 0. |
| C | Firewall App-ID with no user attribution. SSE logs with users and bytes. | 15 s, no errors | 0 | Threshold SPL: 3 users met the day and share conditions, at a median of 56 MB a week. 1 was at 100 MB or more, none at 250 MB. The Web subsearch returned 31 rows a week after its reduction. |
| D | None (inbound web-server logs only). | 7 s, no errors | 0 | No AI upload path exists. |

The drilldowns are limited to AI App-IDs and AI web terms. With a single entity, they completed on B, C and D in 2 to 93 s over 7 days. On Tenant A the risk and Web drilldowns took 6 and 15 s. The firewall drilldown for one user took 26 s per day of data, and its 7-day run went past the 300 s test cap. Without the App-ID filter, one day took 179 s. A test value with a single unescaped backslash matched nothing, and the escaped `entity_search` value matched.

### Deployment

The package ships with `enable_alerting: false`. Before enabling it:

1. Validate the full search against the target tenant and measure the runtime of one weekly run. On a small tenant, decide whether to run it daily instead (see Limitations).
2. Confirm that the Network_Traffic and Web acceleration covers 7 days.
3. Confirm that workstation IPs resolve in the ES asset inventory if host-only scoring is wanted.
4. Derive `_cumulative_mb` with the Threshold SPL.
5. Sanction approved AI API users in `ai_sanctioned_entities`.

The rule is risk-only, with no notable, and is meant to feed the `hdsi_rba_ai_*` risk aggregators. Enabling it, and disabling any rule it replaces, must be one separately approved change.
