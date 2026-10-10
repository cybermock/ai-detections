## Architect Notes
---
**Author:** Trevor Mock, Hurricane Labs LLC. Security Operations Architect

This rule finds users using AI web apps that the organisation has not sanctioned: chat assistants (ChatGPT, Claude, Gemini, Copilot, Grok, Perplexity, DeepSeek and others), AI writing, image, video, voice and app-builder tools. It reads proxy, NGFW URL-filtering, SSE/CASB and enterprise-browser logs in the CIM `Web` model and resolves each host or SSE app name through the common AI provider lookups. Unsanctioned AI use is the most common way company data reaches a third-party model, so this is the base "shadow AI" signal that the AI risk aggregators build on. It creates risk on the `user`, at most once per user and provider per day. System risk on the internal `src`, and rows with no user (system-only), are both off by default and can be enabled with a macro. It does not create a notable. MITRE ATT&CK: T1588.007 (Obtain Capabilities: Artificial Intelligence).

### Prerequisites
- **CIM `Web`, accelerated:** a host in `Web.url_domain`, an app name in `Web.site`, or a URL in `Web.url`, plus `Web.user`, `Web.src`, `Web.action` and `Web.bytes_out`.
  - Most on-premises NGFW and proxy sources fill `url_domain` with a hostname.
  - Some sources leave `url_domain` and `site` empty and log the host only inside `url`. In the largest validation tenant the cloud-delivered NGFW feed did this on 100 % of its rows (about 5.9 million events an hour, all with a user). The url fallback branch covers these sources (see How it works). Use the discovery SPL below to see which of your sourcetypes are url-only.
  - SSE/CASB products often leave `url_domain` empty and put an app name in `site` (for example "ChatGPT" or "Adobe Firefly"). The rule handles this through the `ai_provider_apps` lookup.
  - The NGFW must log the AI URL category. Many firewalls log only blocked or selected categories, so check that allowed AI traffic reaches Splunk.
  - Inbound web server, load-balancer and WAF logs in the Web model are not user activity. The rule drops rows that have no user and a public `src`, which removes them. Rows from a public `src` that do carry a user (remote SSE users behind their home IP) are kept, with risk on the user only.
- **Common package `hdsi_ai_rba_common`:**
  - `ai_domains_filter` with the `ai_provider_domains` and `ai_provider_apps` lookups (provider resolution and `ai_traffic_class`).
  - `ai_unsanctioned_filter(3)` with `ai_sanctioned_entities` (per-user, per-system, per-bunit and organisation-wide approvals).
  - `ai_risk_multiplier` with `ai_department_sensitivity` (identity bunit multiplier).
- **ES assets and identities (optional):** `identity_lookup_expanded` (`bunit` by `user`) and `asset_lookup_by_str` (`bunit` by `src` IP or DNS name). Without a `bunit`, only per-user, per-system and organisation-wide approvals can match, and the multiplier stays 1.0.

Discovery SPL for url-only sourcetypes (cheap: counts only). A sourcetype with a high `url_only_pct` and real users needs the url fallback branch:

```spl
| tstats summariesonly=t allow_old_summaries=t count count(Web.url_domain) as with_url_domain count(Web.site) as with_site count(Web.url) as with_url
    from datamodel=Web where earliest=-1h by sourcetype
| eval url_only_pct=if(with_url>0, round(100*(with_url-max(with_url_domain,with_site))/with_url,1), 0)
| where url_only_pct>50 | sort - count
```

### How it works
- **Main branch:** `tstats` over `Web`, restricted by `hdsi_ai_unsanctioned_web_access_scope` (AI web hosts and subdomains in `url_domain` or `site`, plus SSE app names in `site`). `fillnull_value="unknown"` keeps rows where `site` or `url_domain` is empty. Grouped by `sourcetype`, `user`, `src`, `url_domain` and `site`.
- **Url fallback branch:** a second `tstats` (an `append` subsearch capped at 180 s and 50,000 rows) reads rows from the sourcetypes in `hdsi_ai_unsanctioned_web_access_url_sourcetypes` (ships `"*"`) whose `url` starts with an AI web domain (`hdsi_ai_unsanctioned_web_access_urls`) and whose `url_domain` and `site` do not match the main scope, so no row is counted twice. The host is extracted from the URL (scheme, credentials, port, path and query removed) and the rows join the main branch with `ai_host_source="url"`. The URL patterns are prefixes only, because a leading wildcard scans the whole `url` lexicon (about 97 s for one hour of one large sourcetype, against about 7 s an hour for the prefix patterns).
- **Shared pre-processing (`hdsi_ai_unsanctioned_web_access_prepare`, also used by the Threshold SPL):**
  - Users that match `hdsi_ai_unsanctioned_web_access_invalid_users` become null: placeholders (`unknown`, `-`, empty), IP addresses and GUID-based pseudo-identities.
  - IPv4-mapped IPv6 (`::ffff:a.b.c.d`) is read as IPv4, and placeholder `src` values become null.
  - `src_public`: internal means RFC 1918, 100.64.0.0/10, 169.254.0.0/16, 127.0.0.0/8, IPv6 ULA (`fc00::/7`), link-local (`fe80::/10`), `::1`, or a hostname. Any other IPv4 or IPv6 address is public.
  - `ai_domain` = `url_domain`, else `site`. `ai_input_type` is `host` for hostnames and `app` for `site` app names. Hostnames are cut at `&`, `;`, `,` or whitespace, so an NGFW value such as `gemini.google.com&hfcr_pid=2` still resolves.
- Rows with neither a user nor an internal `src` are dropped. `ai_domains_filter` resolves the provider. Only `usage_type=web` rows are kept: API, IDE, CLI and model-registry traffic belong to other rules.
- Providers listed in `hdsi_ai_unsanctioned_web_access_sanctioned_providers` are dropped.
- **Aggregation:** by `risk_entity` (the user when known, else the internal `src`), `provider` and `usage_type`. A hostname match needs at least `hdsi_ai_unsanctioned_web_access_min_events` events in the window. An SSE app-name match counts from one event.
- **Non-interactive hosts:** a provider whose only hosts are non-interactive is dropped. A host is non-interactive when the common registry marks it `traffic_class` = `background` or `site` (for example `ab.chatgpt.com`, `bzr.openai.com`, `auth.openai.com`, `gemini.gstatic.com`, `downloads.claude.ai`), or when it matches `hdsi_ai_unsanctioned_web_access_auxiliary_hosts` (the Edge Copilot sign-in frame `ms-sso.copilot.*`, which has no registry row).
- **`src`:** set only when exactly one internal source was seen for the entity and provider. When more than `hdsi_ai_unsanctioned_web_access_max_users_per_src` (3) distinct users reach AI providers from the same internal `src` in the window (NAT, proxy, VDI, terminal server), `src` is cleared. Public egress IPs are never kept.
- **Risk objects:** `user` always. `risk_src` (system) carries the `src` only for system-only rows, or on user rows when `hdsi_ai_unsanctioned_web_access_src_risk` = 1. With the defaults, the only risk object is the user.
- **System-only rows are opt-in.** A row with no user is kept only when `hdsi_ai_unsanctioned_web_access_system_only_min_events` is above 0 (ships as 0) and the row reaches that many events. See Known false positives.
- `bunit` is resolved from the identity (by `user`) or the asset (by `src`). Then `ai_unsanctioned_filter(user,src,provider)` drops approved users, systems, business units and organisation-wide approvals. The common macro also looks up the identity `bunit` itself, including by bare user name.
- **Scoring:**
  - `base_score` = 15 × `severity_weight` (0.3 to 1.2, from the lookup), halved when every logged action was a block.
  - `risk_score` = `base_score` × `risk_multiplier`, at least 3 and at most 30. ES applies it to every risk object in the row.
  - The literal `_risk` scores (15 for each object) are only a fallback.
- **Kill-chain field:** `ai_kill_chain_phase="recon"` is the shared AI-RBA value for shadow-AI usage signals. It does not mean ATT&CK reconnaissance. `hdsi_rba_ai_multi_vector_risk` maps `recon` to its `shadow_usage` vector, and `hdsi_rba_ai_privilege_escalation_correlation` counts it as AI activity, so changing it would remove this rule from both.
- **Schedule:** hourly (`17 * * * *`, `-65m@m` to `-5m@m`). Suppression is 24 h on `risk_entity` and `provider`: unsanctioned use is an ongoing state, so it is scored once a day per provider.
- **Suppression key.** The gold convention suppresses on the risk-object fields. With the defaults, `risk_entity` is exactly the one risk object emitted (the user, or the `src` of an opt-in system-only row), so the key is the risk object plus `provider`. It only differs when `hdsi_ai_unsanctioned_web_access_src_risk` = 1: a user who moves between hosts (Wi-Fi then dock, DHCP renewal) is still scored once a day per provider, and the second host gets no system risk from this rule that day.

### Tuning macros
| Macro | Ships as | Purpose |
|---|---|---|
| `hdsi_ai_unsanctioned_web_access_filter` | `()` | Exclusions inline in both `tstats` where clauses (Web field names), e.g. `NOT sourcetype IN ("aws:elb:accesslogs","aws:waf")` or `NOT Web.user IN ("svc_*")`. |
| `hdsi_ai_unsanctioned_web_access_sanctioned_providers` | `"__none__"` | Providers approved for the whole organisation for this rule only, e.g. `"OpenAI","Microsoft Copilot"`. Use the provider names from `ai_provider_domains`. **Set this, or the organisation-wide `*|<provider>` rows below, before enabling.** |
| `hdsi_ai_unsanctioned_web_access_min_events` | `3` | Minimum events per entity and provider in the hourly window for a hostname match. |
| `hdsi_ai_unsanctioned_web_access_src_risk` | `0` | `1` adds the single non-shared internal `src` as a system risk object on user rows. |
| `hdsi_ai_unsanctioned_web_access_system_only_min_events` | `0` | `0` drops rows with no user. A positive value keeps system-only rows that reach that many events per provider in the hour (derive it from the Threshold SPL). |
| `hdsi_ai_unsanctioned_web_access_max_users_per_src` | `3` | A `src` used by more distinct users than this in the window is treated as shared and cleared. |
| `hdsi_ai_unsanctioned_web_access_url_sourcetypes` | `"*"` | Sourcetypes read by the url fallback branch. Narrow it to the url-only sourcetypes from the discovery SPL to save cost, or set `"__none__"` to turn the branch off. |
| `hdsi_ai_unsanctioned_web_access_invalid_users` | regex | `lower(Web.user)` values that are not a person (placeholders, IPs, GUID-based identities). Add tenant service or kiosk accounts here. |
| `hdsi_ai_unsanctioned_web_access_auxiliary_hosts` | regex | Non-interactive hosts that have no `background` row in the common registry: `ms-sso.copilot.microsoft.com` and `ms-sso.copilot.com`. |
| `hdsi_ai_unsanctioned_web_access_prepare` | eval chain | Shared pre-processing for the rule and the Threshold SPL. Do not edit. |
| `hdsi_ai_unsanctioned_web_access_scope` | `url_domain`/`site` IN lists | Pre-filter that keeps the main scan to AI traffic. Do not edit. |
| `hdsi_ai_unsanctioned_web_access_domains` | 240 patterns | `"<domain>*"` and `"*.<domain>*"` for every `usage_type=web` row of `ai_provider_domains`. |
| `hdsi_ai_unsanctioned_web_access_urls` | 534 patterns | URL prefixes for the url fallback branch: `"<domain>*"`, `"http://<domain>*"`, `"https://<domain>*"`, plus `www.` forms for two-label domains. |
| `hdsi_ai_unsanctioned_web_access_apps` | 82 names | Every `usage_type=web` app name of `ai_provider_apps`. |
| `hdsi_ai_unsanctioned_web_access_customizations` | `search *` | Post-aggregation hook. Fields: `risk_entity`, `user`, `src`, `risk_src`, `src_ip_list`, `src_user_count`, `shared_src`, `provider`, `ai_match`, `ai_host_source`, `ai_domains`, `interactive_domains`, `event_count`, `bytes_out`, `web_actions`, `blocked_only`, `sourcetypes`, `severity_weight`, `risk_multiplier`, `base_score`, `risk_score`. |
| `hdsi_ai_unsanctioned_web_access_risk_score` | `search *` | Last pipe. Overrides `risk_score` (max 100). |

The domain, URL and app lists are literal because ES cannot syntax-check a lookup subsearch inside a `tstats` where clause. They include disabled rows, so turning a lookup row on or off (for example the opt-in Microsoft 365 Copilot rows) needs no change here. Only **new** web domains or app names need regenerating. Paste the `definition` value from each search into the matching macro (domains, urls, apps):

```spl
| inputlookup ai_provider_domains | where usage_type="web" | eval d=lower(trim(domain))
| eval p=mvappend("\"".d."*\"", "\"*.".d."*\"") | stats values(p) as p | eval definition=mvjoin(p,",")

| inputlookup ai_provider_domains | where usage_type="web" | eval d=lower(trim(domain))
| eval p=mvappend("\"".d."*\"", "\"http://".d."*\"", "\"https://".d."*\"",
    if(match(d,"^[^.]+\.[^.]+$"), mvappend("\"www.".d."*\"", "\"https://www.".d."*\""), null()))
| stats values(p) as p | eval definition=mvjoin(p,",")

| inputlookup ai_provider_apps | where usage_type="web" | eval a="\"".lower(trim(app_name))."\""
| stats values(a) as a | eval definition=mvjoin(a,",")
```

**Approvals** go in `ai_sanctioned_entities` (lowercase `allow_key`, `enabled=1`, optional `expires` date):
- `<user>|<provider>` or `<user>|*` for a user, `<src>|<provider>` or `<src>|*` for a host, `<bunit>|<provider>` or `<bunit>|*` for a business unit (the identity `bunit`, else the asset `bunit` of the `src`).
- `*|<provider>` approves a provider for the whole organisation in every AI rule that uses `ai_unsanctioned_filter`. Use the sanctioned-providers macro instead when the approval should apply to this rule only.

To stop treating a provider as AI everywhere, set its rows to `enabled=0` in the common lookups. That also affects the other AI rules.

### Threshold
`hdsi_ai_unsanctioned_web_access_min_events` defaults to 3. In validation, 22 % of OpenAI, 49 % of Gemini and 32 % of Anthropic entity-provider pairs had fewer than 3 requests in an hour. To derive a tenant value, profile one week of hourly counts per entity and provider. The SPL uses the rule's own pre-processing macro (`hdsi_ai_unsanctioned_web_access_prepare`), filter, sanctioned providers and non-interactive host logic. It leaves out SSE app-name matches (they do not use the threshold) and the url fallback branch (too costly over a week). It does not apply the shared-`src` cut-off, so its `system_only` population is an upper bound. The `entity_type` split also gives the starting value for `hdsi_ai_unsanctioned_web_access_system_only_min_events`:

```spl
| tstats summariesonly=t allow_old_summaries=t fillnull_value="unknown" count from datamodel=Web
    where `hdsi_ai_unsanctioned_web_access_scope` `hdsi_ai_unsanctioned_web_access_filter` earliest=-7d@d latest=@d
    by _time span=1h sourcetype Web.user Web.src Web.url_domain Web.site
| rename Web.* as *
| `hdsi_ai_unsanctioned_web_access_prepare`
| where isnotnull(user) OR (isnotnull(src) AND src_public=0)
| `ai_domains_filter` | where usage_type="web" AND ai_match!="app_name"
| search NOT provider IN (`hdsi_ai_unsanctioned_web_access_sanctioned_providers`)
| eval risk_entity=coalesce(user,src), entity_type=if(isnotnull(user),"user","system_only"),
    ai_interactive_domain=if(coalesce(ai_traffic_class,"interactive")="interactive" AND NOT match(ai_domain,`hdsi_ai_unsanctioned_web_access_auxiliary_hosts`),ai_domain,null())
| stats sum(count) as events values(ai_interactive_domain) as interactive by _time entity_type risk_entity provider
| where isnotnull(interactive)
| stats count as pairs perc25(events) as p25 perc50(events) as p50 perc90(events) as p90 by entity_type provider
| sort entity_type - pairs
```

Keep the user value between 2 and 5. Higher values mostly remove light users rather than false positives; use the auxiliary-hosts macro or the registry `traffic_class` for background traffic instead.

For system-only rows, a gate at the `p50` keeps half of all hourly host pairs, which is still a lot. In the largest validation tenant (4 h sample) the `system_only` p50 was 2 to 7 events for the main providers (OpenAI 6.8, Anthropic 3, Google Gemini 2, Microsoft Copilot 2) and the p90 was 6 to 25 (OpenAI 24.8, Anthropic 18.8, Google Gemini 7, Microsoft Copilot 6). Start near the `p90` of the providers you care about, so only the heaviest hosts score.

### Known false positives / Limitations
- **Sanctioned providers look unsanctioned until configured.** Out of the box every enabled AI web provider counts. In the largest validation tenant OpenAI, Google Gemini and Microsoft Copilot were most of the output (about 95 % of a 24 h run in the earlier measurement, and 244 of 266 pairs in the 4 h run below). Agree the sanctioned list with the customer before enabling.
- **System risk is opt-in.** NGFW URL logs often carry no user, and the internal `src` is usually a DHCP address. **None of the HDSI AI risk aggregators (`hdsi_rba_ai_*`) read system risk: they all filter `risk_object_type="user"`.** In the largest tenant system-only rows were about 85 % of hourly rows (about 7,100 pairs a day at a 10-event gate), and `src` on user rows would have added about 1,720 system events a day. `hdsi_ai_dns_queries_to_ai_domains` already scores the same hosts once a day. Turn on `hdsi_ai_unsanctioned_web_access_src_risk` or the system-only gate only when the ES asset lookup covers the client ranges and someone will triage asset risk.
- **Shared hosts with system risk on.** The shared-`src` check counts users per hour, while suppression lasts 24 h per entity and provider. A VDI or terminal-server host with 3 or fewer AI users in each hour can therefore still collect one system event per user, provider and day when `src_risk` = 1. Exclude such hosts in the filter macro, or lower `hdsi_ai_unsanctioned_web_access_max_users_per_src`.
- **Url-only sources.** The url fallback uses URL prefixes, so it sees `chatgpt.com/...`, `https://claude.ai/...` and every listed subdomain, but not an unlisted subdomain (for example `academy.claude.com`) that a main-branch source would match through `*.claude.com`. A cloud feed may log the user in a different form (UPN) from the on-premises feed (`DOMAIN\user`). The same person can then produce two user risk objects until ES identity correlation merges them.
- **Pseudo-identities.** An enterprise-browser audit feed in validation logged extension activity under GUID-based identities (`<guid>+<id>@<extension domain>`) that ES cannot match to a person. The invalid-users regex nulls any user containing a GUID, which also covers raw directory object IDs. If your sources log real users only as object IDs, resolve them in the identity framework first or narrow this regex.
- **Background and embedded traffic.** The Edge Copilot sidebar sign-in frame (`ms-sso.copilot.microsoft.com`), Gemini static assets and OpenAI client background hosts appear on endpoints with no chat session. In the earlier 24 h measurement they were the only hosts for about 3,500 pairs a day in one tenant; the registry `traffic_class` and the auxiliary-hosts macro drop them. A host that keeps retrying a blocked site (one source logged more than 100,000 blocked `chatgpt.com` requests in a day) is still a single pair, scored at half weight.
- **Blocked attempts.** Where the NGFW already blocks the AI category, attempts still score at half weight because they show intent and policy pressure. To ignore them, add `| where blocked_only=0` in the customizations macro.
- **SSE app names.** App-name matching depends on the vendor's naming. The common package ships "Microsoft 365 Copilot", "Microsoft Copilot Studio" and "Adobe Spark" disabled (opt-in), so they are not counted; Copilot Studio is still seen through `copilotstudio.microsoft.com`. In the SSE tenant every row has a `site`, and the url fallback found no additional AI web rows there.
- **Opt-in rows.** Microsoft 365 Copilot, Notion and Grammarly rows ship disabled in the common lookup, and the rule does not see them. Microsoft Copilot (consumer) is enabled.
- **Inbound logs.** Inbound WAF and load-balancer logs can contain AI hostnames (a cloud scanner sending an AI `Host` header, a CDN in front of a customer site). They are excluded only because they have no user and a public `src`. If an inbound source maps an authenticated user into `Web.user`, exclude its sourcetype in the filter macro. The discovery SPL also lists internal application access logs as url-only; their URLs rarely start with an AI domain, but narrow `hdsi_ai_unsanctioned_web_access_url_sourcetypes` if they add cost.
- **Overlap.** `hdsi_ai_dns_queries_to_ai_domains` covers DNS lookups to the same providers with system-only risk. This rule adds the user and the web action.

### Validation
Read-only live tests on 2026-10-09 across 4 production ES tenants. Runs used the 4 h test window (`-4h@m` to `-5m@m`) with the shipped defaults.

| Tenant | Web data | Parses (search + 2 drilldowns) | Rows, 4 h | Runtime | Notes |
|---|---|---|---|---|---|
| A | On-premises NGFW URL logs (`url_domain`), a cloud-delivered NGFW feed (host only in `url`, user on every row) and an enterprise browser audit feed | OK | 266 user pairs | 55 s | 6 providers, max score 30, no `risk_src` (system risk off). The url fallback added 23 pairs (19 seen only in the cloud feed: Gemini 9, Anthropic 8, OpenAI 1, xAI 1). The url branch alone took 28 s for 4 h; with leading-wildcard patterns it took 166 s. |
| B | Mostly inbound load-balancer/WAF logs plus a small cloud proxy | OK | 0 | 88 s | No url-only sourcetypes. The previous version scored an internet scanner hitting an AI `Host` header as `unknown` user activity; that row is dropped (no user, public `src`). The proxy saw no enabled AI web provider. |
| C | SSE with app names in `site`, user as UPN, public egress `src` | OK | 0 | 5 s | Over 24 h the enabled app names (Adobe Firefly, Lovable, Casetext, Amazon Q) had at most 17 users, so the rule scores a handful of users a day. Microsoft 365 Copilot (11,700 users) and Copilot Studio (20 users) app names are now opt-in in the common package and are not counted. |
| D | Inbound IIS logs only | OK | 0 | 4 s | No outbound web data. Runs clean. |

No run returned a FATAL or ERROR message. In earlier runs the same day, the web-activity drilldown returned the matching AI hosts for a concrete entity in Tenants A and C. The risk drilldown returned 0 rows because the rule is not deployed.

The earlier 24 h measurement in Tenant A, with the previous common registry, was about 2,370 user pairs a day, and about 110 once OpenAI, Gemini and Copilot were sanctioned. A 4 h window is not a daily rate.

The first version returned 0 rows in Tenants A, C and D and one false row in Tenant B. In Tenant A it grouped every web domain: a 4-hour run took 270 s, and a 4-hour test of the same grouping did not finish in 400 s. It also had these defects:
- `$token$` risk scores, which ES does not support.
- An `unknown` user risk object.
- A `src` fallback to `dest`, which made the AI site the system risk object.
- A 5-minute schedule with a 1-hour suppression.
- MITRE T1071.001 (C2 over web protocols), which does not describe this activity.

### Deployment
The package ships with `enable_alerting: false`. Before enablement:
- Agree the sanctioned providers with the customer and set `hdsi_ai_unsanctioned_web_access_sanctioned_providers`, or add organisation-wide `*|<provider>` rows to `ai_sanctioned_entities`.
- Add individual approvals to `ai_sanctioned_entities`.
- Confirm that the NGFW or proxy logs allowed AI-category traffic and that SSE app names resolve.
- Run the discovery SPL and, if only some sourcetypes are url-only, narrow `hdsi_ai_unsanctioned_web_access_url_sourcetypes` to them.
- Exclude any inbound sourcetypes that carry users.
- Decide whether system risk (`src_risk`, system-only rows) is wanted. It is off by default; enable it only with asset coverage of the client ranges.
- Run the rule over 24 h to measure the daily risk volume.

The rule is risk-only. Enabling it, and disabling any legacy unsanctioned-AI web rules it replaces, must be one separately approved change.
