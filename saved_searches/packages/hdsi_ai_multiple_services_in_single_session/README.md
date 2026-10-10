## Architect Notes
---
**Author:** Trevor Mock, Hurricane Labs LLC. Security Operations Architect

This rule detects one user or host actively using several distinct AI providers (default 4) within one hour, for example ChatGPT, Claude, Gemini and Perplexity in the same hour. Breadth like this is typical of "prompt shopping": the same content, often internal data, is pasted into several services to compare answers. It spreads that data across more providers than any single-provider rule shows. Evidence comes from Web proxy/SSE logs (user attributed) and, where no proxy sees the traffic, from DNS (host attributed). The rule creates risk on `user` and/or `src` and does not create a notable event.

### Prerequisites
- **At least one of:**
  - **`Web` data model** (accelerated) from an egress proxy, SWG or SSE/CASB with a populated `Web.user` and either `Web.url_domain` or `Web.site`. SSE and firewall products that log only an application name in `site` (for example "ChatGPT" or the App-ID `openai-chatgpt`) are supported through `ai_provider_apps`. Inbound server logs (WAF, load balancer, IIS) do not have a user and are ignored by the `Web.user!="unknown"` gate.
  - **`Network_Resolution` data model** (accelerated) with `DNS.src` and `DNS.query` from clients, not only from forwarders. CIM DNS has no user field, so DNS-only rows carry risk on the host only. `DNS.vendor_product` is used to recognise roaming DNS-security clients (see Limitations).
- If neither model has data, the search runs and returns nothing.
- **ES lookups:** `identity_lookup_expanded` (for `bunit` and the user risk multiplier).
- **Common package `hdsi_ai_rba_common`:** `ai_domains_filter` (resolves names, DNS answers and SSE/App-ID app names to a provider and outputs `ai_traffic_class`), `ai_unsanctioned_filter` (allowlist), `ai_risk_multiplier`, and the lookups `ai_provider_domains`, `ai_provider_apps`, `ai_sanctioned_entities` and `ai_department_sensitivity`.

### How it works
- **Hourly** at minute 7 over `-65m@m` to `-5m@m`. The 60-minute dispatch window is the "session".
- **Web branch:** `tstats` over `Web` with the inline `..._web_prefilter` (AI host names, cloud AI patterns and exact SSE/App-ID app names), `Web.user!="unknown"` and the tenant `..._filter`, split by `user`, `src`, `url_domain` and `site`. `ai_domain = coalesce(url_domain, site)` and `ai_input_type` is `app` when only `site` is present.
- **DNS branch (`append`):** `tstats` over `Network_Resolution` with the inline `..._dns_prefilter`, placeholder and loopback sources removed, and the tenant `..._dns_filter`, split by `src`, `query`, `message_type` and `vendor_product`. When a source logs both query and response, the larger per-type count is used, not the sum. Evidence from addresses matching `..._unreliable_dns_src` (roaming DNS-security clients on home-router ranges) is dropped here. `ai_input_type="dns"`, so a DNS name is never treated as an app name.
- **Provider resolution:** `ai_domains_filter` keeps enabled providers only. Dropped before counting: providers in `..._excluded_providers` (IDE coding assistants and tenant-bound Microsoft 365 / Security Copilot by default), registry rows marked `traffic_class` `background` or `site` and IDE-assistant hosts (`..._excluded_traffic`), and names matching `..._background_names` (Copilot SSO, Perplexity Comet browser hosts, telemetry and CDN labels).
- **DNS shared-source guard (`append`):** DNS clients that resolved at least `..._shared_src_names` (3,000) distinct names in the hour are resolvers, forwarders or NAT egress. Their DNS evidence is dropped. Web evidence from the same address is kept because it carries a user.
- **Web shared-address guard (`append`):** a second `tstats` counts the distinct users on every `Web.src` in the hour across **all** Web traffic, not only AI traffic. Users are compared after lowercasing and removing `DOMAIN\` and `@suffix`, so one person logged as `DOMAIN\jdoe` by one source and `jdoe@example.com` by another counts once. An address with more than `..._max_src_users` (1) user is shared: NAT or SSE egress, VDI, terminal server or proxy. A shared address never receives `src` risk and never passes DNS evidence to a user. The users behind it keep their own Web-based risk.
- **Attribution:** a DNS-only row inherits a user only when the address is not Web-shared and exactly one user (after the same normalisation) also has AI Web evidence on it in the hour. The entity is the normalised user, otherwise the host, so `DOMAIN\JDoe`, `jdoe@example.com` and `jdoe` in different sources are aggregated as one person. The emitted `user` keeps its original form (the first value in sort order when several forms were seen), so risk lands on the same `risk_object` string as the other detections for that identity.
- **Evidence gate:** a provider counts as used when the entity made at least `..._min_requests` (3) requests to it in the hour. `ai_unsanctioned_filter(user,src,provider)` then removes allowlisted user, host, group and organisation-wide provider entries (see Tuning).
- **Threshold:** at least `..._min_providers` (4) distinct providers per entity.
- **Scoring:** `base_score = 5 x provider_count` (4 providers = 20). For attributed users it is multiplied by `risk_multiplier` from `ai_risk_multiplier` (bunit sensitivity x 1.25 for privileged/critical identities, cap 2.0). `risk_score = min(40, ...)` and it applies to both risk objects in the row. The `_risk` literal fallback is 20 for `user` and `src`. `src` is only emitted when the entity used exactly one address and that address is not Web-shared, so no risk lands on a multi-host list, a shared egress address or "unknown". Rows left with neither a user nor an emitted `src` are dropped.
- **Output fields:** `entity`, `user`, `user_display`, `src`, `src_display` (a shared address is shown as `<address> (shared address, N Web users)`), `src_web_users`, `provider` (multivalue) and `providers`, `provider_count`, `provider_list`, `usage_type_list`, `evidence_type` (`web`, `dns` or `dns + web`), `request_count`, `ai_domain_sample` (up to 8 names), `ai_domain_count`, `bunit`, `sensitivity_level`, `risk_multiplier`, `base_score`, `risk_score`, `firstTime`, `lastTime`, `ai_activity`, `detection_id`, `mitre_attack`, `ai_kill_chain_phase`, and the drilldown fields below.
- **Drilldowns** use always-populated fields, so they work for user-only rows, host-only rows and shared addresses. Backslashes and quotes are replaced by `*` (a quoted `DOMAIN\user` term otherwise matches nothing):
  - `drill_user` is the user, or `__none__`.
  - `drill_src` is the emitted `src`. When no `src` was emitted, it is the address the evidence came from (a shared address, or the first of several hosts).
  - `drill_web_src` is `drill_src` for host-only rows and `__none__` otherwise, so the Web drilldown filters by user when there is one and by host when there is not.
- **Suppression:** 24 hours per `user,src`. The rule fires at most once a day per entity. MITRE ATT&CK T1588.007 (Obtain Capabilities: Artificial Intelligence).

### Tuning macros
| Macro | Ships as | Purpose |
|---|---|---|
| `hdsi_ai_multiple_services_in_single_session_filter` | `()` | Inline exclusions for both Web `tstats` (Web.* names), e.g. `NOT Web.user IN ("svc_*")` or `NOT sourcetype IN ("aws:waf")` |
| `hdsi_ai_multiple_services_in_single_session_dns_filter` | `()` | Inline exclusions for both DNS `tstats` (DNS.* names), e.g. known resolvers or NAT egress addresses below the guard threshold, or `NOT sourcetype IN (...)` to ignore a roaming DNS feed entirely |
| `hdsi_ai_multiple_services_in_single_session_web_prefilter` | `(Web.url_domain IN (...) OR Web.site IN (...))`: 123 name terms plus 86 app names | Inline Web pre-filter. **Regenerate when `ai_provider_domains` or `ai_provider_apps` change** (SPL below) |
| `hdsi_ai_multiple_services_in_single_session_dns_prefilter` | `(DNS.query IN ("*chatgpt.com*", ...))`: 123 terms | Inline DNS pre-filter: interactive, non-IDE registry rows plus the cloud AI patterns. Regenerate with the SPL below |
| `hdsi_ai_multiple_services_in_single_session_excluded_providers` | `"GitHub Copilot","Cursor","Windsurf","Tabnine","Sourcegraph","Microsoft 365 Copilot","Microsoft Security Copilot"` | Providers that never count. `"__none__"` counts all |
| `hdsi_ai_multiple_services_in_single_session_excluded_traffic` | `in(ai_traffic_class,"background","site") OR usage_type="ide"` | Registry background rows (update checks, A/B tests, auth, extension streams, telemetry), documentation/download sites (`aider.chat`, `ollama.com`, `lmstudio.ai`) and IDE-assistant hosts (e.g. Gemini Code Assist, Amazon Q, JetBrains AI, Kiro) do not count. If you remove `usage_type="ide"`, regenerate the pre-filters with the IDE rows |
| `hdsi_ai_multiple_services_in_single_session_unreliable_dns_src` | Umbrella / Cloud Security / Secure Access `vendor_product` AND `src` in `192.168.0.0/16` or `10.0.0.0/24` | DNS evidence from addresses that are not one host (home routers behind roaming clients). Same definition as `hdsi_ai_dns_queries_to_ai_domains_unreliable_src`. `false()` keeps everything |
| `hdsi_ai_multiple_services_in_single_session_background_names` | `match(ai_domain, ...)` for `ms-sso.copilot*`, the Perplexity Comet sync/safe-browsing/download hosts, and `*telemetry*`, `*sentry*`, `*collector*`, `*segment*`, `*cdn*` labels | Package-specific names that are not evidence of use and have no registry `traffic_class`. `false()` counts everything |
| `hdsi_ai_multiple_services_in_single_session_min_requests` | `3` | Requests per entity per provider per hour before the provider counts |
| `hdsi_ai_multiple_services_in_single_session_min_providers` | `4` | Distinct providers per entity per hour that raise risk |
| `hdsi_ai_multiple_services_in_single_session_shared_src_names` | `3000` | Distinct DNS names per client per hour above which the client is shared infrastructure |
| `hdsi_ai_multiple_services_in_single_session_max_src_users` | `1` | Distinct normalised Web users per address per hour above which the address is shared: no `src` risk and no DNS-to-user inheritance |
| `hdsi_ai_multiple_services_in_single_session_customizations` | `search *` | Post-aggregation hook (fields listed above) |
| `hdsi_ai_multiple_services_in_single_session_risk_score` | `search *` | Last pipe. Override `risk_score` (integer, at most 100). It applies to both `user` and `src` |

**Allowlisting** uses `ai_sanctioned_entities` (common package). `ai_unsanctioned_filter` runs per entity and provider before the providers are counted, so an allowlisted pair simply stops counting toward the total. Keys are lowercase; the macro lowercases `user`, `src`, the group and the provider before matching.
- **A provider licensed for everyone** (e.g. ChatGPT Enterprise): use an organisation-wide row keyed `*|<provider>`, e.g. `group,*,OpenAI,global,2099-12-31,security,chatgpt_enterprise,1,*|openai`. You can also add the provider to `..._excluded_providers`, which affects this rule only.
- **A team that is expected to compare models** (AI engineering, research): use a group row keyed on the ES identity `bunit`, e.g. `group,ai-research,*,group,2099-12-31,security,ai_evaluation_team,1,ai-research|*`. The filter looks up the identity `bunit` itself, first by the raw user value, then by the bare name.
- **One person:** `user,jdoe@example.com,*,global,2099-12-31,security,ai_evaluation_team,1,jdoe@example.com|*`. User keys match the emitted `user` string exactly (lowercased). If the person appears as both `DOMAIN\jdoe` and `jdoe@example.com`, add a row for each form, or use a group row.

**Regenerate the pre-filters** after changing the provider lookups, and paste the result into the two macro definitions. The SPL emits one term per counting `ai_provider_domains` row (about 160 terms today). The shipped macros hold a de-duplicated 123-term list, which drops names already covered by a broader term: for example, `*api.openai.com*` is covered by `*openai.com*`. Both lists match exactly the same events, so removing covered names by hand is optional:

```spl
| inputlookup ai_provider_domains where enabled=1
| where NOT (traffic_class IN ("background","site") OR usage_type="ide")
| eval term="\"*".lower(domain)."*\""
| stats values(term) as terms
| eval terms=mvjoin(terms,",").",\"*bedrock*.amazonaws.com*\",\"*aiplatform.googleapis.com*\",\"*ai.azure.com*\",\"*.openai.azure.com*\",\"*.cognitiveservices.azure.com*\",\"*sagemaker.*.amazonaws.com*\""
| appendcols [| inputlookup ai_provider_apps where enabled=1 | where usage_type!="ide" | eval app="\"".lower(app_name)."\"" | stats values(app) as apps | eval apps=mvjoin(apps,",")]
| eval dns_prefilter="(DNS.query IN (".terms."))", web_prefilter="(Web.url_domain IN (".terms.") OR Web.site IN (".terms.",".apps."))"
| fields dns_prefilter web_prefilter
```

### Threshold
`..._min_providers` defaults to 4 distinct providers per user or host per hour, with `..._min_requests` (3) per provider. Before you change it, measure the hourly distribution with the same exclusions. Pick the smallest value that gives a reviewable number of entities a day. With 24 h suppression, the number of entities a day is about the number of risk events a day:

```spl
| tstats summariesonly=t allow_old_summaries=t fillnull_value="unknown" count from datamodel=Network_Resolution
    where `hdsi_ai_multiple_services_in_single_session_dns_prefilter` NOT DNS.src IN ("unknown","-","0.0.0.0","127.0.0.1","::1")
    by DNS.src DNS.query DNS.message_type DNS.vendor_product _time span=1h
| rename DNS.* as * | stats max(count) as count values(vendor_product) as vendor_product by src query _time
| where NOT (`hdsi_ai_multiple_services_in_single_session_unreliable_dns_src`)
| eval ai_domain=query, ai_input_type="dns" | `ai_domains_filter`
| where NOT provider IN (`hdsi_ai_multiple_services_in_single_session_excluded_providers`) AND NOT (`hdsi_ai_multiple_services_in_single_session_excluded_traffic`) AND NOT (`hdsi_ai_multiple_services_in_single_session_background_names`)
| stats sum(count) as requests by src provider _time
| where requests>=`hdsi_ai_multiple_services_in_single_session_min_requests`
| stats dc(provider) as providers by src _time
| stats count as host_hours dc(src) as hosts by providers
| sort providers
```

Run it over 24 hours. Forwarders show up with high provider counts. Check them with the shared-source SPL below, and if the guard misses them, exclude them in `..._dns_filter`.

**`..._shared_src_names` (3,000 distinct names per client per hour).** Workstations stayed below about 650 names an hour at the 99th percentile on every validation tenant. Forwarders and NAT addresses resolved 6,000 to more than 60,000:

```spl
| tstats summariesonly=t allow_old_summaries=t dc(DNS.query) as names from datamodel=Network_Resolution
    where NOT DNS.src IN ("unknown","-","0.0.0.0","127.0.0.1","::1") by DNS.src _time span=1h
| stats max(names) as max_names_per_hour by DNS.src
| sort - max_names_per_hour | head 50
```

### Known false positives / Limitations
- **Power users of mainstream assistants.** ChatGPT + Claude + Gemini in one hour is common. On the busiest validation tenant, three 24-hour replays gave 51 to 83 hosts a day at a threshold of 3, almost all that combination, and 9 to 15 hosts a day at 4, so the default is 4. The fourth provider was most often QuillBot, DeepL or Perplexity. If the mainstream three are sanctioned, add an organisation-wide `*|<provider>` allowlist row (or `..._excluded_providers`) and lower the threshold.
- **AI engineering and research staff** legitimately compare models and SDKs (Bedrock, Vertex AI, Hugging Face, local LLMs). Allowlist them in `ai_sanctioned_entities` rather than raising the threshold for everyone.
- **DNS from forwarders.** On two validation tenants every DNS-only multi-provider candidate was a forwarder or NAT address (6,000 to 63,000 names an hour). The guard drops them, so those tenants produce no DNS-based risk. Host-level evidence there needs client-level DNS logging, for example endpoint DNS, Sysmon event 22 or Stream at the access layer.
- **Roaming clients of cloud DNS-security services (dropped by default).** A roaming agent (Cisco Umbrella / Cloud Security / Secure Access) logs the laptop's local address, so a home-router address such as `192.168.0.0/16` or `10.0.0.0/24` stands for many unrelated laptops in different homes. On Tenant B, one address that the previous version flagged carried 5 to 7 different roaming identities in every hour of a 6-hour raw check, with the same number of distinct public IPs. In a 24-hour replay, 7 of the 12 hosts that reached 4 providers were in `192.168.0.0/16` (one more was in 10/8), and both rows from the earlier 4-hour run were such addresses. `..._unreliable_dns_src` therefore drops this evidence. In one scheduled hour it removed 314 of 395 AI-resolving roaming sources on Tenant B and 163 of 182 on Tenant C. Other RFC 1918, public and IPv6 roaming sources are kept. In a sibling package's 8-hour sample, public roaming sources were 2 to 6% shared. A tenant whose roaming feed carries the user or device identity can map it into `DNS.src` and set the macro to `false()`. A tenant whose corporate LAN really uses these ranges behind an on-network Umbrella virtual appliance can narrow the ranges.
- **No user on DNS.** CIM `Network_Resolution` has no user field. DNS-only rows give risk to the host unless the address carries exactly one Web user in the same hour (see Attribution). DHCP churn can move an address between hosts.
- **Shared addresses.** Users behind NAT or SSE egress, VDI or a terminal server still receive their own Web-based risk, but the shared address never does. On one validation tenant whose SSE logs the public egress IP as `Web.src`, 35 addresses carried more than 20 users in an hour (up to 617), and in the final check 58 addresses had several users (up to 546). The guard flags at most 50,000 shared addresses an hour, which is the subsearch row limit in `limits.conf`. In a scheduled hour the largest validation tenant had 14,898 addresses with several raw user values, and 13,047 after normalisation: 1,851 addresses (12%) were one person under two name formats. A larger estate should list its egress ranges in `..._filter`.
- **Identity formats.** The entity key strips `DOMAIN\` and `@suffix`, so two different people with the same account name in two domains (or a personal `jdoe@gmail.com` seen by an SSE) would be merged. User normalisation in the Web guard only applies to addresses with up to 50 raw user values. Larger addresses are shared anyway.
- **SSE app-name coverage.** Products that log an app name in `site` are recognised only for names in `ai_provider_apps`. One validation tenant's SSE logged only three AI apps: Microsoft 365 Copilot (opt-in, disabled by default), GitHub Copilot (excluded) and Adobe Firefly. Its Web data therefore never reached 4 providers.
- **Firewall URL logs** that only record blocked or threat categories (benign categories not logged) see little AI traffic. One validation tenant had about 6 million user/host/domain rows an hour in `Web` and none for an AI provider.
- **Pre-filter maintenance.** Names or app names added to the common lookups are not seen until both pre-filters are regenerated.
- **Weak "use" evidence.** A provider counts after 3 requests to any interactive name, so heavy browsing of a provider's marketing or pricing pages counts as use. The registry's background and site rows, Copilot SSO, Perplexity Comet browser hosts, and common extension and browser telemetry hosts are excluded. Before these exclusions, 2 of 57 unguarded host-hours on the busiest tenant reached the threshold only through such names.
- **Pooled providers.** The registry's `Model Registry` provider covers several model hubs, so two hubs count as one provider.
- **Overlap.** `hdsi_ai_dns_queries_to_ai_domains` scores the daily provider count per host. This rule adds risk only for concentrated use within one hour (default 20, at most 40).

### Validation
Read-only tests on 4 production ES tenants, 2026-10-09. v1.0 was run over its auto window (the last 4 hours). v1.1 was run in four ways:
- over its exact scheduled window (`-65m@m` to `-5m@m`) for 8 consecutive weekday business hours on Tenants A and C, and 4 on Tenants B and D;
- as an hour-by-hour replay of the previous 24 hours, to estimate daily volume;
- after the final changes (roaming DNS exclusion, identity normalisation, registry traffic classes, regenerated pre-filters, always-populated drilldown fields), over the last 4 hours (auto window) on a Friday evening;
- with diagnostic variants: the threshold lowered to 2, and the roaming exclusion disabled.

No v1.1 run returned a FATAL or ERROR message. The search and all 3 drilldowns parse on all tenants. A `makeresults` check confirmed the normalisation: `CORP\JDoe`, `jdoe@example.com` and `JDOE` give one key, `jdoe`. It also confirmed that the drilldown fields replace backslashes and quotes with `*`.

| Tenant | Evidence available | v1.0 (4 h) | v1.1 scheduled hours | v1.1 24 h hourly replay | Final version, auto 4 h window | Notes |
|---|---|---|---|---|---|---|
| A | Web: firewall threat/URL logs and an enterprise browser, with users. DNS: about 1.1 billion events a day, from on-network resolvers and a network sensor | 0 rows, 199 s, `_temp_domains` warning | 1 row in 8 business hours (DNS host, 4 providers, score 20, `src` emitted); 92 to 102 s per run | Not replayed in one job: the Web guard returns about 15,000 to 20,700 shared addresses an hour, so a 24 h replay exceeds the subsearch limit. An earlier 4 h window gave 1 user-attributed Web row | 0 rows, 125 s | Before the Web pre-filter, the Web branch returned about 6 million rows an hour and the search took about 3 min. Every DNS candidate with many providers was a forwarder or NAT address at 6,000 to 63,000 names an hour, dropped by the guard. No roaming DNS feed, so the roaming exclusion removes nothing. Web guard subsearch: 9 s |
| B | Web: mostly inbound load-balancer/WAF logs (no user) plus a small SSE proxy. DNS: about 53 million a day from a DNS-security service with roaming clients | 0 rows, 72 s, `_temp_domains` warning | 1 row in 4 business hours (DNS host, score 20) | Before the roaming exclusion: 26 host-hours, 11 hosts at 4 providers, most on home-router addresses (see Limitations) | 0 rows, 51 s. At threshold 2: 17 host rows (the pipeline works). With the roaming exclusion disabled: still 0 at 4 in this window | The roaming exclusion removed 314 of 395 AI-resolving sources in one hour. No user-attributed rows. Fourth providers seen earlier: QuillBot, DeepL, Perplexity, Model Registry, Microsoft Copilot, Synthesia, Bedrock/SageMaker |
| C | Web: SSE logging app names, with the public egress IP as `src`. DNS: about 209 million a day, mostly forwarders plus a roaming DNS-security feed | 0 rows, 4 s, `_temp_domains` warning | 0 rows in 8 business hours; 15 to 17 s per run | 0 entities | 0 rows, 14 s. 0 at threshold 2 | SSE AI apps seen: Microsoft 365 Copilot (opt-in, disabled), GitHub Copilot (excluded), Adobe Firefly. All DNS candidates with many providers were forwarders (9,000 to 43,000 names an hour). The roaming exclusion removed 163 of 182 roaming sources. 58 addresses had several Web users in one hour (up to 546); the Web guard keeps them out of `src` risk |
| D | Web: inbound IIS only. DNS: about 2.8 million a day | 0 rows, 4 s, `_temp_domains` warning | 0 rows in 4 business hours; 14 to 15 s per run | 0 entities | 0 rows, 14 s | Almost no AI DNS activity; no shared Web addresses |

v1.0 could not fire anywhere, for three reasons:
- it only expanded `url_domain`: sites were collected but never used, hence the warning;
- it scanned the entire `Web` model with no pre-filter;
- it ran every 5 minutes over a 10-minute window while describing a one-hour session.

In a weekday business hour, every subsearch stayed well below the 50,000-row limit:
- DNS evidence: 0 to 4,900 rows
- Web shared-address guard: 0 to 20,700
- DNS shared-source guard: 0 to 90

Drilldowns:
- The risk-event drilldown returned in under 6 s.
- The DNS drilldown, with every host as a wildcard, returned in 13 to 196 s.
- The Web drilldown, with every user as a wildcard, hit the 300 s test limit on two tenants.

In use, each drilldown is scoped to one host or user.

### Deployment
The package ships with `enable_alerting: false`. Before you enable it, check the following against the target tenant:
- Validate the complete search over its scheduled window.
- Confirm which data model supplies evidence: Web with users, client-level DNS, or both.
- Confirm that the guards cover the tenant's infrastructure:
  - The DNS shared-source guard removes the tenant's resolvers and NAT addresses.
  - The roaming DNS exclusion matches the tenant's DNS-security product.
  - The Web shared-address guard covers its egress and VDI addresses.
- Derive `..._min_providers` from a day of hourly data.
- Allowlist approved AI evaluation users or groups, and organisation-wide licensed providers.
- Measure the daily suppressed risk shape.

The rule is risk only: it never creates a notable by itself. Enabling it must be one separately approved change.
