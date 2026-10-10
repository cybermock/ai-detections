## Architect Notes
---
**Author:** Trevor Mock, Hurricane Labs LLC. Security Operations Architect

This rule finds a **user or host that starts using several AI providers it has never touched before, in a short burst**. Examples: a user who tries ChatGPT, Gemini and Perplexity for the first time in the same week, or a workstation that starts calling the Anthropic API, AWS Bedrock and GitHub Copilot on the same day. A single new AI tool is ordinary. A burst of several is a change in behaviour that is worth a little risk: someone is shopping for AI capability (MITRE ATT&CK T1588.007, Obtain Capabilities: Artificial Intelligence), possibly ahead of moving data into those services. The rule runs once a day. It creates one risk event on the **user** (from Web data) or the **host** (`src`, from DNS data) on the run after the entity crosses the threshold, and does not create a notable.

v1.0 had no baseline. It looked at 8 days of Web data and called a provider "new" when it was first seen in the last 7 of them, so almost every provider of every user counted as new. It also gave risk to `unknown` users and `src` values, and used MITRE T1071.001 (C2 over web protocols). v1.1 compares the last 7 days against the 14 days before them, uses DNS as well as Web, and resolves providers through the common `ai_domains_filter`. Because a DNS client address is not a stable person, a host must adopt its new providers on **one day** (a user has the whole 7-day window).

### Prerequisites
- **At least one of these, accelerated for at least 21 days:**
  - **`Network_Resolution`** with client DNS queries (`DNS.src`, `DNS.query`, `DNS.message_type`). This path gives **system** risk on `src`. Resolver query logs, a DNS security service and network capture all work. Trailing-dot names (`chatgpt.com.`) are matched.
  - **`Web`** with user-attributed outbound traffic (`Web.user`, `Web.url_domain` and/or `Web.site`). This path gives **user** risk. NGFW URL logs, proxies, enterprise browsers and SSE/CASB products that log an app name in `site` (for example "Adobe Firefly") all work. Rows without a usable user are dropped. Inbound server logs (load balancer, WAF, IIS) contribute nothing, but they are still scanned, so exclude them in `..._web_filter` (see Tuning).
  - **Acceleration range matters.** The search uses `summariesonly=t` over `-21d@d` to `@d`. If a model is accelerated for only 7 days (as on one validation tenant), that path has no baseline and is dropped by the coverage guard. The rule then returns nothing for that path instead of reporting every provider as new. Either extend the acceleration range to at least 21 days, or shorten the windows (see Threshold).
- **ES lookups** `asset_lookup_by_str` and `identity_lookup_expanded` (present in every ES install). They supply `bunit`, so group approvals in `ai_sanctioned_entities` apply, and they feed `ai_risk_multiplier` for users.
- **Common package `hdsi_ai_rba_common`**: `ai_domains_filter` (lookups `ai_provider_domains` and `ai_provider_apps`; its `ai_traffic_class` output marks background hosts), `ai_unsanctioned_filter(3)` (lookup `ai_sanctioned_entities`) and `ai_risk_multiplier` (lookup `ai_department_sensitivity`). The `ai_detection_config` rows `new_provider_velocity_days` and `new_provider_velocity_count` are no longer read. The thresholds are package macros now.

### How it works
- **DNS path (main search).** A `tstats` over `Network_Resolution` is split by day, `src`, `query` and `message_type`. Placeholder and loopback sources and, by default, home-LAN addresses (`..._dns_src_scope`, 192.168.0.0/16) are excluded inline. It is pre-filtered by `..._dns_names`, which has three parts:
  - The exact host names of every enabled `ai_provider_domains` row, with `www.` and trailing-dot forms.
  - 51 recurring service and runtime subdomains of those rows that are not rows themselves, for example `api.business.githubcopilot.com`, `api2.cursor.sh`, `cdn.platform.openai.com` and `assets-proxy.anthropic.com`. Without them, a host that had used a provider only through such a name during the baseline looked new as soon as it touched a listed name.
  - Trailing-wildcard prefixes for the regional cloud AI endpoints that `ai_domains_filter` resolves by pattern: `bedrock*.amazonaws.com` (Bedrock, Bedrock runtime, agents and AgentCore in every region), `runtime.` and `api.sagemaker.<region>.amazonaws.com`, and `<region>-aiplatform.googleapis.com` (regional Vertex AI).

  No term has a leading wildcard. When a source logs both the query and the response, the larger per-type count is used, so nothing is counted twice. Names are resolved with `ai_input_type="dns"`.
- **Web path (`append` subsearch, `maxtime=900`, `maxout=50000`).** A `tstats` over `Web` is split by day, `user`, `url_domain` and `site`. It uses `fillnull_value="unknown"`, so rows where one field is empty, such as `site` on NGFW logs or `url_domain` on SSE logs, are kept. It is pre-filtered by `..._web_scope` (the same host names, subdomains and cloud prefixes as host prefixes, plus `ai_provider_apps` app names). Users that are placeholders or IP addresses are dropped. `ai_domain` is `url_domain`, or `site` when there is no `url_domain`, and an SSE app name is resolved as an app (`ai_input_type="app"`). The subsearch returns one row per user and provider, so the `maxout` limit applies to user-provider pairs, not to events.
- **Daily evidence gate.** A provider is *active* for an entity on a day if one of these is true:
  - Its runtime API names (`..._api_names`: API, CLI, model-registry and local-LLM hosts such as `api.anthropic.com`, `registry.ollama.ai`, Bedrock or Vertex endpoints, plus the plan-specific GitHub Copilot `api.`/`proxy.` hosts and the Cursor model back ends) had at least `..._min_api_queries` (3) DNS queries, or at least 1 Web event. One or two lookups a day are background checks by installed tools, not use.
  - On the Web path, an SSE app session was matched.
  - Otherwise, its non-background names had at least `..._min_dns_queries` (10) DNS queries or `..._min_web_events` (3) web events.

  `..._background_names` never make a provider active. It covers every row the common lookup marks `traffic_class=background` (for example `ab.chatgpt.com`, `bzrcdn.openai.com`, `auth.openai.com`, Copilot telemetry, `gemini.gstatic.com`) plus static, CDN, telemetry and metrics hosts, the Copilot experiment hosts and the Perplexity browser beacons. Provider websites (`traffic_class=site` rows such as `ollama.com`, plus `huggingface.co`, `kaggle.com`, `openrouter.ai` and a few others) are excluded from `..._api_names`, so they need the ordinary bar and never earn the API bonus.
- **First touch versus first active.** For each entity and provider, `first_touch` is the first day with *any* query or event, including background names and prefetch below the gate. `first_active` is the first day that passed the gate. A provider is **new** when `first_touch` falls inside the last `..._window_days` (7) days and it was active at least once. A provider that was only prefetched or touched in the background during the baseline is therefore *not* new when it is later used for real.
- **Coverage guard.** For each path, the first covered day is the earliest day on which the path saw at least 10% of the entities of its busiest day. The path is dropped unless that day is at least `..._window_days + ..._min_baseline_days` (7 + 7) days old.
- **Shared-source guards (DNS).** A DNS client that touched at least `..._shared_src_providers` (15) providers in the window is a resolver, forwarder, proxy or NAT egress, and is dropped. Hosts must also have touched some AI provider before the window (`..._needs_baseline`, hosts only by default).
- **Exclusions and approvals.** Providers in `..._excluded_providers` are removed. Then `ai_unsanctioned_filter(user,src,provider)` removes user, host, `bunit` group and organisation-wide (`*|<provider>`) approvals, before anything is counted.
- **Host burst (DNS).** For a host, a new provider counts only if it became active within `..._host_burst_days` (1, the same day) of the host's latest adoption. DHCP, Wi-Fi and VPN addresses pass between people over a week; requiring the providers to arrive together keeps one person's burst and drops several people's adoptions added together (see Known false positives). Users are not affected.
- **Velocity.** One row per entity with `new_providers`, `provider_list`, `api_provider_list` (new providers used through runtime API names), `org_new_provider_list`, `baseline_providers`, `usage_type_list`, `ai_domain_sample` (up to 8 names), `ai_domain_count`, `event_count`, `first_adoption` and `latest_adoption`. The row is kept when `new_providers >= ..._min_new_providers` (3) **and** the latest adoption falls within the last `..._report_days` (2) complete days. The normal daily run reports the entity the day after it reaches the threshold. If that run is skipped, the next run still reports it. `org_new_provider_list` names new providers that nobody in the organisation touched during the baseline.
- **Suppression.** 72 h on `user,src,new_providers`. The overlapping second day of the report window does not report the same burst twice, but a user whose burst grows (a 4th or 5th new provider within the window) is reported again with the higher score. A host's burst is anchored on its latest day, so a host that adds one more provider on a later day is not re-reported.
- **Scoring.** Each row has exactly one risk object: `user` on Web rows, `src` on DNS rows. The other field is null, so no `unknown` object is emitted.
  - `base_score` is 25 for a user and 15 for a host.
  - Add 5 per provider above the threshold (at most 15), 5 if any provider is new to the organisation, and 5 if any new provider was used through its runtime API names (`api_provider_list` is not `none`).
  - For users, multiply by `risk_multiplier` from `ai_risk_multiplier` (identity `bunit` sensitivity × 1.25 for privileged identities).
  - `risk_score = round(min(60 for a user or 40 for a host, base × multiplier))`.
  - The literal fallback scores in `_risk` are 25 for a user and 15 for a system.

### Tuning macros
| Macro | Ships as | Purpose |
|---|---|---|
| `hdsi_ai_new_provider_adoption_velocity_filter` | `()` | DNS-path exclusions inside the `Network_Resolution` `tstats` (`DNS.*` names), e.g. `NOT DNS.src IN ("10.1.1.10")` for resolvers and proxies, or `NOT DNS.src IN ("10.20.30.*")` for DHCP, Wi-Fi, VPN or VDI pools |
| `hdsi_ai_new_provider_adoption_velocity_dns_src_scope` | `(NOT DNS.src="192.168.*")` | Drops home and hotel LAN addresses reported by roaming DNS-security clients. Replace it with `()` (or with the home subnets only) if your own LAN uses 192.168 ranges |
| `hdsi_ai_new_provider_adoption_velocity_web_filter` | `()` | Web-path exclusions inside the `Web` `tstats` (`Web.*` names), e.g. `NOT sourcetype IN ("aws:elb:accesslogs","aws:waf")`. Set it to `(Web.user="__web_path_disabled__")` to switch the Web path off where `Web` holds no user egress |
| `hdsi_ai_new_provider_adoption_velocity_dns_names` | `(DNS.query IN ("chatgpt.com","chatgpt.com.","www.chatgpt.com", ...) OR DNS.query IN ("api.business.githubcopilot.com", ...) OR DNS.query IN ("bedrock*.amazonaws.com*", ...))`: 768 exact names, 51 subdomains (102 terms) and 11 cloud prefixes | DNS pre-filter. **Regenerate it when rows are added to `ai_provider_domains`** (SPL below) |
| `hdsi_ai_new_provider_adoption_velocity_web_scope` | `(Web.url_domain IN ("bedrock*.amazonaws.com*", ..., "chatgpt.com*", ...) OR Web.site IN (..., "adobe firefly", ...))` | Web pre-filter: host prefixes, subdomain prefixes, cloud prefixes and `ai_provider_apps` app names. Regenerate it together with the DNS list |
| `hdsi_ai_new_provider_adoption_velocity_window_days` | `7` | Velocity window in days. The baseline is the rest of the dispatch window |
| `hdsi_ai_new_provider_adoption_velocity_min_baseline_days` | `7` | Covered baseline days required per path. Below this, the path fails closed |
| `hdsi_ai_new_provider_adoption_velocity_min_new_providers` | `3` | New providers per entity required to report it |
| `hdsi_ai_new_provider_adoption_velocity_report_days` | `2` | Report an entity whose latest adoption is in the last N complete days. 2 catches up after one skipped run; 1 reports only yesterday |
| `hdsi_ai_new_provider_adoption_velocity_host_burst_days` | `1` | Hosts only: new providers must become active within N days of the host's latest adoption. Raise it only where DNS client addresses are static |
| `hdsi_ai_new_provider_adoption_velocity_min_dns_queries` | `10` | Daily DNS queries to non-background web and IDE names for a provider to count as active |
| `hdsi_ai_new_provider_adoption_velocity_min_web_events` | `3` | Daily Web events for a provider to count as active (SSE app sessions and runtime API hosts count from 1) |
| `hdsi_ai_new_provider_adoption_velocity_api_names` | `(in(usage_type,"api","local_llm","model_registry","cli") AND coalesce(ai_traffic_class,"interactive")!="site" AND NOT match(ai_domain,"^(ollama\\.com\|huggingface\\.co\|...)$")) OR match(ai_domain,"^(api\|proxy)\\.(business\|enterprise\|individual)\\.githubcopilot\\.com$\|...")` | Runtime API names that use the lower API bar and earn the API bonus. Provider websites are excluded |
| `hdsi_ai_new_provider_adoption_velocity_min_api_queries` | `3` | Daily DNS queries to runtime API names for a provider to count as used through an API. `1` counts any lookup |
| `hdsi_ai_new_provider_adoption_velocity_background_names` | `coalesce(ai_traffic_class,"")="background" OR match(ai_domain, ...)` covering static, CDN, telemetry, metrics, Copilot experiment and SSO hosts | Names that count as a touch but never as use |
| `hdsi_ai_new_provider_adoption_velocity_shared_src_providers` | `15` | Distinct providers per DNS client above which the client is treated as shared infrastructure |
| `hdsi_ai_new_provider_adoption_velocity_needs_baseline` | `entity_type="system"` | Entities that must have earlier AI activity to be reported. `true()` limits users to established AI users. `false()` requires it for nobody |
| `hdsi_ai_new_provider_adoption_velocity_excluded_providers` | `"Microsoft 365 Copilot","Microsoft Security Copilot"` | Providers that never count in this rule. Add tools during an organisation-wide rollout (e.g. `"GitHub Copilot"`). `"__none__"` keeps all |
| `hdsi_ai_new_provider_adoption_velocity_customizations` | `search *` | Post-aggregation hook (fields listed in How it works, plus `entity`, `entity_type`, `path`, `bunit`) |
| `hdsi_ai_new_provider_adoption_velocity_risk_score` | `search *` | Last pipe. Override `risk_score` (at most 100) here |

Regenerate the two pre-filters after changing the common lookups. Each search outputs one definition, including the fixed subdomains and cloud prefixes. Add a subdomain to `extra` when the "View AI DNS names" drilldown or the sibling DNS rule shows a busy provider host that is not in the list:

```spl
| inputlookup ai_provider_domains where enabled=1
| eval d=lower(domain), n=mvappend(d, d.".", "www.".d, "www.".d.".")
| mvexpand n | eval term="\"".n."\""
| stats values(term) as terms
| eval extra=split("api.business.githubcopilot.com,api.enterprise.githubcopilot.com,api.individual.githubcopilot.com,proxy.business.githubcopilot.com,proxy.enterprise.githubcopilot.com,proxy.individual.githubcopilot.com,telemetry.business.githubcopilot.com,telemetry.enterprise.githubcopilot.com,telemetry.individual.githubcopilot.com,exp.business.githubcopilot.com,exp.enterprise.githubcopilot.com,exp.individual.githubcopilot.com,exp-tas.githubcopilot.com,origin-tracker.business.githubcopilot.com,origin-tracker.enterprise.githubcopilot.com,origin-tracker.individual.githubcopilot.com,api2.cursor.sh,api3.cursor.sh,api4.cursor.sh,api2direct.cursor.sh,agentn.api5.cursor.sh,agentn.global.api5.cursor.sh,agentn.us.api5.cursor.sh,metrics.cursor.sh,marketplace.cursorapi.com,cdn.platform.openai.com,cdn.openai.com,images.openai.com,files.openai.com,sentinel.openai.com,external.auth.openai.com,ios.chat.openai.com,android.chat.openai.com,codex-cloud-backend.chatgpt.com,codex-cloud-environments.chatgpt.com,learn.chatgpt.com,aw.api.openai.com,assets-proxy.anthropic.com,s-cdn.anthropic.com,a-cdn.anthropic.com,a-api.anthropic.com,mcp-proxy.anthropic.com,a.claude.ai,assets.claude.ai,pivot.claude.ai,platform.claude.com,count.perplexity.ai,edge.perplexity.ai,pplx-next-static-public.perplexity.ai,comet-safebrowsing.perplexity.ai,ms-sso.copilot.microsoft.com", ",")
| eval extra=mvmap(extra, "\"".extra."\",\"".extra.".\"")
| eval cloud="\"bedrock*.amazonaws.com*\",\"runtime.sagemaker.*.amazonaws.com*\",\"api.sagemaker.*.amazonaws.com*\",\"us-*aiplatform.googleapis.com*\",\"europe-*aiplatform.googleapis.com*\",\"asia-*aiplatform.googleapis.com*\",\"northamerica-*aiplatform.googleapis.com*\",\"southamerica-*aiplatform.googleapis.com*\",\"australia-*aiplatform.googleapis.com*\",\"me-*aiplatform.googleapis.com*\",\"africa-*aiplatform.googleapis.com*\""
| eval definition="(DNS.query IN (".mvjoin(terms,",").") OR DNS.query IN (".mvjoin(extra,",").") OR DNS.query IN (".cloud."))"
| fields definition
```

For the Web list, use the same `extra` value with `mvmap(extra, "\"".extra."*\"")`:

```spl
| inputlookup ai_provider_domains where enabled=1
| eval d=lower(domain), n=mvappend(d."*", "www.".d."*") | mvexpand n | eval term="\"".n."\""
| stats values(term) as hosts
| appendcols [| inputlookup ai_provider_apps where enabled=1 | eval term="\"".lower(app_name)."\"" | stats values(term) as apps]
| eval extra=split("<same comma-separated list as above>", ","), extra=mvmap(extra, "\"".extra."*\"")
| eval cloud="\"bedrock*.amazonaws.com*\",\"runtime.sagemaker.*.amazonaws.com*\",\"api.sagemaker.*.amazonaws.com*\",\"us-*aiplatform.googleapis.com*\",\"europe-*aiplatform.googleapis.com*\",\"asia-*aiplatform.googleapis.com*\",\"northamerica-*aiplatform.googleapis.com*\",\"southamerica-*aiplatform.googleapis.com*\",\"australia-*aiplatform.googleapis.com*\",\"me-*aiplatform.googleapis.com*\",\"africa-*aiplatform.googleapis.com*\""
| eval definition="(Web.url_domain IN (".cloud.",".mvjoin(hosts,",").",".mvjoin(extra,",").") OR Web.site IN (".cloud.",".mvjoin(hosts,",").",".mvjoin(extra,",").",".mvjoin(apps,",")."))"
| fields definition
```

**Opt-in: customer-named Azure AI endpoints.** Azure OpenAI (`<resource>.openai.azure.com`), Azure AI Foundry (`<resource>.services.ai.azure.com`) and Azure AI Services (`<resource>.cognitiveservices.azure.com`) carry the customer's resource name in front, so they need a leading wildcard. On the largest DNS tenant this added about 35 s per 7 days scanned, so they ship disabled. To include them, append this inside the outer parentheses of `..._dns_names`:

```spl
OR DNS.query IN ("*.openai.azure.com*","*.services.ai.azure.com*","*.cognitiveservices.azure.com*")
```

**Approvals.** Entity approvals go in `ai_sanctioned_entities` (common package), e.g. `user,jdoe,Anthropic,provider,2099-12-31,security,approved_pilot,1,jdoe|anthropic`. Group approvals use the identity or asset `bunit`, e.g. `research|*`. A tool the whole organisation is licensed for can be approved once with the organisation-wide key `*|<provider>` (it then disappears from every AI rule), or removed from this rule only with `..._excluded_providers`.

### Threshold
**`..._min_new_providers` (3) over `..._window_days` (7) against a 14-day baseline.** On the tenant with the richest DNS data, the hosts whose latest adoption fell in the 2-day report window were: 171 with 1 new provider, 38 with 2, and 9 with 3 or more (whole-window count, before the host burst gate). A threshold of 2 would report about 5 times as many hosts. Most of those combine one real service with Gemini or consumer Copilot. Measure your own distribution over the scheduled window. Comment out the final threshold `where` in a copy of the search and append:

```spl
| eval latest_ok=if(latest_adoption>=relative_time(now(),"-2d@d"),1,0)
| stats count by entity_type new_providers latest_ok
```

**`..._host_burst_days` (1).** On Tenant B (roaming DNS-security client, so `src` is the client's internal address) the same scheduled window gave 15 host rows when the whole 7-day window counted, 5 with a 2-day burst and 3 with a same-day burst. Checked against the DNS service's own user field: each of the 3 same-day rows was used by a single identity on its burst day; 2 of the 5 two-day rows mixed 2 to 5 identities on those days; the whole-window rows were mostly addresses with 3 to 9 identities in the week. Raise the value only where DNS client addresses are stable, for example fixed desktop addresses or resolver logs that record the host name.

**`..._min_api_queries` (3).** Runtime API names are often resolved once or twice a day by installed IDE extensions and desktop apps that nobody is using at the moment (GitHub Copilot and Anthropic API names were the commonest). On the richest DNS tenant, compared with v1.1's first cut (any single lookup of an API, CLI, model-registry or local-LLM name counted as use, including `ollama.com` and `huggingface.co`), the current gate cut the hosts that reach 3 new providers in the 21-day window from 31 to 15, and the hosts reported by one run from 14 to 9 (both before the host burst gate). On Tenant C, hosts with 2 new providers fell from 9 to 3. Lower it to 1 only if you want every installed AI tool to count.

**Short acceleration range.** If a model is accelerated for only about a week, scale everything down together:
- `dispatch.earliest_time = -8d@d`
- `..._window_days = 3`
- `..._min_baseline_days = 4`

On the 7-day tenant this produced 3 user rows a day at the default threshold. A 4-day baseline is noisy, though: about 1,000 users a day had one "new" provider. Prefer extending the acceleration range.

**`..._shared_src_providers` (15).** On the two roaming-DNS tenants, most clients touched 1 to 5 providers in 21 days. The count then fell steadily, from about 100 clients at 6 providers to single clients at 12 to 14. Only 2 to 4 clients per tenant touched 15 to 27 providers, which is the profile of a forwarder or egress address. Find the break on your tenant:

```spl
| tstats summariesonly=t allow_old_summaries=t count from datamodel=Network_Resolution
    where `hdsi_ai_new_provider_adoption_velocity_dns_names` by DNS.src DNS.query
| rename DNS.* as * | eval ai_domain=query, ai_input_type="dns" | `ai_domains_filter`
| stats dc(provider) as providers by src
| stats count as clients by providers | sort - providers
```

Run it over 21 days. Check the clients at the top against the asset inventory before you lower the guard.

### Known false positives / Limitations
- **DNS identity: a host row is an address, not a person.** DNS gives a client IP. With a roaming DNS-security client or short DHCP leases, that address passes between people. On Tenant B the DHCP, Wi-Fi and VPN addresses that the previous whole-window version reported had 3 to 9 different users in a week (1 to 3 on most days), and one 192.168 home-LAN address had 6 users in a single day. Three guards address this: home-LAN addresses are out of scope (`..._dns_src_scope`; 17% of the AI DNS clients on Tenant B and 32% on Tenant C, none on Tenant A), a host must adopt its new providers on one day (`..._host_burst_days`), and it must have earlier AI activity (`..._needs_baseline`). A same-day burst can still mix two people on a busy pool address. Before acting on a host row, resolve the address to a device and user for the burst day (DHCP, VPN or EDR logs). An asset-inventory match does not prove a single user: 6 of the 9 addresses the previous version reported on Tenant B were in the asset inventory, and 8 of the 9 had several users. Exclude known pools in `..._filter` if they produce noise.
- **Developer onboarding and tool trials.** All 3 host rows on Tenant B at the default settings were one person adding several developer tools on one day: the Anthropic API with AWS Bedrock and GitHub Copilot, the Anthropic API and GitHub Copilot with Gemini, and Cursor with Amazon Q and a local LLM runtime (score 20 each). That is real capability acquisition, but often sanctioned. Approve known engineering hosts or groups in `ai_sanctioned_entities`. During an organisation-wide rollout, approve the rolled-out tool organisation-wide (`*|<provider>`) or add it to `..._excluded_providers`.
- **The mainstream trio.** "Google Gemini, Microsoft Copilot, OpenAI" in one week is common for users. It happens when a browser or OS update surfaces Gemini and Copilot, and the user then opens ChatGPT. The evidence gate removes pure prefetch, but such rows still score at the base level (25 for a user).
- **Subdomains outside the pre-filter.** The pre-filter holds the apex and `www.` names of the lookup rows, the 51 recurring subdomains and the cloud prefixes. Other subdomains are invisible to this rule, which has two effects. A provider used only through such a name is missed. And a provider that a host used during the baseline only through such a name looks new when the host first touches a listed name. Before the 51 subdomains were added, 41% of the host-provider pairs that looked new for GitHub Copilot on Tenant C (and 31% on Tenant B) were of this kind, because the plan-specific Copilot hosts (`api.business.githubcopilot.com` and similar) carry most Copilot traffic. Those hosts are now listed and count as Copilot runtime use. Customer-named Azure endpoints (`*.openai.azure.com`, `*.services.ai.azure.com`, `*.cognitiveservices.azure.com`) stay out unless you opt in (see Tuning). `hdsi_ai_dns_queries_to_ai_domains` sees every subdomain.
- **Website versus runtime names.** `ollama.com`, `huggingface.co` and similar names are both websites and tool back ends. They count as a provider ("Local LLM", "Model Registry") only after 10 queries in a day, and they never earn the API bonus. Only runtime hosts such as `registry.ollama.ai` show that a model was actually pulled or called.
- **Escalation.** A user whose burst grows is reported again (suppression includes `new_providers`), so a user can carry two risk events for one growing burst; the second one has the higher score. A host's burst is a single day, so a host that adds a provider on a later day starts a new, usually smaller, burst and is not re-reported.
- **Cost.** One run covers 21 days. Run times measured on 2026-10-09 varied with tenant load: about 200 s on the largest DNS tenant (both paths fail closed there), over 120 s on the tenant whose `Web` model holds about 2 billion inbound load balancer/WAF events a day (about 340 s in an earlier full run; 35 to 180 s for the DNS path alone with the Web path switched off), and under 20 s on the other two. Switching the Web path off on a tenant whose `Web` model holds only inbound traffic removes most of the cost there.
- **Web `maxout`.** The Web subsearch returns at most 50,000 user-provider pairs. In validation the largest tenant had about 13,000.
- **Encrypted DNS (DoH/DoT) and uninspected TLS** hide activity from both paths.
- **Null risk object.** A DNS row has a null `user` and a Web row has a null `src`. ES skips a risk object whose field is null. On one validation tenant, a production rule with two risk objects had result rows that produced only one of its two risk events, and no risk event in 3 days came from an absent object field. This rule is not deployed, so its own risk events were not observed.

### Validation
Read-only tests on 4 production ES tenants, 2026-10-09, over the scheduled window (`-21d@d` to `@d`, the time range of the 02:45 run). The search and all 3 drilldowns parse on all tenants. No run returned a FATAL or ERROR message.

| Tenant | Data | v1.0 (8-day Web) | v1.1 rows (scheduled window) | v1.1 runtime | Notes |
|---|---|---|---|---|---|
| A | DNS ~1.1 billion/day and NGFW + enterprise-browser Web with users, both accelerated for 7 days only | 0 rows, hit 300 s limit | 0 | ~200 s | Both paths correctly fail closed: the first covered day was 8 days ago. Regional Vertex AI (11 hosts, about 75,000 queries in 7 days) is visible through the cloud prefixes. With the short-window settings (Threshold): 3 user rows a day, e.g. Gemini + Copilot + OpenAI |
| B | Roaming DNS security service, heavy AI use; Web model is inbound load-balancer/WAF only | 0 rows, hit 300 s limit | 3 hosts (Web path off, as recommended for this tenant) | full run over 120 s; ~180 s with the Web path off | 3 new providers each on one day, all used through a runtime API (Anthropic API, Bedrock, GitHub Copilot, Cursor), score 20. Each address had a single user on its burst day. The whole-window count would have reported 15 addresses, mostly shared by several people. The Web path finds no users |
| C | Roaming DNS plus SSE/CASB app names with users | 0 rows | 0 | ~19 s | Highest velocity in the report window was 2 new providers (2 hosts). Regional Bedrock and SageMaker are visible to the rule |
| D | DNS and IIS server logs, server population only | 0 rows | 0 | ~17 s | No AI names. Expected silence |

Expected daily volume at the default settings: Tenant A none until acceleration is extended (about 3 user rows if tuned to the short window), B about 1 to 3 hosts, C about 0 to 1, D none.

### Deployment
The package ships with `enable_alerting: false`. Before enablement:

1. Check the acceleration range of `Network_Resolution` and `Web` (`| rest /services/datamodel/acceleration`). The search needs 21 days, or the short-window settings above.
2. Exclude resolvers, proxies, DHCP/VPN pools and inbound web sourcetypes in the two filters. Switch the Web path off where `Web` holds no user egress. If your own LAN uses 192.168 addresses, adjust `..._dns_src_scope`.
3. Approve organisation-wide licensed AI (`*|<provider>` in `ai_sanctioned_entities`, or `..._excluded_providers`), and load engineering host and group approvals.
4. Run the search once over the scheduled window (`-21d@d` to `@d`). Review the rows and the run time.

The rule is risk-only (no notable). Enabling it is a separately approved change.
