## Architect Notes
---
**Author:** Trevor Mock, Hurricane Labs LLC. Security Operations Architect

This rule finds hosts whose DNS queries show that someone on them is **using an AI service**: chat sites (ChatGPT, Claude, Gemini, Perplexity, DeepSeek, Grok and dozens more), model APIs (`api.openai.com`, `api.anthropic.com`, OpenRouter, Deepgram), cloud AI endpoints (AWS Bedrock and SageMaker, GCP Vertex AI, Azure OpenAI, Azure AI Foundry and Azure AI Services), local-LLM tooling (Ollama) and model registries (Hugging Face). DNS is the most portable AI-usage signal in the suite. It is present wherever client DNS is logged, it needs no proxy or TLS inspection, and it sees desktop apps, SDKs and scripts that never touch a web proxy. The rule creates **one risk event per host per day** on `src` (system) and does not create a notable.

v1.0 ran every 5 minutes with a threshold of 20 queries per host per provider. It counted resolvers and forwarders as clients, counted logs that record both the query and the response twice, and reported browser prefetch as usage. It also reported the organisation's own GitHub Copilot seats again, after `hdsi_ai_code_assistant_network_connection` had already scored them, and set `user="unknown"`. On the validation tenants it would have produced an estimated 350 to 8,000 risk events a day, mostly noise. v1.1 runs daily, resolves names with the common `ai_domains_filter`, and keeps only evidence that a person or program actually used the service.

### Prerequisites
- **`Network_Resolution` (accelerated)**, fed by client-facing DNS logs: resolver query logs (Windows DNS analytic/debug, BIND, Infoblox), a DNS security service (Cisco Umbrella / Cloud Security and similar) or network capture (Splunk Stream, Zeek). Fields used: `DNS.query` and `DNS.src` (required), `DNS.message_type` and `DNS.vendor_product` (optional: the `tstats` uses `fillnull_value="unknown"`, so a TA that does not fill them still returns rows, but query and response logs are then counted together and the roaming-address rule below cannot recognise the product).
  - `src` must be the **client**. When the only DNS logs come from a forwarder, or from a DNS server that sees its own upstream forwarding, every query looks like it came from that server. The shared-source guard drops such servers (see Threshold), so the rule then returns nothing for them rather than one host carrying everyone's activity.
  - Trailing-dot names (`chatgpt.com.`, as some DNS security services log them), `www.` names and SRV names (`_grpclb._tcp.<region>-aiplatform.googleapis.com`) are handled. `ai_domains_filter` normalises them.
  - DNS server logs that hold only internal zones, or only server traffic, produce no rows (Tenant D below).
- **ES lookup** `asset_lookup_by_str` (present in every ES install). It supplies the asset `bunit`, so group approvals in `ai_sanctioned_entities` work for hosts.
- **Common package `hdsi_ai_rba_common`**: `ai_domains_filter` (lookups `ai_provider_domains` and `ai_provider_apps`) and `ai_unsanctioned_filter(3)` (lookup `ai_sanctioned_entities`). The `ai_detection_config` row `dns_query_threshold` is no longer read. The thresholds are package macros now.

### How it works
- **Pre-filtered `tstats`** over `Network_Resolution` for the previous calendar day, split by `src`, `query`, `message_type` and `vendor_product` (`fillnull_value="unknown"`, so a missing optional field never drops rows). `..._query_prefilter` keeps only names that contain an enabled `ai_provider_domains` domain, or that match a cloud AI endpoint pattern. On the largest tenant (about 1.1 billion DNS events a day) this cut the cost per hour of data from about 115 s to about 34 s. Placeholder and loopback sources (`unknown`, `-`, `0.0.0.0`, `127.0.0.1`, `::1`) are excluded inline.
- **No double counting:** when a source logs both the query and the response (Splunk Stream, Infoblox and Windows DNS in validation), or two sensors log the same client (network capture plus resolver logs on Tenant A), the rule takes the largest of the per-type, per-product counts for each `src`/`query` instead of their sum.
- **Provider resolution:** `ai_domain=query, ai_input_type="dns"` goes into `ai_domains_filter`. The filter does exact match, then parent domain where `match_subdomains=1`, then cloud endpoint patterns. It never treats a name as an app name. Only `enabled=1` rows survive. Providers in `..._excluded_providers` are then removed: by default the coding assistants scored by `hdsi_ai_code_assistant_network_connection` and the tenant-bound Microsoft 365 / Security Copilot.
- **Evidence gate (per host, per provider, per day):** names matching `..._background_names` do not count. These are update checks, browser prefetch, SSO, telemetry and embeddable CDN hosts, for example `bzrcdn.openai.com`, `gemini.gstatic.com` and `cdn.midjourney.com`. A provider counts as used when its API, local-LLM, model-registry or CLI names were queried at least `..._min_api_queries` times (default 1), or its other web/IDE names at least `..._min_queries` times (default 10).
- **Shared-source guard:** an `append` (with `maxtime=900`, because it scans every source) finds DNS clients that resolved at least `..._shared_src_names` distinct names that day (default 10,000). Those clients are resolvers, forwarders, proxies, mail relays and NAT egress addresses, and all their rows are dropped.
- **Roaming-address guard:** `..._unreliable_src` (ships on) drops rows whose `vendor_product` is a roaming DNS-security client (Cisco Umbrella / Cloud Security / Secure Access) and whose `src` is a home-router address (`192.168.0.0/16` or `10.0.0.0/24`). Those clients log the laptop's local address, and a third to three quarters of such addresses carried several roaming identities in the validation samples (see Limitations). Many of them stay under the 10,000-name guard (3,000 to 9,600 names a day), and adding several people's AI use together gave them the highest scores. IPv6, CGNAT (`100.64.0.0/10`), public and other RFC 1918 addresses were almost always one device and are kept. Resolver and network-capture sources are not affected.
- **Approvals:** the asset `bunit` is looked up for `src`. `ai_unsanctioned_filter(user,src,provider)` then removes host approvals (`<src>|<provider>` or `<src>|*`) and asset-group approvals (`<bunit>|<provider>`). The CIM `Network_Resolution` model has no user field, so per-user approvals do not apply.
- **One row per host:** `provider_count`, `provider_list`, `usage_type_list`, `dns_query_count`, `evidence_query_count`, `ai_domain_sample` (up to 8 names), `ai_domain_count` and `vendor_product`.
- **Scoring:** `base_score = round(10 x highest severity_weight) + 3 per additional provider`, and `risk_score = min(30, base_score)`. Weights come from `ai_provider_domains`. A single provider scores 5 to 10 for chat sites, 9 for Model Registry (Hugging Face), 10 or 12 for model APIs and cloud AI endpoints (for example Deepgram and OpenRouter 10, Anthropic and Vertex AI 12, Azure AI Services 8), 11 for Local LLM (Ollama) and 5 for CLI names. The `_risk` literal fallback is 10. No `user` risk object is emitted, so nothing accumulates on an `unknown` user.
- **Cadence:** daily at 01:35 over `-1d@d` to `@d`, suppressed 20 h per `src`. AI use is a daily habit, not an event. The daily window also gives the evidence gate a full day of queries, so light but real use is not missed.

### Tuning macros
| Macro | Ships as | Purpose |
|---|---|---|
| `hdsi_ai_dns_queries_to_ai_domains_filter` | `()` | Exclusions inside both `tstats` where clauses (`DNS.*` names), e.g. `NOT DNS.src IN ("10.1.1.10","10.1.1.11")` for known resolvers, forwarders, proxies or VDI pools |
| `hdsi_ai_dns_queries_to_ai_domains_query_prefilter` | `(DNS.query IN ("*chatgpt.com*", ...))`: 121 lookup names plus 6 cloud patterns | Inline pre-filter. **Regenerate it when rows are added to `ai_provider_domains`** (SPL below). A new name that no term covers is never seen |
| `hdsi_ai_dns_queries_to_ai_domains_excluded_providers` | `"GitHub Copilot","Cursor","Windsurf","Tabnine","Sourcegraph","Microsoft 365 Copilot","Microsoft Security Copilot"` | Providers removed after resolution. Add providers that are licensed for everyone (e.g. `"OpenAI"` with ChatGPT Enterprise, `"Google Gemini"` with Gemini for Workspace). Use `"__none__"` to keep all |
| `hdsi_ai_dns_queries_to_ai_domains_background_names` | `match(ai_domain, ...)` for `bzr`/`bzrcdn.openai.com`, `ab.chatgpt.com`, `gemini.gstatic.com`, `ms-sso.copilot*`, `downloads.claude.ai`, `telemetry` labels and `cdn`/`cdnN` labels | Names that do not count as evidence. The `cdn` term needs a dot after it, so `cdn-lfs.huggingface.co` / `cdn-lfs.hf.co` model downloads still count. Use `false()` to count everything |
| `hdsi_ai_dns_queries_to_ai_domains_min_queries` | `10` | Web/IDE evidence queries per host per provider per day |
| `hdsi_ai_dns_queries_to_ai_domains_min_api_queries` | `1` | API / local-LLM / model-registry / CLI queries per host per provider per day |
| `hdsi_ai_dns_queries_to_ai_domains_shared_src_names` | `10000` | Distinct names per client per day above which the client is treated as shared infrastructure |
| `hdsi_ai_dns_queries_to_ai_domains_unreliable_src` | Umbrella / Cloud Security / Secure Access `vendor_product` AND (`192.168.0.0/16` OR `10.0.0.0/24`) | Eval condition (fields `src`, `vendor_product`) for sources that are not one host. Add other roaming products to the `vendor_product` regex (e.g. `zscaler\|cloudflare`). Use `false()` once the TA maps the roaming device identity to `src` |
| `hdsi_ai_dns_queries_to_ai_domains_customizations` | `search *` | Post-aggregation hook (fields listed in How it works, plus `bunit`, `base_score`, `risk_score`) |
| `hdsi_ai_dns_queries_to_ai_domains_risk_score` | `search *` | Last pipe. Override `risk_score` (at most 100) here |

Regenerate the pre-filter after changing `ai_provider_domains`. Paste the output into the macro definition and keep the six cloud patterns at the end:

```spl
| inputlookup ai_provider_domains where enabled=1
| eval term="\"*".lower(domain)."*\""
| stats values(term) as terms
| eval definition="(DNS.query IN (".mvjoin(terms,",").",\"*bedrock*.amazonaws.com*\",\"*aiplatform.googleapis.com*\",\"*ai.azure.com*\",\"*.openai.azure.com*\",\"*.cognitiveservices.azure.com*\",\"*sagemaker.*.amazonaws.com*\"))"
| fields definition
```

(The shipped list also drops names already covered by a shorter name. That only saves search time and is optional.)

Host approvals go in `ai_sanctioned_entities` (common package), e.g. `system,10.20.30.40,OpenAI,provider,2099-12-31,security,approved_research_host,1,10.20.30.40|openai`. Asset-group approvals use the ES asset `bunit`: `group,research,Anthropic,group,2099-12-31,security,approved,1,research|anthropic`.

### Threshold
**`..._min_queries` (10).** Browser and OS prefetch produces a few lookups a day with no other evidence. On hosts that resolved only that one name, the median per day was 2 for `chatgpt.com`, `gemini.google.com` and `copilot.com`, and the 90th percentile was 5 to 23. Hosts that really use ChatGPT had a median of about 36 queries a day for `chatgpt.com` alone, plus `ws.chatgpt.com` (the live chat socket). Raise the value if single-name rows for consumer Copilot or Gemini dominate. Lower it if light users matter more than noise. Measure your own split with:

```spl
| tstats summariesonly=t allow_old_summaries=t count from datamodel=Network_Resolution
    where `hdsi_ai_dns_queries_to_ai_domains_query_prefilter` by DNS.src DNS.query _time span=1d
| rename DNS.* as * | eval ai_domain=query, ai_input_type="dns" | `ai_domains_filter`
| stats sum(count) as count dc(ai_domain) as names by _time src provider
| eval kind=if(names=1,"single name","several names")
| stats count as host_days p50(count) as p50 p90(count) as p90 by provider kind
| sort provider kind
```

**`..._shared_src_names` (10,000 distinct names per client per day).** In validation, resolvers, forwarders and egress addresses resolved 18,000 to more than 220,000 names a day. Most clients stayed below 3,000, but 114, 24 and 111 clients on Tenants A, B and C resolved 3,000 to 10,000: busy servers and jump hosts, and on the roaming tenants mostly shared home-network addresses (handled by `..._unreliable_src`, not by this guard). Do not lower the value to catch those addresses; real heavy hosts would go with them. Pick a value just above your busiest real workstation or server that should still be scored:

```spl
| tstats summariesonly=t allow_old_summaries=t dc(DNS.query) as names from datamodel=Network_Resolution
    where NOT DNS.src IN ("unknown","-","0.0.0.0","127.0.0.1","::1") by DNS.src
| eval band=case(names<1000,"a <1k",names<3000,"b 1-3k",names<5000,"c 3-5k",names<10000,"d 5-10k",names<20000,"e 10-20k",names<50000,"f 20-50k",true(),"g 50k+")
| stats count as clients by band
```

Run it over one full day. Check the clients in the upper bands against the asset inventory before you lower the value. Mail relays, web proxies and jump hosts are legitimate heavy resolvers whose AI lookups are made on behalf of other people.

### Known false positives / Limitations
- **Roaming DNS clients are not always one host.** Roaming DNS-security clients (Cisco Umbrella / Cloud Security AnyConnect roaming module) log the laptop's local address. Home-router ranges are reused by unrelated laptops: in an 8-hour raw sample, 37% of `192.168.x` and 33% of `10.0.0.x` addresses on Tenant B carried more than one roaming identity, and 42% and 76% on Tenant C carried three or more. Without a guard those shared addresses took the highest scores, because the +3 per extra provider adds several people's AI use together (69 of the 105 Tenant B rows with three or more providers were on these addresses). `..._unreliable_src` therefore ships on for those products and ranges and drops 752 of 2,252 daily rows on Tenant B and 60 of 105 on Tenant C. That AI use is not scored at all. The real fix is in the TA: map the roaming device identity (Umbrella `identities` for identity type *Anyconnect Roaming Client* / *Roaming Computers*) to `src` in `Network_Resolution`, then set `..._unreliable_src` to `false()`. IPv6 sources are different: each was one device in the samples, but roaming laptops rotate IPv6 addresses, so one laptop's AI use can be split over several `src` values across days. They are kept (548 of 1,500 daily rows on Tenant B). Public IPv4 sources were 94 to 97% single-device and are kept; large egress addresses are dropped by `..._shared_src_names`.
- **No user attribution.** The CIM `Network_Resolution` model has no user field, so this is system risk only, even where the DNS product logs one (both roaming tenants log the roaming identity and, on Tenant C, the AD user on every event). Mapping that identity to `src` in the TA gives a stable per-device object and fixes the shared-address problem above. It does not feed the user-based `hdsi_rba_ai_*` aggregators. It adds AI-usage context to a host's ES risk timeline and to system risk rules.
- **Prefetch and embedded content.** Browser-integrated assistants (Gemini in Chrome, Copilot in Edge and Windows) resolve their service names without a prompt being sent. The evidence gate removes most of them. Hosts above 10 queries a day are still reported, at 7 to 10 points. Single-provider Gemini and consumer Copilot rows made up 27 of 79 daily rows on Tenant A and 18 of 45 on Tenant C. Most were hosts that resolved a single name just above the threshold.
- **Unexplained background names.** `bzrcdn.openai.com` and `bzr.openai.com` were resolved by 1,457 and 584 hosts a day on one tenant, where only 129 hosts resolved `chatgpt.com`, and by 1,183 hosts on another. They are treated as background. A host that resolves only those names is not reported. The same applies to `ab.chatgpt.com`, the feature-flag host that an installed ChatGPT client polls (up to 574 times a day on hosts that never resolved `chatgpt.com`; 12 such hosts were scored 10 across Tenants B and C before it was added).
- **Exact-only web providers** (rows with `match_subdomains=0`, e.g. `replit.com`) can only pass the gate on query count. On Tenant C, 183 hosts resolved `replit.com` with no other evidence (median about 4 a day). The 19 hosts above 10 a day are reported at 5 points.
- **Sanctioned enterprise AI** (ChatGPT Enterprise, Gemini for Workspace, Claude for Work) looks the same as personal use in DNS. Add such providers to `..._excluded_providers`. On Tenant B, where ChatGPT is in general use, 987 of 1,500 daily rows (66%) were OpenAI only.
- **Server workloads** that call AI APIs (Vertex AI, Bedrock, SageMaker, Deepgram) are reported once a day at 10 to 12 points. That is intended visibility. Approve known workloads per host in `ai_sanctioned_entities`.
- **DHCP churn**: a `src` IP may belong to different devices on different days. ES asset correlation applies as usual.
- **Encrypted DNS** (DoH/DoT direct from the browser) and VPN-split DNS bypass the logged resolver and are invisible to this rule.
- **Prefilter maintenance:** names from rows added to `ai_provider_domains` are not seen until the pre-filter is regenerated.

### Validation
Read-only tests on 4 production ES tenants, 2026-10-09. v1.0 was run over its auto window (the last 4 hours). v1.1 was run over its exact scheduled window (`-1d@d` to `@d`, the previous calendar day), so its row count equals one day of risk events. No FATAL or ERROR messages in any v1.1 run. The search and all 3 drilldowns parse on all tenants. With every source as a wildcard over one hour, the drilldowns returned in under 25 s on the largest tenant. With one `src` they are faster.

| Tenant | DNS data | v1.0 rows (4 h) | v1.1 rows (1 day) | v1.1 runtime | Notes |
|---|---|---|---|---|---|
| A | Network capture plus resolver logs, about 1.1 billion events a day, query and response both logged | 58 (285 s) | 79 | about 9.5 min (test harness, lookups inlined) | 110 clients resolved more than 10,000 names a day (28 more than 50,000): forwarders and proxies, all dropped. Background `bzrcdn`/`bzr.openai.com` on about 1,450 hosts removed. Rows: Gemini, ChatGPT, Claude (web and API), consumer Copilot, xAI, Deepgram API, GCP Vertex AI server workloads, Azure AI Services, Hugging Face. Roaming guard not applicable (no roaming product) |
| B | Roaming DNS security service, trailing-dot names, heavy AI use | 1,476 | 1,500 | 31 s | One egress address with about 28,000 names a day dropped. Over 900 org-tier GitHub Copilot hosts are no longer double-counted. 752 home-network address rows dropped by the roaming guard. Mostly ChatGPT (see below), with Claude (web and API), Gemini, DeepL, Ollama and Bedrock |
| C | Roaming DNS security service plus on-site forwarders | 254 | 45 | 45 s | 5 forwarder or egress addresses (18,000 to 224,000 names a day) dropped. Of 1,881 hosts with any AI name, 1,078 resolved only `bzrcdn.openai.com` and were not reported. 60 home-network address rows dropped by the roaming guard. Rows: Gemini, ChatGPT, consumer Copilot, Replit, SageMaker and Bedrock workloads, Lovable, Claude, Hugging Face |
| D | Windows DNS server logs, server population only | 0 | 0 | 18 s | No AI names in 7 days. Only 5 clients resolve any public name. Expected silence |

Score mix: on Tenant A, 52 of 79 rows scored 10 (maximum 18). On Tenant B, 1,067 of 1,500 scored 10, and 281 hosts used two or more providers (maximum 21; before the roaming guard the maximum was 27, on a shared home-network address). On Tenant C, 19 of 45 scored 10 (maximum 15).

Expected daily volume (one event per host per day, 5 to 30 points): Tenant A about 80, B about 1,500, C about 45, D none. On Tenant B, adding `"OpenAI"` to `..._excluded_providers` (ChatGPT sanctioned) removes 987 rows. Setting `..._unreliable_src` to `false()` adds back about 750 rows on B and 60 on C, all on shared addresses.

### Deployment
The package ships with `enable_alerting: false`. Before enablement:

1. Confirm that `Network_Resolution` holds **client** DNS queries with external names (run the pre-filter alone over a day).
2. Run the `..._shared_src_names` banding SPL. Add known resolvers and forwarders to `..._filter` and adjust the guard.
3. Put organisation-wide licensed AI providers into `..._excluded_providers`, and load host or asset-group approvals into `ai_sanctioned_entities`.
4. On roaming DNS-security tenants, keep `..._unreliable_src` on unless the TA maps the roaming device identity to `src`. If the DNS product is another roaming service (Zscaler, Cloudflare Gateway and similar), add it to the macro's `vendor_product` regex. If the corporate LAN itself uses `192.168.0.0/16` behind such a product, narrow the ranges.
5. Run the search once over the scheduled window (`-1d@d` to `@d`). Confirm the daily risk volume and the run time. On a tenant with about a billion DNS events a day, expect several minutes.

The rule is risk-only (no notable). Enabling it is a separately approved change.
