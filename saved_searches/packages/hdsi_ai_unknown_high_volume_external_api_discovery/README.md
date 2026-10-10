## Architect Notes
---
**Author:** Trevor Mock, Hurricane Labs LLC. Security Operations Architect

This is a **hunting and discovery search, not a detection**. Once a day it lists the AI-looking services that users and servers reached through DNS or the web proxy but that the common AI provider lookups (`ai_provider_domains`, `ai_provider_apps`) do not know yet. Every AI detection in this repo resolves providers through those lookups, so a service that is missing from them is invisible to all of them. This search finds those gaps. It emits **no risk and no notable**. Its output is a ranked review list for the person who maintains the lookups.

**Deployment type: ad hoc.** Deploy it where an analyst owns the weekly or daily review. It changes nothing on its own. It is deliberately not an RBA rule even though DNS or Web data exists on most tenants: an unknown AI service is a gap in the lookups, not risk on a user, and v1.0 shows what happens when it is scored (see below).

v1.0 could not work and would have been harmful if it had:
- It grouped `tstats` by both `Web.url_domain` and `Web.site` without `fillnull_value`. Every validation tenant fills only one of the two, so `tstats` dropped every row and the search returned 0 rows everywhere. On one tenant it also hit the 300 s limit first.
- Had it returned rows, every non-AI domain with 50 or more requests in a day would have raised risk on the user and the source: up to 100 risk rows a day. Most would have come from inbound load-balancer, WAF and IIS logs, and many would have used the literal user `unknown`.
- It treated "not in the AI lookup" as the signal, which is true for almost the whole internet.

v1.1 looks only at services with AI evidence, ranks them, and leaves the decision to a person.

### Prerequisites
| Data | Fields used | If absent or poor |
|---|---|---|
| `Network_Resolution.DNS` (accelerated) | `query`, `src` | Main source on tenants without AI URL categories. Without DNS, only the Web branch runs |
| `Web` (accelerated), outbound proxy, SWG or SSE | `url_domain`, `site`, `category`, `src`, `user` | The vendor AI URL category is the strongest signal: PAN-DB `artificial-intelligence` and `AI-*`, Netskope/Umbrella `Generative AI`. Without categories the Web branch can only match AI words in `url_domain`. Inbound server logs carry no outbound use and are excluded by default |

Either data model is enough (`data_prereqs` uses OR).

Common package `hdsi_ai_rba_common`:
- `ai_domains_filter` decides whether a name is already known. It normalises the name and matches it exactly, by parent domain, by cloud AI endpoint pattern, and by app name.
- The `ai_provider_domains` and `ai_provider_apps` lookups are read directly to find rows that exist but are disabled.

### How it works
- **DNS branch (`tstats` on `Network_Resolution.DNS`):** `..._dns_scope` keeps queries with AI words or the `.ai` TLD (wildcard terms). Rows are grouped by `query`, with `count`, `dc(src)` and first/last seen.
- **Web branch (`append`, `tstats` on `Web` with `fillnull_value`):** `..._web_scope` keeps rows that have an AI vendor category or an AI-looking `url_domain` or `site`. Rows are grouped by `url_domain`, `site` and `category`. `..._web_filter` removes inbound server sourcetypes. Where `url_domain` is empty, `site` is the candidate: a hostname-shaped `site` (proxies that map the host to `site` only) is treated as a host, anything else (an SSE app name such as "Microsoft Teams") as an app.
- **Normalisation:** the name is lowercased, and the scheme, path or query residue (`/ ? # & ; ,`), port, trailing dots, `*.` and `www.` are stripped. For app names the AI-word regexes see spaces as label boundaries ("Google Gemini" matches `gemini`). Signals:
  - `vendor_ai`: the category matches `..._ai_category_regex`.
  - `name_ai` = 2 (strong): an AI product or model word, or an `ai` label inside the name (`..._ai_name_regex`).
  - `name_ai` = 1 (weak): the `.ai` TLD only (`..._ai_tld_regex`).
  - `..._exclusions` drops internal names, IP literals, ad-tech host labels, CDN CNAME targets and other noise found in validation.
- **Volume gate:** per name, `event_count >= ..._min_events` (50) OR `src_count >= ..._min_sources` (3).
- **Already known?** Each name goes through `ai_domains_filter`; names that resolve to an enabled provider are removed. Names whose exact row, parent row or registrable-base row exists but is disabled (for example the opt-in Microsoft 365 Copilot rows) are also removed: someone already decided about them. A name under a known provider's domain that the lookup does not match becomes `unlisted_host_of_known_provider`, with that provider in `provider_hint`.
- **Service rollup:** names roll up to their registrable domain in two cases: the domain itself looks like AI (for example `vendor.ai`), or every candidate under it is vendor-categorised and there are at least two of them. Otherwise the hostname is the service. This keeps `ai.zoom.us` separate from the rest of `zoom.us`.
- **Ranking:**
  - `review_tier` 1: vendor AI category.
  - `review_tier` 2: strong AI name.
  - `review_tier` 3: `.ai` TLD only.
  - Within a tier, rows rank by distinct sources, then events (`tier_rank`).
  - `..._customizations` runs here, before the cap, so rows it removes free slots for others.
  - The `..._max_results` cap (100) is shared round-robin across tiers: rank 1 of every tier, then rank 2, and so on. A tenant with hundreds of vendor-categorised names still sees its top strong-name and `.ai` rows. `total_candidates` and `tier_candidates` show what was cut.
- **Output (one row per service, sorted by tier then `tier_rank`):** `review_tier`, `tier_rank`, `service`, `total_candidates`, `tier_candidates`, `hostnames` (up to 10), `hostname_count`, `name_type` (host/app), `signal` (dns/web), `reason`, `vendor_category`, `lookup_status`, `provider_hint`, `event_count`, `src_count`, `user_count` (Web only), `firstTime`, `lastTime`, `orig_sourcetype`, `suggested_action`, `mitre_attack` (T1588.007).
- **Cadence:** daily at 01:20 over the previous calendar day (`-1d@d` to `@d`). `action.risk = 0`, `action.notable = 0`, no suppression. Results stay in the scheduled job (TTL two runs) and in Triggered Alerts.

### Tuning macros
| Macro | Ships as | Purpose |
|---|---|---|
| `hdsi_ai_unknown_high_volume_external_api_discovery_filter` | `()` | DNS branch exclusions inside `tstats` (`DNS.*` names), e.g. internal zones or forwarders |
| `hdsi_ai_unknown_high_volume_external_api_discovery_web_filter` | `NOT sourcetype IN (...)` inbound ELB/ALB/WAF/CloudFront/IIS/Apache/nginx/F5 | Web branch exclusions inside `tstats`. Add any other inbound or server log here |
| `hdsi_ai_unknown_high_volume_external_api_discovery_dns_scope` | 28 wildcard terms on `DNS.query` | AI-name prefilter. Keep in step with the name regexes |
| `hdsi_ai_unknown_high_volume_external_api_discovery_web_scope` | AI category terms + the same name terms on `Web.url_domain` and `Web.site` | Web prefilter |
| `hdsi_ai_unknown_high_volume_external_api_discovery_ai_category_regex` | PAN-DB AI categories, Generative AI, AI/ML | Which vendor categories count as AI |
| `hdsi_ai_unknown_high_volume_external_api_discovery_ai_name_regex` | AI vendor/model/product words, `ai` label | Strong name signal (tier 2) |
| `hdsi_ai_unknown_high_volume_external_api_discovery_ai_tld_regex` | `.ai` TLD, `-ai.` | Weak name signal (tier 3) |
| `hdsi_ai_unknown_high_volume_external_api_discovery_exclusions` | Internal suffixes, IP literals, ad-tech labels, CDN/Front Door CNAMEs, AWS ELB/RDS endpoints, App Insights, five `.ai` ad-tech domains, a few known non-AI names | Append reviewed non-AI services and internal domains |
| `hdsi_ai_unknown_high_volume_external_api_discovery_min_events` | `50` | Requests or queries per name per day (OR with sources) |
| `hdsi_ai_unknown_high_volume_external_api_discovery_min_sources` | `3` | Distinct clients per name per day (OR with events) |
| `hdsi_ai_unknown_high_volume_external_api_discovery_max_results` | `100` | Rows returned, shared round-robin across the three tiers |
| `hdsi_ai_unknown_high_volume_external_api_discovery_customizations` | `search *` | Hook on the per-service rows before ranking and the cap, e.g. `search review_tier>1` to review only the name-based tiers, or `search NOT service IN (...)` to park reviewed rows; removed rows free cap slots |

**Closing the loop.** For an AI service, add it to the common `ai_provider_domains` (hostname or registrable domain with `match_subdomains=1`) or `ai_provider_apps`. For a non-AI service, append it to `..._exclusions`. Either way it disappears from the next run, and the AI detections start seeing it once it is in the lookup.

### Threshold
Run this over a normal day. It shows how many candidate services each volume gate would keep, per signal tier:

```spl
| tstats summariesonly=t allow_old_summaries=t count dc(DNS.src) as src_count from datamodel=Network_Resolution.DNS
    where `hdsi_ai_unknown_high_volume_external_api_discovery_dns_scope` `hdsi_ai_unknown_high_volume_external_api_discovery_filter`
    earliest=-1d@d latest=@d by DNS.query
| rename DNS.query as candidate
| eval candidate=replace(replace(lower(candidate),"\\.+$",""),"^www\\d*\\.","")
| where NOT (`hdsi_ai_unknown_high_volume_external_api_discovery_exclusions`)
| eval name_ai=case(match(candidate, `hdsi_ai_unknown_high_volume_external_api_discovery_ai_name_regex`),2, match(candidate, `hdsi_ai_unknown_high_volume_external_api_discovery_ai_tld_regex`),1, true(),0)
| where name_ai>0
| stats sum(count) as event_count max(src_count) as src_count by candidate name_ai
| eval ai_domain=candidate, ai_input_type="dns"
| appendpipe [| `ai_domains_filter` | eval known=1 | fields candidate known]
| eventstats max(known) as known by candidate
| where isnull(known) AND isnotnull(event_count)
| stats count as candidates p50(event_count) as p50_events p90(event_count) as p90_events p90(src_count) as p90_src
        sum(eval(if(event_count>=20 OR src_count>=2,1,0))) as kept_20_2
        sum(eval(if(event_count>=50 OR src_count>=3,1,0))) as kept_50_3
        sum(eval(if(event_count>=100 OR src_count>=5,1,0))) as kept_100_5
        by name_ai
```

- In validation (this search, previous day), the median unknown AI-named DNS name had 1–6 queries. The shipped 50/3 gate drops that long tail of single lookups and kept 23–51% of names (see Validation).
- Raise the gate (100/5) when the list is too long to review. Lower it (20/2) for a one-off hunt on a quiet tenant.
- The gate does not decide what appears first: `review_tier` and `src_count` do.

### Known false positives / Limitations
- **Vendor categories are broad.** PAN-DB files chat widgets, text-to-speech, photo editors, survey tools and even a news site under `artificial-intelligence`. Tier 1 means "the vendor calls it AI", not "generative AI with data risk". Review before adding to the lookup.
- **`.ai` is a general-purpose TLD.** Before the ad-tech exclusion, ad exchanges and tracking pixels on `.ai` were the largest group of name-only hits. Security, analytics and HR vendors on `.ai` still show up in tier 3.
- **Words inside other words.** Label boundaries prevent most collisions (`enrollment`, `coherent`, `openair`). `gpt` inside a random token and `gemini` as a brand (a crypto exchange) still match. Add such names to `..._exclusions` once reviewed.
- **AI features of ordinary companies (largest tier 2 group on two tenants).** An AI word in a label also matches the website chatbot, `chatbot-*`, `ai-assistant.*` and `copilot` subdomains of retail, telco, energy, food-service and government sites, and the staging or dev aliases of providers (`*-stg`, `cloud-dev`). They are real AI endpoints but rarely lookup material: add the reviewed ones to `..._exclusions`. Front Door and CDN aliases (one was a Front Door alias of the opt-in Microsoft 365 Copilot host, which the common lookup ships disabled on purpose) and AWS ELB/RDS endpoint names (a tenant's own infrastructure) are excluded by default.
- **Big tenants have many vendor-categorised names.** On the tenant with PAN AI categories, tier 1 alone had 126–136 candidates. The round-robin cap shows the top 34 of each tier; raise `..._max_results` or filter with `..._customizations` to work deeper.
- **Hostnames in `Web.site`.** A `site` value is treated as a host only when it is hostname-shaped (labels separated by dots). An app name with a dot ("Character.AI") is therefore treated as a host, which is harmless: `ai_domains_filter` resolves it the same way.
- **Source counts are approximate.** `src_count` is the maximum over name variants and branches, not a union. DNS `src` can be a resolver, a forwarder or, for roaming cloud DNS, a home or public address. `user_count` comes from Web only.
- **Registrable domain is a heuristic.** Two-level public suffixes are handled for common forms (`co.uk`, `com.au` ...), not the full public suffix list.
- **"Known" means known on this search head.** The search compares against the deployed common lookups. A tenant that changed them sees a different list. Disabled rows, such as the opt-in Microsoft 365 Copilot rows, count as known and are hidden.
- **No risk.** The search changes no risk score. Its value comes through the lookups: once a reviewed service is added, every AI detection covers it.
- **Cost.** One day on the busiest tenant (about 1.1B DNS and 1.3B Web events a day) took 94–108 s. Do not run it over more than a day in one job on such a tenant.

### Validation
Read-only tests on 4 production ES tenants on 2026-10-09. Window: the previous calendar day (the scheduled window). Repeated for the day before.

| Tenant | AI evidence in data | v1.0 (before) | v1.1 parses (search + 2 drilldowns) | Candidate services, scheduled day / day before | Rows returned (runtime) | Top of list |
|---|---|---|---|---|---|---|
| A | PAN URL logs with 17 AI category/sourcetype combinations (~1M AI-categorised events/day); DNS ~1.1B/day | Harness timeout; earlier baseline fetch failed | OK | 865 / 936 (tier 1: 126 / 136) | 100: 34 tier 1, 33 tier 2, 33 tier 3 (94–108 s) | Tier 1: DuckDuckGo AI chat (`duck.ai`, ~600 sources), text-to-speech and chatbot SaaS. Tier 2: Gemini in Google Workspace endpoints (~23,000 sources), Adobe GenAI APIs, Zoom AI Companion. Tier 3: `.ai` SaaS |
| B | Roaming cloud DNS ~53M/day; Web is inbound ELB/WAF plus a small proxy without AI categories | 0 rows, auto-finalised at 300 s | OK | 128 / 137 | 100: 43 tier 2, 57 tier 3 (65–82 s) | Zoom AI Companion (`ai.zoom.us`, ~1,100 sources), Gemini in Workspace, Adobe GenAI APIs, Anthropic/OpenAI VS Code extension gallery, Lucid AI, Copilot in Azure |
| C | DNS ~209M/day; Netskope `Generative AI` category on SSE app names | 0 rows | OK | 200 / 194 | 100: 50 tier 2, 50 tier 3 (6–7 s) | Adobe GenAI APIs, vendor AI-assistant subdomains, provider staging aliases, Lucid AI, Gemini in Workspace |
| D | DNS ~2.8M/day with no AI-named queries; Web is inbound IIS only | 0 rows | OK | 0 / 0 | 0 (5 s) | Correctly silent |

- **Round-robin cap (A).** Before the shared cap, the top 100 on tenant A were all tier 1 (broad PAN categorisations such as a news site, a search engine, tracking pixels), and the Gemini in Workspace endpoint with ~23,000 sources was hidden. With the shared cap it is the first tier 2 row.
- **`..._customizations` before the cap.** With `search review_tier>1` in the hook, tenant A returned 100 rows (50 tier 2, 50 tier 3) of 739 name-based candidates. When the hook ran after the cap, the same filter returned 0 rows.
- **Netskope app names (C).** Every SSE app in the `Generative AI` category resolved to a known provider or to an opt-in disabled row, so no app-name rows were returned. The app-name path was exercised (category terms and, since this revision, AI-word terms on `site`) and stayed silent.
- **Volume gate (Threshold search, DNS names, previous day).** With 50/3, tenant A kept 623 of 1,228 `.ai`-only names and 139 of 280 strong-name names. Tenant B kept 186 of 614 and 60 of 202, tenant C 255 of 954 and 72 of 460. Tenant D had none.
- **Exclusions are evidence-based.** Before the label-bounded regexes and the shipped exclusions, these were top hits on two or three tenants:
  - substring collisions: `llm` inside other words (for example `enrollment`), company names containing `gemini`, `cohere` or `openai` as part of a longer word;
  - Windows location inference;
  - Application Insights `*.ai.monitor.azure.com`;
  - CDN CNAMEs of known providers;
  - ad-tech `sync.`/`rtb.`/`ssp.` hosts on `.ai`.
  - `.ai` ad-tech and ad-measurement domains at the top of tier 3 (`axon.ai`, `vdo.ai`, `hybrid.ai`, `trinitymedia.ai`, `mgln.ai`);
  - query-string residue in `url_domain` (a `gemini.google.com&...` value that hid a known provider).
- **Inbound logs.** With the default `..._web_filter`, the inbound ELB/WAF hostnames on tenant B (an internal application name contained `gpt`) no longer appear.
- **Drilldowns** were run with a real service value (`ai.zoom.us`). DNS clients took 2.5–19 s and Web activity 2–54 s. Both are exact-name or subdomain wildcard `tstats`.
- **Stability.** All runs completed with no FATAL or ERROR message. Between the scheduled day and the day before, candidate totals moved by 3% (C), 7% (B) and 8% (A).
- **App-name path (synthetic check).** `site` values were classified as expected: "Microsoft Teams" as an app, `https://Foo.Bar.com:443/x` and `www.copilot-x.com.` as hosts, "Google Gemini" and "Some AI Tool" as strong AI app names, "Enrollment Portal" as no match.

### Deployment
The package ships with `enable_alerting: false` and `deployment_type: adhoc`. It creates no risk events and no notables, so enabling it does not change any RBA score.

Before enablement:
1. Confirm accelerated `Network_Resolution.DNS` and/or outbound `Web` data.
2. Add the tenant's inbound Web sourcetypes to `..._web_filter`.
3. Add internal DNS zones to `..._filter` or `..._exclusions`.
4. Name the analyst who reviews the list and owns the follow-up changes to the common lookups.

Scheduling it is a separately approved change. Lookup edits that follow from its output are also separately approved changes to `hdsi_ai_rba_common`.
