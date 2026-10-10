# AI-DISCOVERY-001 - HDSI AI Unknown High-Volume External API Discovery

> **AD HOC PACKAGE - HUNTING AND DISCOVERY, NOT A DETECTION.** `deployment_type: adhoc`. This search writes **no risk and no notable**. Its output is a ranked review list for the person who maintains the common AI provider lookups. Deploy or schedule it only where a named analyst owns that review.

> **Detection ID:** AI-DISCOVERY-001
> **Package:** `hdsi_ai_unknown_high_volume_external_api_discovery` v1.1.0 (deployment type: **adhoc**)
> **Search name:** `Network - HDSI AI Unknown High-Volume External API Discovery - Rule`
> **Status:** Active as a hunting search. `action.risk = 0`, `action.notable = 0`, no suppression. Results stay in the scheduled job (TTL two runs) and in Triggered Alerts.
> **Risk:** none
> **MITRE ATT&CK:** T1588.007 - Obtain Capabilities: Artificial Intelligence (context annotation only)
> **Data Model:** Network_Resolution.DNS and/or Web (either is enough)
> **Schedule:** `20 1 * * *` (daily at 01:20, when scheduled)
> **Lookback Window:** `-1d@d` to `@d` (the previous calendar day)
> **Kill Chain Phase:** not applicable (the multi-vector aggregator ignores it)
> **Last Updated:** 2026-10-09

---

## Overview

Every AI detection in this repo resolves providers through two lookups in the common package `hdsi_ai_rba_common`: `ai_provider_domains` and `ai_provider_apps`. An AI service missing from them is invisible to every rule. This search finds those gaps. Once a day it lists AI-looking services that users and servers reached through DNS or the outbound web proxy and that the lookups do not know yet. It ranks them for review.

A service qualifies when the proxy or SSE vendor classifies it as AI, or when its name carries an AI product or model word or the `.ai` TLD. It must also pass a volume gate: 50 events or 3 distinct sources in the day.

The search scores nothing. An unknown AI service is a gap in the lookups, not risk on a user. v1.0 showed what happens otherwise. It would have raised risk on every non-AI domain with 50+ requests a day, mostly from inbound load-balancer, WAF and IIS logs and often on the literal user `unknown`. In fact it returned 0 rows everywhere, because its `tstats` split dropped every row.

The "analyst" here is the lookup owner, not a Tier 1 responder. The steps below are a review workflow rather than incident triage.

---

## MITRE ATT&CK Mapping

| Field | Value |
|---|---|
| Technique ID | T1588.007 |
| Technique Name | Obtain Capabilities: Artificial Intelligence |
| Tactic | Resource Development |
| Sub-technique | T1588.007 (annotation for context; the search does not assert malicious use) |

---

## Detection Logic

### Plain English

1. **DNS branch:** `tstats` on `Network_Resolution.DNS` for queries that match `..._dns_scope` (AI words or the `.ai` TLD, as wildcard terms), grouped by `query` with `count`, `dc(src)` and first/last seen.
2. **Web branch:** an `append` of a `tstats` on `Web` with `fillnull_value="unknown"`. It keeps rows with an AI vendor category or an AI-looking `url_domain` or `site` (`..._web_scope`). Inbound server sourcetypes are excluded by `..._web_filter`. Where `url_domain` is empty, `site` is the candidate. A hostname-shaped `site` is treated as a host, anything else (an SSE app name) as an app.
3. **Normalise** the name. Lowercase it, strip scheme, path or query residue, port, trailing dots, `*.` and `www.`, and score the signals:
   - `vendor_ai`: the category matches an AI category;
   - `name_ai` = 2: an AI product or model word, or an `ai` label;
   - `name_ai` = 1: the `.ai` TLD only.

   `..._exclusions` drops internal names, IP literals, ad-tech hosts, CDN CNAMEs and other reviewed noise.
4. **Volume gate:** `event_count >= 50` OR `src_count >= 3`.
5. **Already known?** Run each name through `ai_domains_filter` and drop names that resolve to an enabled provider. Also drop names whose exact, parent or registrable-base row exists but is disabled: someone already decided about them. A host under a known provider's domain that the lookup does not match becomes `unlisted_host_of_known_provider`, with a `provider_hint`.
6. **Roll up** to a service: the registrable domain when it looks like AI, or when every host under it is vendor-categorised and there are at least two of them. Otherwise the hostname itself.
7. **Rank:**
   - `review_tier` 1 = vendor AI category, 2 = strong AI name, 3 = `.ai` TLD only;
   - within a tier, rows are ordered by sources, then events;
   - `..._customizations` runs before the cap;
   - the `..._max_results` cap (100) is shared round-robin across tiers.

### Key Fields

| Field | Description | Example Value |
|---|---|---|
| `review_tier` / `tier_rank` | Signal tier (1 vendor category, 2 AI name, 3 `.ai` TLD) and rank within it | `2` / `1` |
| `service` | Service to review (registrable domain or hostname, or app name) | `ai.zoom.us` |
| `hostnames` / `hostname_count` | Up to 10 hostnames rolled into the service | `ai.zoom.us` |
| `name_type` / `signal` | `host` or `app`; `dns` and/or `web` | `host` / `dns` |
| `reason` / `vendor_category` | Why it qualified; the vendor category if any | `ai_name` |
| `lookup_status` / `provider_hint` | `unlisted`, or `unlisted_host_of_known_provider` with the known provider | `unlisted` |
| `event_count` / `src_count` / `user_count` | Volume, distinct clients (approximate), distinct users (Web only) | `5400` / `1100` / `0` |
| `total_candidates` / `tier_candidates` | How many rows existed before the cap | `128` / `43` |
| `suggested_action` | What to do with the row | `Review the service; if it is an AI service add its domain to ai_provider_domains, ...` |

### Thresholds

| Parameter | Default | Macro | Notes |
|---|---|---|---|
| Events per name per day | 50 | `hdsi_ai_unknown_high_volume_external_api_discovery_min_events` | OR with sources |
| Distinct sources per name per day | 3 | `hdsi_ai_unknown_high_volume_external_api_discovery_min_sources` | OR with events |
| Rows returned | 100 | `hdsi_ai_unknown_high_volume_external_api_discovery_max_results` | Shared round-robin across the three tiers |

---

## Review Workflow

> **Estimated review time:** 20-40 minutes a day for the first weeks. It drops sharply as reviewed services are added to the lookups or to the exclusions.

Replace `<service>` with a value from the results.

### Step 1: Open the results

Open the latest run from Triggered Alerts or the Jobs page. To run it on demand, open the saved search and run it over the previous day (`-1d@d` to `@d`). Do not run it over more than one day in one job on a large tenant. One day took 94-108 s on the busiest validation tenant.

- Work tier by tier. Tier 1 is "the vendor calls it AI". It is broad and includes chat widgets, text-to-speech, photo editors, even a news site. Tier 2 holds the most actionable rows. Tier 3 is mostly `.ai` SaaS.
- Rows with `lookup_status=unlisted_host_of_known_provider` are the quickest wins. They are usually a missing hostname or a missing `match_subdomains=1` on an existing provider row.

### Step 2: See who resolves the service (DNS)

```spl
| tstats summariesonly=t allow_old_summaries=t count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Network_Resolution.DNS
    where (DNS.query="<service>" OR DNS.query="<service>." OR DNS.query="*.<service>" OR DNS.query="*.<service>.")
    by DNS.src DNS.query
| rename DNS.* as *
| convert ctime(firstTime) ctime(lastTime)
| sort - count
```

- Many sources means broad adoption, often an embedded AI feature of an existing SaaS product (for example the AI assistant of a meeting or office suite). A few sources means individual tool use.
- DNS `src` can be a resolver, a forwarder or a roaming client's public address. Treat counts as approximate.

### Step 3: See the web activity (who, how much, which category)

```spl
| tstats summariesonly=t allow_old_summaries=t fillnull_value="unknown" count sum(Web.bytes_out) as bytes_out dc(Web.url) as url_count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Web
    where (Web.url_domain="<service>" OR Web.url_domain="*.<service>" OR Web.site="<service>" OR Web.site="*.<service>")
    by Web.user Web.src Web.url_domain Web.site Web.category sourcetype
| rename Web.* as *
| eval url_domain=coalesce(nullif(url_domain,"unknown"),nullif(site,"unknown")), mb_out=round(bytes_out/1024/1024,2)
| convert ctime(firstTime) ctime(lastTime)
| table firstTime lastTime user src url_domain category sourcetype count url_count mb_out
| sort - count
```

- `mb_out` shows whether users send data to the service (uploads), not just load a page.
- If `sourcetype` is an inbound server log, add it to `..._web_filter`.

### Step 4: Check what the lookups already contain

```spl
| inputlookup ai_provider_domains
| where like(lower(domain), "%<service>%") OR like(lower(provider), "%<provider hint>%")
| table provider domain usage_type enabled match_subdomains traffic_class severity_weight confidence last_verified notes
```

```spl
| inputlookup ai_provider_apps
| where like(lower(app_name), "%<service>%")
| table app_name provider usage_type enabled source_product severity_weight notes
```

### Step 5: Research and decide

Check the vendor's site and documentation. Decide:

- **AI service that matters for policy** (a generative AI chat, writing, image, voice or code tool that accepts user content): add it to `ai_provider_domains` (hostname or registrable domain, with `match_subdomains=1` where appropriate) or `ai_provider_apps`. Set `usage_type`, `severity_weight` and `traffic_class`.
- **Unlisted host of a known provider:** add the host, or set `match_subdomains=1` on the provider's row.
- **Not AI, or not relevant** (ad tech, analytics, a retailer's chatbot subdomain, a provider's staging alias, the tenant's own infrastructure): append it to `hdsi_ai_unknown_high_volume_external_api_discovery_exclusions`.
- **Undecided:** park it with `search NOT service IN (...)` in `..._customizations`, which frees its cap slot.

### Step 6: Close the loop

Lookup changes go to the common package `hdsi_ai_rba_common` and are separately approved changes. Once a service is in the lookup, it disappears from the next run and every AI detection starts to see it. Most web rules need no change. Rules with literal pre-filters (for example the unsanctioned web access and time-of-day rules) need their generated macros regenerated when **new** web domains or app names are added. The package READMEs give the SPL.

---

## True Positive Indicators

For this search, a useful row is:

- a generative AI service that accepts user content (prompts, files, code) and is absent from the lookups;
- many internal sources or users, or measurable `mb_out`;
- an unlisted host of a known provider (a coverage gap in an existing provider row).

---

## False Positive Scenarios

| Scenario | Likelihood | Mitigation |
|---|---|---|
| Broad vendor AI categories (chat widgets, text-to-speech, photo editors, survey tools, a news site) | High in tier 1 | Review, then add to `..._exclusions` |
| `.ai` TLD used by security, analytics, HR and ad-tech vendors | High in tier 3 | Ad-tech `.ai` domains are excluded by default. Append others after review |
| AI features of ordinary companies (website chatbots, `chatbot-*`, `ai-assistant.*`, `copilot` subdomains). This was the largest tier-2 group on two tenants | Medium | Add the reviewed names to `..._exclusions` |
| Word collisions (`gpt` inside a random token, `gemini` as a crypto brand) | Low | Add to `..._exclusions` |
| Inbound server logs (an internal application name containing `gpt`) | Low with the default `..._web_filter` | Add the sourcetype to `..._web_filter` |
| Internal zones and forwarders | Low | Add to `..._filter` or `..._exclusions` |

---

## Response Actions

### If the service is an AI service

1. Add it to `ai_provider_domains` or `ai_provider_apps` in `hdsi_ai_rba_common`, as a separately approved change.
2. If policy prohibits it, ask the proxy or SSE owner to block or categorise it.
3. If Step 3 shows meaningful uploads by specific users, raise a hunting lead. Check those users' risk with `| from datamodel:"Risk.All_Risk" | search risk_object="<user>" source="* - HDSI *"`.

### If the service is not AI or not relevant

1. Append it to `hdsi_ai_unknown_high_volume_external_api_discovery_exclusions`.
2. Record the decision, so the next reviewer does not repeat the research.

---

## Tuning Guidance

### Reducing noise

- Add the tenant's inbound Web sourcetypes to `..._web_filter` and internal DNS zones to `..._filter` before the first run.
- Use `..._customizations` to focus a review, for example `search review_tier>1` to see only the name-based tiers. Removed rows free cap slots, because the hook runs before the cap.

### Adjusting thresholds

Shows how many unknown AI-named DNS names each volume gate keeps, per name tier:

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
| stats count as candidates
        sum(eval(if(event_count>=20 OR src_count>=2,1,0))) as kept_20_2
        sum(eval(if(event_count>=50 OR src_count>=3,1,0))) as kept_50_3
        sum(eval(if(event_count>=100 OR src_count>=5,1,0))) as kept_100_5
        by name_ai
```

Raise the gate to 100/5 when the list is too long to review. Lower it to 20/2 for a one-off hunt on a quiet tenant. `review_tier` and `src_count`, not the gate, decide what appears first.

---

## Related Detections

| Detection ID | Search name | Relationship |
|---|---|---|
| AI-012 | `Network - HDSI AI DNS Queries To AI Domains - Rule` | Scores DNS to **known** AI domains. This search finds the unknown ones |
| AI-028 | `Network - HDSI AI Unsanctioned Web Access - Rule` | Scores web use of known AI web apps. Its literal domain and app macros need regenerating after new web rows are added |
| AI-041 | `Network - HDSI AI Time-of-Day Usage Pattern Anomaly - Rule` | Its exact-name pre-filter needs regenerating after new web rows are added |
| n/a | `Audit - HDSI AI Health Lookup Staleness Alert - Rule` | Health check on the same common lookups |

---

## Data Requirements

| Requirement | Details |
|---|---|
| Data Model | `Network_Resolution.DNS` and/or `Web`, accelerated (either is enough) |
| Required Fields | DNS: `query`, `src`. Web: `url_domain`, `site`, `category`, `src`, `user`, `bytes_out` (drilldown) |
| Sourcetype Examples | DNS: resolver or roaming cloud DNS logs. Web: outbound proxy, NGFW URL logs with categories (PAN-DB `artificial-intelligence` / `AI-*`), SSE with `Generative AI` category |
| CIM Compliance | Outbound traffic only. A vendor AI URL category is the strongest signal. Without one, the Web branch matches AI words only |
| Acceleration | Required |
| Lookups | Common: `ai_provider_domains`, `ai_provider_apps` (read directly and through `ai_domains_filter`) |
| Macros | Common: `ai_domains_filter`. Package: `hdsi_ai_unknown_high_volume_external_api_discovery_*` |

### Validation summary (read-only live tests, 2026-10-09, 4 production ES tenants, previous calendar day, repeated for the day before)

| Tenant | AI evidence in data | Parses (search + 2 drilldowns) | Candidates (scheduled day / day before) | Rows returned (runtime) | Notes |
|---|---|---|---|---|---|
| A | NGFW URL logs with AI categories; DNS about 1.1B a day | OK | 865 / 936 | 100: 34 tier 1, 33 tier 2, 33 tier 3 (94-108 s) | The round-robin cap brought a Gemini in Google Workspace endpoint (about 23,000 sources) to the top of tier 2 |
| B | Roaming cloud DNS about 53M a day; inbound Web | OK | 128 / 137 | 100: 43 tier 2, 57 tier 3 (65-82 s) | Top: a meeting-suite AI companion (about 1,100 sources) |
| C | DNS about 209M a day; SSE `Generative AI` category | OK | 200 / 194 | 100: 50 tier 2, 50 tier 3 (6-7 s) | Every categorised SSE app was already known or opt-in |
| D | DNS about 2.8M a day, no AI-named queries | OK | 0 / 0 | 0 (5 s) | Correctly silent |

v1.0 returned 0 rows on every tenant. On one tenant it was auto-finalised at 300 s, and on another the test harness timed out.

---

## Revision History

| Date | Author | Notes |
|---|---|---|
| 2026-02-19 | Codex | Initial runbook added for AI-DISCOVERY-001. |
| 2026-10-09 | Trevor Mock (Hurricane Labs) | 1.1.0: rewritten for the released ad hoc package `hdsi_ai_unknown_high_volume_external_api_discovery` and the search `Network - HDSI AI Unknown High-Volume External API Discovery - Rule`. It is now a hunting and discovery search with no risk and no notable. It reads DNS and outbound Web with `fillnull_value`, requires AI evidence (vendor category, AI name or `.ai` TLD), compares names against the common lookups, and ranks rows into three review tiers with a shared round-robin cap. Runs daily over the previous day. Review workflow with working drilldown SPL. Live validation across Tenants A-D added |
