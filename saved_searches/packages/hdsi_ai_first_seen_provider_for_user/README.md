## Architect Notes
---
**Author:** Trevor Mock, Hurricane Labs LLC. Security Operations Architect

This daily rule finds a user who starts using a rarely used AI provider. The user must have no use of that provider in the previous 30 days (of accelerated data model history), and the provider must have been used by at most 10 users in the organisation that day. Mainstream tools (ChatGPT, Gemini, Copilot) produce hundreds of "first uses" a day in a large tenant, so they are excluded by the rarity gate. What remains is a short list of people adopting, or trying to reach, niche or unvetted AI services (voice cloning, transcription bots, code agents, model routers). Each finding says whether the traffic was allowed or `all blocked` by the proxy/NGFW; blocked-only attempts score at half weight. The rule adds risk to the user, never to a system, and does not create a notable.

### Prerequisites

At least one of these, with a populated `user`:

| Source | Fields used | Notes |
|---|---|---|
| CIM `Web` (accelerated) | `Web.user`, `Web.url_domain` and/or `Web.site`, `Web.src` | Forward proxy, SWG or SSE/CASB. A hostname in `url_domain` or `site` works. SSE app names in `site` (e.g. Netskope "GitHub Copilot") are resolved through `ai_provider_apps`. Inbound web server, ELB and WAF logs have no user and are ignored. |
| CIM `Network_Traffic` (accelerated) | `All_Traffic.user`, `All_Traffic.app`, `All_Traffic.src` | NGFW App-ID with user identification (Palo Alto User-ID). Only App-IDs listed in `ai_provider_apps` are seen. |

- Rows without a real user (empty, `unknown`, `-`, an IP address, a machine account ending in `$`) are dropped. No risk is ever written to an "unknown" user.
- `summariesonly=t`: the history window is limited to the data model acceleration range. If Web or Network_Traffic is accelerated for less than 30 days, the history is shorter and "first use" is less reliable. One validation tenant accelerates only 7 days. Check the range with `| rest /services/admin/summarization by_tstats=t splunk_server=local count=0 | search summary.id="*Web*" OR summary.id="*Network_Traffic*" | table summary.id summary.time_range`.
- ES lookups: `identity_lookup_expanded`. It merges the account formats of one person (see How it works) and provides `bunit` for the risk multiplier. With no identity data the rule still runs; formats then merge only when the UPN local part equals the account name.
- `Web.action` / `All_Traffic.action` (optional): used to label blocked-only attempts. Without it every finding counts as allowed.
- Common package `hdsi_ai_rba_common`: `ai_domains_filter`, `ai_unsanctioned_filter`, `ai_risk_multiplier`, and the `ai_provider_domains`, `ai_provider_apps`, `ai_sanctioned_entities`, `ai_department_sensitivity` lookups.

### How it works

- **Window (yesterday, `-1d@d` to `@d`).** Two `tstats` searches read AI traffic only: Web is pre-filtered by `hdsi_ai_first_seen_provider_for_user_web_scope`, a literal list of every lookup domain, subdomain wildcard, cloud AI endpoint pattern and SSE app name. Network_Traffic is pre-filtered by the App-ID list in `hdsi_ai_first_seen_provider_for_user_nt_scope`.
- **Resolve.** `hdsi_ai_first_seen_provider_for_user_resolve` drops unattributed users. It looks each user up in `identity_lookup_expanded` and takes the identity record's first UPN as the canonical identity, so `DOMAIN\jsmith`, `jsmith` and `john.smith@example.com` of one person count as one `user_key`, even when the UPN local part differs from the account name. A user with no identity record falls back to the lowercase user without a `DOMAIN\` prefix or `@suffix`. A comma list such as `account,location` (some cloud proxies) is reduced to its first element. It then resolves the provider with `ai_domains_filter`. App names (SSE `site`, App-ID) are matched with `ai_input_type=app`. Hostnames are matched with `ai_input_type=host`. Providers in `hdsi_ai_first_seen_provider_for_user_sanctioned_providers` are dropped.
- **Candidates.** `hdsi_ai_first_seen_provider_for_user_candidate_terms` keeps providers with no more than `max_org_users` distinct users in the window. It builds one filter from those providers' users (the raw values seen in the window plus every identity alias of those users), enabled lookup domains (with subdomain wildcards), app names and App-IDs, and the raw hosts seen in the window.
- **NGFW volume guard.** In the window App-ID subsearch, an App-ID with more than `max_org_users` users that day is collapsed to one `__aggregate__` row. This keeps the subsearch under the 50,000-row cap; one tenant has more than 75,000 Gemini App-ID users a day. Those users still count towards the provider's rarity gate.
- **History.** `appendpipe` and `map` run one `tstats` over the 30 days before the window (`hdsi_ai_first_seen_provider_for_user_baseline`, `-31d@d` to window start). The search is restricted to the candidate users and providers, so it reads a few users rather than all AI traffic. This keeps the scan affordable in a tenant with billions of traffic events a day. The filter is a dynamic subsearch inside `map`, because a subsearch in a top-level `tstats where` cannot be syntax-checked.
- **Decision.** History is matched on any overlap between the normalised keys of the window user (the account, the canonical identity and every identity alias) and the keys of the history rows for that provider. This finds earlier use under another linked account format even when part of the person's formats are missing from the identity data. A (user_key, provider) pair is reported when:
  - it has window activity and no overlapping history activity;
  - the provider had at most `max_org_users` users that day;
  - the user made at least `min_events` window events (any match type: hostname, SSE app name or App-ID), not counting subdomain hits on `incidental_hosts`.

  `access_outcome` is `allowed` when at least one window event was not blocked, and `all blocked` when every event matched `blocked_actions`. Blocked-only findings get `blocked_weight` (0.5).

  `ai_unsanctioned_filter` then removes approved users, systems and bunits.
- **Scoring.** `risk_score = min(40, max(5, round(20 x severity_weight x risk_multiplier x outcome_weight)))`, where `outcome_weight` is 1 for allowed and `blocked_weight` for all-blocked:
  - `severity_weight` comes from the provider lookup, 0.3 to 1.2.
  - `risk_multiplier` comes from `ai_risk_multiplier` (identity bunit sensitivity x 1.25 for privileged or critical identities, capped at 2.0).
  - The static fallback in `_risk` is 20 on the `user` object only.
  - Suppression: 24 hours per `user,provider`.
  - The risk object is the UPN when one was seen or is known from identity data, otherwise the raw account value. `user_terms` holds every account format of the person, quoted with backslashes escaped; the three drilldowns filter on it (`Web.user IN ($user_terms$)`), so `DOMAIN\user` risk objects drill down correctly.
- MITRE ATT&CK: T1588.007 (Obtain Capabilities: Artificial Intelligence).

### Tuning macros

| Macro | Ships as | Purpose |
|---|---|---|
| `hdsi_ai_first_seen_provider_for_user_filter` | `()` | Web exclusions, inline in the window Web `tstats` (e.g. `NOT Web.user IN ("svc_*")`, `NOT sourcetype IN ("aws:elb:accesslogs","aws:waf")`). An excluded user never becomes a candidate, so the history search needs no exclusion. |
| `hdsi_ai_first_seen_provider_for_user_nt_filter` | `()` | Network_Traffic exclusions, inline in the window App-ID `tstats` (e.g. `NOT All_Traffic.user IN ("svc_*")`). |
| `hdsi_ai_first_seen_provider_for_user_max_org_users` | `10` | Rarity gate: the most distinct users a provider may have in the day. |
| `hdsi_ai_first_seen_provider_for_user_min_events` | `3` | Minimum window events for any match type. Drops embedded players, link previews, SSO redirects and single CASB page events. |
| `hdsi_ai_first_seen_provider_for_user_blocked_actions` | regex | Action values that mean the proxy/NGFW stopped the request (`blocked`, `deny`, `drop`, `reset-*`, `sinkhole`...). Add vendor-specific verbs. |
| `hdsi_ai_first_seen_provider_for_user_blocked_weight` | `0.5` | Score weight for an `all blocked` first use. `1` scores attempts like use; `0` drops them. |
| `hdsi_ai_first_seen_provider_for_user_incidental_hosts` | regex | Subdomains such as `share.`, `cdn.`, `files.`, `try.`, `docs.` and `help.` show someone viewing content, not using the tool. Hits on them do not count towards `min_events`. |
| `hdsi_ai_first_seen_provider_for_user_baseline` | `-31d@d` | Start of the history window (30 days before the daily window). Keep it inside the acceleration range. |
| `hdsi_ai_first_seen_provider_for_user_sanctioned_providers` | `"__none__"` | Org-wide sanctioned providers, quoted, e.g. `"OpenAI","Microsoft Copilot"`. |
| `hdsi_ai_first_seen_provider_for_user_web_scope` / `_domains` / `_apps` / `_nt_scope` | literal lists | Window pre-filters generated from the common lookups. Regenerate when the lookups gain domains or app names (SPL below). |
| `hdsi_ai_first_seen_provider_for_user_resolve` / `_candidate_terms` | logic | Shared normalisation and the history filter builder. Do not edit for tuning. |
| `hdsi_ai_first_seen_provider_for_user_customizations` | `search *` | Post-scoring hook. |
| `hdsi_ai_first_seen_provider_for_user_risk_score` | `search *` | Last pipe. Override `risk_score` (max 100). |

Regenerate the literal lists after a lookup change:

```spl
| inputlookup ai_provider_domains | eval p=if(match_subdomains=1, mvappend("\"".lower(domain)."*\"", "\"*.".lower(domain)."*\""), "\"".lower(domain)."*\"")
| stats values(p) as p | eval p=mvjoin(p, ",")
```
Then append the six cloud patterns already in `_domains`. For `_apps`, use `| inputlookup ai_provider_apps | eval p="\"".lower(app_name)."\"" | stats values(p) as p | eval p=mvjoin(p, ",")`.

### Threshold

`max_org_users` = 10 suits a large tenant: one validation tenant has tens of thousands of AI users a day. In a small organisation, use a lower value. Derive it from the daily distinct users per provider, and choose a value below the providers your organisation treats as mainstream:

```spl
| tstats summariesonly=t allow_old_summaries=t fillnull_value="unknown" count from datamodel=Web where earliest=-7d@d latest=@d Web.user=* `hdsi_ai_first_seen_provider_for_user_web_scope` by _time span=1d Web.user Web.url_domain Web.site
| rename Web.* as * | eval data_source="web"
| append [| tstats summariesonly=t allow_old_summaries=t count from datamodel=Network_Traffic where earliest=-7d@d latest=@d All_Traffic.user=* `hdsi_ai_first_seen_provider_for_user_nt_scope` by _time span=1d All_Traffic.user All_Traffic.app | rename All_Traffic.* as * | eval data_source="network_traffic"]
| `hdsi_ai_first_seen_provider_for_user_resolve`
| stats dc(user_key) as users by _time provider
| stats median(users) as median_daily_users max(users) as max_daily_users by provider | sort - median_daily_users
```
This counts distinct people (`user_key`) per provider per day across both sources, which is exactly what the gate measures. In a very large NGFW tenant the App-ID subsearch can hit the 50,000-row append limit; that only undercounts providers that are clearly mainstream. Run it one day at a time if it is slow.
Providers listed as sanctioned in `sanctioned_providers` do not need to be under the gate.

### Known false positives / Limitations

- **A new hire, a returning leaver or a newly onboarded proxy** has no history, so every rare provider they touch is a first use. Exclude onboarding cohorts in `_filter`, or expect a short burst after a new data source goes live.
- **The same person in two user formats** (e.g. `DOMAIN\jsmith` on the NGFW and `john.smith@corp` on the SSE) is merged through `identity_lookup_expanded`, and the history search also looks up every identity alias. A person whose formats are not linked in the ES identity data (no identity record, or the account is missing from it) is merged only when the UPN local part equals the account name; otherwise one person can produce two findings on two risk objects. In validation, one tenant logs short account names in `DOMAIN\user` form and first.last UPNs elsewhere, and about two thirds of its flagged users had no identity record. On one day two people were each reported twice for the same provider (once per format). Load both formats into the ES identity data to fix this; the rule needs no change.
- **Provider labels pool services.** Rarity and history are keyed on the lookup's `provider` label, and some labels group several services: `Model Registry` covers huggingface.co, hf.co and modelscope.cn, so earlier use of one counts as history for the others, and the finding reads `Model Registry` with the domain in `ai_domain_list`. Split such rows in `ai_provider_domains` if the services must be judged separately.
- **Blocked attempts.** In the largest validation tenant about a quarter of first uses were blocked-only (every request denied by the proxy or NGFW). They are reported as `access_outcome=all blocked` at half weight. Earlier blocked attempts also count as history, so a user who was blocked last week and is allowed today is not reported again.
- **Accelerated history.** The message says "up to N days of accelerated history": with `summariesonly=t`, history before the acceleration range is not searched.
- **Subdomain history.** History covers the provider's lookup domains, their subdomain wildcards, and the hosts seen in the window. Cloud API providers (Bedrock, SageMaker, Azure AI Services) have no lookup rows, so only the exact hosts seen in the window are checked.
- **Rarity is measured on the detection day.** A provider with a few users each day can still pass on a quiet day, such as a weekend.
- **Embedded or incidental hits** (a shared avatar video, a meeting-recording link, a link preview) are reduced in two ways: by `incidental_hosts`, and by `min_events`, which applies to every match type. SSE/CASB app names are not exempt: an SSE logs page-level events, and in validation single-event app-name matches (one page view of an image tool or assistant) were incidental. In validation, shared-content subdomains of meeting-bot and avatar-video providers (`files.`, `try.`, `share.`, `cdn.`) were the main source of first uses that were not real adoption. A browser app that calls a provider API directly (for example a transcription widget calling `api.<provider>`) still counts as use.
- NGFW App-ID coverage depends on `ai_provider_apps`. Validation saw `openai-base`, `claude-base`, `anthropic-api-base`, `xai-grok`, `elevenlabs-base`, `bing-ai-base`, `google-workspace-duet-ai` and others that the lookup does not yet list. Until they are added, those App-IDs are invisible to the NGFW leg.
- Disabled-by-default providers in the common lookups, such as Microsoft 365 Copilot (MC1462915), are never reported.

### Validation

Read-only live tests on 2026-10-09 against 4 production ES tenants, on two full days: day 1 is the most recent scheduled window (2026-10-09, tenant time) and day 2 the day before it (2026-10-08).

| Tenant | Data reality | Parses (search + 3 drilldowns) | Risk rows day 1 / day 2 | All-blocked share | Runtime | Notes |
|---|---|---|---|---|---|---|
| A | NGFW URL logs in Web (`url_domain`, user) and NGFW App-ID with User-ID in Network_Traffic. Both are accelerated for only 7 days. | OK | 31 / 41 | 8 of 31 / 12 of 41 | about 10 min | Tens of thousands of AI users a day. Most findings are Web; 4-5 a day are App-ID. Niche providers included Lovable, QuillBot, Vertex AI, Hugging Face (`Model Registry`), Cohere, DeepL, Deepgram, ElevenLabs, Synthesia, Fireworks, OpenRouter and Perplexity. Scores 5-24. Most `DOMAIN\user` risk objects are users with no identity record (about two thirds of flagged users had none), so their formats cannot be merged. |
| B | Web is mostly inbound load-balancer and WAF logs with no user, plus a small cloud proxy. No App-ID data. | OK | 1 / 0 | 1 of 1 | 5-6 min | One blocked Hugging Face CDN attempt from the cloud proxy, which logs the same device in two formats (`name` and `name,site`); the comma handling merged them into one finding. The scan cost is the window pre-filter over a very large inbound Web summary. Exclude the inbound sourcetypes in `_filter`. |
| C | SSE/CASB: `site` holds the app name, `url_domain` is empty, users are UPNs. The NGFW has no user. | OK | 1 / 1 | 0 | 15 s | App-name matches (Casetext, Lovable) with 5-19 events. Applying `min_events` to app names removed single-page-view findings (an image tool, an assistant, a voice tool) that the previous version reported. |
| D | Inbound IIS only, very little Network_Traffic. | OK | 0 / 0 | - | 6 s | No egress data with users. |

Drilldowns were run with real flagged values: for `DOMAIN\user` users the Web and App-ID drilldowns return the finding's traffic (the previous `Web.user="$user$"` form returned 0 rows), and the risk drilldown on an existing `DOMAIN\user` risk object returns its events with the escaped `user_terms` form and 0 with the unescaped form. The threshold SPL above ran in all four tenants. The previous release of this version, on the same 2026-10-08 window in Tenant A, gave 46 findings. The drop to 41 comes mostly from applying `min_events` to App-ID matches.

Before this version, the rule ran every 15 minutes on a 24-hour window and grouped `tstats` by `Web.url_domain` and `Web.site` without `fillnull_value`. Every row with either field empty was dropped, so it returned nothing in Tenants A and C. In Tenant B it emitted 4 risk events on the user "unknown" from inbound scanner traffic. Its `$_weighted_risk$` token score is not supported by ES.

### Deployment

The package ships with `enable_alerting: false`. Before enablement, complete these checks on the target tenant:

1. Confirm that Web or Network_Traffic carries real user names for egress traffic.
2. Check the acceleration range against `_baseline`.
3. Run the search over the last 7 days, one day at a time, and review the daily volume.
4. Set `max_org_users` and `sanctioned_providers` for the organisation.
5. Confirm the rule's runtime fits the daily schedule. It runs at 02:17. Validation saw seconds on small tenants and about 10 minutes on a tenant with billions of NGFW events a day.

The rule writes risk only, to the user. Enabling it is a separately approved change.
