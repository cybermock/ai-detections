## Architect Notes
---
**Author:** Trevor Mock, Hurricane Labs LLC. Security Operations Architect

This daily rule finds users whose AI usage yesterday was far above that of their peers. It compares each user's AI requests and AI upload volume (bytes out) with the other AI users of the same identity business unit (`bunit`). Users whose bunit is unknown or too small are compared with each other in one residual organisation-wide group. A user is reported only when the value is a robust statistical outlier, at least 10 times the peer median, and above an absolute floor. Heavy AI use far beyond colleagues doing the same job is a useful insider-risk and data-exposure signal for RBA. The rule adds risk to the user only and does not create a notable.

### Prerequisites

At least one of these, with a populated `user` on egress traffic:

| Source | Fields used | Notes |
|---|---|---|
| CIM `Network_Traffic` (accelerated) | `All_Traffic.user`, `All_Traffic.app`, `All_Traffic.bytes_out`, `All_Traffic.src` | NGFW App-ID with user identification (Palo Alto User-ID). Only App-IDs listed in `ai_provider_apps` are seen. Gives sessions and bytes. |
| CIM `Web` (accelerated) | `Web.user`, `Web.url_domain` and/or `Web.site`, `Web.bytes_out`, `Web.src` | Forward proxy, SWG or SSE/CASB. A hostname in `url_domain` or `site` works, and SSE app names in `site` (e.g. Netskope "GitHub Copilot") resolve through `ai_provider_apps`. URL-filtering logs without bytes (e.g. PAN URL logs) are scored on requests only. Inbound web server, ELB and WAF logs have no user and are ignored. |

- Rows without a real user (empty, `unknown`, `-`, an IP address, a machine account ending in `$`) and service accounts (`_service_accounts`) are dropped before the statistics. No risk is ever written to an "unknown" user.
- ES identities: `identity_lookup_expanded` provides `bunit`, the peer group key. It is looked up by the raw user and then by the bare account name (without `DOMAIN\` or `@suffix`). ES identities carry no `department` field. Without `bunit` the rule still works, with one organisation-wide peer group per data source.
- Common package `hdsi_ai_rba_common`: `ai_domains_filter`, `ai_unsanctioned_filter`, `ai_risk_multiplier`, and the `ai_provider_domains`, `ai_provider_apps`, `ai_sanctioned_entities` and `ai_department_sensitivity` lookups.
- The data model must be accelerated (`summariesonly=t`). No raw-event fallback.

### How it works

- **Window.** Daily at 04:30 over yesterday (`-1d@d` to `@d`).
- **Collect.** A `tstats` over `Network_Traffic` reads only AI App-IDs (`_nt_scope`, tenant exclusions in `_filter`). An appended `tstats` over `Web` reads only AI hosts and SSE app names (`_web_scope`, tenant exclusions in `_web_filter`). Both lists are literal macros generated from the common lookups. The Web leg is reduced to one row per user inside the subsearch, so it stays under the 50,000-row `append` limit. The NGFW leg is the main search because one validation tenant has about 75,000 App-ID users a day.
- **Resolve (`_resolve`).** Drops unattributed and service accounts, resolves the provider with `ai_domains_filter` (App-IDs and SSE app names as `ai_input_type=app`, hostnames as `host`), drops background hosts (`ai_traffic_class=background` in the common registry: telemetry, auth, CDN and extension stream hosts such as `stream.quillbot.com` or `ab.chatgpt.com`, which add requests without user activity), drops `_sanctioned_providers`, and sums `requests` and `bytes_out` per person (`user_key`, the lowercased bare account name without `DOMAIN\` or `@suffix`) and data source. The `DOMAIN\user` and `user@domain` rows of one person therefore count once; `user` becomes the `DOMAIN\user` form when one was seen, and `user_aliases` lists every form.
- **Peer statistics (`_peer_stats`).** The peer group is the user's `bunit` when that bunit has at least `_min_peer_size` AI users in the data source that day. Everyone else (no bunit, or a bunit below `_min_peer_size`) forms one residual group per data source, labelled `org-wide, no qualifying bunit`. It excludes the users of qualifying bunits, so it equals all AI users of the source only where no bunit qualifies. For each group, it computes the median and the MAD of `log10(value+1)` for requests and bytes. The robust z-score is `0.6745 x (value - median) / MAD`, with the MAD floored at 0.1. The log scale and the median/MAD stop a few very heavy users from inflating the spread, which is what hid outliers in the old mean/stdev version.
- **Decision.** A user is an outlier when the peer group has at least `_min_peer_size` users and either of these holds:
  - **requests:** `requests >= _min_requests`, `requests >= _ratio x peer median`, and `rz_requests >= _zscore`;
  - **bytes_out:** `MB out >= _min_mb`, `bytes_out >= _ratio x peer median`, and `rz_bytes >= _zscore`.
  
  `ai_unsanctioned_filter` then removes approved rows (see "Approving users" below). It runs twice, once on `user` and once on the bare `user_key`, and before the per-person dedup, so an approved row in one data source cannot hide an unapproved outlier in the other. A person still seen in both data sources is then reported once (`dedup user_key`), on the more extreme row.
- **Scoring.** The base is 20 for a requests outlier, 30 for a bytes outlier and 40 for both. `risk_score = min(60, max(15, round(base x risk_multiplier)))`, where `risk_multiplier` comes from `ai_risk_multiplier` (bunit sensitivity x 1.25 for privileged or critical identities, capped at 2.0). The static fallback in `_risk` is 20 on the `user` object only. In validation the multiplier was 1.00 on every finding in every tenant (see Limitations), so in practice the score is the base 20/30/40 until `ai_department_sensitivity` keys match the tenant's bunit values.
- **Suppression.** 7 days per `user`. A persistent heavy user is reported at most once a week. In validation of an earlier version, about a quarter of the daily outliers were also outliers the day before.
- **MITRE ATT&CK.** A bytes outlier (`bytes_out` or `requests and bytes_out`) carries `mitre_attack=T1567` (Exfiltration Over Web Service) and `ai_kill_chain_phase=exfiltration`. A requests-only outlier shows heavy use, not upload volume, so it carries `mitre_attack=T1588.007` (Obtain Capabilities: Artificial Intelligence) and `ai_kill_chain_phase=collection`. The annotation lists both techniques.
- **Output fields.** `ai_risk_multiplier` also adds `sensitivity_level`; the search removes it (and `_final_multiplier`) so that only `risk_multiplier` reaches the risk event. `ai_unsanctioned_filter` removes its own `_allow_*` working fields.
- **Drilldowns.** Risk events, AI web activity and AI App-ID traffic for the person. They pre-filter on `*<user_key>` / `<user_key>@*` and then keep rows whose computed `user_key` equals the finding's. They never put the raw `$user$` inside a quoted search value, where the backslash of `DOMAIN\user` matches nothing.

### Tuning macros

| Macro | Ships as | Purpose |
|---|---|---|
| `hdsi_ai_user_peer_group_usage_anomaly_filter` | `()` | Network_Traffic exclusions, inline in the first (App-ID) `tstats` (e.g. `NOT All_Traffic.user IN ("svc_*")`). Excluded users also leave the peer statistics. |
| `hdsi_ai_user_peer_group_usage_anomaly_web_filter` | `()` | Web exclusions, inline in the appended Web `tstats` (e.g. `NOT Web.user IN ("svc_*")`, `NOT sourcetype IN ("aws:elb:accesslogs","aws:waf")`). Excluded users also leave the peer statistics. |
| `hdsi_ai_user_peer_group_usage_anomaly_min_peer_size` | `10` | Minimum AI users in a bunit (otherwise the user joins the residual `org-wide, no qualifying bunit` group) and in any scored group. |
| `hdsi_ai_user_peer_group_usage_anomaly_zscore` | `3.5` | Robust (modified) z-score threshold. |
| `hdsi_ai_user_peer_group_usage_anomaly_ratio` | `10` | The value must be at least this multiple of the peer median. |
| `hdsi_ai_user_peer_group_usage_anomaly_min_requests` | `2500` | Absolute floor for a requests outlier (NGFW sessions or proxy/SSE rows per day). |
| `hdsi_ai_user_peer_group_usage_anomaly_min_mb` | `100` | Absolute floor for a bytes outlier (MB out per day). |
| `hdsi_ai_user_peer_group_usage_anomaly_service_accounts` | regex | Service and application accounts removed before the statistics (`svc`, `srv`, `service`, `svcacct`, `app`, `bot`, `sys` prefixes). Adapt to the naming standard; `"^$"` keeps every account. |
| `hdsi_ai_user_peer_group_usage_anomaly_sanctioned_providers` | `"__none__"` | Org-wide sanctioned providers, quoted (e.g. `"Google Gemini"`). Their traffic is ignored, so heavy use of an approved enterprise assistant is not an anomaly. |
| `hdsi_ai_user_peer_group_usage_anomaly_web_scope` / `_domains` / `_apps` / `_nt_scope` | literal lists | Pre-filters generated from the common lookups. Regenerate when the lookups gain domains or app names (SPL below). |
| `hdsi_ai_user_peer_group_usage_anomaly_resolve` / `_peer_stats` / `_user_key` | logic | Shared normalisation and statistics. Do not edit for tuning. |
| `hdsi_ai_user_peer_group_usage_anomaly_customizations` | `search *` | Post-scoring hook. |
| `hdsi_ai_user_peer_group_usage_anomaly_risk_score` | `search *` | Last pipe. Override `risk_score` (max 100). |

#### Approving users

- **A provider for the whole organisation:** add it to `_sanctioned_providers` (quoted, e.g. `"Anthropic"`). Its traffic is removed before the statistics, for users with one provider and with several. The common organisation-wide key `*|<provider>` in `ai_sanctioned_entities` only removes a finding whose only provider is that one, because a finding with several providers is matched with provider `*`.
- **A person:** add `<account>|<provider>` (finding with one provider) or `<account>|*` (several providers) to `ai_sanctioned_entities`. Use the bare account name, i.e. the finding's `user_key` (no `DOMAIN\` and no `@suffix`). It matches every user format of that person. An entry with the full `DOMAIN\user` value only matches on days when that form is the finding's `user`, and the form can change from day to day (see `user_aliases`).
- **A business unit:** add `<bunit>|<provider>` or `<bunit>|*`. Use the lowercased identity `bunit` as shown in the finding's `bunit` field.
- Keys are case-insensitive. Entries need `enabled=1` and an empty or future `expires`.

The package no longer reads `peer_group_zscore` from `ai_detection_config`. The threshold changed meaning (robust z-score instead of mean/stdev z-score), so it is now the `_zscore` macro.

Regenerate the literal lists after a lookup change (last regenerated 2026-10-09 from the common lookups: 330 domain patterns and 105 app names, including the new `claude-*`, `anthropic-api*`, `openai-*` and `google-gemini-*` App-IDs):

```spl
| inputlookup ai_provider_domains | eval d=lower(domain)
| eval p=case(match_subdomains=1, mvappend("\"".d."*\"", "\"*.".d."*\""), match(d,"^[^.]+\.[^.]+$"), mvappend("\"".d."*\"", "\"www.".d."*\""), true(), "\"".d."*\"")
| stats values(p) as p | eval p=mvjoin(p, ",")
```
The `www.` variant covers two-label domains with `match_subdomains=0` (for example `replit.com`), because `ai_domains_filter` strips a leading `www.`. Then append the five cloud AI endpoint patterns that are not in the lookup: `"*.cognitiveservices.azure.com*"`, `"*.services.ai.azure.com*"`, `"*aiplatform.googleapis.com*"`, `"*sagemaker.*amazonaws.com*"` and `"bedrock*.amazonaws.com*"`. For `_apps`, use `| inputlookup ai_provider_apps | eval p="\"".lower(app_name)."\"" | stats values(p) as p | eval p=mvjoin(p, ",")`.

### Threshold

The defaults suit a large organisation that logs NGFW App-ID traffic with User-ID. To set tenant values, run the statistics for each of the last 7 days (change `earliest`/`latest` one day at a time) and look at the shape of the heaviest users:

```spl
| tstats summariesonly=t allow_old_summaries=t count sum(All_Traffic.bytes_out) as bytes_out values(All_Traffic.src) as src from datamodel=Network_Traffic where earliest=-1d@d latest=@d All_Traffic.user=* `hdsi_ai_user_peer_group_usage_anomaly_nt_scope` by All_Traffic.user All_Traffic.app
| rename All_Traffic.* as * | eval data_source="network_traffic", ai_domain=app, ai_input_type="app"
| `hdsi_ai_user_peer_group_usage_anomaly_resolve`
| append maxtime=900 [| tstats summariesonly=t allow_old_summaries=t fillnull_value="unknown" count sum(Web.bytes_out) as bytes_out values(Web.src) as src from datamodel=Web where earliest=-1d@d latest=@d Web.user=* `hdsi_ai_user_peer_group_usage_anomaly_web_scope` by Web.user Web.url_domain Web.site | rename Web.* as * | eval data_source="web", ai_input_type=if(url_domain="unknown","app","host"), ai_domain=lower(coalesce(nullif(url_domain,"unknown"),nullif(site,"unknown"))) | `hdsi_ai_user_peer_group_usage_anomaly_resolve`]
| `hdsi_ai_user_peer_group_usage_anomaly_peer_stats`
| eval mb=bytes_out/1048576
| stats count as users dc(peer_group) as peer_groups median(requests) as med_req perc99(requests) as p99_req max(requests) as max_req median(mb) as med_mb perc99(mb) as p99_mb max(mb) as max_mb count(eval(rz_requests>=3.5 AND requests>=2500)) as req_out count(eval(rz_bytes>=3.5 AND mb>=100)) as mb_out by data_source
```

- Keep `_min_requests` and `_min_mb` above the p99 of a normal day, so that the floors, and not the z-score alone, set the volume.
- A small organisation, or a source with no bytes, usually needs a lower `_min_requests`. Lower it only after reviewing the users it would add.
- Aim for a handful of users a day. With 7-day suppression, persistent heavy users stop repeating.

### Known false positives / Limitations

- **Power users and AI-heavy roles.** In Tenant A on 2026-10-08, the findings were mostly heavy users of mainstream assistants, not rare tools:
  - **Bytes outliers (20).** 14 of the 16 bytes-only findings involved Anthropic App-IDs, with 105-2,300 sessions and 143-752 MB out. Most of this volume is `anthropic-api-base`: 92 users that day, 15 of them over 100 MB. That is API and agentic coding clients (such as Claude Code), which resend the working context on every turn. So hundreds of MB a day is normal for an active developer, and it is also exactly the source-code exposure the rule exists to show. The other 2 bytes-only findings were Google Gemini only (see Ambient App-IDs). The 4 findings on both requests and bytes (106-1,038 MB) were IDE coding assistants (Cursor, GitHub Copilot, Windsurf) together with OpenAI and Gemini.
  - **Requests-only outliers (13).** 10 NGFW findings with 2,900-11,300 sessions were Google Gemini, OpenAI and Anthropic App-ID users; one also used GitHub Copilot. The 3 URL-log (Web) findings were one QuillBot user (12,620 rows on `quillbot.com` itself), one GitHub Copilot user (3,196) and one developer using Aider, Anthropic, Copilot, Gemini and a local LLM (2,698).
  
  A requests-only finding carries the lowest base score (20) and `collection`, not `exfiltration`. Approve known developers or AI-heavy teams as described in "Approving users". If an API provider is approved for the whole organisation, `_sanctioned_providers` removes it from the statistics. A bunit peer group only absorbs this behaviour when identities carry a meaningful bunit and the role has at least `_min_peer_size` AI users.
- **Ambient App-IDs.** In Tenant A, the NGFW `google-gemini` App-ID was seen for about 75,000 users a day, so almost every user counts as a Gemini user. That keeps the residual peer medians tiny (15 sessions, 0.16 MB). It also means a large Google upload classified as Gemini becomes a bytes outlier: on 2026-10-08, one finding had 91 Gemini sessions and 244 MB. If Gemini is the sanctioned enterprise assistant, add `"Google Gemini"` to `_sanctioned_providers`.
- **In practice the absolute floors decide, not the peer group.** Where identities have no `bunit` (two of four validation tenants had none for AI users), or bunits are very fine-grained (one tenant had over 6,000 distinct values), almost everyone falls into the residual `org-wide, no qualifying bunit` group. In Tenant A, 30 of 33 findings were scored against a residual group: 27 against the NGFW group of about 59,000 users and 3 against the URL-log group of about 2,900 users (median 3 rows). Only 3 were scored against a bunit, of 20, 25 and 50 users. Against medians this small, every value above `_min_requests` or `_min_mb` is also far above `_ratio` x median and the z-score cut-off. The rule then works as an absolute daily-volume threshold on AI traffic, ranked by peer z-score. That is still useful, but it is not a department comparison until identities carry a coarse bunit. Set the floors with the Threshold SPL. In Tenant A on that day, raising `_min_mb` from 100 to 250 would cut the bytes-only findings from 16 to 8.
- **The risk multiplier was inert.** `ai_risk_multiplier` matches `ai_department_sensitivity` on the whole bunit, then its last path segment, then its first. It now also falls back to the bare account name, as the peer statistics do. Tenant A bunits are region/unit paths whose segments match none of the shipped keys, and the other tenants have no bunit for AI users. So `risk_multiplier` was 1.00 on all 33 findings. Add the tenant's bunit values or segments to `ai_department_sensitivity` (common package) to get escalation for sensitive units.
- **User formats.** One source can carry several formats. Tenant A's NGFW logs both `DOMAIN\user` and `user@domain` for the same people: its 30 NGFW findings were 18 `DOMAIN\user` and 12 `user@domain`, and its 3 URL-log findings were `DOMAIN\user`. The rule merges the formats on `user_key` (bare account name), so a person is not split into two smaller peers. Two different people with the same account name in different domains or UPN suffixes would also be merged; exclude or rename them in `_customizations` if the organisation has such collisions. Suppression is on `user`, which is the `DOMAIN\user` form whenever one was seen that day, so a person whose chosen form changes can be reported again inside the 7 days.
- **Request counts are not comparable across sources.** NGFW sessions, proxy requests and URL-filtering log rows differ, so statistics are computed per data source.
- **Bytes depend on the source.** URL-filtering logs (e.g. PAN URL logs) carry no bytes, so they are scored on requests only. SSE logs record bytes per connection, not per prompt or upload.
- **Service accounts** are removed by a naming regex. An automation account that is not named that way still enters the statistics and can be reported. Add it to `_filter` (NGFW) or `_web_filter` (Web). In Tenant A the two heaviest Anthropic senders that day were an unattributed (`unknown`) user (about 6.6 GB) and a regex-matched service account (about 1 GB). Both were correctly dropped. Every named person above 100 MB on the Anthropic App-IDs was reported.
- **Scan cost.** In a tenant whose Web data model is dominated by inbound load-balancer and WAF logs, the Web pre-filter took about 4-5 minutes and found no user. Exclude inbound sourcetypes in `_web_filter`.
- Disabled-by-default providers in the common lookups (Microsoft 365 Copilot under MC1462915, Grammarly and others) are never counted. Validation saw a Grammarly App-ID with millions of sessions a day, which is invisible to this rule until a tenant enables it.

### Validation

Read-only live tests on 2026-10-09 against 4 production ES tenants. The scheduled window is the previous day (2026-10-08). The results below are for this version, with the common lookups and pre-filter lists as of 2026-10-09.

| Tenant | Data reality | Parses (search + 3 drilldowns) | Risk rows (2026-10-08) | Runtime | Notes |
|---|---|---|---|---|---|
| A | NGFW App-ID with User-ID (about 59,000 users in the residual NGFW group, about 75,000 App-ID users in all) and NGFW URL logs in Web (about 2,900 users in the residual URL-log group after background hosts are dropped, no bytes). About a third of findings have a `bunit`. | OK | 33 | about 5 min (297 s) | 30 NGFW and 3 URL-log findings. 13 were requests-only (2,700-12,600 rows or sessions against peer medians of 3-24), 16 bytes-only (143-752 MB) and 4 both (106-1,038 MB), against a 0.16 MB residual median. 30 were scored against residual groups and 3 against bunits of 20-50 users. `risk_multiplier` was 1.00 on all 33. Scores: 20 (x13), 30 (x16), 40 (x4). The earlier version with the older lookups found 15 on the same day. Most of the increase is the Anthropic App-IDs now in `ai_provider_apps` (see Limitations). |
| B | Web is mostly inbound load-balancer and WAF logs with no user, plus a small cloud proxy. No App-ID data. | OK | 0 (earlier full run) | over 2 min; about 4-5 min in full | No user-attributed AI egress. The cost is the Web pre-filter over a large inbound summary. This round's run was capped at 120 s and stopped before the end. The earlier full run returned 0 rows. Exclude the inbound sourcetypes in `_web_filter`. |
| C | SSE/CASB: `site` holds the app name, `url_domain` is empty, users are UPNs. About 226 scored AI users a day, mostly GitHub Copilot; this SSE logs about a dozen AI apps and no ChatGPT, Claude or Gemini traffic. The NGFW has no user. | OK | 0 | about 7 s | In the earlier analysis the highest robust z was 3.10 on requests and 2.51 on bytes. The heaviest user made 272 requests, below the 2,500 floor, and sent about 138 MB with no robust bytes outlier. The UPN matches ES identities only through the bare-name fallback. |
| D | Inbound IIS only, very little Network_Traffic. | OK | 0 | about 7 s | No egress data with users. |

Drilldowns: the parse check passes in all four tenants, but it replaces tokens with `*`, so it cannot catch token problems. The web and App-ID drilldowns were therefore also run in Tenant A with the real tokens of a `DOMAIN\user` finding and a URL-log finding. They returned the person's rows (5 and 2 rows, about 1-2 minutes each because of the leading-wildcard pre-filter). The previous form, with the raw `DOMAIN\user` token inside a quoted `tstats` value, returned 0 rows. The risk drilldown shows only HDSI AI risk events (`source="*HDSI AI*"`). No tenant has any yet, so it returned 0 rows for the test findings. Its user matching was checked with the source filter removed: it found a Tenant A user's existing risk event, stored under the bare account name, from the `DOMAIN\user` finding.

Before this version, the rule returned nothing in all four tenants:
- In Tenants A and B it read 7 days of every Web domain for every user and hit the 300-second search limit (auto-finalized with 0 rows).
- In Tenant C it grouped `tstats` by `url_domain` and `site` without `fillnull_value`, so every SSE row was dropped.
- Its peer group was `bunit` with a fallback of "general", and a group needed only 5 users. With mean/stdev, the largest possible z-score in a group of n users is (n-1)/sqrt(n), so the 2.5 threshold could never be met in a group of fewer than 9. In large groups, a few very heavy users inflated the standard deviation and hid everyone else.
- It also emitted `src="unknown"` and had no protection against the user "unknown".

### Deployment

The package ships with `enable_alerting: false`. Before enablement, complete these checks on the target tenant:

1. Confirm that `Network_Traffic` (App-ID with User-ID) or `Web` carries real user names for egress AI traffic.
2. Run the Threshold SPL for 7 days and set `_min_requests`, `_min_mb` and `_sanctioned_providers` for the organisation.
3. Adapt `_service_accounts` to the naming standard, and exclude inbound Web sourcetypes in `_web_filter`.
4. Run the full search for several past days and review the daily volume and the users reported.
5. Confirm that the runtime fits the 04:30 schedule. Validation saw seconds on small tenants and about 5 minutes on the largest.
6. Decide how to handle developers who use API and agentic coding clients. They produced most of the bytes findings in Tenant A. Approve them, or the provider, as described in "Approving users", or accept them as intended risk.

The rule writes risk only, to the user. Enabling it is a separately approved change.
