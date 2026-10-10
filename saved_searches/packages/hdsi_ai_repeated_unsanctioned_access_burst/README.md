## Architect Notes
---
**Author:** Trevor Mock, Hurricane Labs LLC. Security Operations Architect

This rule finds a user, or an internal host with no user, that **keeps trying to reach an AI provider after the organisation's web control has blocked it**. The web control can be a proxy, NGFW URL filtering, an SSE/CASB or an enterprise browser. A single blocked page load is policy working as intended. Ten or more blocked requests spread over at least three separate minutes in a 15-minute window means a person or an installed tool is persisting against the policy. That is shadow-AI intent the policy has not yet stopped: the same person may move to a personal device, a different provider or an evasion technique. The rule creates risk on `user` and `src` and no notable.

v1.0 counted every request (allowed or blocked) and raised risk at 10 requests in 10 minutes. It never fired on the validation tenants, for three reasons. Its `tstats` split by both `Web.url_domain` and `Web.site` without `fillnull_value`, so every row from a proxy that fills only one of them was dropped. It matched AI-provider names in inbound WAF logs. Its risk scores were `$token$` values, which ES does not support. Repairing only the split would have made it fire on ordinary use: on the largest tenant, about 1,100 user-and-provider 15-minute windows a day reach 10 requests. v1.1 keeps the purpose, repeated access the organisation has not sanctioned, but uses the organisation's own enforcement as the definition of "unsanctioned".

### Prerequisites
| Data | Fields used | If absent |
|---|---|---|
| `Web` data model (accelerated) with **outbound** user web traffic from a control that blocks AI destinations | `action` (must contain `blocked` or another value in `..._blocked_actions`), `url_domain` and/or `site`, `user`, `src` | No rows. A web control that only allows, warns, isolates or logs AI traffic produces no refused requests, so it gives this rule nothing to count |

- `url_domain` or `site` must carry a hostname or an SSE/App-ID application name that `ai_domains_filter` can resolve. Both are read with `fillnull_value="unknown"`, so a proxy that fills only one of them works.
- `user` is optional. Without it the rule raises system risk on internal `src` addresses only.
- From `hdsi_ai_rba_common` (required prerequisite package): `ai_domains_filter` (lookups `ai_provider_domains`, `ai_provider_apps`), `ai_unsanctioned_filter(3)` (lookup `ai_sanctioned_entities`) and `ai_risk_multiplier` (lookup `ai_department_sensitivity`). It also uses the ES lookup `identity_lookup_expanded` (`bunit`).

### How it works
- **Read only refused requests.** `tstats` over `Web`, filtered inline by `..._blocked_actions` and `..._filter`, split by `user`, `src`, `url_domain`, `site`, `action`, `sourcetype` and 1-minute `_time`. Filtering on `action` inside `tstats` keeps the run cheap: about 8 s per 15-minute window on the largest validation tenant, against about 200 s for all Web traffic.
- **Resolve the provider.** `ai_domain` is `url_domain`, or `site` when there is no `url_domain`. In the second case `ai_input_type="app"`, so SSE app names resolve too. `ai_domains_filter` keeps enabled AI providers only, so opt-in providers (for example Microsoft 365 Copilot) are ignored until a tenant enables them.
- **Attribute.** Placeholder users (`unknown`, `-`, empty) are nulled. A user-less row takes the user seen from the same `src` in the window, when exactly one user was seen. Each row is keyed by `entity`: the user, or `src` when there is no user.
- **Aggregate per entity and provider:** `blocked_attempts` (refused requests) and `blocked_minutes` (distinct minutes with a refusal). A row passes when `blocked_attempts >= ..._min_attempts` (10) **and** `blocked_minutes >= ..._min_minutes` (3). The minutes condition is what makes this "repeated": one blocked page load produces many refused sub-requests in a single minute.
- **Risk objects.** `user` when attributed. `src` when the entity used exactly one source address. A host-only row whose `src` matches `..._unreliable_src` is dropped. That macro ships as "public IPv4", which removes inbound WAF, load-balancer and web-server logs whose `src` is an internet client. No row carries an `unknown` risk object.
- **Approvals.** The user's ES identity `bunit` is looked up. `ai_unsanctioned_filter(user,src,provider)` then removes users, hosts and groups approved for that provider.
- **Scoring.** `risk_score = max(1, min(50, round(base x severity_weight x risk_multiplier)))`. The base is 20 when a user is attributed and 10 for host-only rows. `severity_weight` (0.3 to 1.2) comes from the provider lookups. `risk_multiplier` is the identity `bunit` sensitivity, x1.25 for privileged identities, capped at 2.0. The value applies to every risk object in the row. The `_risk` literal fallbacks are 20 for `user` and 10 for `src`.
- **Drilldowns.** Each row carries `entity_dd`, which is `entity` with every backslash and double quote replaced by `*`. Both drilldowns substitute `$entity_dd$`, not `$entity$`. Users often arrive as `DOMAIN\user`, and a backslash substituted raw into a quoted SPL term acts as an escape, so the term never matches. The `*` wildcard matches the backslash without needing any escaping. The risk drilldown lists the entity's own risk events (the user, or the host for host-only rows). The web drilldown lists allowed and blocked AI traffic for the entity per provider, domain and action, with active minutes.
- **Cadence.** Every 15 minutes (`3-59/15`) over `-20m@m` to `-5m@m`, suppressed for 24 h per `entity` and `provider`. A tool that retries all day therefore produces one event per day, not 96.

### Tuning macros
| Macro | Ships as | Purpose |
|---|---|---|
| `hdsi_ai_repeated_unsanctioned_access_burst_filter` | `()` | Exclusions inside the `tstats` where clause (`Web.*` names), e.g. `NOT Web.src IN ("10.20.0.0/16")` |
| `hdsi_ai_repeated_unsanctioned_access_burst_blocked_actions` | `Web.action IN ("blocked","block","denied","deny","dropped","drop","rejected","reset")` | Values that mean the control refused the request. Add your TA's verb if it is not CIM `blocked`. Do not add `isolate`, `warn` or `reported` |
| `hdsi_ai_repeated_unsanctioned_access_burst_min_attempts` | `10` | Minimum refused requests per entity and provider in 15 minutes (see Threshold) |
| `hdsi_ai_repeated_unsanctioned_access_burst_min_minutes` | `3` | Minimum distinct minutes with a refusal in 15 minutes |
| `hdsi_ai_repeated_unsanctioned_access_burst_unreliable_src` | public IPv4 (`match(src,"^[0-9]{1,3}([.][0-9]{1,3}){3}$") AND NOT` RFC 1918 or CGNAT) | Eval expression. Host-only rows that match are dropped. Append guest or BYOD Wi-Fi, NAT and VPN pools. `false()` keeps everything |
| `hdsi_ai_repeated_unsanctioned_access_burst_customizations` | `search *` | Post-scoring hook (fields: `entity`, `user`, `user_display`, `src`, `src_display`, `bunit`, `provider`, `usage_type`, `ai_domain_sample`, `ai_domain_count`, `blocked_attempts`, `blocked_minutes`, `action`, `orig_sourcetype`, `severity_weight`, `risk_multiplier`, `sensitivity_level`, `base_score`, `risk_score`, `firstTime`, `lastTime`, and `entity_dd` for the drilldowns) |
| `hdsi_ai_repeated_unsanctioned_access_burst_risk_score` | `search *` | Last pipe. Override `risk_score` (1 to 100) here |

Approved exceptions go in `ai_sanctioned_entities` (common package), keyed `<user, src or bunit>|<provider>`. One example is a research team that is allowed a provider the proxy blocks for everyone else.

### Threshold
The two thresholds work together. Raising `min_attempts` mostly removes short bursts. Raising `min_minutes` removes single page loads. Volume after the 24 h suppression is driven by the number of distinct entities, not the threshold: on the largest tenant, 10/3 and 20/3 gave 1,158 and 1,045 qualifying windows, both from about 185 entities. Measure your tenant over a full day before changing either value:

```spl
| tstats summariesonly=t allow_old_summaries=t fillnull_value="unknown" count from datamodel=Web
    where `hdsi_ai_repeated_unsanctioned_access_burst_blocked_actions`
    by Web.user Web.src Web.url_domain Web.site _time span=1m
| rename Web.* as *
| eval ai_domain=lower(coalesce(nullif(url_domain,"unknown"),nullif(site,"unknown"))), ai_input_type=if(isnull(nullif(url_domain,"unknown")),"app","host")
| `ai_domains_filter`
| eval entity=coalesce(nullif(user,"unknown"), src)
| bin _time span=15m as window
| stats sum(count) as attempts dc(_time) as minutes by entity provider window
| stats count as windows dc(entity) as entities
    count(eval(attempts>=10 AND minutes>=3)) as at_10_3
    count(eval(attempts>=20 AND minutes>=3)) as at_20_3
    count(eval(attempts>=10 AND minutes>=5)) as at_10_5
    p90(attempts) as p90_attempts p99(attempts) as p99_attempts
```

Run it over `-24h@h` to `@h`. Expect roughly one risk event per qualifying entity and provider per day.

### Known false positives / Limitations
- **Machine retries look like persistence.** A blocked desktop app (ChatGPT desktop or mobile apps, an IDE with a personal GitHub Copilot sign-in, a meeting-transcription agent), or a browser tab left open on a blocked provider, retries constantly. On the largest tenant, most qualifying windows had refusals in 11 to 15 of the 15 minutes, from entities that qualified in 9 or more windows a day. The 24 h suppression limits each of them to one event a day. The drilldown shows the pattern: the same few endpoints (`ab.chatgpt.com`, `ws.chatgpt.com`, `codex-cloud-backend.chatgpt.com`, `*.individual.githubcopilot.com`) in nearly every minute. Remove the tool or its sign-in, or add the host to `..._filter` or an `ai_sanctioned_entities` entry.
- **Host-only rows dominate where the firewall has no user mapping.** On the largest tenant, about 135 of 190 daily events had no user. Many were mobile apps (`ios.chat.openai.com`) on networks without User-ID. Put guest and BYOD ranges in `..._unreliable_src`, or the RBA system risk lands on short-lived DHCP addresses.
- **Inbound server logs.** WAF, load-balancer and IIS/Apache access logs map into `Web` with internet clients as `src` and no user. Scanners send Host headers that resolve to AI providers. On one tenant, 453 such entities a day would have qualified at a threshold of 1. The public-IPv4 default of `..._unreliable_src` removes them, and only real proxy users remained. If your internal clients use public address space, replace the default with an explicit list of your egress or server ranges. The guard does not catch inbound web servers behind a load balancer or reverse proxy: their logs carry the balancer's private address as `src`, so they pass as an internal host. One validation tenant already maps blocked requests from inbound web-server and CMS access logs into `Web`. None resolved to an AI provider during validation, so this is a latent risk, not an observed false positive. Exclude those sourcetypes or balancer addresses in `..._filter`, for example `NOT sourcetype IN ("iis","access_combined","aws:elb:accesslogs")` or `NOT Web.src IN ("10.1.2.0/24")`. Check `orig_sourcetype` on the first results: it should list only your proxy, firewall, SSE or enterprise-browser sourcetypes.
- **User form.** On the NGFW tenant, almost every attributed user arrived as `DOMAIN\user` (lower-cased by this rule). Most of those do not match ES identities (`bunit` was filled on 3% of rows), so their `risk_multiplier` stays 1.0 and group approvals do not apply. UPN-form users matched. Other detections may keep the original case or a different form, so the same person can build up RBA risk under more than one risk object string. Normalise users in the TA, or list the `DOMAIN\user` form as an identity key, so that one person has one risk object. `bunit` values that are hierarchical paths do not match the simple names in `ai_department_sensitivity`, so the multiplier stayed 1.0 for every validation row.
- **No refusal, no detection.** SSE feeds that map every connection to one action (on one tenant every Netskope event had `action=isolate`) and controls that only warn or isolate are invisible to this rule. Use `hdsi_ai_unsanctioned_web_access` for usage visibility on those tenants.
- **Shared source addresses.** A user seen from several addresses gets user risk only (`src_display` = "N hosts"). An explicit proxy that reports itself as `src` collapses its users into one host-only entity unless the proxy logs the user.

### Validation
Read-only tests on 4 production ES tenants, 2026-10-09. "Daily events" is a 24-hour simulation of the scheduled 15-minute windows with the 24 h suppression applied.

| Tenant | Web data reality | Parses (search + 2 drilldowns) | v1.0 (4 h) | v1.1 (4 h auto window) | v1.1 daily events (simulated) | Notes |
|---|---|---|---|---|---|---|
| A | NGFW URL filtering (`url_domain`, no `site`) plus a little enterprise-browser audit data; AI traffic heavy, with many blocks | OK | 0 rows (all rows dropped by the `Web.site` split) | 80 to 106 rows on reruns during the day, 50 to 60 s (79 of 80 rows in the last run came from NGFW logs, 1 from the enterprise browser) | about 190 (about 55 user, 135 host-only) | 14 providers in 24 h (mostly OpenAI, Anthropic, Microsoft Copilot, QuillBot, GitHub Copilot). Scores 5 to 24, mean 13. 15-minute run about 8 s. Drilldown for one host over 4 h: 14 s |
| B | Mostly inbound load-balancer and WAF logs plus a small DNS-security proxy | OK | 0 rows | 0 rows, 9 s | 0 | Proxy blocks to AI reached at most 5 attempts per window. 453 inbound WAF "entities" removed by the public-IP guard |
| C | SSE with `site` = app name, every event `action=isolate` | OK | 0 rows (all rows dropped by the `Web.url_domain` split) | 0 rows, 2 s | 0 | No refused requests in the data. GitHub Copilot, Adobe Firefly and others are visible to `hdsi_ai_unsanctioned_web_access` |
| D | Inbound IIS only | OK | 0 rows | 0 rows, 1 s | 0 | No outbound web data. Expected silence |

No FATAL or ERROR messages on any tenant. v1.0's web drilldown ran over all Web traffic and hit the 300 s limit on two tenants. The v1.1 web drilldown filters on the entity inside `tstats` and lists allowed and blocked AI traffic side by side. It was tested end to end on Tenant A with real `entity_dd` values from the run. Two `DOMAIN\user` entities returned 113 and 2 rows (13 to 66 s over 4 h; the slow one was a service account seen on many hosts), and a host entity returned 5 rows. The same SPL with the raw `DOMAIN\user` value returned 0 rows, which is the defect `entity_dd` fixes. The risk drilldown's wildcard form was checked against existing `DOMAIN\user` risk objects in the Risk data model on Tenants A and B. All 5 sampled objects returned exactly as many risk events as their original value.

### Deployment
The package ships with `enable_alerting: false`. Before enablement:

1. Confirm that the tenant's web control blocks AI destinations and that blocks appear as `Web.action=blocked` (or a value listed in `..._blocked_actions`) with a resolvable `url_domain` or `site`.
2. Run the Threshold SPL over a full day and decide whether to keep 10/3.
3. Put guest, BYOD, NAT and VPN ranges in `..._unreliable_src`, and approved users or groups in `ai_sanctioned_entities`.
4. Run the saved search over `-20m@m` to `-5m@m` a few times and confirm that the rows and scores look right.

The rule is risk-only (no notable). Enabling it is a separately approved change.
