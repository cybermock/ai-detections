## Architect Notes
---
**Author:** Trevor Mock, Hurricane Labs LLC. Security Operations Architect

> **Incubating — not released.** This package lives in `saved_searches/incubating/` because it has only been proven with synthetic test events; none of the four validation tenants had both corporate SSO sign-ins to an AI provider and user-attributed AI traffic. Promote it to `saved_searches/packages/` only after it produces real results in a customer environment (see [`saved_searches/incubating/README.md`](../README.md)).

This rule finds **users who use an AI service through a personal account while the organisation runs a corporate tenant of the same service**. It looks for a user who reaches an AI provider (ChatGPT, Claude, Perplexity, Cursor, Mistral) repeatedly in a day, through proxy/SSE web requests or firewall App-ID sessions, but has no successful sign-in to the organisation's SSO app for that provider (for example an Okta or Entra ID SAML app for the provider's enterprise plan) in the lookback, while other users do sign in that way. Prompts and files sent through a personal account sit outside corporate retention, DLP, audit logs and offboarding. Each finding raises modest risk on the `user`. The rule creates no notable.

**Deployment type: ad hoc.** The rule needs two kinds of data in the same tenant: user-attributed AI traffic, and corporate SSO sign-ins to the provider. No validation tenant had both (see Validation), so the rule is not part of the global baseline.

v1.0 could not work anywhere:
- It needed an email address inside `Web.cookie`. The cookie field was empty in all 4 tenants. The major AI providers do not put the account email in a cookie anyway.
- It used the identity's corporate email as a regular expression (`match(cookie, corp_email)`). Dots matched any character, and a `+` in an address broke the regex.
- It grouped `tstats` by `Web.cookie`, which creates one row per session cookie.
- It required an identity email, put risk on an `unknown` user or source, and mapped the behaviour to T1078.004 (adversary use of cloud accounts).

### Prerequisites
| Data | Fields used | If absent or poor |
|---|---|---|
| `Authentication` (accelerated) | `user`, `app`, `action=success`, `sourcetype` | Corporate SSO sign-ins to the provider's IdP app (Okta, Entra ID, Google Workspace SAML). Without them no provider qualifies and the rule stays silent by design. Google Workspace OAuth grants (`gws:reports:token`) do not count: "Sign in with Google" looks the same for a personal and a corporate account |
| `Web` (accelerated) **or** `Network_Traffic` (accelerated) | Web: `user`, `src`, `url_domain`/`site`. Network_Traffic: `user`, `src`, `app` (App-ID) | User-attributed egress to the provider: proxy/SSE logs with a user, or firewall logs with User-ID. Inbound web-server or WAF logs do not count. Without this data the rule stays silent |
| ES `identity_lookup_expanded` | `identity`, `email`, `bunit` | Optional. When a user resolves, the identity email is the join key between the traffic and the SSO data, and `bunit` feeds group allow-listing and the risk multiplier. When it does not resolve, the key is the user name with any `DOMAIN\` prefix and `@domain` suffix removed |
| Common package `hdsi_ai_rba_common` | `ai_domains_filter`, `ai_unsanctioned_filter(3)`, `ai_risk_multiplier` | Provider resolution (hostnames, SSE app names, App-IDs), the allow-list and the identity multiplier |

Both halves must use user names that join. Okta and Entra ID log UPNs or email addresses. Proxies and firewalls often log `DOMAIN\sam`. If the sAMAccountName differs from the UPN local part and the ES identity lookup does not map both, nobody matches. The `..._min_matched_users` health gate then keeps the provider out instead of flagging everyone (see How it works).

### How it works
- **AI activity, user-attributed (daily, `-1d@d` to `@d`, in 1-hour buckets):**
  - `Web` (main search): `..._web_scope` prefilter (provider hostnames and SSE app names) inside `tstats`, grouped by hour, user, source, `url_domain` and `site` with `fillnull_value="unknown"`. `site` keeps SSE app names such as "ChatGPT" when `url_domain` is empty.
  - `Network_Traffic` (`append maxtime=900 maxout=50000`): `..._traffic_scope` App-ID prefilter, grouped by hour, user, source and App-ID. `..._app_id_map` folds App-ID variants (`claude-base`, `claude-post`, `claude-upload`, FortiGate `anthropic-claude`, `openai-chatgpt-uploading`, ...) onto the names the common `ai_provider_apps` lookup knows. The explicit `maxtime` matters: on the busiest tenant this branch alone takes over 2 minutes, and the default 60-second subsearch limit silently cut it short in an earlier version.
  - Both branches go through `ai_domains_filter` (`ai_input_type=app` for App-IDs and domain-less SSE names). API usage (`usage_type=api`) is dropped, because API keys are not SSO-backed. Rows without a user are excluded.
- **Corporate SSO (lookback `..._sso_lookback`, 30 days, `append maxtime=900`):** successful `Authentication` events for the apps in `..._sso_apps`, minus API-platform, Azure, MCP/connector/add-in apps and Google Workspace OAuth grants. `..._sso_provider` maps each app name to the provider string from `ai_domains_filter`.
- **Join key:** `user_key` = the identity email if the user resolves in `identity_lookup_expanded`, otherwise the user name, in both cases lower-cased and without `DOMAIN\` and `@domain`. The key only decides whether a corporate sign-in exists; activity and risk stay on the raw `user`, so two users who share a key are still reported separately.
- **Per provider:**
  - `provider_sso_users`: distinct users with a corporate sign-in. The provider qualifies only at `..._min_sso_users` (3) or more, which shows that a corporate tenant exists.
  - `provider_matched_users`: users of the provider in the day who also have a corporate sign-in. This is the identity-join health check, gated at `..._min_matched_users` (3). A tenant whose two log sources never line up gets no findings instead of a flood.
- **Decision, per user and provider:** AI activity, no corporate sign-in for that provider in the lookback, `activity_count` of at least `..._min_activity` (20), and activity in at least `..._min_active_hours` (2) distinct clock hours. `activity_count` is the larger of Web requests and App-ID sessions, not their sum, because a firewall that feeds both data models logs the same use twice.
- **Allow-list:** `ai_unsanctioned_filter(user,src,provider)` drops users, devices or groups approved for personal use in `ai_sanctioned_entities`. The identity `bunit` is looked up just before it, so `<bunit>|<provider>` group entries work. The device check uses the first source address only.
- **Scoring (dynamic, one risk object):** `risk_score = min(50, max(5, round(20 × highest provider severity_weight × risk_multiplier)))`. `risk_multiplier` comes from `ai_risk_multiplier` (identity `bunit` sensitivity, ×1.25 for privileged or critical identities). The literal `_risk` score (20) is the fallback. A typical user scores 20 a day. Repeated daily use adds up in the risk index, and the aggregators decide when that becomes a finding. No system risk is raised: the user is the subject, and `src` is context.
- **Output:** one row per user with `provider_list`, `web_requests`, `network_sessions`, `activity_count`, `active_hours`, `evidence_list`, `ai_domain_sample` (hostnames or raw App-IDs), `src_list`, `bunit`, `corporate_sso_app_list`, `sso_since` (start of the lookback, used in the risk message), `provider_sso_users`, `provider_matched_users`, `risk_multiplier`, `risk_score` and `mitre_attack` (T1588.007 AI capabilities, T1567 Exfiltration Over Web Service). Suppressed for 24 h per `user`.

### Tuning macros
| Macro | Ships as | Purpose |
|---|---|---|
| `hdsi_ai_usage_from_personal_account_oauth_mismatch_filter` | `()` | Exclusions inside the `Web` `tstats` where clause (`Web.*` names), e.g. shared kiosks or service accounts |
| `hdsi_ai_usage_from_personal_account_oauth_mismatch_traffic_filter` | `()` | The same for the `Network_Traffic` branch (`All_Traffic.*` names) |
| `hdsi_ai_usage_from_personal_account_oauth_mismatch_web_scope` | Hostnames and SSE app names of OpenAI, Anthropic, Perplexity, Cursor, Mistral | `Web` prefilter. Extend it when you map a new provider |
| `hdsi_ai_usage_from_personal_account_oauth_mismatch_traffic_scope` | App-IDs of the same providers (no generic or API App-IDs) | `Network_Traffic` prefilter |
| `hdsi_ai_usage_from_personal_account_oauth_mismatch_app_id_map` | `case()` folding App-ID variants onto `ai_provider_apps` names | Add a firewall's App-ID variant here if it is dropped by `ai_domains_filter` |
| `hdsi_ai_usage_from_personal_account_oauth_mismatch_sso_apps` | `*openai*`, `*chatgpt*`, `*anthropic*`, `*claude*`, `*perplexity*`, `*cursor*`, `*mistral*`, minus `*api*`, `*azure*`, `*mcp*`, `*connector*`, `*plugin*`, `*add-in*`, `* for google*` (and Gmail, Slack, Outlook) and `gws:reports:token` | IdP app names that represent the corporate tenant. **Pin your exact app names here** (see Limitations) |
| `hdsi_ai_usage_from_personal_account_oauth_mismatch_sso_provider` | `case()` from app name to provider | Must return the same provider string as `ai_domains_filter` (`OpenAI`, `Anthropic`, `Perplexity`, `Cursor`, `Mistral`) |
| `hdsi_ai_usage_from_personal_account_oauth_mismatch_sso_lookback` | `-30d@d` | How long a corporate sign-in counts. Keep it at least as long as the provider's longest session. The risk message reads the date from this macro |
| `hdsi_ai_usage_from_personal_account_oauth_mismatch_min_sso_users` | `3` | Corporate SSO users needed before a provider counts as having a corporate tenant |
| `hdsi_ai_usage_from_personal_account_oauth_mismatch_min_matched_users` | `3` | Identity-join health gate (see How it works) |
| `hdsi_ai_usage_from_personal_account_oauth_mismatch_min_activity` | `20` | Daily requests or sessions per user and provider, the larger of the two sources (Threshold) |
| `hdsi_ai_usage_from_personal_account_oauth_mismatch_min_active_hours` | `2` | Distinct clock hours with activity in the day. Separates repeated use from a single visit, independent of how verbose the log source is (Threshold) |
| `hdsi_ai_usage_from_personal_account_oauth_mismatch_customizations` | `search *` | Post-aggregation hook (fields listed in the macro description) |
| `hdsi_ai_usage_from_personal_account_oauth_mismatch_risk_score` | `search *` | Last pipe. Rescale or override `risk_score` |

Google Gemini and Microsoft Copilot are deliberately not mapped. Corporate Gemini use signs in through the Google Workspace login, and Copilot through the Microsoft 365 login. Neither leaves a provider-specific app sign-in, so every user of those services would look personal. Users who are allowed to keep a personal account belong in the common `ai_sanctioned_entities` lookup (`<user>|<provider>`, or `<bunit>|<provider>` for a whole business unit).

### Threshold
Run this over a normal working week. It mirrors the rule (both branches, hourly buckets, larger-of-the-two activity) and shows, per provider, whether the identity join works and how many daily findings each setting would produce. On a large firewall estate the `Network_Traffic` branch over 7 days can take 10 minutes or more; run it off-hours or shorten the window.

```spl
| tstats summariesonly=t allow_old_summaries=t fillnull_value="unknown" count from datamodel=Web
    where `hdsi_ai_usage_from_personal_account_oauth_mismatch_web_scope` NOT Web.user IN ("unknown","-","")
    earliest=-7d@d latest=@d by _time span=1h Web.user Web.url_domain Web.site
| rename Web.* as *
| eval ai_domain=lower(coalesce(nullif(url_domain,"unknown"),nullif(site,"unknown"))), ai_input_type=if(isnull(nullif(url_domain,"unknown")),"app","host"), evidence="web"
| append maxtime=1800 maxout=50000 [| tstats summariesonly=t allow_old_summaries=t count from datamodel=Network_Traffic
    where `hdsi_ai_usage_from_personal_account_oauth_mismatch_traffic_scope` NOT All_Traffic.user IN ("unknown","-","")
    earliest=-7d@d latest=@d by _time span=1h All_Traffic.user All_Traffic.app
  | rename All_Traffic.* as *
  | eval app=lower(app), ai_domain=`hdsi_ai_usage_from_personal_account_oauth_mismatch_app_id_map`, ai_input_type="app", evidence="network"]
| `ai_domains_filter`
| where usage_type!="api"
| eval day=relative_time(_time,"@d")
| stats sum(eval(if(evidence="web",count,0))) as web sum(eval(if(evidence="network",count,0))) as net dc(_time) as hours by day user provider
| eval daily=max(web,net), is_ai=1
| append maxtime=900 [| tstats summariesonly=t allow_old_summaries=t count from datamodel=Authentication
    where Authentication.action="success" `hdsi_ai_usage_from_personal_account_oauth_mismatch_sso_apps` earliest=-37d@d latest=@d
    by Authentication.user Authentication.app
  | rename Authentication.* as *
  | eval provider=`hdsi_ai_usage_from_personal_account_oauth_mismatch_sso_provider`, is_sso=1
  | where isnotnull(provider) | fields user provider is_sso]
| lookup identity_lookup_expanded identity as user OUTPUT email as id_email
| eval user_key=replace(replace(lower(coalesce(mvindex(id_email,0),user)),"^.*\\\\",""),"@.*$","")
| eventstats dc(eval(if(is_sso=1,user_key,null()))) as sso_users max(is_sso) as has_sso_any by provider
| eventstats max(is_sso) as has_sso by user_key provider
| where is_ai=1
| stats max(sso_users) as sso_users dc(day) as days dc(eval(if(has_sso=1,user_key,null()))) as matched_users
        dc(eval(if(isnull(has_sso),user_key,null()))) as no_sso_ai_users
        p50(eval(if(has_sso=1,daily,null()))) as p50_corporate_daily p50(eval(if(has_sso=1,hours,null()))) as p50_corporate_hours
        dc(eval(if(isnull(has_sso) AND daily>=20 AND hours>=2,user_key."|".day,null()))) as findings_20_2h
        dc(eval(if(isnull(has_sso) AND daily>=50 AND hours>=3,user_key."|".day,null()))) as findings_50_3h by provider
| eval per_day_20_2h=round(findings_20_2h/days,1), per_day_50_3h=round(findings_50_3h/days,1)
```

Read the result per provider:
- `sso_users` below `..._min_sso_users` means the provider has no corporate tenant in the data. The rule stays silent for it.
- `matched_users` near 0 while `sso_users` is large means the two data sources use different user formats. Fix the ES identity lookup (map the proxy/firewall name to the IdP email) before enabling the rule.
- `p50_corporate_daily` and `p50_corporate_hours` describe a normal corporate user's day. Set `..._min_activity` to about half of `p50_corporate_daily` (never below 10) and `..._min_active_hours` to 2 or 3.
- `per_day_20_2h` / `per_day_50_3h` are the daily risk events to expect at the shipped setting and at a stricter one.

### Known false positives / Limitations
- **Partial licensing is the intended finding, and it can be large.** If only some staff hold an enterprise seat, everyone else who uses the provider is reported. On the tenant with the most AI traffic (A), the Threshold search for one day gave 265 OpenAI and 106 Anthropic users at the shipped gates (101 and 84 at 50 requests over 3 hours). That tenant has no corporate tenant for either provider, so the rule is silent there; if it ran one, those users would be reported. A synthetic emulation with about a third of users given a corporate sign-in returned 304 users for the day. During a licence rollout, allow-list business units in `ai_sanctioned_entities` (`<bunit>|<provider>`) or raise `..._min_activity`.
- **Wildcard SSO app names can create false positives.** A non-tenant app that matches `..._sso_apps` makes its own users look corporate (quieter for them), but it can also lift a provider over `..._min_sso_users`, after which every other user of that provider is reportable (noisier). Validation found such apps on three tenants: Google Workspace OAuth grants for Claude and "Claude for Google Drive", Microsoft 365 MCP connector apps for Claude in Entra ID, and an OpenAI API-platform app. The shipped exclusions remove all of them, but app names vary: pin the exact names of your corporate apps.
- **Long SSO sessions.** A corporate user whose provider session outlives the lookback, or who signs in through a desktop app that refreshes tokens silently, has no recent IdP sign-in. Keep `..._sso_lookback` at least as long as the provider's maximum session lifetime, and check drilldown 4 before acting.
- **Activity counts depend on the log source.** On a per-request proxy, 20 requests is about one chat page load; on a per-session firewall it is a working day. `..._min_active_hours` is the portable gate. Activity also counts provider hostnames that need no sign-in (help, status, community and marketing pages); the hour and activity gates keep a single such visit out.
- **Join-key collisions.** The key fallback keeps only the local part of the user name, so `jsmith` in two domains share one key. A corporate sign-in by one of them then hides the other's personal use (a missed finding, not a false one). Each raw user is still scored on their own activity. Map both users to emails in the ES identity lookup if your estate has such collisions.
- **No account identity.** The rule infers a personal account from the missing corporate sign-in. It never sees the account itself: no proxy, firewall or SSE source in validation carried the AI account's email (the `Web.cookie` premise of v1.0). Netskope application events can carry the login identity (`from_user`) and app instance (`instance_id`, `sanctioned_instance`), but only for some apps. In validation they did so for Microsoft 365 Copilot only, and not for ChatGPT, Claude or Gemini. They are also not in the CIM `Web` model.
- **App-ID coverage.** Generic and API App-IDs (`openai-base`, `openai-api`, `anthropic-api-*`) are out of scope: `openai-base` alone was about 4,800 users a day on one tenant, a median of 4 sessions each, mostly background traffic. A new App-ID variant that is neither in `ai_provider_apps` nor folded by `..._app_id_map` is dropped silently; check the drilldown 3 App-IDs against the rule output after a firewall content update.
- **Shared or NAT sources** do not matter for the decision, because the subject is the user. A proxy that logs the wrong user (shared kiosk logins) should be excluded in `..._filter`.

### Validation
Read-only tests on 4 production ES tenants on 2026-10-09.

v1.1 needs both halves in one tenant. No tenant had both, so the shipped rule correctly returned 0 rows everywhere. The positive path was then checked on the tenant with the most AI traffic by replacing the SSO half with a synthetic one.

| Tenant | Corporate AI SSO users (30 d, after exclusions) | User-attributed AI users (1 d, mapped providers) | Parses (rule + 4 drilldowns) | Daily run: rows (runtime) | Notes |
|---|---|---|---|---|---|
| A | 0 (only Google Workspace OAuth grants, now excluded) | OpenAI ~3,080 (Web) and ~335 (App-ID), Anthropic ~85 (Web) and ~136 (App-ID, via `..._app_id_map`), Perplexity ~18, Cursor 2. Sources: firewall URL and App-ID logs | OK | 0 (187 s) | Silent by design: no corporate tenant. No subsearch auto-finalize message (the v1.1-draft App-ID branch was cut at 60 s). Synthetic emulation (about 31% of App-ID users given a corporate sign-in): 304 users reported, every output field populated, Claude App-ID evidence present |
| B | OpenAI ~970, Anthropic ~50 (Okta) | 0. `Web` is inbound load-balancer/WAF logs, and the small cloud proxy logs no AI traffic with a user. No App-ID user data | OK | 0 (36 s) | Silent by design: no user-attributed AI traffic. This is the tenant the rule is built for, once a forward proxy or SSE with users is onboarded |
| C | none | 0 in the window (2 Anthropic users in 7 d, below the gates) | OK | 0 (10 s) | The SSE's `Web` feed (connection events) carries Microsoft 365/GitHub Copilot app names only. Its application events are not in CIM `Web`. Firewall App-ID data has no user |
| D | OpenAI ~39, Anthropic ~11 (Entra ID; 5 MCP-connector users now excluded) | 0. `Web` is inbound IIS only | OK | 0 (11 s) | Silent by design: no user-attributed AI traffic |

- **v1.0 baseline (same day):** parses and returns 0 rows on all four tenants. `Web.cookie` held no email-bearing value in 24 h anywhere. Only one tenant had any cookie values at all (177 inbound load-balancer events). No URL carried an account email to an AI provider either. The v1.0 web drilldown scanned the whole `Web` model and ran 258 s and 302 s (time limit) on two tenants. The v1.1 drilldowns are scoped by user.
- **Account identity in SSE data:** on the SSE tenant (C), application events carried the logged-in account (`from_user`) only for Microsoft 365 Copilot (about 700 users a day, 13 with an account in a different domain). ChatGPT, Claude and Gemini events carried no account or instance. That is why v1.1 infers personal use from the missing corporate sign-in instead of reading the account.
- **Identity join:** IdP users were email/UPN on all three tenants with AI SSO apps. Proxy and firewall users were `DOMAIN\user` or email (A), bare names (B), email (C). `identity_lookup_expanded` held an email for 99% of identities on B, 49% on C and none on D, so D relies on the name fallback.
- The rule, the 4 drilldowns, both `data_prereqs` searches and the Threshold search (1-day window) ran with no FATAL or ERROR message on all four tenants. `data_prereqs` search 1 passes on B and D, search 2 on A only, which matches the table.

### Deployment
The package is configured with `enable_alerting: false` and `deployment_type: adhoc`, the type it takes once promoted to `saved_searches/packages/`. Before enablement:
1. Confirm that the tenant has a corporate SSO app for at least one mapped provider (`data_prereqs` search 1), and pin its exact name in `..._sso_apps` / `..._sso_provider`.
2. Confirm that user-attributed AI traffic exists in `Web` or `Network_Traffic` (`data_prereqs` search 2). Inbound web-server and WAF logs do not count.
3. Run the Threshold search. Confirm that `matched_users` is healthy, and set `..._min_activity` and `..._min_active_hours`.
4. Emulate a week at the daily cadence and review the users it would report. Allow-list licensed-rollout business units first if the volume is high.

The rule is risk-only (user object, no notable). Enabling it is a separately approved change.
