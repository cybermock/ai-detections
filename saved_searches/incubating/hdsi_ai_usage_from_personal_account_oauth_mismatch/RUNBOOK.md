# AI-026 - AI Usage From Personal Account / OAuth Mismatch

> **Incubating — not released.** This package lives in `saved_searches/incubating/` because it has only been proven with synthetic test events; none of the four validation tenants had both corporate SSO sign-ins to an AI provider and user-attributed AI traffic. Promote it to `saved_searches/packages/` only after it produces real results in a customer environment (see [`saved_searches/incubating/README.md`](../README.md)).

> **DEPLOYMENT TYPE: AD HOC.** This package (`deployment_type: adhoc`) is **not** part of the global baseline. It only works in a tenant that has **both** a corporate SSO app for an AI provider (in `Authentication`) **and** user-attributed AI traffic (in `Web` or `Network_Traffic`). None of the 4 validation tenants had both, so it returned 0 rows everywhere by design. Deploy it per tenant after the checks in "Data Requirements".

> **Detection ID:** AI-026
> **Package:** `hdsi_ai_usage_from_personal_account_oauth_mismatch` v1.1.0 (`deployment_type: adhoc`, `enable_alerting: false`)
> **Search name:** `Identity - HDSI AI Usage From Personal Account / OAuth Mismatch - Rule`
> **Status:** Incubating (not released); ad hoc once promoted. Risk-only (`action.notable = 0`). Notables come from the HDSI RBA AI aggregators
> **Risk object:** `user` only (raw user as logged by the proxy/firewall). No system risk
> **Risk score:** dynamic, `min(50, max(5, round(20 x highest provider severity_weight x risk_multiplier)))`. Typical user: 20. Literal fallback 20
> **MITRE ATT&CK:** T1588.007 Obtain Capabilities: Artificial Intelligence (Resource Development); T1567 Exfiltration Over Web Service (Exfiltration)
> **Data Model:** `Authentication` (corporate SSO) plus `Web` and/or `Network_Traffic` (App-ID)
> **Schedule:** `25 1 * * *` (daily at 01:25)
> **Lookback Window:** `-1d@d` to `@d` for AI activity; `-30d@d` to now for SSO sign-ins (`..._sso_lookback`)
> **Suppression:** 24 hours per `user` (`86400s`)
> **Kill Chain Phase:** `exfiltration`
> **Last Updated:** 2026-10-09

---

## Overview

This detection finds **users who use an AI service through a personal account while the organisation runs a corporate tenant of the same service**. A user who reaches OpenAI (ChatGPT), Anthropic (Claude), Perplexity, Cursor or Mistral repeatedly in a day, through proxy/SSE requests or firewall App-ID sessions, but has no successful sign-in to the organisation's SSO app for that provider (an Okta, Entra ID or Google Workspace SAML app for the enterprise plan) in the last 30 days, while other users do, is most likely using a personal account. Prompts and files sent that way are outside corporate retention, DLP, audit logging and offboarding.

The rule infers the personal account from the **missing corporate sign-in**. It never sees the account itself: no proxy, firewall or SSE source in validation carried the AI account's email. (v1.0 read an email from `Web.cookie`; that field was empty in all 4 tenants and the providers do not put the account email in a cookie.)

Each finding raises modest risk (typically 20) on the user. Repeated daily use accumulates in the risk index and the aggregators decide when it becomes a notable.

---

## MITRE ATT&CK Mapping

| Field | Value |
|---|---|
| Technique ID | T1588.007, T1567 |
| Technique Name | Obtain Capabilities: Artificial Intelligence; Exfiltration Over Web Service |
| Tactic | Resource Development, Exfiltration |
| Sub-technique | T1588.007 (Artificial Intelligence) |

The v1.0 mapping (T1078.004 Valid Accounts: Cloud Accounts) described adversary use of cloud accounts and was replaced. The annotation is `{"mitre_attack": ["T1588.007", "T1567"]}`.

---

## Detection Logic

### Plain English

1. **AI activity, user-attributed.** `Web` (pre-filtered by `..._web_scope`: provider hostnames in `url_domain`/`site` and SSE app names in `site`) and an appended `Network_Traffic` branch (`..._traffic_scope` App-IDs, folded by `..._app_id_map` onto the names in `ai_provider_apps`) are counted in 1-hour buckets per user. `site` is used when `url_domain` is empty. Rows without a user are dropped.
2. `ai_domains_filter` resolves the provider. API usage (`usage_type=api`) is dropped, because API keys are not SSO-backed.
3. **Corporate SSO.** An appended `Authentication` search lists successful sign-ins in the last 30 days to the apps in `..._sso_apps` (API-platform, Azure, MCP/connector/add-in apps and Google Workspace OAuth grants are excluded) and maps each app to a provider with `..._sso_provider`.
4. **Join key.** `user_key` = the identity email if the user resolves in `identity_lookup_expanded`, else the user name, lowercased without `DOMAIN\` and `@domain`. The key only decides whether a corporate sign-in exists; activity and risk stay on the raw `user`.
5. **Provider health gates.** A provider qualifies only with at least `..._min_sso_users` (3) users who sign in through the corporate app, and at least `..._min_matched_users` (3) users seen in the traffic who also have a corporate sign-in (proof that the two log sources' user names join).
6. **Decision per user and provider:** AI activity, no corporate sign-in for that provider in the lookback, `activity_count` >= `..._min_activity` (20, the larger of Web requests and App-ID sessions), in at least `..._min_active_hours` (2) distinct clock hours.
7. Approved users, devices or groups are removed with `ai_unsanctioned_filter(user,src,provider)` (the identity `bunit` is looked up first so group entries work).
8. **Scoring:** `20 x highest provider severity_weight x risk_multiplier`, minimum 5, capped at 50.

### Key Fields

| Field | Description | Example Value |
|---|---|---|
| `user` | Raw user from the proxy/firewall (risk object) | `CORP\jsmith` |
| `user_key` | Join key (identity email local part or bare name) | `jsmith` |
| `provider_list` | Provider(s) used without a corporate sign-in | `OpenAI` |
| `web_requests` / `network_sessions` / `activity_count` | Activity in the day; `activity_count` is the larger of the two | `0` / `46` / `46` |
| `active_hours` | Distinct clock hours with activity | `5` |
| `ai_domain_sample` | Up to 5 hostnames or raw App-IDs | `chatgpt.com, openai-chatgpt` |
| `corporate_sso_app_list` | The corporate IdP app(s) for the provider | `ChatGPT Enterprise` |
| `sso_since` | Start of the SSO lookback | `2026-09-09` |
| `provider_sso_users` / `provider_matched_users` | Provider health gates | `25` / `18` |
| `src_list`, `bunit` | Context | `192.0.2.40`, `finance` |
| `risk_multiplier`, `risk_score` | Score inputs and result | `1.0`, `20` |

### Thresholds

| Parameter | Default | Macro | Notes |
|---|---|---|---|
| Corporate SSO users per provider | 3 | `..._min_sso_users` | Below it, a pilot or test sign-in would make everyone else look personal |
| Matched users per provider | 3 | `..._min_matched_users` | Identity-join health check |
| Daily activity per user and provider | 20 | `..._min_activity` | Larger of Web requests and App-ID sessions |
| Distinct active clock hours | 2 | `..._min_active_hours` | The portable gate between one visit and repeated use |
| SSO lookback | `-30d@d` | `..._sso_lookback` | Keep it at least as long as the provider's longest session |

(Macro names are prefixed `hdsi_ai_usage_from_personal_account_oauth_mismatch`.)

---

## Triage Steps

> **Estimated triage time:** 10-15 minutes

Replace `$user$` with the risk object and `$user_key$` with the `user_key` field. For a `DOMAIN\user` risk object, match on the bare name (`risk_object="*jsmith"`) if the quoted backslash form returns nothing.

### Step 1: Validate the risk event

```spl
| from datamodel:"Risk.All_Risk"
| search source="Identity - HDSI AI Usage From Personal Account / OAuth Mismatch - Rule" risk_object="$user$"
| table _time, risk_object, risk_object_type, risk_score, risk_message
| sort - _time
```

- Note the provider, the corporate SSO app named in the message and `sso_since`.
- One event per day is the maximum (24-hour suppression). Several consecutive days mean sustained personal use.

### Step 2: Confirm the AI activity

Web (drilldown 2):

```spl
| tstats summariesonly=t allow_old_summaries=t fillnull_value="unknown" count sum(Web.bytes_out) as bytes_out min(_time) as firstTime max(_time) as lastTime values(Web.http_user_agent) as http_user_agent
    from datamodel=Web
    where Web.user="$user$" `hdsi_ai_usage_from_personal_account_oauth_mismatch_web_scope`
    by Web.user Web.src Web.url_domain Web.site
| rename Web.* as *
| eval url_domain=if(url_domain="unknown",site,url_domain)
| convert ctime(firstTime) ctime(lastTime)
| table firstTime, lastTime, user, src, url_domain, count, bytes_out, http_user_agent
| sort - count
```

Firewall App-ID (drilldown 3):

```spl
| tstats summariesonly=t allow_old_summaries=t count sum(All_Traffic.bytes_out) as bytes_out min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest) as dest
    from datamodel=Network_Traffic
    where All_Traffic.user="$user$" `hdsi_ai_usage_from_personal_account_oauth_mismatch_traffic_scope`
    by All_Traffic.user All_Traffic.src All_Traffic.app All_Traffic.action
| rename All_Traffic.* as *
| convert ctime(firstTime) ctime(lastTime)
| table firstTime, lastTime, user, src, app, action, count, bytes_out, dest
| sort - count
```

- Is the activity interactive use of the chat or IDE service (chat hosts, upload App-IDs), or only help, status, community or marketing pages?
- Upload bytes (`bytes_out`, `openai-chatgpt-uploading`, `claude-upload`) raise the concern.

### Step 3: Look for a corporate sign-in under a different name

Drilldown 4 searches the corporate SSO apps for any user name resembling the key:

```spl
| tstats summariesonly=t allow_old_summaries=t count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Authentication
    where `hdsi_ai_usage_from_personal_account_oauth_mismatch_sso_apps` Authentication.user="*$user_key$*"
      earliest=`hdsi_ai_usage_from_personal_account_oauth_mismatch_sso_lookback` latest=now
    by Authentication.user Authentication.app Authentication.action
| rename Authentication.* as *
| convert ctime(firstTime) ctime(lastTime)
| table user, app, action, count, firstTime, lastTime
| sort - lastTime
```

- A successful sign-in under another form (e.g. `john.smith@` against `jsmith`) means the identity join failed for this user: a **false positive**. Map both names in the ES identity lookup.
- Only failed sign-ins, or a sign-in just before `sso_since`, may mean a long-lived session or a desktop app refreshing tokens. Check with the user before acting.

### Step 4: Identify the user

```spl
| inputlookup identity_lookup_expanded
| search identity="$user_key$" OR email="$user_key$@*"
| table identity, first, last, email, bunit, category, priority, managedBy
```

- Does the user hold a licence for the corporate tenant (check with the licence owner)? If seats were only partly rolled out, the user may have no corporate option yet.

### Step 5: Check related AI risk and sanctioned status

```spl
| from datamodel:"Risk.All_Risk"
| search risk_object="$user$" source="*HDSI AI*"
| stats count as events, sum(risk_score) as total_risk, dc(source) as detections, values(source) as sources by risk_object
```

```spl
| inputlookup ai_sanctioned_entities
| search enabled=1 (entity="$user$" OR entity="$user_key$" OR entity="*")
| table entity_type, entity, provider, scope, expires, owner, reason, allow_key
```

- Upload, DLP or personal-email detections for the same user make a personal-account finding much more serious.
- Users or business units allowed to keep a personal account belong in `ai_sanctioned_entities` (`<user>|<provider>` or `<bunit>|<provider>`).

### Step 6: Make a determination

- **True Positive:** the user repeatedly uses the provider's chat/IDE service and has no corporate sign-in under any name: a personal account outside corporate controls.
- **Benign True Positive:** personal use is allowed for this user or unit, or the user has no seat yet during a rollout. Approve with an expiry.
- **False Positive:** a corporate sign-in exists under another name (identity join), the session outlived the lookback, or the "activity" is non-chat pages (help, status, docs).

---

## True Positive Indicators

- Multiple active hours on several days, on chat or upload hosts/App-IDs.
- `bytes_out` or upload App-IDs present (files or long prompts sent).
- No corporate sign-in under any form of the user's name in the lookback (Step 3 empty).
- The user holds a corporate seat but still uses a personal account (bypassing retention and DLP deliberately).
- Co-occurring upload, DLP or personal-email AI detections.

---

## False Positive Scenarios

Evidence from read-only validation on 4 production ES tenants (Tenant A-D), 2026-10-09.

| Scenario | Likelihood | Mitigation |
|---|---|---|
| Partial licensing: everyone without a seat is reported (on Tenant A, the threshold search gave 265 OpenAI and 106 Anthropic users a day at the shipped gates; a synthetic emulation with about a third of users given a corporate sign-in returned 304 users) | High during a rollout | Intended finding. Allow-list business units (`<bunit>|<provider>`) during the rollout or raise `..._min_activity` |
| Non-tenant app matching the `..._sso_apps` wildcards (seen on three tenants: Google Workspace OAuth grants for Claude and "Claude for Google Drive", Entra ID MCP connector apps, an OpenAI API-platform app) | Low after v1.1 (all excluded) | Pin the exact corporate app names in `..._sso_apps` / `..._sso_provider` |
| User name formats that do not join (IdP UPN vs proxy `DOMAIN\sam`) | Medium | The `..._min_matched_users` gate stops a total failure; map individual mismatches in the ES identity lookup |
| Long provider sessions or desktop apps with silent token refresh | Medium | Keep `..._sso_lookback` at least as long as the provider's session lifetime; check Step 3 |
| Visits to help, status, community or marketing pages | Low | The 20-activity and 2-hour gates keep single visits out |
| Join-key collision (`jsmith` in two domains) | Low | Causes a missed finding, not a false one; map both users in the identity lookup |

---

## Response Actions

### If confirmed True Positive

1. **Contain:** if the organisation's policy forbids personal AI accounts, block the provider's consumer sign-in for the user (SSE tenant restriction or instance control where the product supports it), leaving the corporate tenant reachable.
2. **Notify:** the user and their manager; remind them of the corporate tenant and the AI acceptable use policy.
3. **Investigate:** check what was sent (SSE/DLP content logs where available) and whether co-occurring upload or DLP detections exist.
4. **Remediate:** ask the user to move work content to the corporate tenant and to delete work conversations from the personal account. Issue a seat if the user lacks one.
5. **Document:** record provider, duration, evidence and disposition.

### If Benign True Positive

1. Add `<user>|<provider>` or `<bunit>|<provider>` to `ai_sanctioned_entities` with an expiry and reason.
2. Close the aggregator notable (if any) as benign.

---

## Tuning Guidance

### Reducing false positives

- **Pin the corporate app names** in `hdsi_ai_usage_from_personal_account_oauth_mismatch_sso_apps` and map them in `..._sso_provider`. The shipped wildcards are a starting point only.
- Exclude shared kiosks, jump hosts and service accounts in `..._filter` (`Web.*`) and `..._traffic_filter` (`All_Traffic.*`).
- Add a firewall's new App-ID variant to `..._app_id_map` if `ai_domains_filter` drops it, and to `..._traffic_scope`.
- Google Gemini and Microsoft Copilot are deliberately not mapped: their corporate use signs in through the Google Workspace or Microsoft 365 login, so every user would look personal.

### Adjusting thresholds

Run the README Threshold search (both branches, hourly buckets, one week). Per provider it returns `sso_users`, `matched_users`, `p50_corporate_daily`, `p50_corporate_hours` and the expected daily findings at two settings (`per_day_20_2h`, `per_day_50_3h`):

- `matched_users` near 0 with a large `sso_users`: the identity join is broken; fix the ES identity lookup before enabling.
- Set `..._min_activity` to about half of `p50_corporate_daily` (never below 10) and `..._min_active_hours` to 2 or 3.

A quick check that a corporate tenant exists for each provider (the first `data_prereqs` search):

```spl
| tstats summariesonly=t count dc(Authentication.user) as sso_users
    from datamodel=Authentication
    where Authentication.action=success `hdsi_ai_usage_from_personal_account_oauth_mismatch_sso_apps` earliest=-30d@d
    by Authentication.app
| eval app_lc=lower('Authentication.app')
| eval provider=case(match(app_lc,"openai|chatgpt"),"OpenAI", match(app_lc,"anthropic|claude"),"Anthropic", match(app_lc,"perplexity"),"Perplexity", match(app_lc,"cursor"),"Cursor", match(app_lc,"mistral"),"Mistral")
| table provider, Authentication.app, sso_users, count
```

---

## Related Detections

| Detection ID | Name | Relationship |
|---|---|---|
| AI-RISK-005 | Threat - HDSI RBA AI Multi-Vector Risk - Rule | Counts this rule in the `risky_access` vector |
| AI-RISK-001 / AI-RISK-002 | Threat - HDSI RBA AI User Risk Threshold Exceeded - Rule / ... User Critical Risk Threshold Exceeded - Rule | User risk aggregators (60 / 90 rolling 24 h) |
| AI-027 | Network - HDSI AI Personal Email To AI Service Upload Correlation - Rule | Another personal-channel data path |
| AI-016 | Identity - HDSI AI Privileged Account Service Usage - Rule | Shares the Authentication SSO dependency |
| AI-028 | Network - HDSI AI Unsanctioned Web Access - Rule | Base AI web access; often co-fires |

---

## Data Requirements

| Requirement | Details |
|---|---|
| Data Model | `Authentication` (required) plus `Web` or `Network_Traffic` (at least one, user-attributed egress) |
| Required Fields | Authentication: `user`, `app`, `action=success`, `sourcetype`. Web: `user`, `src`, `url_domain` or `site`. Network_Traffic: `user`, `src`, `app` (App-ID) |
| Sourcetype Examples | Okta, Entra ID sign-in logs, Google Workspace SAML (not `gws:reports:token`); forward proxy/SSE with users; PAN-OS/FortiGate traffic with User-ID |
| CIM Compliance | Both halves must use user names that join (identity email, or the bare name). Inbound web-server/WAF logs do not count |
| Acceleration | Required for all three data models (`summariesonly=t`) |
| Lookups | Common package `hdsi_ai_rba_common` (`ai_domains_filter`, `ai_unsanctioned_filter(3)`, `ai_risk_multiplier`); ES `identity_lookup_expanded` (`email`, `bunit`, optional) |

**Ad hoc deployment checklist:** (1) `data_prereqs` search 1 passes (corporate SSO app for a mapped provider) and its exact name is pinned; (2) `data_prereqs` search 2 passes (user-attributed AI traffic); (3) the Threshold search shows healthy `matched_users`; (4) a week at the daily cadence has been emulated and reviewed.

Validation (2026-10-09, 4 production ES tenants): the rule and its 4 drilldowns parse on all tenants with no errors. Daily run: 0 rows on A-D (A 187 s, B 36 s, C 10 s, D 11 s). Tenant A has AI traffic but no corporate tenant; Tenants B and D have corporate SSO apps but no user-attributed AI egress; Tenant C has neither for the mapped providers.

---

## Revision History

| Date | Author | Change |
|---|---|---|
| 2026-02-22 | Brainstorm SOC | Initial production runbook |
| 2026-10-09 | Trevor Mock, Hurricane Labs | 1.1.0: rewritten for v1.1.0 (ad hoc). New search name, daily cadence, logic replaced: missing corporate SSO sign-in instead of `Web.cookie` email; Web plus App-ID evidence; provider health gates; user-only dynamic risk (cap 50); MITRE T1588.007/T1567; Risk data model triage SPL; live-validation evidence |
| 2026-10-10 | Trevor Mock, Hurricane Labs LLC | Moved to `saved_searches/incubating/` (not released): only proven with synthetic test events; no validation tenant had the data. Was `docs/runbooks/AI-026.md` |
