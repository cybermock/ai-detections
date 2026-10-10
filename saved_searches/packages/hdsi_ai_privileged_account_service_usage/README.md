## Architect Notes
---
**Author:** Trevor Mock, Hurricane Labs LLC. Security Operations Architect

This rule adds user risk when a **privileged account** uses an AI service. A privileged account is a built-in or break-glass administrator (`Administrator`, `root`, `admin`, `globaladmin`), a separate admin account (`adm-jdoe`, `jdoe_admin`, `jdoeadm`), a domain or enterprise admin, or a service account. Such accounts exist to administer systems. Chatting with ChatGPT, Claude or Gemini from one is poor credential hygiene, and it is also a common sign that an attacker is using the account. Admin context such as scripts, configs, secrets and network details can also be pasted into an external model. The rule emits at most one risk event per account per day on the `user` object, listing every AI provider seen for that account in the run that fired. It creates no notable and no system risk.

Version 1.1.0 rebuilds the rule from validation on 4 production ES tenants. The 1.0 rule read only `Web.url_domain`/`Web.site` with no `fillnull_value`, so tstats dropped every row where either field was empty. That left it blind in every tenant, including the one with the right data. It also treated job-title categories such as "administrative assistant" as privileged, and it used a `$_mult_user_risk$` token as the risk score, which ES does not support.

### Prerequisites

| Requirement | Used for | If absent |
|---|---|---|
| ES identities (`identity_lookup_expanded`) with `category` (and ideally `bunit`) | Deciding who is privileged | Only the naming-convention fallback can mark accounts as privileged |
| **At least one** of the evidence sources below, carrying the account name in `user` | Seeing AI use | The rule returns nothing |
| `Web` data model: proxy or SSE logs with `user` plus `url_domain` or `site` | Web branch | Branch is empty (inbound IIS/ELB logs never match AI names) |
| `Network_Traffic` data model: firewall App-ID in `app` and User-ID in `user` (e.g. Palo Alto `pan:traffic`) | App-ID branch | Branch is empty (port-only ASA/FortiGate logs have no AI App-IDs) |
| `Authentication` data model: IdP sign-ins with the application in `app` (Okta, Entra ID, Google Workspace token logs) | SSO branch | Branch is empty |
| `hdsi_ai_rba_common` | `ai_domains_filter`, `ai_unsanctioned_filter`, and the `ai_provider_domains`, `ai_provider_apps`, `ai_sanctioned_entities` and `ai_department_sensitivity` lookups | Search fails |

DNS (`Network_Resolution`) is deliberately not used: it identifies a host, not an account.

### How it works

- **Three branches, all keyed on the account.** Each branch is pre-filtered inside its tstats to AI names: Web (`..._web_scope`), Network_Traffic App-IDs (`..._traffic_scope`, which also matches the `-base`, `-post`, `-upload` and similar App-ID variants) and successful Authentication to AI applications (`..._sso_scope`). An App-ID is looked up in `ai_provider_apps` exactly as logged first; only when there is no exact row is a trailing `-base` removed. On Tenant A this resolves `perplexity-ai-base` and `bing-ai-base`, which the older strip-first logic turned into names with no row. Web uses `fillnull_value="unknown"`, so domain-less SSE app names in `site` still work. IdP application labels are reduced to lookup keys by `..._sso_app_name`, e.g. "ChatGPT Enterprise" becomes `chatgpt` and "OpenAI SSO" becomes `openai`.
- **Privileged accounts only (`..._privileged_users`).** The account is looked up in `identity_lookup_expanded` twice: once as logged (lowercased) and once as the bare name with `DOMAIN\` and `@domain` removed. The checks run in this order:
  0. **Computer accounts** (names ending in `$`) are dropped. Firewall User-ID can map a machine account to a host IP, and on Tenant A one `adm-<host>$` computer account otherwise matched the admin naming convention.
  1. **Built-in administrator** (`..._builtin_admin`): the bare name is `administrator`, `admin`, `root`, `globaladmin`, `superadmin`, `superuser`, `sysadmin`, `adminuser` or a similar top-level admin name. This always counts, whether or not the name is an ES identity.
  2. **ES default-list exclusion.** Any other identity that exists only in the ES built-in default account list (category `default`/`privileged` with no directory data, e.g. anonymous, guest, public, test, oracle, cisco, adm) is dropped. Those are generic device and shared names, not someone's admin account. Built-in admin names are checked first, so this exclusion never hides `Administrator` or `root`.
  3. **ES admin category** (`..._privileged_identity`): a category value equals an admin category such as `privileged`, `admin` or `domain_admin` (whole-value match). Basis `es_identity`.
  4. **ES service-account category** (`..._service_identity`): `service`, `service_account` or `service_accounts`. Basis `service_account`, sanction group `privileged_service`.
  5. **Naming convention** (`..._privileged_name`): the name follows an admin pattern. A suffix without a separator, such as `jdoeadm`, counts only when `jdoe` is itself an identity.
- **Provider resolution.** `ai_domains_filter` resolves domains, App-IDs and app names. Disabled lookup rows, including the opt-in Microsoft 365 Copilot and Gemini for Workspace rows, never alert. Registry rows with `traffic_class=background` (for example `ab.chatgpt.com`, `bzr.openai.com`, `gemini.gstatic.com` and the Copilot telemetry hosts) are dropped before counting: they are client telemetry and feature flags, not use.
- **Evidence thresholds** (per account and provider, in the 65-minute window). Web plus App-ID evidence must reach `..._min_events` (3). For suite-embedded providers (`..._ambient_providers`: Google Gemini, Microsoft Copilot, Microsoft 365 Copilot, Gemini for Workspace) it must reach `..._ambient_min_events` (25). An SSO sign-in counts on its own only for non-ambient providers: an IdP sign-in to "Microsoft Copilot" is as routine as the App-ID traffic for it.
- **Sanctioned use** (per provider, before the per-account roll-up). `ai_unsanctioned_filter(user,src,provider)` removes allowlisted rows. The rule sets the group to `privileged` (built-in admin or ES admin category), `privileged_service` (ES service account) or `privileged_naming` (naming convention), so `privileged|github copilot` in `ai_sanctioned_entities` sanctions GitHub Copilot for every admin account and `privileged_service|openai` sanctions OpenAI API use by every service account. The organisation-wide key `*|<provider>` (for example `*|github copilot`) also applies. User keys (`<account>|<provider>` or `<account>|*`) and system keys on the first source address work as usual. The common filter removes its `_allow_*` working fields itself.
- **Scoring.** The `_risk` base is a literal 30. Each surviving account and provider gets `row_score = min(60, max(15, round(30 x basis_weight x severity_weight x bunit_multiplier)))`. `basis_weight` is 1.5 for a built-in administrator and 1.0 otherwise. `severity_weight` comes from the provider row (0.3 to 1.2). `bunit_multiplier` comes from `ai_department_sensitivity` for the identity `bunit`, matched like the common `ai_risk_multiplier` (whole value, then last path segment, then first, separators `/ \ > | :`), capped at 2.0. The common `ai_risk_multiplier` itself is not used: its 1.25 privileged factor would apply to every row of this rule and count privilege twice. The rows are then rolled up to one row per account: `risk_score = min(60, highest row_score + 5 per additional provider)`. Typical score is 30 (45 for a built-in administrator), with a range of 15 to 60.
- **Schedule and suppression.** Hourly (`23 * * * *`, `-65m@m` to `-5m@m`). Suppression is on the risk object, `user`, for 24 hours, so an account adds at most 60 risk points a day from this rule. The risk event lists every provider in that run (`provider` is multivalue, `provider_list` is the joined text). A provider the account first uses later in the same day is not raised again; the App-ID and web drilldowns show the whole day.

### Tuning macros

| Macro | Ships as | Purpose |
|---|---|---|
| `hdsi_ai_privileged_account_service_usage_filter` | `()` | Inline exclusions for the Web tstats (`Web.*` names) |
| `hdsi_ai_privileged_account_service_usage_traffic_filter` | `()` | Inline exclusions for the Network_Traffic tstats (`All_Traffic.*`) |
| `hdsi_ai_privileged_account_service_usage_sso_filter` | `()` | Inline exclusions for the Authentication tstats (`Authentication.*`) |
| `hdsi_ai_privileged_account_service_usage_web_scope` | AI domains and app names (generated 2026-10-09) | Web pre-filter; regenerate when common lookups grow |
| `hdsi_ai_privileged_account_service_usage_traffic_scope` | `All_Traffic.app IN ("openai*","claude*",...)` | App-ID pre-filter; regenerate when App-ID rows are added |
| `hdsi_ai_privileged_account_service_usage_sso_scope` | `Authentication.app IN ("*chatgpt*","*openai*",...)` | IdP application pre-filter; add a word per new provider |
| `hdsi_ai_privileged_account_service_usage_sso_app_name` | eval expression | IdP label to lookup key: a distinctive provider word (chatgpt, openai, claude, anthropic, ...) anywhere in the label wins, so `<org>-chatgpt-sso` resolves; otherwise strips SSO, Enterprise, Edu, Team, ... |
| `hdsi_ai_privileged_account_service_usage_privileged_identity` | whole-value category match: privileged, admin, domain_admin, enterprise_admin, tier0, ... | Which ES categories mean an admin account. Append `OR user_priority="critical"` to include critical-priority identities |
| `hdsi_ai_privileged_account_service_usage_service_identity` | whole-value category match: service, service_account, service_accounts | Which ES categories mean a service account (basis `service_account`, group `privileged_service`); `false()` to leave service accounts out |
| `hdsi_ai_privileged_account_service_usage_builtin_admin` | `administrator`, `admin`, `root`, `globaladmin`, ... | Built-in and break-glass admin names, always privileged and scored x1.5; add tenant break-glass names, or `false()` to switch off |
| `hdsi_ai_privileged_account_service_usage_privileged_name` | admin naming regex | Naming-convention fallback; `false()` to use ES categories only |
| `hdsi_ai_privileged_account_service_usage_privileged_users` | lookup and filter pipeline | Identity matching, computer-account drop, built-in admin check and default-account exclusion |
| `hdsi_ai_privileged_account_service_usage_min_events` | `3` | Web plus App-ID events per account and provider per hour |
| `hdsi_ai_privileged_account_service_usage_ambient_providers` | `"Google Gemini","Microsoft Copilot","Microsoft 365 Copilot","Gemini for Workspace"` | Providers embedded in everyday suites: higher threshold, SSO alone does not count |
| `hdsi_ai_privileged_account_service_usage_ambient_min_events` | `25` | Threshold for ambient providers |
| `hdsi_ai_privileged_account_service_usage_customizations` | `search *` | Filter on the final one-row-per-account result (e.g. `search NOT privilege_basis="account_naming"`); exclude single providers through `ai_sanctioned_entities` instead |
| `hdsi_ai_privileged_account_service_usage_risk_score` | `search *` | Last pipe; adjust `risk_score` (integer, at most 100) |

### Threshold

Check first that the tenant marks privileged accounts at all. The first search lists the ES categories. The second shows how many identities each criterion catches, using the rule's own macros:

```spl
| inputlookup identity_lookup_expanded
| eval c=mvmap(category,lower(category))
| stats count by c priority | sort - count
```

```spl
| inputlookup identity_lookup_expanded
| eval user=mvindex(identity,0)
| `hdsi_ai_privileged_account_service_usage_privileged_users`
| stats count by privilege_basis
```

`..._min_events` and `..._ambient_min_events` are per account, per provider, **per hour**, so derive them from hourly buckets. The saved search cannot be reused for this: its threshold `where` sits before the last pipes, so anything appended there only sees rows that already passed. Run the App-ID branch on its own instead (it is where the thresholds matter; SSO always counts and the Web branch is usually small) over 24 hours to 7 days:

```spl
| tstats summariesonly=t allow_old_summaries=t count from datamodel=Network_Traffic
    where NOT All_Traffic.user IN ("unknown","-") `hdsi_ai_privileged_account_service_usage_traffic_scope`
    by _time span=1h All_Traffic.user All_Traffic.app
| rename All_Traffic.* as *
| eval app_lc=lower(trim(app))
| `hdsi_ai_privileged_account_service_usage_privileged_users`
| lookup ai_provider_apps app_name as app_lc OUTPUT app_name as app_exact
| eval ai_domain=if(isnotnull(app_exact),app_lc,replace(app_lc,"-base$","")), ai_input_type="app"
| `ai_domains_filter`
| where coalesce(ai_traffic_class,"interactive")!="background"
| stats sum(count) as hourly_events by _time user provider
| eval ambient=if(in(provider,`hdsi_ai_privileged_account_service_usage_ambient_providers`),1,0)
| stats count as account_hours dc(user) as accounts p50(hourly_events) as p50 p90(hourly_events) as p90 max(hourly_events) as max by ambient provider
```

Set `..._ambient_min_events` above the `p90` of the ambient providers and `..._min_events` below the typical `p50` of deliberate use. On Tenant A (24 h, re-run 2026-10-09 with the current logic), privileged-account Gemini App-ID hours numbered 196 across 46 accounts, with p50 1, p90 5 and max 22, so none reached 25. OpenAI hours had p50 23.5 and Anthropic hours p50 7, and all of those hours above 3 events passed.

Regenerate the inline scopes after the common lookups change:

```spl
| inputlookup ai_provider_domains | where enabled=1
| stats values(eval(lower(domain))) as d
| eval web_terms="\"*".mvjoin(d,"\",\"*")."\""
```
Paste `web_terms` into both `Web.url_domain IN (...)` and `Web.site IN (...)` of `..._web_scope`, keep the cloud patterns, and append the enabled `ai_provider_apps` names to the `Web.site` list.

```spl
| inputlookup ai_provider_apps | where enabled=1 AND NOT match(app_name,"\s")
| eval a=replace(lower(app_name),"-base$","")
| stats values(a) as a | eval traffic_terms="\"".mvjoin(a,"*\",\"")."*\""
```
Then remove terms already covered by a shorter prefix (`claude-post*` is covered by `claude*`) before pasting into `..._traffic_scope`. Add a `*word*` to `..._sso_scope` for each new provider.

### Known false positives / Limitations

- **Suite-embedded AI.** The `google-gemini` App-ID fires for nearly every Google Workspace user (about 75,000 users a day on Tenant A). Privileged accounts there showed Gemini App-ID traffic in about 200 account-hours a day across 46 to 51 accounts, almost all at 1 to 5 events per hour. The hourly ambient threshold (25) removed all of it on both measured days. "Microsoft 365 Copilot" is ambient too, which also covers the enabled Copilot Studio App-IDs (`ms-copilot-studio`): Copilot Studio use by an admin account needs 25 events in an hour to count. Remove the provider from the list if a tenant wants every Copilot Studio session scored. Add other suite-embedded providers to `..._ambient_providers`, or sanction them for everyone with `*|<provider>` or for admins with `privileged|<provider>` in `ai_sanctioned_entities`.
- **SSO to suite or sanctioned assistants.** IdP labels such as "Microsoft Copilot" resolve to an ambient provider and no longer count on their own. "GitHub Copilot Business" resolves to GitHub Copilot, which is not ambient: an admin account that signs in to a licensed GitHub Copilot through the IdP gets risk once a day until the tenant sanctions it (`privileged|github copilot` or `*|github copilot`). Labels that name only the suite, such as "Gemini for Google Workspace", "M365 Copilot" or "Copilot Studio", do not reduce to an `ai_provider_apps` key and are ignored by design; they would be ambient anyway.
- **Service accounts.** ES categories `service`/`service_account` count as privileged (basis `service_account`). Sanctioned automation that calls an AI API, such as an integration host using the `openai-api` App-ID, will fire once a day. Sanction it per account (`<account>|openai`) or for all service accounts (`privileged_service|openai`), lower its weight in `..._risk_score` (for example `eval risk_score=if(privilege_basis="service_account",round(risk_score/2),risk_score)`), or set `..._service_identity` to `false()`. On Tenant D, 1 of 24 ES-category identities is a service account only.
- **Built-in administrator names.** `admin` and `root` are sometimes also used as generic local or appliance accounts (for example, a script on a Linux server calling an AI API as `root`). Such hits are still worth a look but are not always a person. Remove names from `..._builtin_admin`, or sanction `user|provider` pairs, if a tenant has a known automation account with one of these names. No built-in administrator account showed AI App-ID traffic (24 h) or AI SSO sign-ins (7 days) on Tenants A to D.
- **Naming convention.** The fallback trusts names. Shared application admin accounts without a separator (a synthetic example: `appadmin`) are only caught when the base name (`app`) is itself an identity, or when the account has an admin ES category. Computer accounts ending in `$` are never matched. A tenant whose normal accounts end in `adm` should set `..._privileged_name` to `false()`.
- **ES identity quality.** On one tenant `category` holds job titles. Hence the whole-value match: a substring test on "admin" flagged thousands of "administrative assistant" identities. On another tenant `priority=critical` marks VIP employees, not admin accounts, so critical priority is opt-in. Most tenants mark few or no admin accounts as `privileged`, and several had none.
- **User formats.** Users are matched as logged and as a bare name. Two directories with the same short name can collide.
- **SSO coverage.** IdP logs show the sign-in, not usage volume (`mb_out` is 0 for SSO-only rows). An application label that neither contains a distinctive provider word nor reduces to an `ai_provider_apps` key is ignored (for example a label that names only the organisation); extend `..._sso_app_name` or ask for a common lookup row.
- **App-ID coverage.** After the common registry update, every AI App-ID seen on Tenant A in a 4-hour sample resolved (20 App-IDs, including `anthropic-api-base`, `perplexity-ai-base`, `bing-ai-base`, `xai-grok` and `openai-codex`). `google-workspace-duet-ai` has an opt-in row that ships disabled, so it is ignored until the tenant enables it; if it is enabled, it is treated as ambient (Gemini for Workspace).
- **Cost.** About 18-20 s per hourly run on the largest tenant (Web and App-ID volumes in the hundreds of millions of events per hour). A 4-hour window took 55-66 s on Tenants A and B, and a 24-hour single run took 252 s (A) and 292 s (B), so run backfills in chunks of a few hours.

### Validation

Read-only live runs on 2026-10-09 across 4 production ES tenants. The saved search and all four drilldowns parsed in all four tenants, and the final real run (4 h window) finished without FATAL or ERROR in each. "Identities" counts entries of `identity_lookup_expanded` by `privilege_basis` using the rule's own macros. "Hourly production" replays the App-ID branch hour by hour over 24 h with the current thresholds and counts the accounts that would get a risk event under the per-account daily suppression. Earlier 24 h single runs of the previous revision are kept for context. All counts vary from day to day.

| Tenant | Identities (builtin / ES admin / ES service / naming) | Data present for the rule | 1.0 rule (4 h) | 1.1 rule (4 h, final) | Hourly production (24 h) | Notes |
|---|---|---|---|---|---|---|
| A | 6 / 301 / 0 / 9; 50 more ES-category matches are default-list names and excluded; categories mix job titles | Web (user set, few AI domains), App-ID + User-ID (strong), Google token logs | 0 rows | 0 rows, 60 s | 2 accounts (3 account-provider pairs: Anthropic, OpenAI; Gemini 0 of 196 account-hours) | One `adm-<host>$` computer account is now excluded from the naming count. An earlier 24 h single run gave 9 rows for 8 accounts in 252 s |
| B | 5 / 0 / 0 / 88; critical priority = VIPs | Okta SSO to ChatGPT Enterprise, OpenAI and Claude Enterprise (several hundred users a week); Web mostly inbound | 0 rows | 0 rows, 52 s | 0 (no App-ID data) | SSO branch resolves all three apps; no privileged account signed in during 7 days |
| C | 5 / 0 / 0 / 19 | SSE web with app names in `site`; App-ID on one user | 0 rows (tstats dropped null `url_domain`) | 0 rows, 7 s | 0 | Branches return data; no privileged account matched |
| D | 0 / 23 / 1 / 0 | Entra ID sign-ins to an Anthropic app and to a hyphenated custom ChatGPT SSO app | 0 rows | 0 rows, 8 s | 0 | Custom ChatGPT label resolves via the provider-word rule; none of these users is a privileged identity |

Synthetic checks (makeresults through the rule's own tail, all tenants): a built-in administrator with ChatGPT (30 events), Claude (5) and background `ab.chatgpt.com` traffic (50) produced one row with providers Anthropic and OpenAI, request_count 35 (background dropped) and risk_score 50 (45 + 5). A Gemini SSO sign-in and 10 Gemini web events were dropped as ambient, while an "OpenAI SSO" sign-in counted on its own. IdP labels: "ChatGPT Enterprise", "Claude for Work", "OpenAI SSO", "Acme-chatgpt-sso", "GitHub Copilot Business" and "Kaggle" resolve; "Microsoft Copilot" resolves as ambient; "Gemini for Google Workspace", "M365 Copilot" and "Copilot Studio" do not resolve.

### Deployment

The package ships with `enable_alerting: false`. Before enablement, the architect should:

1. Confirm that the tenant's ES identities or naming convention actually identify privileged accounts (Threshold section).
2. Confirm that at least one evidence source carries the account name.
3. Run the search over a few hours at a time (see Cost) for 7 days and review the providers and accounts it returns.
4. Sanction approved combinations in `ai_sanctioned_entities` (`privileged|<provider>`, `privileged_service|<provider>`, `*|<provider>` or per account).

The rule is risk-only. Enabling it must be one separately approved change.
