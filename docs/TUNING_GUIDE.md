# Tuning Guide

**Author:** Trevor Mock, Hurricane Labs LLC. Security Operations Architect

This guide covers tuning the HDSI AI RBA packages for one tenant: what to do before enabling anything, how to approve sanctioned AI use, how to keep the provider registry accurate, how to set per-detection thresholds, and how to tell whether a detection is noisy. It applies to the released package layout under `saved_searches/packages/`. Every SPL block uses the shipped stanza names and macros and was run read-only against 4 production ES tenants (Splunk Cloud 10.4-10.5, ES 8.5-8.7), called Tenant A-D here, on 2026-10-09 and 2026-10-10.

Each package README is the detailed reference for its own logic, threshold SPL and validation results. This guide covers the decisions that span packages.

---

## 1. How tuning works in this content

**Detections write risk only.** Every `hdsi_ai_*` detection ships with `action.risk = 1` and `action.notable = 0`. Notables come from five aggregators (`hdsi_rba_ai_*`). The two user-risk band rules read their thresholds from `ai_detection_config`. The health checks (`hdsi_ai_health_*`) raise audit notables and write no risk. Every package ships with `enable_alerting: false`.

Tuning a detection therefore means controlling how much risk it writes and to which objects. Notable volume is tuned in the aggregators.

**Where each kind of change lives.** Never edit the `search =` line of a shipped saved search. Every change goes into one of the places below.

| What you change | Where | Scope |
|---|---|---|
| Approved AI use (who may use which provider) | `ai_sanctioned_entities` lookup (common package) | Every detection that calls `ai_unsanctioned_filter` |
| What counts as an AI provider, host or app name | `ai_provider_domains`, `ai_provider_apps` lookups (common) | Every Web, DNS and App-ID detection |
| Which AI tools are recognised by process name | `ai_tool_processes` lookup (common) | Process-based detections that call `ai_process_filter` / `ai_process_enrich` |
| How much a business unit's risk is scaled | `ai_department_sensitivity` lookup (common) | Every detection that calls `ai_risk_multiplier` |
| Aggregator notable bands | `ai_detection_config` rows `medium_risk_threshold`, `high_risk_threshold` (common) | The two user-risk band aggregators |
| Exclusions read before aggregation | `<package>_filter` macro | One package |
| Row-level post-processing | `<package>_customizations` macro | One package |
| Score override | `<package>_risk_score` macro | One package |
| Thresholds, provider lists, guards | Named macros such as `<package>_min_events` | One package |

**Hook macro rules.** Each detection package ships three hooks:

- `<package>_filter` ships as `()`. It sits **inline in the first `tstats` `where` clause** (or the raw base search), so it takes data model field names: `Web.user`, `DNS.src`, `All_Traffic.app`, `Processes.process_name`, or `sourcetype`. Never write it as a piped command. `| ()` is a fatal parse error, and that mistake once broke every search in the pack.
- `<package>_customizations` ships as `search *`. It is piped after the rule's normalisation, so it sees the result field names (`user`, `src`, `provider`, `ai_domain`).
- `<package>_risk_score` ships as `search *` and is the last pipe. Use it to set a numeric field named `risk_score` (1-100). That value overrides the score of **every** risk object in the row, user and system alike.

Aggregators, health checks and the hunting search Unknown High-Volume External API Discovery (which writes no risk) have `_filter` and `_customizations` but no `_risk_score`.

**Making a change in Splunk Cloud.** The packages install into the app context `HurricaneLabsContentUpdates`. You can edit macros under Settings > Advanced search > Search macros. Lookups are CSV files in the same app. Edit them with a lookup editor (for example the Splunk App for Lookup File Editing), or upload a replacement file under Settings > Lookups > Lookup table files. Treat every lookup or macro change as a detection change: review it, record it, and deploy it as a separately approved change.

> [!IMPORTANT]
> `saved_searches/deploy.py` compiles `confs/*.conf` (including `transforms.conf`) and views. It does not carry the CSV files under `lookups/`. Install the common package's ten CSVs separately, and **keep the tenant's own copies of `ai_sanctioned_entities`, `ai_department_sensitivity`, `ai_provider_apps` and `ai_provider_domains`**. The repository copies ship with disabled example rows and generic keys. Uploading them over a tuned tenant file erases the tenant's approvals and mappings. A `| lookup` on a lookup with no CSV is a fatal search error, so a missing file breaks every dependent detection at once.

**Record what you changed.** This read-only search lists the numeric and placeholder tuning macros that are currently deployed, with their app and last update time. Run it before and after every package update and compare the output with your change record:

```spl
| rest /servicesNS/-/-/admin/macros count=0 splunk_server=local
| search title="hdsi_ai_*" OR title="hdsi_rba_ai_*"
| where match(definition, "^\s*(-?[0-9.]+|\"__none__\"|null\(\)|false\(\)|-\d+[dhm](@[dhm])?)\s*$")
| table title definition eai:acl.app eai:acl.sharing updated
| sort title
```

To test a macro change without deploying it, edit the macro in a working copy of the repository and render the package with `python3 saved_searches/tools/render_live_spl.py <package> [--drilldowns]`. The output is self-contained SPL with the repository macros expanded and the repository lookups inlined. Paste it into the search bar to see what the change would do. The rendered search uses the repository copies of the lookups, so it does not reflect tenant lookup edits. Test those with the deployed search instead.

---

## 2. Per-tenant tuning workflow

Work through these phases in order. Most noise problems found in validation came from the data (inbound server logs in the Web model, shared or roaming source addresses, SSE app names, sanctioned enterprise AI), not from thresholds.

### Phase 0: Profile the tenant's data (before deploying)

Run the three profiles in [section 6.1](#61-tenant-data-profile): the Web host shape, the Web direction, and the AI evidence by source. Use them to decide:

- **Which packages have a data path at all.** Check each package's `data_prereqs` in `package.yml`. The CIM DLP model (`DLP`, dataset `DLP_Incidents`) had no data in any validation tenant. Email existed in three tenants.
- **Whether the Web model is user egress.** In Tenant B the Web model was almost entirely inbound load-balancer and WAF logs (77% public source addresses, no user), and in Tenant D it was inbound IIS only. Web rules do not treat these as user activity, but they add search cost. Exclude such sourcetypes in the Web packages' `_filter` macros, for example `(NOT sourcetype IN ("aws:elb:accesslogs","aws:waf"))`.
- **Which DNS feed you have.** On-premises resolvers and sensors log the real client. Roaming DNS-security clients log home-router addresses that different laptops share, so turn on the `_unreliable_src` guards (see [section 5](#5-detection-thresholds-and-named-macros)). Some feeds log names with a trailing root dot (`chatgpt.com.`). The common resolver strips it, and the shipped `tstats` prefilters carry both forms.
- **Which `adhoc` packages to skip.** Three packages ship with `deployment_type: adhoc` because their data path or setup is rare: After Hours Service Usage, Copy-Paste Correlation To AI Service, and Unknown High-Volume External API Discovery. Each README states the exact data requirement. Four more detections are not released at all: Access From Unmanaged Device, Browser Extension High-Volume Data Transmission, DLP Violation On Service Upload, and Usage From Personal Account / OAuth Mismatch sit in `saved_searches/incubating/` until a customer environment proves them on real data. Their tuning rows below are kept for that day.

### Phase 1: Set up the common package

1. Map the tenant's ES identity `bunit` values in `ai_department_sensitivity` ([section 4](#4-business-unit-sensitivity)).
2. Load sanctioned AI use into `ai_sanctioned_entities`: organisation-wide licences first, then groups, then API integration servers ([section 3](#3-allowlisting-approved-ai-use)).
3. Add the proxy's and firewall's AI application names to `ai_provider_apps` ([section 6.3](#63-find-ai-app-names-and-app-ids-the-registry-does-not-know)).
4. Decide on the opt-in rows: Microsoft 365 Copilot and Gemini for Workspace ([section 3.6](#36-opt-in-rows-microsoft-365-copilot-and-gemini-for-workspace)).

### Phase 2: Set mandatory per-package values

A few packages need a tenant value before they produce anything useful:

- `hdsi_ai_after_hours_service_usage_utc_offset` ships as `null()`, and the rule emits nothing until it is set. Set the standard (winter) UTC offset of business hours, such as `-5`, and set `..._dst_rule` to `"us"`, `"eu"` or `"none"`.
- Roaming DNS-security tenants: set the `_unreliable_src` macros on Code Assistant Network Connection and API Access From Non-Dev Endpoint (both ship as `false()`). DNS Queries To AI Domains and Multiple Services In Single Session ship with the guard on.
- Baseline rules need accelerated history. First Seen Provider needs 31 days of Web/Network_Traffic summaries, Usage Volume Anomaly and Time-of-Day need 15 days, and New Provider Adoption Velocity needs 21 days. One validation tenant accelerated Web and Network_Traffic for only 7 days, so New Provider Adoption Velocity stayed silent there by design.

### Phase 3: Enable detections (risk only) and observe

Enable the detections whose data path exists. They write risk and raise no notables, so the SOC queue does not change. Leave the five aggregators disabled. After a few days, run the noise review in [section 7](#7-judging-noise). Fix problems in this order:

1. Data problems: inbound logs, shared or placeholder sources, the wrong DNS feed.
2. Approved use: allowlist or provider exclusion.
3. Registry errors: a host that is not AI, or a background host.
4. Thresholds.
5. Scores.

### Phase 4: Calibrate and enable the aggregators

After at least two weeks of AI risk, run the threshold SPL in the `hdsi_rba_ai_user_risk_threshold_exceeded` README to set `medium_risk_threshold` and `high_risk_threshold` in `ai_detection_config`. Agree the expected daily notable count with the SOC. Then enable the medium and critical band rules together, with identical `_filter`, `_user_key` and `_excluded_accounts` macros. Enable Multi-Vector Risk, Data Collection Kill Chain and Privilege Escalation Correlation after that.

### Phase 5: Maintain

- Keep `hdsi_ai_health_lookup_staleness_alert` and `hdsi_ai_health_data_model_availability` enabled. They report missing lookups, stale registry rows, allowlist entries about to expire, and data models that stopped or degraded.
- Review `ai_sanctioned_entities` expiries monthly ([section 3.7](#37-check-the-allowlist)).
- Re-run the app-name discovery searches ([section 6.3](#63-find-ai-app-names-and-app-ids-the-registry-does-not-know)) quarterly and after proxy or firewall upgrades, because vendors rename App-IDs and SSE app labels.
- After every package update, re-run the deployed-macro listing in section 1 and re-apply any tenant overrides that the update replaced.

---

## 3. Allowlisting approved AI use

### 3.1 How `ai_unsanctioned_filter` matches

Most detections call `` `ai_unsanctioned_filter(<user_field>,<system_field>,<provider_field>)` `` before scoring. For every row it builds these candidate keys and looks each one up in `ai_sanctioned_entities.allow_key`:

| Key | Built from |
|---|---|
| `lower(<user>)\|lower(<provider>)` and `lower(<user>)\|*` | the user field, exactly as the detection holds it |
| `lower(<system>)\|lower(<provider>)` and `lower(<system>)\|*` | the system field (`src` or `dest`), exactly as held |
| `<group>\|lower(<provider>)` and `<group>\|*` | the identity group (see below) |
| `*\|lower(<provider>)` | organisation-wide approval of one provider |

The **group** is the first non-empty value of `user_group`, `user_category`, `bunit`, the ES identity `bunit` of the user, and finally `category`. The macro looks the identity `bunit` up itself: first by the raw user value, then by the bare name with `DOMAIN\` and `@suffix` removed. The value `unknown` is ignored.

A matching row removes the event when it is **active**:

- `enabled` is `1` or empty;
- `expires` is empty, or a `YYYY-MM-DD` date that is today or later.

Any other date format makes the row **inactive**, because the date cannot be parsed. The `scope`, `owner` and `reason` columns are documentation only. The macro never reads them.

### 3.2 Choose the narrowest key that covers the approval

| Approval | Row to add (`entity_type,entity,provider,scope,expires,owner,reason,enabled,allow_key`) | Notes |
|---|---|---|
| Licensed for the whole organisation (ChatGPT Enterprise, Copilot for everyone) | `group,*,OpenAI,global,2027-06-30,security,ChatGPT Enterprise,1,*\|openai` | Applies in every detection that calls the filter. `*\|*` is never matched, so there is no "approve everything" key. |
| Licensed for one business unit | `group,engineering,GitHub Copilot,group,2027-06-30,security,licensed seats,1,engineering\|github copilot` | `entity` is the lowercased ES identity `bunit` value. Works only where identities carry `bunit`. In Tenants B and D most users had none, so use user or organisation keys there. |
| One person, one provider | `user,jdoe@example.com,Anthropic,provider,2027-03-31,security,research pilot,1,jdoe@example.com\|anthropic` | Add one row per user format the data sources emit (see 3.4). |
| A server that calls AI APIs | `system,app-srv-01,OpenAI,global,2027-12-31,platform,production integration,1,app-srv-01\|openai` | The key must equal the `src`/`dest` value the detection emits: hostname or IP, exactly. There is no CIDR matching. |
| Any provider for one person or host | `user,jdoe@example.com,*,global,2027-03-31,ciso,approved researcher,1,jdoe@example.com\|*` | Use sparingly. It hides that person from every AI detection that calls the filter. |

Rules that avoid silent failures:

- **`allow_key` must equal `lower(entity)|lower(provider)`**, with `*` for all providers. The lookup is case-insensitive, but a typo or a stray space makes the row match nothing.
- **Keep keys unique.** The common package ships five disabled `EXAMPLE_ONLY` rows, including `*|microsoft 365 copilot`. To approve one of those, edit the example row and set `enabled=1`. Do not add a second row with the same key: the common package documents that the first row wins, so a disabled first row keeps the approval off.
- **Always set an expiry.** Use 30-90 days for individual exceptions and pilots and 6-12 months for team and organisation licences. The staleness health check warns 14 days before an entry expires.

### 3.3 The provider string must match what the detection emits

`provider` is a join key. It must equal, case-insensitively, the provider label the detection carries when it calls the filter. Most network detections use the registry names (`OpenAI`, `Anthropic`, `Google Gemini`, `Microsoft Copilot`, `GitHub Copilot`, `Microsoft 365 Copilot` and so on). The full list is in the `hdsi_ai_rba_common` README under "Provider names". Exceptions:

- **Process-based rules** use the `ai_tool_processes` labels, and some of those differ from the network labels: `Amazon` versus `Amazon Q`, `Codeium` versus `Windsurf`, and `Microsoft Copilot` (legacy `gh-copilot`) versus `GitHub Copilot`. To approve such a tool everywhere, add one row per label.
- `hdsi_ai_unsanctioned_desktop_app_execution` emits its own labels: `OpenAI`, `Anthropic`, `Cursor`, `Windsurf`, `ByteDance`, `Amazon`, `Perplexity`, `Pieces`, `Msty` and `AnythingLLM`.
- `hdsi_ai_user_peer_group_usage_anomaly` passes the single provider when a row has one, and `*` when a row spans several providers. Only `<user>|*`, group `|*` or organisation keys can approve a multi-provider row.
- `hdsi_ai_agent_autonomous_action_detection` passes the agent's provider for routine agent activity only. High-signal categories (credential access, persistence, system change, network transfer, destructive actions) use a sentinel value and **cannot be allowlisted**. That is deliberate.

To see the exact objects and providers your detections are scoring, and whether an active row already covers them, run this over the last 7-14 days once detections are enabled:

```spl
index=risk (source="* - HDSI AI * - Rule" OR detection_id="hdsi_ai_*") NOT source="* - HDSI AI Health * - Rule"
| eval provider_l=lower(coalesce(mvindex(provider,0),"*")), object_l=lower(risk_object)
| stats count as risk_events sum(risk_score) as total_risk dc(source) as detections values(source) as sources by risk_object_type object_l provider_l
| eval key_this_provider=object_l."|".provider_l, key_all_providers=object_l."|*"
| lookup ai_sanctioned_entities allow_key as key_this_provider OUTPUT enabled as provider_entry_enabled
| lookup ai_sanctioned_entities allow_key as key_all_providers OUTPUT enabled as all_entry_enabled
| sort 0 - total_risk
| head 50
```

`key_this_provider` is the user or system row you would add. Rules that aggregate several providers into one row (they write `provider_list` instead of `provider`) show `*` here. Read their risk message for the providers.

### 3.4 User formats differ between data sources

User and system keys are matched on the **raw value** the detection holds. They are not merged across formats. In validation, firewall and endpoint data carried `DOMAIN\user`, SSE and IdP data carried UPNs (`user@example.com`), and some sources carried bare account names. The same person can therefore need two or three user rows. Two packages normalise the user before the filter:

- `hdsi_ai_usage_following_data_access_spike` passes the bare account name (`ukey`: lowercased, `DOMAIN\` and `@suffix` removed).
- `hdsi_ai_user_peer_group_usage_anomaly` calls the filter twice: once with the bare `user_key` and once with `user`.

For these, a bare-name row (`jdoe|openai`) is the one that matches. This search lists every person whose AI risk arrives under more than one format:

```spl
index=risk (source="* - HDSI AI * - Rule" OR detection_id="hdsi_ai_*") risk_object_type="user"
| eval person=lower(replace(replace(risk_object,"^.*\\\\",""),"@.*$",""))
| stats dc(risk_object) as forms values(risk_object) as risk_object_forms values(source) as sources by person
| where forms>1
| sort 0 - forms
```

Case differences do not matter, because every key is lowercased. Domain and UPN differences do. Where the tenant's identities carry `bunit`, a group key avoids the problem completely, because the macro resolves the identity from either format.

### 3.5 Package-level provider lists

Several packages also carry their own provider lists. These lists act before or instead of the allowlist and apply to that package only:

| Macro | Ships as | Use it when |
|---|---|---|
| `hdsi_ai_unsanctioned_web_access_sanctioned_providers`, `hdsi_ai_first_seen_provider_for_user_sanctioned_providers`, `hdsi_ai_user_peer_group_usage_anomaly_sanctioned_providers`, `hdsi_ai_access_via_vpn_proxy_evasion_sanctioned_providers` | `"__none__"` | A provider is sanctioned for everyone but you want the rule-specific effect only. An organisation row `*\|<provider>` covers all of these rules at once and is normally the better choice. |
| `hdsi_ai_dns_queries_to_ai_domains_excluded_providers`, `hdsi_ai_multiple_services_in_single_session_excluded_providers` | IDE assistants (GitHub Copilot, Cursor, Windsurf, Tabnine, Sourcegraph) plus Microsoft 365 Copilot and Microsoft Security Copilot | Add enterprise AI that every device resolves, for example `"OpenAI"` with ChatGPT Enterprise. On Tenant B this cut DNS risk from about 1,500 to about 510 events a day. |
| `hdsi_ai_new_provider_adoption_velocity_excluded_providers` | Microsoft 365 Copilot, Microsoft Security Copilot | Add a provider during a company-wide rollout, so the rollout does not count as adoption velocity. |
| `hdsi_ai_high_volume_upload_to_ai_service_excluded_providers`, `hdsi_ai_gradual_data_exfiltration_via_ai_excluded_providers`, `hdsi_ai_usage_following_data_access_spike_excluded_providers` | `"Microsoft 365 Copilot"` | Volume from a tenant-bound assistant: Copilot carried about 1.4 GB a day through an SSE app name for ordinary users in one tenant. |
| `hdsi_ai_api_access_from_non_dev_endpoint_excluded_providers` / `_sanctioned_endpoints` | `"GitHub Copilot","Cursor","Suno"` / `"__none__"` | Add the organisation's own cloud AI endpoints, such as `"contoso-*.openai.azure.com"`, to `_sanctioned_endpoints`. |
| `hdsi_ai_code_assistant_network_connection_sanctioned_tools` | `"GitHub Copilot (Business/Enterprise)"` | Add `"GitHub Copilot"` when Copilot is licensed company-wide. On Tenant A this cut volume from about 225 to about 90 events a day. Prefer this to an organisation key `*\|github copilot`: the key also hides personal-tier Copilot, while this macro keeps `GitHub Copilot (personal)` visible. |
| `hdsi_ai_privileged_account_service_usage_ambient_providers` | Google Gemini, Microsoft Copilot, Microsoft 365 Copilot, Gemini for Workspace | Providers that are part of the desktop or browser for everyone. They need `_ambient_min_events` (25) rather than `_min_events` (3). |

### 3.6 Opt-in rows: Microsoft 365 Copilot and Gemini for Workspace

In the registries, `enabled=0` means the row is **not** treated as AI use. Two groups of rows ship that way:

- **`OPT_IN_M365_COPILOT`:** domains `copilot.cloud.microsoft` and `m365copilotapp.svc.cloud.microsoft`, and the app names `microsoft 365 copilot`, `microsoft copilot studio`, `ms-office365-copilot`, `ms-office365-copilot-upload` and `ms-office65-copilot-upload`. Microsoft Message Center MC1462915 moves every Microsoft 365 web user to `copilot.cloud.microsoft` between September and November 2026. After that, the host is the ordinary Microsoft 365 home page. In the October validation, the disabled app name `microsoft 365 copilot` appeared for about 800 distinct users an hour in Tenant C's SSE data. Enabled, every Office user would become an AI user in every Web and DNS rule.
- **`OPT_IN_WORKSPACE_GEMINI`:** `appsgenaiserver-pa.googleapis.com`, `appsgenaiserver-pa.clients6.google.com` and the PAN App-ID `google-workspace-duet-ai`. That App-ID came from about 2,600 sources an hour in Tenant A.

Set these rows to `enabled=1` only if the organisation has **not** licensed or approved the product and wants to see its use. If you do opt in, the Web packages whose prefilters were generated from every registry row see the hosts at once: Unsanctioned Web Access, First Seen Provider For User, User Peer Group Usage Anomaly, Access From Unmanaged Device and Prompt Injection Indicators. Rules that list `Microsoft 365 Copilot` in an `_excluded_providers` macro (see 3.5) keep ignoring it until you remove it there too.

Consumer and separate Copilot products stay enabled: `copilot.microsoft.com`, `copilot.com`, Copilot Studio, Security Copilot and Copilot for Finance. The PAN App-ID `google-gemini` is also ambient: about 16,000 sources an hour in Tenant A. Approve it with an organisation row or a group row, or rely on the ambient-provider thresholds.

### 3.7 Check the allowlist

Run this after every edit. It flags keys that do not match their entity and provider, duplicate keys, unparseable dates, expired and soon-to-expire rows, and provider labels that appear in no registry:

```spl
| inputlookup ai_sanctioned_entities
| eval provider_l=lower(trim(provider)), expected_key=lower(trim(entity))."|".provider_l, today=relative_time(now(),"@d"), exp_epoch=strptime(expires,"%Y-%m-%d")
| eval key_check=if(lower(allow_key)=expected_key, "ok", "MISMATCH: expected ".expected_key), status=case(coalesce(tonumber(enabled),1)!=1, "disabled", len(expires)>0 AND isnull(exp_epoch), "INACTIVE: bad date (use YYYY-MM-DD)", len(expires)>0 AND exp_epoch<today, "expired", len(expires)>0 AND exp_epoch<today+14*86400, "active, expires within 14 days", true(), "active")
| eventstats count as rows_with_key by allow_key
| join type=left max=1 provider_l [| inputlookup ai_provider_domains | append [| inputlookup ai_provider_apps] | append [| inputlookup ai_tool_processes] | eval provider_l=lower(provider) | stats count as registry_rows by provider_l]
| eval provider_check=case(provider_l="*", "all providers", isnotnull(registry_rows), "known registry provider", true(), "not in a registry: check the package README for its provider label")
| table status entity_type entity provider expires owner reason allow_key key_check rows_with_key provider_check
```

Fix every `MISMATCH`, every `rows_with_key` above 1, and every `INACTIVE: bad date` row. A provider that is "not in a registry" is correct only for the detection-specific labels listed in 3.3.

### 3.8 Detections the allowlist does not cover

These packages do not call `ai_unsanctioned_filter`, on purpose. Tune them with their `_filter` macro or their own allow macros:

- API Key Exposure In Code/DLP, Compromised Plugin/Extension Installation and Prompt Injection Indicators In Web Uploads. Each hit is a security event whether or not AI use is approved.
- Generated Phishing Indicators. Use `hdsi_ai_generated_phishing_indicators_allowed_hosts` for the organisation's own sites on AI builders.
- Unknown High-Volume External API Discovery. This is a hunting search that writes no risk.
- The health checks and the five aggregators.

---

## 4. Business-unit sensitivity

`ai_risk_multiplier` scales risk by who the user is. It reads the field `user` and sets `risk_multiplier`:

1. It resolves the identity in `identity_lookup_expanded`, first by the raw value and then by the bare name. Built-in names such as `administrator` and `root` are never bare-matched.
2. It takes the identity **`bunit`**. ES identities in all four validation tenants have no `department` field, so `bunit` is the supported key. An empty `bunit` becomes `general`.
3. It looks the value up in `ai_department_sensitivity.department`: first the whole lowercased value, then its **last** path segment, then its **first** path segment. The separators are `/ \ > | :`. Middle segments are never matched.
4. It multiplies by 1.25 when the identity `category` is the whole word `priv`/`privileged` (optionally with `_user`/`_account`) or `priority` is `critical`.
5. It caps the result at 2.0. The shipped `executive` row (2.5) therefore acts as 2.0.

The shipped keys (`finance`, `legal`, `hr`, `security`, `engineering` and so on) are examples. In validation they matched almost nothing: Tenant A identities carry hierarchical paths, and Tenants B and C use their own unit names. Until the lookup is mapped, every multiplier is 1.00. This search lists the tenant's `bunit` values with the segment the macro would try and the multiplier it would get today:

```spl
| inputlookup identity_lookup_expanded
| eval bunit=lower(trim(mvindex(bunit,0))), bunit=if(isnull(bunit) OR bunit="", "general", bunit), leaf=trim(replace(bunit,"^.*[/\\\\>|:]","")), top=trim(replace(bunit,"[/\\\\>|:].*$",""))
| stats count as identities by bunit leaf top
| lookup ai_department_sensitivity department as bunit OUTPUT risk_multiplier as m_whole
| lookup ai_department_sensitivity department as leaf OUTPUT risk_multiplier as m_leaf
| lookup ai_department_sensitivity department as top OUTPUT risk_multiplier as m_top
| eval multiplier=round(min(coalesce(tonumber(m_whole),tonumber(m_leaf),tonumber(m_top),1.0),2.0),2), matched_by=case(isnotnull(m_whole), "whole value", isnotnull(m_leaf), "last segment", isnotnull(m_top), "first segment", true(), "not mapped (1.0)")
| sort 0 - identities
| head 50
```

Guidance:

- Add rows for the units that hold sensitive data or authority: finance, legal, HR, executive, security, research and development, and source-code owners. Use the exact lowercased `bunit` value, or its leaf or top segment for paths. Keep everything else at 1.0, because a multiplier above 1 on a large unit raises the whole tenant's AI risk.
- Keep multipliers between 1.0 and 2.0. Detections already cap per-event scores (typically at 40-80), and the aggregators decide what becomes a notable.
- Identities with no `bunit` (`general`) were the large majority in every tenant: about 260,000 in Tenant A, 10,000 in B and 64,000 in C. Sensitivity scaling only helps once the ES identity source populates `bunit`, which is an identity-management change.

Host-only detections (DNS Queries To AI Domains, Access From Unmanaged Device, Local LLM Listening Port Detected) do not apply the multiplier.

---

## 5. Detection thresholds and named macros

Every named macro is `<package>_<suffix>`. The tables list each package's suffixes with their shipped values. Volumes are risk events a day from the validation tenants (A / B / C / D) with the shipped defaults. They are a yardstick, not a target. Each package README has the threshold SPL and the reasoning for every value.

### 5.1 Web, SSE and firewall App-ID detections

| Package (`hdsi_ai_…`) | Threshold and guard macros (shipped value) | Validation volume A / B / C / D | First thing to tune |
|---|---|---|---|
| `unsanctioned_web_access` | `_min_events` 3 per entity, provider and hour; `_system_only_min_events` 0 (off); `_src_risk` 0; `_max_users_per_src` 3; `_sanctioned_providers` | ~2,370 (~110 with OpenAI, Google Gemini and Microsoft Copilot sanctioned) / 0 / ~40 / 0 | Sanction the enterprise assistants. Keep `_min_events` between 2 and 5. |
| `first_seen_provider_for_user` | `_baseline` -31d@d; `_max_org_users` 10; `_min_events` 3; `_blocked_weight` 0.5; `_sanctioned_providers` | 30-40 / 0-1 / ~1 / 0 | Needs 31 days of accelerated history. `_max_org_users` defines "rare in the organisation". |
| `multiple_services_in_single_session` | `_min_providers` 4; `_min_requests` 3; `_shared_src_names` 3000; `_max_src_users` 1; `_excluded_providers` | 0-2 / 9-15 / 0 / 0 | Raise `_min_providers` to 5 if power users dominate. |
| `after_hours_service_usage` (adhoc) | `_utc_offset` **null() (required)**; `_dst_rule` "none"; `_after_hours` before 06:00, from 20:00, weekends; `_min_requests` 50; `_min_buckets` 2; `_upload_mb` 5 | silent until the clock is set; then 5-8 / 0 / 2-4 / 0 | Set the clock. Edit `_after_hours` for shift patterns. |
| `time_of_day_usage_pattern_anomaly` | `_zscore` 3; `_min_requests` 20; `_min_baseline_days` 5; `_max_usual_days` 1 | ~4 / 0 / 0 / 0 | SSE tenants count sessions, not requests. Tenant C needed `_min_requests` 3 to see anything (about 1 a day). |
| `usage_volume_anomaly` | `_zscore` 4; `_min_baseline_days` 7; `_min_baseline_floor` 4; `_min_requests` 100; `_min_sessions` 500; `_min_mb` 20; `_fleet_min_users` 20; `_coverage_share` 0.02 | 2-6 / 0 / 0-1 / 0 | `_zscore`. Keep the absolute floors. |
| `user_peer_group_usage_anomaly` | `_min_peer_size` 10; `_zscore` 3.5; `_ratio` 10; `_min_mb` 100; `_min_requests` 2500; `_sanctioned_providers` | 9-15 (before 7-day suppression) / 0 / 0 / 0 | Peer groups are `bunit` values. Without `bunit`, users fall into one tenant-wide group. |
| `repeated_unsanctioned_access_burst` | `_min_attempts` 10 blocked requests; `_min_minutes` 3; `_unreliable_src` | ~190 / 0 / 0 / 0 | Machine retries from blocked desktop apps look like persistence. Raise `_min_minutes`. |
| `privileged_account_service_usage` | `_min_events` 3; `_ambient_min_events` 25; `_ambient_providers` | ~3 / 0 / 0 / 0 | Fix naming conventions in `_privileged_name` first. |
| `high_volume_upload_to_ai_service` | `_low_mb` 50, `_medium_mb` 100, `_high_mb` 500, `_critical_mb` 2000 (MB per source-hour); `_max_user_sessions` 1000; `_excluded_providers` | ~24 / 0 / 0-1 / 0 | Sanction API integration servers by system key, then set `_low_mb` from the README SPL. Never set it below about 25 MB. |
| `gradual_data_exfiltration_via_ai` (weekly) | `_cumulative_mb` 250; `_min_active_days` 3; `_active_day_mb` 1; `_max_day_share` 0.5; `_max_user_srcs` 20; `_host_requires_asset` 1; `_host_max_day_mb` 1024 | ~23 per weekly run / 0 / 0 / 0 | Approved API users first, then `_cumulative_mb`. |
| `usage_following_data_access_spike` | `_min_files` 100; `_min_upload_mb` 5; `_max_upload_srcs` 5 | 0-1 / 0 / 0 / 0 | Uses the bare account name for allowlisting (see 3.4). |
| `personal_email_to_ai_service_upload_correlation` | `_min_email_bytes` 5242880; `_min_ai_bytes` 1048576; `_corporate_mail_users` 25 | 0 everywhere | Needs a proxy that logs bytes per user. |
| `browser_extension_activity` | `_tier_scores` (capture 30, page reader 20, writer 10 and so on) | ~29 / ~24 / ~7 / 0 | Allowlist approved extensions' vendors. |
| `browser_extension_high_volume_data_transmission` (incubating, not released) | `_threshold_mb` 10 per source-hour | 0 | Needs Web `bytes_out`. NGFW URL logs have none. |
| `prompt_injection_indicators_in_web_uploads` | `_pattern_exclusions`; `_weak_patterns`; `_blocked_factor` 0.5; `_src_only_factor` 0.5 | ~0 | Pattern libraries, not thresholds. |
| `voice_cloning_api_access` | `_min_app_events` 2; `_min_api_events` 10; `_min_browse_events` 5; `_upload_mb` 1; `_shared_src_names` 10000 | 7-8 / 1-3 / 1-8 / 0 | Sanction licensed voice vendors. Tenant C's volume was one licensed product. |
| `llm_model_file_download` | `_min_mb` 500; `_min_cdn_events` 25; `_shared_src_names` 10000 | ~1 / ~1.4 / 0 / 0 | Allowlist ML build hosts by system key. |
| `suspicious_model_file_exfiltration` | `_min_mb` 100; `_min_evidence_mb` 10 | ~0 | Allowlist ML teams that publish models. |
| `usage_from_personal_account_oauth_mismatch` (incubating, not released) | `_sso_lookback` -30d@d; `_min_sso_users` 3; `_min_matched_users` 3; `_min_activity` 20; `_min_active_hours` 2 | 0 as shipped | Pin `_sso_apps` to the tenant's IdP application names first. |
| `generated_phishing_indicators` | `_min_score` 20; `_allowed_hosts`; `_discard_actions` | 2-3 / 0 / 0 / under 0.2 | Add your own AI-builder sites to `_allowed_hosts`. |

### 5.2 DNS and network detections

| Package (`hdsi_ai_…`) | Threshold and guard macros (shipped value) | Validation volume A / B / C / D | First thing to tune |
|---|---|---|---|
| `dns_queries_to_ai_domains` | `_min_queries` 10 per host, provider and day; `_min_api_queries` 1; `_shared_src_names` 10000; `_unreliable_src` (on); `_excluded_providers`; `_background_names` | ~80 / ~1,500 (~510 with `"OpenAI"` excluded) / ~45 / 0 | Exclude enterprise AI that every device resolves. |
| `code_assistant_network_connection` | `_sanctioned_tools`; `_max_users_per_src` 3; `_unreliable_src` false() | ~225 (~90 with `"GitHub Copilot"` sanctioned) / ~200 (~100 with `_unreliable_src` set) / ~65 / 0 | Licence tier and roaming addresses. |
| `api_access_from_non_dev_endpoint` | `_require_known_asset` 1; `_max_users_per_src` 3; `_dev_categories`; `_dev_sources` false(); `_excluded_providers`; `_sanctioned_endpoints`; `_unreliable_src` false() | ~36 (~13 after approving one embedded speech vendor and the Vertex AI servers) / ~5 / ~1 / 0 | Mark developer hosts through asset categories or `_dev_sources`. Approve integration servers. |
| `access_via_vpn_proxy_evasion` | `_min_base_score` 20; `_max_users_per_src` 3; `_sanctioned_providers` | 40-80 / 0 (~10 at 10) / 0-2 / 0 | Mostly host-only. Exclude corporate privacy relays with `_web_exclusions`. |
| `new_provider_adoption_velocity` | `_window_days` 7; `_min_baseline_days` 7; `_min_new_providers` 3; `_report_days` 2; `_min_dns_queries` 10; `_min_web_events` 3; `_min_api_queries` 3; `_shared_src_providers` 15; `_excluded_providers` | 0 (needs 21 days of acceleration) / 3-6 / 0-1 / 0 | Acceleration range first. |
| `access_from_unmanaged_device` (incubating, not released) | `_min_queries` 5; `_min_subnet_hosts` 10; `_min_subnet_coverage` 0.9; `_client_ranges`; `_home_network_ranges`; `_unmanaged_categories`; `_dns_sources` | 0 everywhere | Needs on-network resolver logs and an asset inventory that registers guest or BYOD ranges. |
| `unknown_high_volume_external_api_discovery` (adhoc, hunting, no risk) | `_min_events` 50; `_min_sources` 3; `_max_results` 100 | review rows, capped at 100 a day | Feed what you find into `ai_provider_domains`. |
| `local_llm_listening_port_detected` | `_ports` 11434, 1234, 1337, 4891; `_generic_ports`; `_process_lookback` -7d@h | 0 | Port list. |

### 5.3 Endpoint, DLP and health packages

The endpoint detections match tool names, command lines and IOCs rather than counts, and all of them produced about 0 risk events a day in every validation tenant. Tune them through their lists and their `_filter` macro, and approve developer and CI use in `ai_sanctioned_entities` (user plus system key):

- Agent Autonomous Action Detection (`_min_actions` 3)
- Agent Framework Execution
- Unsanctioned CLI Execution
- Scripted CLI Invocation
- Unsanctioned Desktop App Execution
- Local LLM Framework Execution (`_nonhuman_accounts`)
- MCP Server Execution: about 1 a day on Tenant C only
- Assisted Lateral Movement
- Deepfake Tool Execution/Access
- Compromised Plugin/Extension Installation (`_service_accounts`)
- API Key Exposure In Code/DLP. If you enable a new pattern in `ai_api_key_patterns`, add its literal prefix to `_process_prefilter` too.
- Copy-Paste Correlation To AI Service (adhoc; `_min_pastes` 3; about 12-20 a day where enterprise-browser paste telemetry exists)

DLP rules:

- DLP Violation On Service Upload (incubating, not released; `_blocked_factor` 0.5) needs an AI-bound egress DLP or CASB feed in the CIM `DLP` model.
- Sanctioned DLP Violation (`_purview_min_confidence` 85, `_purview_ignored_types`, `_blocked_factor` 0.5) also reads Microsoft Purview `DLPRuleMatch` audit events. It produced about 0.07 events a day on Tenant A and up to about 1 a day on Tenant C.

Health checks:

- Data Model Availability: `_required_models` "__none__", `_min_expected` 100, `_degraded_pct` 10, `_max_silence_hours` 24.
- Lookup Staleness Alert: `_max_age_days` 90, `_stale_row_pct` 50, `_expiry_warn_days` 14, `_required_controls` `medium_risk_threshold,high_risk_threshold`.

### 5.4 Aggregators (notables)

| Package | Knobs | Notes |
|---|---|---|
| `hdsi_rba_ai_user_risk_threshold_exceeded` (medium) | `ai_detection_config` `medium_risk_threshold` 60 and `high_risk_threshold` 90 (60 and 90 also apply if a row is missing); `_min_detections` 2 | Notable when a person's 24 h HDSI AI risk is in the medium band and comes from at least 2 detections. |
| `hdsi_rba_ai_user_critical_risk_threshold_exceeded` (high) | `high_risk_threshold` 90; `_min_detections` 1 | Keep its `_filter`, `_user_key`, `_excluded_accounts` and `_risk_index` identical to the medium rule's, or the bands overlap. |
| `hdsi_rba_ai_multi_vector_risk` | `_min_vectors` 3 of 6; `_min_high_impact` 1; `_new_vector_window` "-65m" | Raise `_min_vectors` to 4 if three-vector notables are mostly benign power users. Reads user **and** system risk. |
| `hdsi_rba_ai_data_collection_kill_chain` | `_window_hours` 4; `_order_tolerance_minutes` 60; `_risk_object_types` user, system | Collection then exfiltration on one entity. |
| `hdsi_rba_ai_privilege_escalation_correlation` | `_min_ai_risk` 20; `_priv_techniques`; `_priv_rule_regex` | Privilege change followed by AI execution or exfiltration risk. |

Calibrate the bands with the threshold SPL in the `hdsi_rba_ai_user_risk_threshold_exceeded` README after two to four weeks of AI risk. Put `medium_risk_threshold` near the p95 of daily per-person totals (not below 40), and `high_risk_threshold` near the p99, at least 30 points above medium. Keep medium below high; the staleness health check flags an inverted band.

---

## 6. Calibration SPL for the tenant's data realities

The Web model looked different in every validation tenant:

- **Tenant A:** NGFW URL logs fill `url_domain` and leave `site` empty.
- **Tenant B:** mostly inbound load-balancer and WAF logs.
- **Tenant C:** a Netskope SSE proxy that puts an application name ("ChatGPT", "Microsoft Teams") in `site` and leaves `url_domain` empty.
- **Tenant D:** inbound IIS only.

DNS names sometimes carry a trailing root dot. Calibration searches that assume `Web.url_domain` is always present silently return nothing on SSE tenants. The searches below use the calling pattern the detections use:

- `fillnull_value="unknown"` on `tstats`, because a null `by` field drops the whole row;
- `ai_domain=lower(coalesce(nullif(url_domain,"unknown"), nullif(site,"unknown")))`;
- `` `ai_domains_filter` `` for provider resolution. It strips schemes, ports, `www.` and trailing dots, and matches app names only when the value came from `site` or `app`, or when `ai_input_type="app"` is set.

Run them over 1-4 hours first. On a tenant with about a billion DNS events a day, a 1-hour DNS resolution took about 26 s.

### 6.1 Tenant data profile

**Web host shape: where the hostname is.** This tells you whether the tenant's Web rows carry `url_domain`, a hostname in `site`, an SSE app name in `site`, or nothing:

```spl
| tstats summariesonly=t allow_old_summaries=t fillnull_value="unknown" count from datamodel=Web by sourcetype Web.url_domain Web.site
| rename Web.* as *
| eval host_shape=case(url_domain!="unknown", "url_domain", match(site,"^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)+(:\d+)?$"), "site_is_hostname", site!="unknown", "site_is_app_name", true(), "no_host")
| stats sum(count) as events dc(url_domain) as url_domains dc(site) as sites by sourcetype host_shape
| eventstats sum(events) as sourcetype_events by sourcetype
| eval pct_of_sourcetype=round(100*events/sourcetype_events,1)
| sort 0 - sourcetype_events host_shape
```

In 1 hour, Tenant A's firewall URL logs were 99.4% `url_domain`. Tenant C's SSE connection logs were 99.8% `site_is_app_name`. Sourcetypes that are 100% `no_host` cannot contribute to any Web AI rule.

**Web direction: is this user egress?** Inbound server, WAF and load-balancer logs have public source addresses and no user:

```spl
| tstats summariesonly=t allow_old_summaries=t fillnull_value="unknown" count from datamodel=Web by sourcetype Web.src Web.user
| rename Web.* as *
| eval src_kind=case(src="unknown", "none", cidrmatch("10.0.0.0/8",src) OR cidrmatch("172.16.0.0/12",src) OR cidrmatch("192.168.0.0/16",src) OR cidrmatch("100.64.0.0/10",src), "private", match(src,"^\d{1,3}(\.\d{1,3}){3}$"), "public_ipv4", true(), "other"), has_user=if(in(lower(user),"unknown","-",""),"no","yes")
| stats sum(count) as events by sourcetype src_kind has_user
| eventstats sum(events) as sourcetype_events by sourcetype
| eval pct_of_sourcetype=round(100*events/sourcetype_events,1)
| sort 0 - sourcetype_events - events
```

How to read the result:

- A sourcetype that is mostly `public_ipv4` with `has_user=no` is inbound: Tenant B's load-balancer logs were 77.5% that. Exclude it in the Web packages' `_filter`.
- Private sources with `has_user=no` are user egress that the proxy did not attribute. Tenant A's firewall URL logs were 53% that. Those rows can only become system risk, which most Web rules keep opt-in.
- An SSE that reports the user's public egress address with a user (Tenant C) is fine for user rules, but its `src` is not a host.

### 6.2 AI evidence by source

**Web.** This shows which providers the registry resolves from the tenant's Web data and how (exact host, subdomain, app name). The prefilter is the Unsanctioned Web Access package's scope macro, so it needs that package deployed and covers `usage_type=web` providers:

```spl
| tstats summariesonly=t allow_old_summaries=t fillnull_value="unknown" count dc(Web.user) as users from datamodel=Web where `hdsi_ai_unsanctioned_web_access_scope` by sourcetype Web.url_domain Web.site
| rename Web.* as *
| eval ai_domain=lower(coalesce(nullif(url_domain,"unknown"), nullif(site,"unknown")))
| `ai_domains_filter`
| eval evidence=if(ai_match="app_name", "app name in site", if(url_domain!="unknown", "url_domain", "hostname in site"))
| stats sum(count) as events max(users) as max_users_one_name dc(ai_domain) as names values(evidence) as evidence values(ai_match) as matched_by by provider usage_type ai_traffic_class
| sort 0 - events
```

`ai_traffic_class="background"` rows are telemetry, A/B testing, sign-in refresh and updater hosts that installed apps poll without a user action. In Tenant A, OpenAI background hosts reached 50 users in one hour, against at most 9 users on any single interactive OpenAI name. Volume, burst and first-seen rules drop them. Presence rules keep them.

**DNS.** Resolve providers on **distinct query names**, not on `src` x `query` rows. The resolver runs five lookups per row, so this is the difference between seconds and minutes on large tenants. The prefilter is the DNS package's macro, which carries every registry name with and without the trailing dot:

```spl
| tstats summariesonly=t allow_old_summaries=t count dc(DNS.src) as srcs from datamodel=Network_Resolution where `hdsi_ai_dns_queries_to_ai_domains_query_prefilter` by DNS.query
| rename DNS.* as *
| eval trailing_dot=if(match(query,"\.$"), "yes", "no"), ai_domain=query, ai_input_type="dns"
| `ai_domains_filter`
| stats sum(count) as queries max(srcs) as max_srcs_one_name dc(ai_domain) as names values(trailing_dot) as trailing_dot values(ai_match) as matched_by by provider ai_traffic_class
| sort 0 - queries
```

`ai_input_type="dns"` stops single-label names (`claude.`, `cursor`, `gamma`: internal hosts and search-suffix lookups) from matching AI app names. Tenant B's names all carried a trailing dot. They resolved the same way as Tenant A's and C's dot-less names, because the resolver strips the dot.

If you write your own DNS `tstats` prefilter, add both forms of each name (`"*.chatgpt.com"`, `"*.chatgpt.com."`) or wildcard the end (`"*chatgpt.com*"`). An exact `DNS.query="chatgpt.com"` misses every trailing-dot answer.

**Per-entity hourly volume, for count thresholds.** This search uses the same normalisation and splits SSE app-name evidence from hostname evidence. SSE proxies count sessions or connections, which are far fewer than the HTTP requests a firewall or proxy logs, so one threshold cannot fit both:

```spl
| tstats summariesonly=t allow_old_summaries=t fillnull_value="unknown" count from datamodel=Web where `hdsi_ai_unsanctioned_web_access_scope` by _time span=1h Web.user Web.src Web.url_domain Web.site
| rename Web.* as *
| eval user=if(in(lower(user),"unknown","-",""), null(), user), ai_domain=lower(coalesce(nullif(url_domain,"unknown"), nullif(site,"unknown")))
| `ai_domains_filter`
| where ai_traffic_class="interactive"
| eval entity=coalesce(user, "src:".src), unit=if(ai_match="app_name", "SSE app sessions", "requests")
| stats sum(count) as events by _time entity provider unit
| stats count as entity_hours perc50(events) as p50 perc90(events) as p90 perc99(events) as p99 max(events) as max by provider unit
| sort 0 - entity_hours
```

Run it over 7 days. On Tenant A in 1 hour, interactive OpenAI entity-hours had p50 4, p90 17 and p99 182 requests, and Google Gemini had p50 3 and p90 11. The defaults sit near the p50: `_min_events` 3 for presence, and 20-50 for after-hours and time-of-day volume. A threshold near the p90 keeps roughly the heaviest tenth of entity-hours.

### 6.3 Find AI app names and App-IDs the registry does not know

App names are vendor-specific and change with proxy and firewall content updates. A name missing from `ai_provider_apps` is invisible to every rule. These searches list AI-categorised Web names and AI-looking App-IDs, with a status for each:

- `resolved`: the registry maps it.
- `listed with enabled=0`: an opt-in or deliberately silenced row.
- `NOT RESOLVED`: a candidate to review.

```spl
| tstats summariesonly=t allow_old_summaries=t fillnull_value="unknown" count dc(Web.user) as users from datamodel=Web where (Web.category="*artificial*intelligence*" OR Web.category="AI-*" OR Web.category="*generative ai*" OR Web.category="* AI" OR Web.category="* AI *" OR Web.category="AI *" OR Web.category="*machine learning*") by Web.url_domain Web.site Web.category
| rename Web.* as *
| eval name=lower(coalesce(nullif(url_domain,"unknown"), nullif(site,"unknown"))), ai_domain=name, ai_input_type=if(url_domain="unknown" AND NOT match(name,"^[a-z0-9_-]+(\.[a-z0-9_-]+)+(:\d+)?$"), "app", "host")
| appendpipe [ `ai_domains_filter` | eval resolved=1 ]
| stats max(resolved) as resolved values(provider) as provider max(count) as events max(users) as users values(category) as category by name
| lookup ai_provider_apps app_name as name OUTPUT enabled as app_row_enabled
| lookup ai_provider_domains domain as name OUTPUT enabled as domain_row_enabled
| eval status=case(resolved=1, "resolved", app_row_enabled="0" OR domain_row_enabled="0", "listed with enabled=0 (opt-in or silenced)", true(), "NOT RESOLVED")
| sort 0 status - events
```

```spl
| tstats summariesonly=t allow_old_summaries=t count dc(All_Traffic.src) as srcs from datamodel=Network_Traffic where (All_Traffic.app="*gpt*" OR All_Traffic.app="*openai*" OR All_Traffic.app="*claude*" OR All_Traffic.app="*anthropic*" OR All_Traffic.app="*gemini*" OR All_Traffic.app="*copilot*" OR All_Traffic.app="*perplexity*" OR All_Traffic.app="*deepseek*" OR All_Traffic.app="*mistral*" OR All_Traffic.app="*llm*" OR All_Traffic.app="*-ai" OR All_Traffic.app="*-ai-*" OR All_Traffic.app="ai-*" OR All_Traffic.app="*.ai*") by All_Traffic.app
| rename All_Traffic.* as *
| eval ai_domain=app, ai_input_type="app"
| appendpipe [ `ai_domains_filter` | eval resolved=1 ]
| stats max(resolved) as resolved values(provider) as provider max(count) as sessions max(srcs) as srcs by app
| eval app_lc=lower(app)
| lookup ai_provider_apps app_name as app_lc OUTPUT enabled as app_row_enabled
| eval status=case(resolved=1, "resolved", app_row_enabled="0", "listed with enabled=0 (opt-in or silenced)", true(), "NOT RESOLVED")
| sort 0 status - sessions
```

Not every `NOT RESOLVED` row is AI use. In validation, Tenant A's list included firewall-categorised speech CDNs, chatbot widgets, a search engine's AI mode and `llmnr` (a Windows name-resolution protocol caught by `*llm*`). Add a row only when the name is a generative AI service someone uses on purpose:

- Use `ai_provider_apps` for app names and App-IDs. `app_name` is lowercase, and add the `-base`/`-post`/`-upload` variants the firewall emits.
- Use `ai_provider_domains` for hostnames.
- Reuse an existing `provider` string, or check the provider-name rules in the common README before inventing one.

### 6.4 Registry fields that change detection behaviour

| Column | Effect | When to change it |
|---|---|---|
| `enabled` | `0` removes the row from every rule. An exact `enabled=0` row for one host silences that host even when its parent has `match_subdomains=1`. | Silence a non-AI or ambient host without losing its parent domain. |
| `match_subdomains` | `1` extends the row to every subdomain, matched against the parent, the grandparent and the registrable base. Rows with `0` match only exactly. | Set `1` only where the whole tree is AI-specific (`chatgpt.com`, `claude.ai`). Multi-purpose SaaS bases stay `0`. In Tenant C, 183 hosts resolved the exact-only `replit.com` with no other evidence. |
| `traffic_class` | `background` (telemetry, updaters, A/B tests; also weight 0.3) or `site` (documentation and downloads) are dropped by volume, burst and first-seen rules. | Mark a host `background` when installed apps poll it without a user action. In Tenants A and B, `bzr`/`bzrcdn.openai.com` were resolved by far more hosts than `chatgpt.com` itself. |
| `severity_weight` | 0.3-1.2. Scales per-event risk in most network rules. | Lower it for a provider that is mostly benign in your tenant, rather than excluding it. |
| `usage_type` | `web`, `api`, `ide`, `cli`, `local_llm`, `model_registry`. Rules filter on these values. | Do not invent values; a repository test enforces the vocabulary. |

**After you add or change a registry row, check the prefilters.** Most Web, DNS and App-ID packages keep a static `tstats` prefilter macro that was generated from the registry on 2026-10-09, so `tstats` reads only candidate rows. A host or app name that is not covered by a package's prefilter never reaches `ai_domains_filter` in that package, whatever the lookup says. After adding a row, search the package macros for its registrable domain or app name, for example:

```sh
grep -l 'newvendor.ai' saved_searches/packages/*/confs/macros.conf
```

Packages whose prefilter wildcards both sides of each base name (`*name*`) already cover new subdomains of a listed base. Packages with exact-term prefilters (Time-of-Day, Usage Volume Anomaly, Gradual Data Exfiltration, Prompt Injection) need the new name added. The macro description in each package says how its prefilter was built.

---

## 7. Judging noise

A detection is noisy when it writes risk that an analyst would not want counted against the person or host. Volume alone does not prove noise: Unsanctioned Web Access wrote about 2,370 events a day on Tenant A because people really were using unsanctioned AI. Measure each detection on four things, then sample the evidence.

### 7.1 Per-detection risk profile

Run over whole days (for example `-14d@d` to `@d`):

```spl
index=risk (source="* - HDSI AI * - Rule" OR detection_id="hdsi_ai_*") NOT source="* - HDSI AI Health * - Rule"
| eval is_ipv4=if(match(risk_object,"^\d{1,3}(\.\d{1,3}){3}$"),1,0), placeholder=if(match(lower(risk_object),"^(unknown|-|none|null|n/a|)$") OR (risk_object_type="user" AND is_ipv4=1), 1, 0), public_ip=if(risk_object_type="system" AND is_ipv4=1 AND NOT (cidrmatch("10.0.0.0/8",risk_object) OR cidrmatch("172.16.0.0/12",risk_object) OR cidrmatch("192.168.0.0/16",risk_object) OR cidrmatch("100.64.0.0/10",risk_object)), 1, 0)
| bin _time span=1d
| stats count as events dc(risk_object) as objects sum(risk_score) as points max(risk_score) as max_score sum(placeholder) as placeholder_events sum(public_ip) as public_ip_events by _time source risk_object_type
| stats count as days avg(events) as events_per_day avg(objects) as objects_per_day avg(points) as points_per_day max(max_score) as max_score sum(placeholder_events) as placeholder_events sum(public_ip_events) as public_ip_events by source risk_object_type
| foreach *_per_day [ eval <<FIELD>>=round('<<FIELD>>',1) ]
| sort 0 - events_per_day
```

And the objects that dominate each detection:

```spl
index=risk (source="* - HDSI AI * - Rule" OR detection_id="hdsi_ai_*") NOT source="* - HDSI AI Health * - Rule"
| stats count as events sum(risk_score) as points by source risk_object_type risk_object
| eventstats sum(points) as detection_points dc(risk_object) as detection_objects by source
| eval share_pct=round(100*points/detection_points,1)
| sort 0 source - points
| streamstats count as rank by source
| where rank<=5
```

### 7.2 What to look for

| Signal | Healthy | Noise indicator | Usual fix |
|---|---|---|---|
| `events_per_day` against the validation volume in section 5 | Same order of magnitude for a tenant with similar data | Ten times higher, or a detection that should be near 0 writing every day | Phase 0 data check first, then allowlist or exclusions |
| `events_per_day` against `objects_per_day` | Close to 1:1. Most rules suppress per object for 24 h. | Many events per object a day | Check that the suppression fields match the risk objects. A shared `src` is a common cause. |
| `placeholder_events` | 0. The rules drop `unknown`, empty and IP-only users. | Any | Placeholder values such as `Web browser` in a firewall user field. Null them in `_customizations` and report the gap. |
| `public_ip_events` on system objects | 0 | Any | Inbound server logs, SSE egress addresses or roaming DNS clients. Use `_filter` on the sourcetype, or the `_unreliable_src` / `_untrusted_src` guards. |
| `share_pct` of the top object | Low, spread across many objects | One object holds most of a detection's points | Resolver, NAT, proxy, jump host or service account. Approve or exclude it by system key, or raise the package's shared-source guard (`_shared_src_names`, `_max_users_per_src`). |
| `max_score` | At or below the rule's documented cap (typically 40-80) | Many events at the cap | Check `risk_multiplier` (a mis-mapped `bunit`) and `severity_weight` |
| Contribution to user notables | Several detections behind each notable | One detection supplies most of every medium notable (`top_detection_share` in the notable) | Lower that detection's score through `_risk_score`, or raise its threshold |

Then sample the evidence. Open the drilldowns on 10-20 random risk events per detection and classify each one as:

- **true positive:** unsanctioned or risky use;
- **benign true positive:** real AI use that is approved or expected;
- **false positive:** not AI use, or not this person or host.

Treat them differently:

- **Benign true positives** belong in `ai_sanctioned_entities` or a provider exclusion list, not in a higher threshold.
- **False positives** point to the registry (a non-AI host, a missing `background` mark), the data (inbound logs, shared addresses), or the rule's `_filter`.
- **Thresholds** are the right knob only when a true signal is drowned by light, legitimate repetition. The section 6.2 percentiles show where that repetition sits.

### 7.3 Patterns seen in validation

- **Enterprise assistants dominate.** OpenAI, Google Gemini, Microsoft Copilot and GitHub Copilot were the bulk of AI evidence in every tenant with AI data. Sanctioning the licensed ones is the largest single reduction. On Tenant A, sanctioning three providers cut Unsanctioned Web Access from about 2,370 to about 110 events a day.
- **Ambient assistants.** Browser- and OS-integrated assistants (Gemini in Chrome, Copilot in Edge and Windows, the Workspace side panel) generate evidence without a prompt. Keep the opt-in rows disabled, and keep the ambient-provider thresholds.
- **Background polling.** Installed desktop apps and IDE extensions resolve their backends all day. The registry `background` class and each package's `_background_*` macro remove most of it. Add new polling hosts to the registry with `traffic_class=background`, not to a package regex.
- **Shared and roaming addresses.** Roaming DNS-security clients log home-router addresses that different laptops share. Resolvers, forwarders and egress addresses resolve tens of thousands of names a day. Use the `_unreliable_src` and `_shared_src_names` guards rather than lowering thresholds.
- **Inbound server logs in the Web model.** Scanners send Host headers for AI domains. The rules ignore rows without a user from public sources, but the data still costs search time. Exclude those sourcetypes with `_filter`.
- **API integration servers.** Firewall App-IDs expose server-to-API uploads of several GB a day. Approve those servers by system key before you enable the upload-volume rules.
- **Identity gaps.** Unmapped `bunit` values leave every multiplier at 1.00, and missing `bunit` disables group allowlisting and peer groups. These are not noise, but they limit how precisely you can tune.

### 7.4 Order of fixes

1. **Data scoping:** `<package>_filter` for sourcetypes, inbound logs and known service accounts (data model field names, inline).
2. **Approved use:** `ai_sanctioned_entities`, preferring organisation and group keys, then the package provider lists in 3.5.
3. **Registry accuracy:** `enabled=0` exact rows, `traffic_class=background`, `match_subdomains=0`, `severity_weight`.
4. **Named thresholds and guards:** the section 5 macros, set from the package README's threshold SPL.
5. **Row-level rules:** `<package>_customizations`. Example: `where provider_count>=2`.
6. **Scores:** `<package>_risk_score`, for example `eval risk_score=min(coalesce(risk_score,20),20)`. Remember that it overrides every risk object in the row.
7. **Retire:** if a detection has no viable data path in the tenant, leave it disabled. Its README documents the data it needs.

Change one thing at a time and re-run the section 7.1 profile over the following days.

---

## 8. Performance notes

- All shipped searches use `tstats summariesonly=t allow_old_summaries=t`. They see only accelerated data. Check that Web, Network_Resolution, Network_Traffic, Endpoint and Email acceleration covers the longest lookback you enable: 31 days for First Seen Provider, 21 for New Provider Adoption Velocity, 15 for Usage Volume Anomaly and Time-of-Day.
- The heaviest daily rules on a large tenant (about a billion DNS events or 7 billion firewall sessions a day) ran for several minutes: DNS Queries To AI Domains, Usage Volume Anomaly, First Seen Provider and User Peer Group Usage Anomaly. They are scheduled at staggered early-morning minutes. Keep them apart if you move them.
- Do not remove a package's prefilter macro to "see more". On the largest validation tenant, Unsanctioned Web Access without its prefilter did not finish an hourly window.
- `append [...]` subsearches silently truncate at 50,000 rows and auto-finalize after 60 s. If you extend a search in `_customizations`, use chained `tstats prestats=t append=t` instead.
