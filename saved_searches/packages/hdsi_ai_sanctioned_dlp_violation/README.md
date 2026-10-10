## Architect Notes
---
**Author:** Trevor Mock, Hurricane Labs LLC. Security Operations Architect

This rule raises risk when a **DLP control finds sensitive content going to an AI service the organisation has approved**. Examples are a user pasting a password, a cloud client secret or a card number into a Microsoft 365 Copilot prompt, or a CASB/endpoint DLP incident for a PII file uploaded to an allow-listed ChatGPT Enterprise workspace. Approved tools still should not receive credentials or regulated data: the content is retained in prompt history, can resurface through Copilot memory or grounding, and credentials pasted anywhere must be rotated. The rule raises risk on the user (and on the source host when the DLP feed names one). It creates no notable.

Treat it as a data-handling signal rather than proof of theft. It is labelled MITRE T1567 (Exfiltration Over Web Service, the same ID as in the common `ai_mitre_mapping` lookup) because content leaves the user's control for a web AI service, but for in-tenant Microsoft 365 Copilot the data stays inside the organisation's Microsoft 365 boundary. The value is that a credential or regulated record was put where it should not be, and that someone must rotate it or follow up. Scores are kept modest for that reason.

It has two data paths:
- **Microsoft Purview DLP for Microsoft 365 Copilot** (`o365:management:activity`, `Operation=DLPRuleMatch`, Copilot locations). Wherever Purview DLP policies cover the Copilot location, this path needs only the O365 audit index set in `..._purview_events`. Two of the four validation tenants had such policies.
- **CIM DLP incidents** (`DLP.DLP_Incidents`) whose destination resolves to an AI provider that `ai_sanctioned_entities` allow-lists for the user, host, identity group (`bunit`) or the whole organisation. This path is the complement of `hdsi_ai_dlp_violation_on_service_upload`: both rules use the same `tstats` grouping, the same content gate and the same common `ai_unsanctioned_filter`, so each AI-bound incident is scored by exactly one of the two rules once both are deployed. That complement is incubating and not released (see [`saved_searches/incubating/hdsi_ai_dlp_violation_on_service_upload/`](../../incubating/hdsi_ai_dlp_violation_on_service_upload/README.md)), so on release this rule covers sanctioned providers only, and DLP incidents to unsanctioned AI providers are not covered by any released rule. It needs an egress DLP/CASB feed and a populated allow-list; no validation tenant had either.

v1.0 could not run anywhere:
- It read a data model named `Data_Loss_Prevention`. That name does not exist, so every run and its DLP drilldown failed with a FATAL error. The CIM model is `DLP`, dataset `DLP_Incidents`.
- It grouped by `DLP.file_name`, which is not a CIM DLP field.
- It never checked `ai_sanctioned_entities`. Had it run, it would have re-scored every incident that the unsanctioned rule already scores, despite its name.
- It used the `$_mult_user_risk$` token as a risk score, which ES does not support, and put `$_final_multiplier$` in the message (fields starting with `_` are dropped from risk events).
- It turned missing users and hosts into the literal risk object `unknown`.

### Prerequisites
| Data | Fields used | If absent or poor |
|---|---|---|
| Office 365 Management Activity audit (Splunk Add-on for Microsoft Office 365), `Operation=DLPRuleMatch` | `UserId`, `Location`, `SessionMetadata.AppHost`, `SessionMetadata.AppHostCategories{}`, `PolicyDetails{}.PolicyName`, `...Rules{}.RuleMode`, `...Rules{}.Severity`, `...Rules{}.Actions{}`, `...ConditionsMatched.SensitiveInformation{}.SensitiveInformationTypeName` and `.Confidence`, `RemediationDetails.RemediationActivity`, `ItemMetadata.Id`, `ItemMetadata.Name` | No Purview DLP policy on the Copilot location: the path is silent. The add-on input must collect the `DLP.All` content type; these events have `DLP_All` in their `source`. |
| `DLP.DLP_Incidents` (CIM, tags `dlp` + `incident`, scoped by `cim_DLP_indexes`), optional | `dest`, `app`, `user`/`src_user`, `src`, `object`, `signature`, `dlp_type`, `severity`, `action`, `vendor_product` | No egress incidents: the path is silent. Data-at-rest scanners never name an AI destination and produce nothing. |
| `ai_sanctioned_entities` (common), CIM path only | `allow_key` = `<user>\|<provider>`, `<host>\|<provider>`, `<bunit>\|<provider>`, `*\|<provider>` (organisation-wide), or `\|*` for any provider | Empty or all-disabled (as shipped): the CIM path is silent by design. Every AI-bound incident then belongs to the unsanctioned rule. |
| ES `identity_lookup_expanded` | `bunit` (group allow-list key, looked up by `ai_unsanctioned_filter` itself); `bunit`, `category`, `priority` (through `ai_risk_multiplier`) | Missing identities score with multiplier 1.0, and `<bunit>\|<provider>` entries cannot match them. |

- **Acceleration is not required.** The CIM path runs `summariesonly=false`. The DLP model was not accelerated on any validation tenant, so `summariesonly=true` (as in v1.0) would never return data.
- **Deployment gate (`package.yml`):** the package deploys when either path has data. Purview: a `tstats ... TERM(DLPRuleMatch)` with a Copilot location or first-party AI host category in the last 7 days (true on Tenants A and C; 1–72 s). CIM: a DLP incident whose `app` or `dest` names an AI service since the start of yesterday (true on no validation tenant). The CIM check is a `summariesonly=false` scan of the DLP model, which is unscoped (`cim_DLP_indexes` = `()`) on most tenants: over 7 days it took 103–129 s on two tenants, over `-1d@d` it took 9–21 s, so the gate uses `-1d@d`. A tenant whose DLP feed reaches AI services less than daily should deploy the package by hand. A tenant with O365 audit but no Copilot DLP policy (Tenant D) gets no hourly job that can never fire.
- **Common package `hdsi_ai_rba_common`:** `ai_domains_filter` (destination host, URL or CASB app name to provider), `ai_unsanctioned_filter(3)` (used in reverse, see below), `ai_risk_multiplier`.

### How it works
- **CIM path.**
  - `tstats summariesonly=false fillnull_value="unknown"` over `DLP.DLP_Incidents` by `user`, `src_user`, `src`, `dest`, `app`, `signature` and `dlp_type` (the same grouping as the unsanctioned rule), so each row holds the hits of one policy and data type. `unknown`, empty, `SYSTEM`/service and machine accounts become null; rows with neither user nor host, or neither `dest` nor `app`, are dropped.
  - `..._content_evidence` keeps only content hits: a CIM `dlp_type`, or a policy name that names a data class (PII, PCI, secrets, source code, confidential...). A file name or a rated severity alone is not evidence, because CASB/SSE add-ons tag access-control, threat and malicious-site alerts `dlp`+`incident` and those carry file names and severities too. The definition is copied verbatim from `hdsi_ai_dlp_violation_on_service_upload_content_evidence`; keep the two identical.
  - `ai_domain = mvappend(dest, app)`, `mvexpand`, `ai_domains_filter`, then `dedup` on the pre-expansion row, so a row that matches on both `dest` and `app` counts once.
  - **Sanctioned check:** `appendpipe [ ai_unsanctioned_filter(user,src,provider) ]` copies the rows that are *not* allow-listed. `eventstats` marks their originals and both are removed. What remains is exactly the set that `ai_unsanctioned_filter` would have dropped: an active (enabled, not expired) user, host or group entry for that provider or for `*`, or an organisation-wide `*|<provider>` entry. The group is the user's ES identity `bunit`, which the common macro looks up itself (raw user value first, then the bare name without `DOMAIN\` or `@suffix`). Neither DLP rule pre-loads `bunit`, so both see the same group key, and expiry and group handling stay identical to the common macro.
- **Purview path** (`append` subsearch):
  - `..._purview_events` + `..._purview_window`: `DLPRuleMatch` events **indexed** in the dispatch hour (`_index_earliest=-65m@m`, `_index_latest=-5m@m`) whose event time is within 72 h. The O365 audit API delivers late, so a pure `_time` window would miss events (see Late data below).
  - `..._purview_ai_scope` keeps Microsoft first-party generative AI: `AppHostCategories` containing `FIRST_PARTY` or a `Copilot*` location (`Copilot-Sydney` = prompts, `Copilot.M365` = items Copilot processes). Exchange, SharePoint, OneDrive, Teams and Endpoint DLP matches are ignored.
  - Sensitive information types (SITs) are paired with their confidence. A type counts when its confidence is at least `..._purview_min_confidence` (85), or at least 75 for high-impact types. Types matching `..._purview_ignored_types` (IP addresses) never count.
  - `..._purview_content_evidence` keeps a match only if a SIT survived or the tenant rated the rule medium/high. Label-only and low-severity access rules (for example "do not let Copilot process external email") are dropped.
  - One row per user: distinct matched items (`ItemMetadata.Id`), policies, SITs, rule actions and modes. Prompt text is never copied: a prompt shows as `prompt in <app host>`, and SIT detected values are never read.
  - Provider is `Microsoft 365 Copilot`, `severity_weight` 1.0 (the registry weight describes usage noise, not data sensitivity). No host risk object: Purview Copilot events carry no client host.
- **Outcome.** CIM rows are `blocked` only when every action was block/deny/quarantine/prevent/restrict. Purview rows are `blocked` only when one rule is **itself** enforced (`RuleMode` = `Enable`) and has a block or `RestrictAccess` action. The test runs per rule (`spath` on `PolicyDetails{}.Rules{}`), so an enforced notify-only rule next to a simulation rule with `BlockAccess` is `not blocked`. `RestrictWebGrounding` only withholds web search, and simulation (`Test*`) rules enforce nothing; in both cases the prompt reached Copilot, so they count as `not blocked`. The event-level `RemediationDetails.RemediationActivity` is not used: on Tenant C it read `ContentBlocked` on about 37,000 simulation-only matches in 7 days.
- **Scoring (dynamic):**
  - Base 30 when the DLP severity is high/critical or any data type matches `..._high_impact_types` (credentials, secrets, tokens, payment cards, bank accounts, US SSN); 20 for medium or unrated; 10 for low.
  - × provider `severity_weight` (CIM path; 0.3–1.2) × identity `risk_multiplier` (1.0–2.0) × `..._blocked_factor` (0.5) when everything was blocked.
  - `risk_score = min(45, max(5, round(...)))`. A single match therefore stays below the 60-point `medium_risk_threshold` in `ai_detection_config` even for a privileged identity. It needs corroboration from another detection before the user threshold fires. The unsanctioned rule caps at 80: here the destination is approved, but the content is not.
  - ES applies a row's `risk_score` to every risk object in that row. A row that names both a user and a host is therefore split into two rows (`risk_target` = `user` / `system`), and the host row gets half the user score (minimum 5). The literal `_risk` scores (user 20, system 10) are the fallback when `risk_score` is absent.
- **Cadence and suppression:** hourly (`23 * * * *`, `-65m@m` to `-5m@m`), suppressed 24 h per `user`+`src`. A user produces at most one risk event a day from this rule.
- **Output fields:** `risk_target`, `user_display`/`src_display`, `provider`, `ai_domains` (normalised host or Copilot app host), `data_sources`, `violations`, `dlp_policies`, `dlp_types`, `dlp_actions`, `policy_modes` (`enforced`/`simulation`), `dlp_severity_max`, `dlp_outcome`, `objects`, `vendor_product`, `risk_multiplier`, `risk_score`, `mitre_attack` (T1567 Exfiltration Over Web Service).

### Tuning macros
| Macro | Ships as | Purpose |
|---|---|---|
| `hdsi_ai_sanctioned_dlp_violation_filter` | `()` | CIM path exclusions inside the `tstats` where clause (`DLP_Incidents.*` names) |
| `hdsi_ai_sanctioned_dlp_violation_content_evidence` | CIM `dlp_type` or a data-class policy name | CIM path content gate. Keep identical to `hdsi_ai_dlp_violation_on_service_upload_content_evidence` |
| `hdsi_ai_sanctioned_dlp_violation_purview_events` | `index=* sourcetype="o365:management:activity" Operation="DLPRuleMatch"` | Purview base search. Set the O365 index; append `NOT` terms for policies to ignore |
| `hdsi_ai_sanctioned_dlp_violation_purview_window` | 72 h event time, last hour by index time | Late-arrival handling. Keep the index window aligned with the dispatch window |
| `hdsi_ai_sanctioned_dlp_violation_purview_ai_scope` | first-party AI host category or `Copilot*` location | Which Purview locations count as sanctioned AI |
| `hdsi_ai_sanctioned_dlp_violation_purview_content_evidence` | SIT present or rule severity medium/high | Purview content gate |
| `hdsi_ai_sanctioned_dlp_violation_purview_min_confidence` | `85` | SIT confidence floor (65 low, 75 medium, 85 high); high-impact types count from 75 |
| `hdsi_ai_sanctioned_dlp_violation_purview_ignored_types` | `"^(ip address)"` | SIT names that never count |
| `hdsi_ai_sanctioned_dlp_violation_high_impact_types` | credentials, secrets, tokens, cards, bank accounts, US SSN | Raises the base score to 30. Add the national IDs your organisation holds |
| `hdsi_ai_sanctioned_dlp_violation_blocked_factor` | `0.5` | Score factor when everything was blocked; `0` drops blocked rows |
| `hdsi_ai_sanctioned_dlp_violation_customizations` | `search *` | Post-aggregation hook (fields listed in the macro description) |
| `hdsi_ai_sanctioned_dlp_violation_risk_score` | `search *` | Last pipe. Rescale or override `risk_score` |

What counts as sanctioned for the CIM path lives in the common `ai_sanctioned_entities` lookup (`<user>|<provider>`, `<host>|*`, `<bunit>|<provider>`, or `*|<provider>` for the whole organisation), not in this package. The same entry moves the incident out of the incubating `hdsi_ai_dlp_violation_on_service_upload` where that rule is deployed.

### Threshold
There is no count threshold: one credential or regulated record in an AI prompt is actionable. The tenant-specific number is the Purview confidence floor. To set it, look at what your Copilot DLP policies match over 30 days and which types are noise:

```spl
index=* sourcetype="o365:management:activity" Operation="DLPRuleMatch" earliest=-30d latest=now
| rename "PolicyDetails{}.Rules{}.ConditionsMatched.SensitiveInformation{}.SensitiveInformationTypeName" as sit,
         "PolicyDetails{}.Rules{}.ConditionsMatched.SensitiveInformation{}.Confidence" as conf,
         "SessionMetadata.AppHostCategories{}" as hostcat
| where match(lower(mvjoin(hostcat,",")),"first_party") OR match(lower(coalesce(Location,"")),"^copilot")
| where isnotnull(sit)
| eval pair=mvzip(sit,conf,"#") | mvexpand pair
| eval sit=mvindex(split(pair,"#"),0), conf=tonumber(mvindex(split(pair,"#"),1))
| stats count dc(UserId) as users by sit conf
| sort - count
```

Keep the floor at 85 if foreign national-ID or tax-number types appear at 65–75 for users who do not handle such data. Lower it to 75 if your relevant types are mostly reported at 75. Put types that are never sensitive in `..._purview_ignored_types`, including types your organisation cannot hold that Purview still reports at 85 (on one validation tenant, a foreign tax-ID type and a DEA-number type). Replace `index=*` with your O365 audit index.

### Known false positives / Limitations
- **The Microsoft default Copilot DLP policy is broad.** "Default DLP policy - Protect sensitive M365 Copilot interactions" (DSPM for AI, simulation mode) matched about 25 foreign national-ID, tax-number and IP-address types on one validation tenant, mostly at confidence 65–75. That was 1–3 users a day. The confidence floor, the ignored-types list and the narrowed high-impact list cut 30 days from 4 users and 68 items to 2 users. **Those 2 are still probably noise:** they matched a foreign tax-ID type and a DEA-number type that the policy reported at confidence 85, from a simulation-mode policy. A confidence floor cannot remove types that Purview reports at high confidence. Run the threshold search, then add those type names to `..._purview_ignored_types`. Non-high-impact types score 20, not 30, so such residue adds little risk.
- **Access rules on the Copilot location dominate the volume.** On one tenant about 6,000 `DLPRuleMatch` events a day came from a low-severity simulation rule that stops Copilot processing external email, touching about 1,400 users a week. They carry no sensitive type and are dropped by the content gate. If your tenant rates such rules medium/high, exclude them in `..._purview_events`.
- **Simulation rules count.** In simulation (`TestWithNotifyUser`/`TestWithoutNotifyUser`) nothing is enforced, so the content did reach Copilot. Each finding shows `policy_modes`. On the validation tenant the same prompt usually matched both an enforced rule and its simulation twin; distinct items are counted, so it is not double-counted.
- **Pattern matches are not proof.** "All Credential Types" and "General Password" also fire on documentation examples and test credentials, often at confidence 75 and from simulation-mode rules. One such match scores 30 (45 at most with a privileged identity), which is not enough to cross a user threshold alone. The risk message carries the type names, not the values; check the Purview alert or Activity Explorer for the matched value.
- **Third-party AI governed by Purview** (Edge inline DLP, network DLP, connected ChatGPT Enterprise) is out of scope for the Purview path, because no validation tenant had such events to confirm the field shape. Map that feed to the DLP model and allow-list the provider to use the CIM path.
- **CIM path: group allow-list entries need ES identities.** A `<bunit>|<provider>` entry matches only users that resolve in `identity_lookup_expanded` (raw value or bare account name). The common macro takes the group from `user_group`, `user_category` or `bunit` on the row first, then the identity `bunit`, then `category`; DLP incidents usually carry none of the row fields, so the identity `bunit` decides. Host-only incidents have no group: use host entries for them.
- **CIM path: version coupling.** The complement holds only while this package and `hdsi_ai_dlp_violation_on_service_upload` run against the same `hdsi_ai_rba_common` and keep the same content gate. With an older common package (no identity `bunit` or `*|<provider>` keys), a group or organisation-wide entry would drop an incident from neither or both rules.
- **CIM path: Microsoft 365 Copilot hosts.** The Copilot Chat hosts `copilot.cloud.microsoft` and `m365copilotapp.svc.cloud.microsoft`, and the Microsoft 365 Copilot CASB/App-ID names (`microsoft 365 copilot`, `microsoft copilot studio`, `ms-office365-copilot*`), ship disabled in the common registries because after the Microsoft MC1462915 redirect they are the generic Microsoft 365 home page. A CIM incident to them is therefore ignored by both DLP rules. `copilotstudio.microsoft.com`, `copilotforfinance.microsoft.com` and the PAN App-IDs `ms-copilot-studio`/`ms-copilot-studio-post` map to `Microsoft 365 Copilot` with `enabled=1`, so a CIM incident naming them does match and needs a `Microsoft 365 Copilot` allow-list entry to land here (the shipped example `*|microsoft 365 copilot` is disabled). The Purview path covers Copilot prompts without any of these hosts.
- **Late data.** The O365 audit API delivers `DLPRuleMatch` late. Over 30 days (all `DLPRuleMatch`, including out-of-scope locations), lag reached 5.7 days on Tenant C (p90 about 2.7 h, p99 about 8.3 h) and 36 h on Tenant A (p99 about 35 h). The in-scope events that score, Copilot prompts with a sensitive type, lagged at most about 6.5 h over 30 days on Tenant C and under 7 minutes over 7 days on Tenants A and C. The 72 h event-time lookback covers Tenant A's 30-day maximum and Tenant C's p99, and in live tests it cost the same as 24 h. Events later than 72 h are missed. The CIM path uses an event-time window, so a laggy CIM DLP feed needs a wider `dispatch.earliest_time`.
- **Subsearch limits.** The Purview path is an `append` subsearch: 60 s and 50,000 rows by default. It aggregates per user before returning, and one hourly slot took 1–7 s on the validation tenants.

### Validation
Read-only live tests on 4 production ES tenants, 2026-10-09. Parse checks (search and 3 drilldowns) and the hourly run are from the final version (per-policy CIM grouping, per-rule Purview outcome, 72 h lookback). The 30 d replays are from the previous round: the Purview gate and scoring are unchanged since, and on Tenant C every in-scope match in the last 7 days had one rule per event, so the per-rule outcome change does not alter those results.

| Tenant | Purview Copilot DLP | CIM DLP model | v1.0 | v1.1 parse | v1.1 rows: hourly run / 30 d replay | Notes |
|---|---|---|---|---|---|---|
| A | Yes: Microsoft default Copilot policy (simulation), about 6 matched items a day, 1–4 users | Data-at-rest file auditing only (about 100/7 d, internal file servers) | FATAL `Data_Loss_Prevention` not found | OK | 0 / 2 users | Without the confidence floor: 4 users, mostly foreign national-ID types at 65–75. Remaining: a tax-ID type and a DEA-number type at confidence 85 from the simulation-mode default policy, score 20. Probably noise: add both to `..._purview_ignored_types`. Hourly run 16 s |
| B | No O365 audit data | None; `cim_DLP_indexes` = `()` | FATAL | OK | 0 / 0 (7 d) | The 7 d replay took 109 s because the DLP model is unscoped. The hourly run took 16 s; CIM prereq over `-1d@d` 21 s |
| C | Yes: about 6,000 matches a day on Copilot locations, about 99% of them (30 d) from a low-severity external-email access rule on `Copilot.M365`; sensitive-type matches in prompts on about 1 user-day a day | Data-at-rest only (6/7 d); CASB alerts outside `cim_DLP_indexes` | FATAL | OK | 0 / 23 users | All 23 had credential, password, cloud client secret/token, payment-card or US SSN types in Copilot prompts (Office, Outlook, Teams). Score 30, outcome not blocked (web-grounding restriction or simulation). The external-email rule (about 1,400 users a week) and label-only matches were gated out. 7 d: every in-scope match had a single rule; about 37,000 simulation-only matches carried `ContentBlocked` remediation (not used as block evidence). Hourly run 11 s |
| D | O365 audit present, no `DLPRuleMatch` | None in the model | FATAL | OK | 0 / 0 | Hourly run 6 s; 30 d replay 65 s; CIM prereq over `-1d@d` 18 s (103 s over 7 d). The new `searches` prereq (Copilot `DLPRuleMatch` in 7 d) is false here, so the package is not deployed |

A synthetic test ran the final rendered search on Tenant D with hand-built CIM incident rows, hand-built Purview events and test-only allow-list entries in place of the shipped lookup:
- Kept (user score / host score): a user allow-listed for OpenAI uploading a credit-card file to `chatgpt.com` (high, 30 / 15); a user whose group (`bunit`) is allow-listed for OpenAI (medium, 20 / 10); an organisation-wide `*|anthropic` entry for an upload to `claude.ai` (medium, 20 / 10); a user allow-listed for `*` with 500 "Block GenAI Apps" alerts and one blocked "PCI Outbound" hit through the CASB app name `ChatGPT` (only the PCI hit counted: `violations=1`, medium, blocked, 10 / 5).
- Dropped: a non-allow-listed user, an expired entry, a disabled entry, and access-control alerts that carry a file name and a high severity but no data type or data-class policy name (the earlier gate kept these).
- Purview outcome: an enforced notify-only rule plus a simulation `BlockAccess` rule in the same event scored `not blocked` (30; the per-event test gave `blocked`, 15); an enforced `RestrictAccess` rule scored `blocked` (15); an enforced `RestrictWebGrounding` rule scored `not blocked` (30).
- The group case set `bunit` on the row, which the common macro reads before its own identity lookup; the identity lookup itself was not exercised, because test identities cannot be added to a production tenant.

### Deployment
The package ships with `enable_alerting: false`. Before you enable it:
1. Set the O365 audit index in `..._purview_events`.
2. Run the threshold search, and review the confidence floor and the ignored types against your Copilot DLP policies.
3. If you have an egress DLP/CASB feed in the DLP model, populate `ai_sanctioned_entities` with user, host, `bunit` or organisation-wide (`*|<provider>`) entries, so the CIM path has something to complement.
4. Measure the daily suppressed risk shape for one week.

The rule is risk-only (no notable). Enabling it is a separately approved change.
