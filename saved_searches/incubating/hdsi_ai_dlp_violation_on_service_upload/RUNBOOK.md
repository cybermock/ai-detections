# AI-020 - DLP Violation On AI Service Upload

> **Incubating — not released.** This package lives in `saved_searches/incubating/` because it has only been proven with synthetic test events; none of the four validation tenants had an egress DLP or CASB incident feed in the CIM `DLP` model. Promote it to `saved_searches/packages/` only after it produces real results in a customer environment (see [`saved_searches/incubating/README.md`](../README.md)).

> **AD HOC PACKAGE (once promoted).** `deployment_type: adhoc`. This rule needs an **egress DLP or CASB incident feed** (inline web/CASB DLP, endpoint DLP with browser or upload channels, or Purview Endpoint DLP) mapped to the CIM `DLP` model (dataset `DLP_Incidents`) with `dest` or `app` naming the destination. None of the 4 validation tenants had such a feed in the model. Deploy it only where the readiness check in Tuning Guidance returns AI-bound incidents with content evidence.

> **Detection ID:** AI-020 (package `hdsi_ai_dlp_violation_on_service_upload`, `detection_id="hdsi_ai_dlp_violation_on_service_upload"`)
> **Search name:** `Audit - HDSI AI DLP Violation On Service Upload - Rule`
> **Status:** Incubating (not released). Ad hoc once promoted, with `enable_alerting: false`
> **Output:** Risk only (`action.notable = 0`). Notables come from the `Threat - HDSI RBA AI ...` aggregators
> **Risk Score:** Dynamic on `user` and `src` (system): base 60 (high/critical DLP severity), 50 (medium or unrated), 35 (low/informational), x provider `severity_weight` (0.3-1.2) x `risk_multiplier` (1.0-2.0) x `..._blocked_factor` (0.5 when every incident was blocked); clamped 10-80. Literal `_risk` fallback user 60 / system 30
> **MITRE ATT&CK:** T1567 - Exfiltration Over Web Service (Exfiltration)
> **Data Model:** `DLP.DLP_Incidents` (CIM `DLP`; the old `Data_Loss_Prevention` name does not exist)
> **Schedule:** `11 * * * *` (hourly at :11)
> **Lookback Window:** `-65m@m` to `-5m@m`; suppression 24 h (`86400s`) per `user,src`
> **Kill Chain Phase:** `ai_kill_chain_phase="exfiltration"`
> **Last Updated:** 2026-10-09

---

## Overview

This detection raises risk when a **DLP control matched sensitive content moving to an unsanctioned AI service**: a PCI file uploaded to ChatGPT, PII pasted into DeepSeek, source code posted to an AI API. It reads CIM DLP incidents, keeps only those with content evidence (a DLP data type or a data-class policy name), and resolves the destination host (`dest`) or CASB application name (`app`) to an AI provider through the common `ai_domains_filter`. Approved providers for the user, host or business unit are removed.

When it fires it is the strongest single AI data-exposure signal in the pack. It is an exfiltration-phase input to `Threat - HDSI RBA AI Data Collection Kill Chain - Rule` and counts in the `data_exposure` vector of the multi-vector aggregator. DLP hits to **sanctioned** providers go to `Audit - HDSI AI Sanctioned DLP Violation - Rule` instead; the two rules split incidents with the same allow-list.

v1.0 could not run anywhere (non-existent model name, a non-CIM `file_name` group-by, a `$token$` risk score that reached about 270, and `unknown` risk objects). The current version fixes all four.

---

## MITRE ATT&CK Mapping

| Field | Value |
|---|---|
| Technique ID | T1567 |
| Technique Name | Exfiltration Over Web Service |
| Tactic | Exfiltration |
| Sub-technique | N/A |

---

## Detection Logic

### Plain English

1. `tstats summariesonly=false fillnull_value="unknown"` over `DLP.DLP_Incidents` where `dest` or `app` is set, grouped by `user`, `src_user`, `src`, `dest`, `app`, `signature` and `dlp_type` (one row per policy hit). Acceleration is not required.
2. `user = coalesce(user, src_user)`. Placeholders, `SYSTEM`/service and machine accounts become null. Rows with neither user nor host, or with neither `dest` nor `app`, are dropped.
3. **Content-evidence gate** (`..._content_evidence`): each policy row must have a CIM `dlp_type` or a policy/signature name that names a data class (PII, PCI, PHI, SSN, secrets, source code, confidential...). A file name or a severity alone is not evidence. This removes CASB access-control and threat alerts that add-ons also tag `dlp`+`incident`.
4. `ai_domain = mvappend(dest, app)`, `mvexpand`, then `ai_domains_filter` resolves a hostname/URL or CASB app name to an enabled AI provider; `dedup` keeps one match per incident row.
5. `ai_unsanctioned_filter(user,src,provider)` removes approved `<user>|<provider>`, `<host>|<provider>`, `<bunit>|<provider>`, `|*` and `*|<provider>` pairs.
6. Rows are aggregated to one per `user` + `src` (incident count, providers, AI domains, policies, objects, DLP types/actions/vendor, highest severity, outcome), then scored with `ai_risk_multiplier`.

### Key Fields

| Field | Description | Example Value |
|---|---|---|
| `user`, `src` | Risk objects (either may be null) | `jdoe@example.com`, `ws-0142` |
| `user_display`, `src_display` | Readable values when one side is missing | `no attributed host` |
| `provider`, `ai_domains`, `usage_types` | AI provider(s), resolved destinations and registry usage type | `OpenAI`, `chatgpt`, `web` |
| `violations` | Content-evidence incidents in the window | `3` |
| `dlp_policies`, `dlp_types` | Policy names and CIM data types (first five) | `PCI Outbound` |
| `objects` | Files involved (first five) or `not recorded` (paste/post) | `cards_q3.xlsx` |
| `dlp_severity_max`, `dlp_actions`, `dlp_outcome` | Highest severity, actions, `blocked` / `not blocked` | `high`, `allowed`, `not blocked` |
| `vendor_product`, `bunit` | DLP product and ES identity business unit | `<CASB product>`, `finance` |
| `severity_weight`, `risk_multiplier`, `risk_score` | Scoring inputs and result | `1.0`, `1.0`, `60` |

### Thresholds

| Parameter | Default Value | Macro | Notes |
|---|---|---|---|
| Count threshold | none | n/a | One content DLP incident to an unsanctioned AI service is actionable |
| Content evidence | `dlp_type` present, or data-class word in `signature` | `hdsi_ai_dlp_violation_on_service_upload_content_evidence` | Add your policy naming convention if it names no data class |
| Blocked factor | `0.5` | `hdsi_ai_dlp_violation_on_service_upload_blocked_factor` | `1` = score blocked like completed; `0` = drop fully blocked rows |
| Score clamp | 10-80 | (in SPL) | Override in `..._risk_score` |

---

## Triage Steps

> **Estimated triage time:** 15-20 minutes. Replace `<user>`, `<src>` and `<provider>` with the risk event values. If `cim_DLP_indexes` is `()` on the tenant, keep time ranges short: the tag search then covers every index.

### Step 1: Validate the risk event

```spl
| from datamodel:"Risk.All_Risk"
| search source="Audit - HDSI AI DLP Violation On Service Upload - Rule" (risk_object="<user>" OR risk_object="<src>")
| table _time risk_object risk_object_type risk_score risk_message
| sort - _time
```

- The message lists the policies, objects, highest DLP severity and outcome.
- `outcome blocked` means the control worked; the risk is the attempt.

### Step 2: Identify the user and host

```spl
| inputlookup identity_lookup_expanded
| search identity="<user>"
| table identity first last email managedBy priority bunit category
```

```spl
| inputlookup asset_lookup_by_str
| search ip="<src>" OR dns="<src>" OR nt_host="<src>"
| table ip dns nt_host owner priority bunit category
```

- Does the user's role justify handling the data class named by the policy?
- Missing identities score with multiplier 1.0 and cannot match group approvals.

### Step 3: Review the DLP incidents

Same as the rule's second drilldown; `content_evidence` shows which rows the gate scored. It covers every destination, not only AI services:

```spl
| tstats summariesonly=false allow_old_summaries=true fillnull_value="unknown" count min(_time) as firstTime max(_time) as lastTime values(DLP_Incidents.object) as objects values(DLP_Incidents.severity) as dlp_severity values(DLP_Incidents.action) as dlp_action values(DLP_Incidents.vendor_product) as vendor_product from datamodel=DLP.DLP_Incidents where (DLP_Incidents.user="<user>" OR DLP_Incidents.src_user="<user>" OR DLP_Incidents.src="<src>") by DLP_Incidents.user DLP_Incidents.src DLP_Incidents.dest DLP_Incidents.app DLP_Incidents.signature DLP_Incidents.dlp_type
| rename DLP_Incidents.* as *
| eval signature=nullif(signature,"unknown"), dlp_type=nullif(dlp_type,"unknown")
| eval content_evidence=if(`hdsi_ai_dlp_violation_on_service_upload_content_evidence`,"yes","no")
| convert ctime(firstTime) ctime(lastTime)
| table firstTime lastTime user src dest app signature dlp_type content_evidence dlp_severity dlp_action objects vendor_product count
| sort - content_evidence - count
```

- Open the incident in the DLP or CASB console for the matched content snippet, file hash and full policy detail.
- CIM DLP has no direction field: confirm in the console whether the content was **uploaded to** the AI service or **downloaded from** it.
- If `dest` is an IP, the provider came from the CASB `app` name.

### Step 4: Check for related detections

```spl
| from datamodel:"Risk.All_Risk"
| search (risk_object="<user>" OR risk_object="<src>") source="*HDSI AI*"
| stats sum(risk_score) as total_risk dc(source) as detections values(source) as sources by risk_object risk_object_type
| sort - total_risk
```

- Run over `-24h` and `-7d`. A collection detection before this one (`Endpoint - HDSI AI Copy-Paste Correlation To AI Service - Rule`, `Endpoint - HDSI AI Usage Following Data Access Spike - Rule`) is the data-collection kill chain.
- User thresholds: medium 60, critical 90 in a rolling 24 h. A single unblocked high-severity hit scores 60.

### Step 5: Determine sanctioned status

```spl
| inputlookup ai_sanctioned_entities
| eval allow_key=lower(allow_key)
| search allow_key IN ("<user>|<provider>", "<src>|<provider>", "<bunit>|<provider>", "<user>|*", "<src>|*", "*|<provider>")
| table entity_type entity provider scope expires owner reason enabled allow_key
```

- If the provider is approved for this user or group, the incident belongs to `Audit - HDSI AI Sanctioned DLP Violation - Rule`; an event here means the approval is missing, expired or disabled.

### Step 6: Make a determination

- **True Positive:** regulated or confidential content sent to an unsanctioned AI service.
- **Benign True Positive:** an approved AI service whose approval is missing from `ai_sanctioned_entities`, or test data deliberately matching a DLP policy.
- **False Positive:** the alert is an access-control or threat alert whose policy name contains a data-class word, or a download from the AI service rather than an upload.

---

## True Positive Indicators

- `dlp_outcome = not blocked` and `dlp_severity_max` high or critical.
- The data class (PCI, PHI, PII, secrets, source code) is regulated or business-critical.
- Multiple `violations` or multiple providers in one window.
- The user has no business need for the data class, or `risk_multiplier` > 1 (sensitive business unit or privileged).
- A collection-phase AI detection precedes the incident (kill-chain aggregator notable).

---

## False Positive Scenarios

| Scenario | Likelihood | Mitigation |
|---|---|---|
| CASB/SSE access-control or app-blocking alert whose policy name contains a data-class word | Medium | Exclude the policy by name in `..._filter` (`NOT DLP_Incidents.signature IN ("<policy>")`). The gate already removed about 35,000 GenAI app-blocking alerts a day in the Tenant C replay |
| Content downloaded from the AI service (no direction in CIM DLP) | Medium | Exclude download policies in `..._filter` if the feed names direction in the policy |
| Approved AI service missing from the allow-list | Medium | Add `<user>|<provider>` / `<bunit>|<provider>` / `*|<provider>` approvals |
| Blocked attempt | Medium | Already scored at half weight; set `..._blocked_factor` to `0` to drop fully blocked rows |
| Data-at-rest DLP (file-share auditing) | None (never resolves to AI) | Optionally exclude the scanner in `..._filter` to save search cost |

---

## Response Actions

### If confirmed True Positive

1. **Contain:** block uploads to the provider for the user or group in the DLP/CASB policy (or move the policy from monitor to block).
2. **Notify:** the user's manager, data governance / privacy, and legal or compliance for regulated data (PCI, PHI, PII may be reportable).
3. **Investigate:** retrieve the matched content and file from the DLP console; check whether the provider retains or trains on submissions for the account type used; look for further uploads over `-30d`.
4. **Remediate:** request deletion at the provider where possible, rotate any secrets or keys in the content, and point the user to an approved AI service.
5. **Document:** record findings in the case management system.

### If Benign True Positive

1. Add the approval to `ai_sanctioned_entities` with an `expires` date (incidents then go to the sanctioned DLP rule).
2. Document the business justification in the `reason` field.
3. Close the investigation as "Benign True Positive."

---

## Tuning Guidance

### Reducing false positives

- Confirm the DLP/CASB incident index is in `cim_DLP_indexes`; an index left out is invisible to the model.
- Exclude access-control policies whose names contain a data-class word in `..._filter`.
- If your DLP policy names contain no data-class word, add your naming convention to `..._content_evidence` (for example `match(signature,"^<your DLP policy prefix>")`). Use `true()` only if the feed holds nothing but content incidents; a permissive gate on a large CASB feed can hit the `mvexpand` memory limit.
- On laggy incident APIs, widen `dispatch.earliest_time` (for example `-2h@h`); the 24 h suppression absorbs the overlap.

### Adjusting thresholds

Readiness check (run over 7 days before enabling; scope `cim_DLP_indexes` first if it is `()`):

```spl
| tstats summariesonly=false allow_old_summaries=true fillnull_value="unknown" count values(DLP_Incidents.object) as object values(DLP_Incidents.severity) as dlp_severity from datamodel=DLP.DLP_Incidents by DLP_Incidents.vendor_product DLP_Incidents.dest DLP_Incidents.app DLP_Incidents.signature DLP_Incidents.dlp_type
| rename DLP_Incidents.* as *
| eval object=mvfilter(object!="unknown"), dlp_severity=mvfilter(dlp_severity!="unknown"), signature=nullif(signature,"unknown"), dlp_type=nullif(dlp_type,"unknown")
| eval has_destination=if(dest!="unknown" OR app!="unknown",1,0), content_evidence=if(`hdsi_ai_dlp_violation_on_service_upload_content_evidence`,1,0)
| eval ai_domain=mvappend(nullif(dest,"unknown"),nullif(app,"unknown")), dlp_row=dest."|".app."|".vendor_product."|".coalesce(signature,"")."|".coalesce(dlp_type,"")
| mvexpand ai_domain
| `ai_domains_filter`
| dedup dlp_row
| stats sum(count) as ai_incidents sum(eval(count*content_evidence)) as ai_incidents_with_content values(provider) as providers by vendor_product
```

If `ai_incidents_with_content` is 0 while `ai_incidents` is large, the feed holds access-control alerts and no content hits. An empty result can log a harmless `Field 'ai_domain' does not exist` warning.

### Adding allowlist entries

```
entity_type,entity,provider,scope,expires,owner,reason,enabled,allow_key
group,finance,OpenAI,group,2026-12-31,security,approved_chatgpt_enterprise_finance,1,finance|openai
user,jdoe@example.com,Anthropic,provider,2026-12-31,security,approved_claude_pilot,1,jdoe@example.com|anthropic
```

A group key matches the user's ES identity `bunit`, so it works only for users present in `identity_lookup_expanded`.

---

## Related Detections

| Detection ID | Name | Relationship |
|---|---|---|
| AI-038 | `Audit - HDSI AI Sanctioned DLP Violation - Rule` | The same incidents for **sanctioned** providers; the allow-list splits them between the two rules |
| AI-033 | `Audit - HDSI AI API Key Exposure In Code/DLP - Rule` | Secrets exposure, partly from the same DLP feed |
| AI-025 | `Endpoint - HDSI AI Copy-Paste Correlation To AI Service - Rule` | Collection-phase precursor (pastes into AI pages) |
| AI-007 | `Network - HDSI AI High Volume Upload To AI Service - Rule` | Volume-based upload signal without content inspection |
| AI-RISK-003 | `Threat - HDSI RBA AI Data Collection Kill Chain - Rule` | This rule is an exfiltration-phase input |
| AI-RISK-005 | `Threat - HDSI RBA AI Multi-Vector Risk - Rule` | This rule contributes to the `data_exposure` vector |

---

## Data Requirements

| Requirement | Details |
|---|---|
| Data Model | CIM `DLP`, dataset `DLP_Incidents` (tags `dlp` + `incident`, scoped by `cim_DLP_indexes`) |
| Required Fields | `dest` and/or `app` (destination), `user`/`src_user`, `src`, `signature`, `dlp_type`, `severity`, `action`, `object`, `vendor_product` |
| Sourcetype Examples | Inline web/CASB DLP, endpoint DLP with browser or upload channels, Microsoft Purview Endpoint DLP |
| CIM Compliance | `dest` (hostname/URL) or `app` (CASB app name) must name the destination; data-at-rest scanners never resolve to AI |
| Acceleration | Not required (`summariesonly=false`); used automatically if `DLP` is accelerated |
| Lookups | `ai_provider_domains`, `ai_provider_apps`, `ai_sanctioned_entities`, `identity_lookup_expanded`, `ai_department_sensitivity` (common package `hdsi_ai_rba_common`) |
| Validation (2026-10-09) | 0 rows on all 4 tenants (4 h and 7 d): no egress DLP feed in the model anywhere (Tenants A and C hold data-at-rest auditing only). Replay of the logic on a CASB feed outside `cim_DLP_indexes` on Tenant C: 1,607 user/host rows in 24 h without the content gate, 0 with it. Search and drilldowns parse on A-D |

---

## Revision History

| Date | Author | Change |
|---|---|---|
| 2026-02-13 | Brainstorm SOC | Initial creation |
| 2026-10-09 | Trevor Mock, Hurricane Labs LLC | 1.1.0: rewritten as the ad hoc package `hdsi_ai_dlp_violation_on_service_upload`. CIM `DLP.DLP_Incidents` replaces the non-existent `Data_Loss_Prevention` model; per-policy content-evidence gate; destination resolution from `dest` or CASB `app`; per-provider allow-list shared with the sanctioned DLP rule; dynamic score clamped 10-80 with blocked factor; no `unknown` risk objects; risk-only; triage SPL updated to the current search name and `Risk.All_Risk` |
| 2026-10-10 | Trevor Mock, Hurricane Labs LLC | Moved to `saved_searches/incubating/` (not released): only proven with synthetic test events; no validation tenant had the data. Was `docs/runbooks/AI-020.md` |
