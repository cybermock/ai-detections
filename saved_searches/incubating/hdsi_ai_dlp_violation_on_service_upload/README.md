## Architect Notes
---
**Author:** Trevor Mock, Hurricane Labs LLC. Security Operations Architect

> **Incubating — not released.** This package lives in `saved_searches/incubating/` because it has only been proven with synthetic test events; none of the four validation tenants had an egress DLP or CASB incident feed in the CIM `DLP` model. Promote it to `saved_searches/packages/` only after it produces real results in a customer environment (see [`saved_searches/incubating/README.md`](../README.md)).

This rule raises risk when a **DLP control matched sensitive content moving to an unsanctioned AI service**. Examples are a PCI file uploaded to ChatGPT, PII pasted into DeepSeek, or source code posted to an AI API. It reads CIM DLP incidents (`DLP.DLP_Incidents`), keeps only incidents with content evidence (a DLP data type or a data-class policy name), and resolves each incident's destination host (`dest`) or application name (`app`) to an AI provider through the common `ai_domains_filter`. Incidents whose user, host or identity group is allow-listed for that provider in `ai_sanctioned_entities` are dropped. When it fires, it is the strongest single AI data-exposure signal in the pack. It raises risk on the user and on the source host. It creates no notable.

**Deployment type: ad hoc.** The logic is validated, but it depends on one data feed. That feed is an egress DLP or CASB incident feed (inline web/CASB DLP, endpoint DLP with browser or upload channels, or Purview Endpoint DLP) mapped to the DLP data model with `dest` or `app` naming the destination. None of the four validation tenants had such a feed in the model. Deploy the rule where the readiness check below returns AI-bound incidents.

v1.0 could not run anywhere:
- It read a data model named `Data_Loss_Prevention`. That name does not exist, so every run was a FATAL error. The CIM model is `DLP`, dataset `DLP_Incidents`.
- It grouped by `DLP.file_name`, which is not a CIM DLP field. `tstats` would have dropped every row.
- It used the `$_mult_user_risk$` token as a risk score, which ES does not support. The score reached about 270.
- It turned unknown users and hosts into the literal risk object `unknown`.

### Prerequisites
| Data | Fields used | If absent or poor |
|---|---|---|
| `DLP.DLP_Incidents` (CIM, tags `dlp` + `incident`, scoped by `cim_DLP_indexes`) | `dest`, `app`, `user`/`src_user`, `src`, `object`, `signature`, `dlp_type`, `severity`, `action`, `vendor_product` | No incidents: the rule stays silent. If `dest` and `app` are both missing, the destination cannot be resolved and the row is dropped. Data-at-rest scanners (file-share auditing) never name an AI destination and produce nothing |
| `cim_DLP_indexes` macro | must include the DLP/CASB alert index | On Tenant C it listed only a file-auditing index, and on Tenant A that index plus one other non-DLP index. On Tenants B and D it was `()`, which searches every index. A CASB alert index left out of the macro is invisible to the model |
| ES `identity_lookup_expanded` | `bunit` (group allow-list key, looked up by `ai_unsanctioned_filter` itself; also shown in the output); `bunit`, `category`, `priority` (through `ai_risk_multiplier`) | Missing identities score with multiplier 1.0, and `<group>\|<provider>` allow-list entries cannot match them |

- **Acceleration is not required.** The search runs `summariesonly=false`. DLP incident volume is small, and the DLP model was not accelerated on any of the four tenants. With `summariesonly=true` the rule would return nothing on all four. The hourly window took 4–10 s on every tenant. Longer windows cost more where `cim_DLP_indexes` is `()`, because the tag search then covers every index: 7-day searches on such a tenant took 1–5 minutes. Scope `cim_DLP_indexes` before running the readiness check there. If you accelerate `DLP`, the search uses the summaries automatically.
- **Common package `hdsi_ai_rba_common`:**
  - `ai_domains_filter`: provider resolution from `ai_provider_domains` and `ai_provider_apps`, including CASB app names such as `chatgpt`, `google bard` or `anthropic`.
  - `ai_unsanctioned_filter(3)`: allow-list by user, host, identity group (`bunit`) or organisation-wide (`*|<provider>`), per provider.
  - `ai_risk_multiplier`: identity sensitivity.

### How it works
- **Base search:** `tstats summariesonly=false fillnull_value="unknown"` over `DLP.DLP_Incidents`, grouped by `user`, `src_user`, `src`, `dest`, `app`, `signature` and `dlp_type`. It collects `object`, `severity`, `action` and `vendor_product`. Grouping by policy and data type means each row holds the hits of one policy only, so the content gate below judges each policy hit separately. `fillnull_value` keeps incidents that lack one of the group-by fields.
- **Identity hygiene:** `user = coalesce(user, src_user)`. The values `unknown`, empty, `SYSTEM`/service accounts and machine accounts (`...$`) become null. A null `src` stays null. Rows with neither a user nor a host, or with neither `dest` nor `app`, are dropped. No risk object is ever the literal `unknown`.
- **Content-evidence gate (`..._content_evidence`):** each policy row is kept only if it shows a content-inspection hit: a CIM `dlp_type`, or a policy/signature name that names a data class (DLP, PII, PCI, PHI, SSN, card numbers, secrets, passwords, API or private keys, source code, confidential, classified…). A file name (`object`) or a rated `severity` on its own is **not** evidence. CASB/SSE add-ons tag access-control, malicious-site and threat alerts as `dlp`+`incident` too, and those alerts carry file names (download/upload activity) and severities. On one validation tenant, GenAI app-blocking alerts tagged this way resolved to AI providers about 35,000 times a day. The gate removes all of them. Because it runs before aggregation, an access-control alert never adds to the count, severity, outcome or policy list of a user who also has a genuine DLP hit.
- **Destination resolution:** `ai_domain = mvappend(dest, app)` and `mvexpand`. `ai_domains_filter` resolves a hostname or URL in `dest` (exact, subdomain or cloud AI endpoint patterns) or a CASB application name in `app`. That name passes the app-name gate because it equals the row's `app`. `dedup` on the pre-expansion row keeps one match per incident row, so counts are not doubled. Only enabled providers survive. Opt-in rows such as Microsoft 365 Copilot count only after a tenant enables them.
- **Allow-list:** `ai_unsanctioned_filter(user,src,provider)` removes approved `<user>|<provider>`, `<host>|<provider>` and `<bunit>|<provider>` pairs, `|*` entries for any provider, and organisation-wide `*|<provider>` entries. Matching is case-insensitive and expired or disabled entries are ignored. The macro looks up the user's ES identity `bunit` itself (raw user value first, then the bare name without `DOMAIN\` or `@suffix`). The search then looks up `bunit` again for display only. DLP hits to sanctioned providers belong to `hdsi_ai_sanctioned_dlp_violation`.
- **Aggregation:** one row per `user` + `src`. The row carries the incident count (`violations`), providers, normalised AI domains, policies, objects (first five), DLP types/actions/vendor, highest DLP severity (`critical`, `high`, `medium`, `low`, `informational` or `unrated`) and outcome. All of these come from content-evidence rows only. The outcome is `blocked` only when every action was block/deny/quarantine/prevent/restrict.
- **Scoring (dynamic, applied to both risk objects):**
  - Base 60 for high or critical DLP severity, 50 for medium or unrated, 35 for low or informational.
  - The base is multiplied by the provider `severity_weight` (0.3–1.2), by the identity `risk_multiplier` (1.0–2.0) and, for fully blocked rows, by `..._blocked_factor` (0.5).
  - `risk_score = min(80, max(10, round(...)))`. The literal `_risk` scores (user 60, system 30) are the fallback.
  - Examples: a typical unblocked high-severity upload to ChatGPT scores 60. A blocked medium-severity one scores 25. A critical hit to an AI API endpoint by a sensitive identity is capped at 80.
- **Output fields:** `user_display`/`src_display` (readable when one side is missing), `provider`, `ai_domains`, `usage_types`, `bunit`, `violations`, `dlp_policies`, `dlp_types`, `dlp_actions`, `dlp_severity_max`, `dlp_outcome`, `objects`, `vendor_product`, `risk_multiplier`, `risk_score`, `mitre_attack` (T1567 Exfiltration Over Web Service).
- **Drilldowns:** the user's risk events, and that user's or host's DLP incidents grouped per policy, with a `content_evidence` yes/no column showing which rows the gate scored. The incident drilldown covers every destination, not only AI services.
- **Cadence and suppression:** hourly (`-65m@m` to `-5m@m`), suppressed for 24 h per `user`+`src`. One user/host pair produces at most one risk event a day, and the message lists every provider seen in that window.

### Tuning macros
| Macro | Ships as | Purpose |
|---|---|---|
| `hdsi_ai_dlp_violation_on_service_upload_filter` | `()` | Exclusions inside the `tstats` where clause (`DLP_Incidents.*` names), e.g. `NOT DLP_Incidents.vendor_product="<data-at-rest scanner>*"`, or `NOT DLP_Incidents.signature IN ("<access-control policy>")` for an app-blocking policy whose name happens to contain a data-class word |
| `hdsi_ai_dlp_violation_on_service_upload_content_evidence` | `dlp_type` present, or a data-class word in `signature` | Eval condition, evaluated per policy row before aggregation, that separates content DLP hits from access-control and threat alerts. If your DLP policy names contain no data-class word, add your naming convention (for example `match(signature,"^<your DLP policy prefix>")`). Use `true()` only if the feed contains nothing but content incidents |
| `hdsi_ai_dlp_violation_on_service_upload_blocked_factor` | `0.5` | Score factor when every incident in the row was blocked. `1` = treat it like a completed upload, `0` = drop blocked attempts |
| `hdsi_ai_dlp_violation_on_service_upload_customizations` | `search *` | Post-aggregation hook (fields listed in the macro description) |
| `hdsi_ai_dlp_violation_on_service_upload_risk_score` | `search *` | Last pipe. Rescale or override `risk_score` |

Approved AI use, for example an enterprise ChatGPT workspace for one department, belongs in the common `ai_sanctioned_entities` lookup (`<user>|<provider>`, `<bunit>|<provider>`, `<host>|*`, or `*|<provider>` for the whole organisation), not in this package. A group entry matches the user's ES identity `bunit`, so it works only for users present in the ES identity framework (matched on the raw user value or the bare account name).

### Readiness check (no count threshold)
One content DLP incident to an unsanctioned AI service is already actionable, so the rule has no count threshold. The `package.yml` prerequisite search is a coarse pointer: it checks for DLP incidents whose `app` or `dest` contains the name of a well-known AI service or cloud AI endpoint (Azure OpenAI, Bedrock, Vertex AI) in the last 7 days. Data-at-rest file auditing alone does not satisfy it. It does not apply the opt-in and allow-list rules, so the search below is the authoritative check. Before you enable the rule, run this search over 7 days (scope `cim_DLP_indexes` first if it is `()`). It shows how many incidents resolve to AI providers and how many of those carry content evidence:

```spl
| tstats summariesonly=false allow_old_summaries=true fillnull_value="unknown" count
    values(DLP_Incidents.object) as object values(DLP_Incidents.severity) as dlp_severity
    from datamodel=DLP.DLP_Incidents
    by DLP_Incidents.vendor_product DLP_Incidents.dest DLP_Incidents.app DLP_Incidents.signature DLP_Incidents.dlp_type
| rename DLP_Incidents.* as *
| eval object=mvfilter(object!="unknown"), dlp_severity=mvfilter(dlp_severity!="unknown"), signature=nullif(signature,"unknown"), dlp_type=nullif(dlp_type,"unknown")
| eval has_destination=if(dest!="unknown" OR app!="unknown",1,0), content_evidence=if(`hdsi_ai_dlp_violation_on_service_upload_content_evidence`,1,0)
| eval ai_domain=mvappend(nullif(dest,"unknown"),nullif(app,"unknown")), dlp_row=dest."|".app."|".vendor_product."|".coalesce(signature,"")."|".coalesce(dlp_type,"")
| mvexpand ai_domain
| `ai_domains_filter`
| dedup dlp_row
| stats sum(count) as ai_incidents sum(eval(count*content_evidence)) as ai_incidents_with_content values(provider) as providers by vendor_product
```

`ai_domains_filter` drops rows that do not resolve, so this lists AI-bound incidents only (an empty result can log a harmless `Field 'ai_domain' does not exist` warning). Drop the four lines from `eval ai_domain=` to `dedup` to see every incident with its `has_destination` flag. If `ai_incidents_with_content` is 0 while `ai_incidents` is large, the feed holds access-control alerts and no content hits. Extend `..._content_evidence` only after you confirm that the AI-bound rows are real DLP content matches whose policy names lack a data-class word.

### Known false positives / Limitations
- **Access-control and threat alerts tagged as DLP.** Some CASB/SSE add-ons tag every alert type (access policy, malicious site, malware, compromised credential, DLP) `dlp`+`incident`, and their DLP alerts map no CIM `dlp_type` or `severity`. On one validation tenant the rule logic was replayed on such a feed, which sits outside `cim_DLP_indexes`. Without a gate it produced 1,607 user/host rows in 24 h (about 35,000 alerts) and at least 3,876 rows in 7 days, all from GenAI app-blocking alerts on users browsing AI apps. With the gate it produced none. Unsanctioned access is covered by the Web/DNS rules in this pack. An earlier draft of this gate also accepted any file name or any rated severity (including informational). A synthetic test showed that this let an access-control alert, a malicious-site alert and a policy alert on a file download through. The shipped gate rejects all three.
- **No direction in CIM DLP.** `DLP_Incidents` has no upload/download field, so a content match on a file *downloaded from* an AI app counts like an upload. The risk message therefore says the incident "involved" the AI service. If your feed separates directions in the policy name, exclude download policies in `..._filter`.
- **Policy names drive the gate.** Where the DLP product maps no `dlp_type` (common for CASB feeds), the gate depends on the policy name containing a data-class word. A DLP policy named only for a channel (for example "Outbound policy 7") is dropped unless you add its naming convention to `..._content_evidence`. An access-control policy whose name contains a data-class word passes, so exclude it by name in `..._filter`.
- **Data-at-rest DLP** (file-share auditing, discovery scans) populates the model on two validation tenants. Its `dest` is an internal file server, so it never resolves to AI and costs one cheap search an hour. Exclude it in `..._filter` if you prefer.
- **`dest` is often an IP address** in CASB feeds (100% on the tenant with a CASB feed). Resolution then relies on `app`. Keep the CASB app names in the common `ai_provider_apps` lookup current.
- **Overlap with `hdsi_ai_sanctioned_dlp_violation`.** Both rules split incidents with the same common `ai_unsanctioned_filter`, which now derives the identity group (`bunit`) itself. This rule no longer pre-loads `bunit` before the macro, so a `<bunit>|<provider>` entry sends an incident to exactly one of the two rules. That holds only while both packages run against the current `hdsi_ai_rba_common`. With an older common package, the group key differs between the rules and an incident can be scored twice or not at all.
- **Late-arriving DLP data.** Incident APIs (CASB, Purview) can deliver events tens of minutes late. Events whose `_time` is more than about 5 minutes behind ingestion can fall between hourly windows. On laggy feeds, widen `dispatch.earliest_time` (for example `-2h@h`). The 24 h suppression absorbs the overlap.
- **Paste/post DLP without a file** has no `object`. It passes the gate through its `dlp_type` or a data-class policy name and shows `objects = not recorded`.
- **Permissive gate on a large CASB feed.** If you set `..._content_evidence` to `true()` on a feed with hundreds of thousands of AI-bound alerts, the `mvexpand` step can hit the 500 MB limit and truncate results (seen in the no-gate replay). Keep a gate on CASB feeds.

### Validation
Read-only live tests on 4 production ES tenants, 2026-10-09. The 4 h runs and parse checks are from the final version (grouped per policy). The 7 d runs and the Tenant C replay are from the previous round, which grouped per user/host/destination only. Per-policy grouping can only keep fewer rows than that, so those zero results still hold.

| Tenant | DLP model data | v1.0 | v1.1 parse (rule + 2 drilldowns) | v1.1 rows (4 h / 7 d) | Notes |
|---|---|---|---|---|---|
| A | Yes, data-at-rest file auditing only (~130 incidents/7 d, `dest` = internal file servers, no `app`); model not accelerated | FATAL `Data_Loss_Prevention` not found | OK | 0 / 0 | Correct: no egress DLP. 4 h run 10 s, 7 d run 11 s. The DLP drilldown returns the file-auditing incidents. The old prerequisite search reported "met" (132 incidents); the v1.1 AI-bound prerequisite correctly reports "not met" |
| B | None; `cim_DLP_indexes` = `()`; not accelerated | FATAL | OK | 0 / 0 | Index-unscoped tag search: 4 h run 10 s, 7 d run 63 s, 7 d prerequisite 97 s; a 7 d breakdown by vendor and index hit the 300 s job cap |
| C | Data-at-rest only in the model. A CASB alert feed tagged `dlp`+`incident` (millions of alerts a week, `dest` = IP, `app` always set) sits outside `cim_DLP_indexes` | FATAL | OK | 0 / 0 | Rule logic replayed on the CASB feed: 24 h without a gate 1,607 user/host rows, with the v1.1 gate 0; 7 d without a gate at least 3,876 rows, with the gate 0. Every AI-bound alert was an app-blocking alert on browsing; the feed's genuine DLP alerts went to non-AI apps |
| D | None in the model; a DLP product's incidents exist only in a test index and are not CIM-tagged | FATAL | OK | 0 / 0 | 4 h run 5 s, 7 d run 19 s |

Synthetic tests fed hand-built incident rows through the full rendered pipeline on Tenant A. The final round used 13 per-policy rows:
- **Kept and scored:**
  - a PCI-policy file to the ChatGPT app (high, 60)
  - a blocked medium PCI hit (25)
  - a `dlp_type`-only hit to DeepSeek with a non-descriptive policy name (unrated, 50)
  - a secrets hit to `api.openai.com:443` from a machine account (critical; user nulled, host scored 72)
  - an informational "PII Outbound" hit to claude.ai (reported as `informational`, 35)
- **Dropped:** an app-blocking alert, an informational "access control" alert (scored 35 in v1.0), a malicious-site alert with a file name and `med` severity, and the opt-in M365 Copilot destination. The previous round also dropped a policy alert on a file download and a compromised-credential alert.
- **Mixed user/host/app (the per-policy fix):** 500 high-severity "Block GenAI Apps" alerts and one blocked medium "PCI Outbound" hit for the same user, host and ChatGPT app. The result was `violations=1`, policy `PCI Outbound`, `medium`, `blocked`, score 25. Before per-policy grouping, the same input produced `violations=501`, both policies, `high`, `not blocked` and score 60.
- **Group allow-list:** with `engineering|google gemini` and `finance|openai` enabled in `ai_sanctioned_entities`, the PII hit by an `engineering` user to Gemini and the confidential hit by a `Finance` user to ChatGPT were dropped. With the shipped (disabled) entries, both were scored (60 and 50).
- **Readiness check:** the per-policy version below parsed and ran on Tenant A (4 h, 11 s, 0 AI-bound incidents).

### Deployment
The package is configured with `enable_alerting: false` and `deployment_type: adhoc`, the type it takes once promoted to `saved_searches/packages/`. Before you enable it:
1. Confirm that the DLP/CASB incident index is in `cim_DLP_indexes`.
2. Run the readiness check, and confirm that AI-bound incidents carry content evidence (a `dlp_type` or a data-class policy name).
3. Review the `ai_sanctioned_entities` allow-list (user, host or ES identity `bunit` per provider), so approved AI services do not raise risk.
4. Measure the daily suppressed risk shape for one week.

The rule is risk-only (no notable). Enabling it is a separately approved change.
