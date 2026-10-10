# AI-024 - HDSI AI Browser Extension High-Volume Data Transmission

> **Incubating — not released.** This package lives in `saved_searches/incubating/` because it has only been proven with synthetic test events; none of the four validation tenants had a forward proxy, SWG or SSE that logs the destination host and request bytes for the catalogued extension backends. Promote it to `saved_searches/packages/` only after it produces real results in a customer environment (see [`saved_searches/incubating/README.md`](../README.md)).

> **Ad hoc package once promoted (`deployment_type: adhoc`).** This rule needs a forward proxy, SWG or SSE that writes the destination host **and** the request bytes (`Web.bytes_out`) for the catalogued vendors into the CIM Web model. None of the 4 validation tenants had that data in volume, so it returned 0 rows everywhere. Deploy it only to tenants that pass the prerequisite check under [Data Requirements](#data-requirements). On other tenants, AI-021 (Browser Extension Activity) covers the same products without needing bytes.

> **Detection ID:** AI-024
> **Package:** `hdsi_ai_browser_extension_high_volume_data_transmission` (v1.1.0, `deployment_type: adhoc`, requires `hdsi_ai_rba_common`)
> **Search name:** `Network - HDSI AI Browser Extension High-Volume Data Transmission - Rule`
> **Status:** Incubating (not released); ad hoc once promoted. Risk-only (`action.notable = 0`, `action.risk = 1`); the HDSI RBA AI aggregators decide when accumulated risk becomes a notable.
> **Risk Objects / Score:** `src` (system) and `user` (only when the proxy attributes exactly one real user). Dynamic: base 30 at the threshold, 40 at 5x, 50 at 20x; `risk_score = min(60, round(base x risk_multiplier))`, applied to both objects. Literal fallback 30 / 30.
> **MITRE ATT&CK:** T1567 (Exfiltration Over Web Service), T1176.001 (Software Extensions: Browser Extensions)
> **Data Model:** `Web` (forward proxy / SWG / SSE with request bytes)
> **Schedule:** `17 * * * *` (hourly at :17)
> **Lookback Window:** `-65m@m` to `-5m@m`
> **Suppression:** 24 h (`86400s`) on `src,user`
> **Kill Chain Phase:** `exfiltration` (`ai_kill_chain_phase`)
> **Last Updated:** 2026-10-09

---

## Overview

This detection finds a host that sends a **large volume of data in one hour to the backend of an extension-first AI assistant**. Monica, Sider, MaxAI, Merlin, HARPA, Tactiq, Wordtune and similar products are sold mainly as browser extensions. They read the open page, an uploaded document or a meeting transcript and post it to the vendor's own LLM backend, outside any sanctioned AI provider.

The rule adds up `Web.bytes_out` from one `src` to **all** catalogued backend hosts in the hourly window and fires when the total reaches the threshold (default 10 MB). Page and meeting text is kilobytes per request, so 10 MB in an hour means document uploads or bulk page capture.

Hosts such as `api.monica.im` and `api2.sider.ai` also serve the vendor's web app, so a finding means "data sent to this product's backend", not proof that the extension is installed. Mainstream providers' extensions (ChatGPT, Claude, Copilot, Gemini, Perplexity) share hosts with their web apps; their upload volume is covered by AI-007 (High Volume Upload To AI Service).

---

## MITRE ATT&CK Mapping

| Field | Value |
|---|---|
| Technique ID | T1567, T1176.001 |
| Technique Name | Exfiltration Over Web Service; Software Extensions: Browser Extensions |
| Tactic | Exfiltration; Persistence |
| Sub-technique | T1176.001 |

The annotation is `{"mitre_attack": ["T1567", "T1176.001"]}`, and the SPL sets `mitre_attack` to the same two IDs.

---

## Detection Logic

### Plain English

1. `tstats` over `Web` for the hourly window keeps requests with `Web.bytes_out>0` whose `Web.url_domain` **or** `Web.site` matches `..._domains(1)` (20 vendor domains plus 8 exact SSE app names such as `Monica AI`, `Sider AI`). It groups by `user`, `src`, `url_domain` and `site`, with `fillnull_value="-"` so rows with an empty `site` or `user` are kept. `ext_domain = url_domain`, or `site` when `url_domain` is empty.
2. `..._catalog` maps each host or app name to a product. Rows with no product are dropped.
3. `unknown`, `-` and IP-shaped users and rows without a `src` are dropped. No risk object is ever the literal `unknown`.
4. `bunit` is resolved (identity by `user`, then asset by `ip` or `dns`, then CIDR) and `ai_unsanctioned_filter(user,src,provider)` applies the allowlist per product.
5. **Sum per `src`** across every product, host and user; apply the threshold to that total (`total_mb >= threshold_mb`). `user` is set only when exactly one real user was seen.
6. **Score:** 30 at the threshold, 40 at 5x, 50 at 20x; x `risk_multiplier` (identity `bunit` sensitivity, x1.25 for privileged identities, 1.0 without a user), capped at 60.

### Key Fields

| Field | Description | Example Value |
|---|---|---|
| `src` | Sending host (system risk object) | `10.20.30.40` |
| `user` / `user_display` | Single proxy user, or up to 5 users, or "not attributed" | `jdoe@example.com` |
| `ext_product_list` | Products whose backends received data | `Monica, Sider` |
| `ext_domain_list` | Up to 10 hosts or app names | `api.monica.im, api2.sider.ai` |
| `total_mb` | Request MB summed over the hour | `48.2` |
| `mb_in` | Response MB (sanity check for swapped directions) | `1.3` |
| `request_count` | Requests in the hour | `310` |
| `threshold_mb` | Threshold in effect | `10` |
| `bunit` | Business unit used for allowlisting | `finance` |
| `base_score`, `risk_multiplier`, `risk_score` | Scoring | `30, 1.0, 30` |

### Thresholds

| Parameter | Default Value | Macro | Notes |
|---|---|---|---|
| Volume threshold | 10 MB per `src` per hour | `hdsi_ai_browser_extension_high_volume_data_transmission_threshold_mb` | Starting floor, not a measured value. Derive per tenant (Tuning Guidance) |
| Base score bands | 30 / 40 (5x) / 50 (20x) | in SPL | |
| Score cap | 60 | in SPL; override in `..._risk_score` | Applies to `src` and `user` |

---

## Triage Steps

> **Estimated triage time:** 10-15 minutes. There is no notable for this rule. You reach it from an HDSI RBA AI aggregator notable (often `Threat - HDSI RBA AI Data Collection Kill Chain - Rule`) or a risk event.

### Step 1: Validate the risk event

```spl
| from datamodel:"Risk.All_Risk"
| search source="Network - HDSI AI Browser Extension High-Volume Data Transmission - Rule" risk_object IN ("$src$","$user$")
| table _time, risk_object, risk_object_type, risk_score, risk_message
| sort - _time
```

- The risk message gives the MB sent, request count, products, hosts and threshold.

### Step 2: Review the backend traffic and confirm direction

Handles proxies that fill `url_domain`, `site`, or only one of them:

```spl
| tstats summariesonly=t allow_old_summaries=t fillnull_value="-" count sum(Web.bytes_out) as bytes_out sum(Web.bytes_in) as bytes_in values(Web.http_method) as http_method values(Web.url) as url values(Web.http_user_agent) as http_user_agent min(_time) as firstTime max(_time) as lastTime
    from datamodel=Web
    where Web.src="$src$" (`hdsi_ai_browser_extension_high_volume_data_transmission_domains(Web.url_domain)` OR `hdsi_ai_browser_extension_high_volume_data_transmission_domains(Web.site)`)
    by Web.user Web.src Web.url_domain Web.site
| rename Web.* as *
| eval url_domain=if(url_domain="-",site,url_domain), mb_out=round(bytes_out/1048576,2), mb_in=round(bytes_in/1048576,2)
| convert ctime(firstTime) ctime(lastTime)
| table firstTime, lastTime, user, src, url_domain, count, mb_out, mb_in, http_method, http_user_agent, url
| sort - mb_out
```

- `mb_out` should clearly exceed `mb_in` and come from `POST`/`PUT` requests. If `mb_in` is larger and the methods are `GET`, the proxy may log total bytes or swap directions; treat the finding as unconfirmed.
- Upload endpoints and file names in `url` show whether documents were sent.

### Step 3: See where else the host uploaded data

```spl
| tstats summariesonly=t allow_old_summaries=t fillnull_value="-" count sum(Web.bytes_out) as bytes_out
    from datamodel=Web
    where Web.src="$src$" Web.bytes_out>0
    by Web.url_domain Web.site
| rename Web.* as *
| eval url_domain=if(url_domain="-",site,url_domain), mb_out=round(bytes_out/1048576,2)
| stats sum(count) as count sum(mb_out) as mb_out by url_domain
| sort - mb_out
| head 25
```

- A host that uploads heavily everywhere (backup, sync, video calls) puts the AI backend volume in context. A host whose largest upload destination is the AI backend is the stronger finding.
- A `src` with many users is likely NAT, VDI or a terminal server (see False Positive Scenarios).

### Step 4: Identify the host owner and user

```spl
| inputlookup asset_lookup_by_str where ip="$src$"
| table asset, ip, dns, nt_host, owner, bunit, category, priority
```

```spl
| inputlookup identity_lookup_expanded where identity="$user$"
| table identity, first, last, email, managedBy, bunit, category, priority
```

### Step 5: Check for related AI risk on the same objects

```spl
| from datamodel:"Risk.All_Risk"
| search risk_object IN ("$src$","$user$") source="*HDSI AI*"
| stats sum(risk_score) as total_risk dc(source) as detections values(source) as rules count as events by risk_object, risk_object_type
| sort - total_risk
```

- This rule is an **upload** phase detection for `Threat - HDSI RBA AI Data Collection Kill Chain - Rule`: preceded within 4 hours by a collection detection (for example AI-021 Browser Extension Activity, copy-paste or a data-access spike) for the same user, it raises a high-severity notable.
- It counts in the high-impact `data_exposure` vector of `Threat - HDSI RBA AI Multi-Vector Risk - Rule`.

### Step 6: Determine sanctioned status

```spl
| inputlookup ai_sanctioned_entities
| where tonumber(enabled)=1 AND (lower(entity)=lower("$src$") OR lower(entity)=lower("$user$") OR entity="*")
| table entity_type, entity, provider, scope, expires, owner, reason, allow_key
```

- Keys are `<user>|<product>`, `<src>|<product>`, `<bunit>|<product>` or `*|<product>`, all lowercase (for example `sales|tactiq`).

### Step 7: Make a determination

- **True Positive:** an unapproved AI assistant received documents or bulk page content from a user who handles sensitive data.
- **Benign True Positive:** an approved product (Brisk for education, Tactiq or Bardeen for sales) used as intended. Allowlist it.
- **False Positive:** bytes counted in the wrong direction, or a shared egress `src` that sums many users. Fix the data or exclude the `src`.

---

## True Positive Indicators

- `total_mb` well above the threshold (40 or 50 base score bands) from a single-user host.
- `POST`/`PUT` upload requests carrying files, at times that match the user's access to sensitive systems.
- The product is a page reader or meeting-capture tool, and the user works with confidential data.
- AI-021, a copy-paste or a data-access-spike detection for the same user shortly before.
- The user has a sanctioned AI alternative but used an unapproved extension.

---

## False Positive Scenarios

Evidence is from read-only live tests on 4 production ES tenants (Tenant A-D) on 2026-10-09.

| Scenario | Likelihood | Mitigation |
|---|---|---|
| Source logs hosts but no bytes (Tenant A NGFW URL logs: about 195 requests a day to Sider, Monica, Wordtune, Brisk, Liner, Glasp, Merlin, all unmeasurable) | High: the main limitation | Not a false positive but silent coverage loss; deploy only where the prerequisite check returns `mb_out` |
| Proxy logs total bytes or swaps directions | Medium | Compare `mb_out` with `mb_in` in Step 2 before trusting a finding |
| Shared `src` (NAT, VDI, terminal server) summing many users | Medium | Exclude it in `..._filter`, e.g. `NOT Web.src IN ("192.0.2.10")`, or rely on the user risk object |
| Approved products (Brisk, Tactiq, Bardeen) | Medium | Allowlist in `ai_sanctioned_entities` |
| SSE app-name matching (Tenant C: wildcard names such as `*Monica*` matched unrelated retail and news sites) | Low with shipped exact names | Use exact app names only; confirm the names your SSE uses and add them to both the domains macro and the catalog |

---

## Response Actions

### If confirmed True Positive

1. **Contain:** remove the extension (browser-management policy or EDR) and block the vendor backend domains at the proxy if the product is not approved.
2. **Notify:** inform the user's manager and the data governance team. If regulated data may be involved, involve privacy or legal.
3. **Investigate:** identify the documents or pages sent (upload URLs, file names, the systems the user accessed in the same hour) and whether the vendor account is personal or corporate. Request deletion from the vendor where the contract allows it.
4. **Remediate:** enforce an extension allowlist, apply DLP to uploads to unsanctioned AI backends, and point the user to the sanctioned AI assistant.
5. **Document:** record the findings in the case management system.

### If Benign True Positive

1. Add a row to `ai_sanctioned_entities` (common package) with `allow_key` `<bunit>|<product>`, `<user>|<product>` or `<src>|<product>` (all lowercase), an expiry date and the justification in `reason`.
2. If an aggregator notable was raised, close it as Benign True Positive and reference the approval.

---

## Tuning Guidance

### Reducing false positives

- Exclude proxy egress, NAT and shared hosts in `..._filter` instead of raising the threshold.
- Confirm SSE app names in your tenant before relying on the app-name path.
- To monitor QuillBot, add `quillbot.com` and `*.quillbot.com` to the domains macro and a matching `case` branch to the catalog, then allowlist licensed users.

### Adjusting thresholds

Profile 7 days of hourly per-`src` totals, then set the threshold to `max(10, 3 x p99_mb)` so the rule fires a few times a week at most:

```spl
| tstats summariesonly=t allow_old_summaries=t fillnull_value="-" sum(Web.bytes_out) as bytes_out from datamodel=Web
    where Web.bytes_out>0 (`hdsi_ai_browser_extension_high_volume_data_transmission_domains(Web.url_domain)` OR `hdsi_ai_browser_extension_high_volume_data_transmission_domains(Web.site)`) earliest=-7d@h latest=@h
    by _time span=1h Web.src
| eval mb=bytes_out/1048576
| stats count as src_hours dc(Web.src) as srcs perc95(mb) as p95_mb perc99(mb) as p99_mb max(mb) as max_mb count(eval(mb>=10)) as hours_over_10
```

If the same `src` dominates `max_mb`, check whether it is a proxy egress or shared host and exclude it.

### Key tuning macros

| Macro | Ships as | Use |
|---|---|---|
| `hdsi_ai_browser_extension_high_volume_data_transmission_filter` | `()` | Inline exclusions in the `tstats` (`Web.*` names) |
| `..._domains(1)` / `..._catalog` | 20 vendor domains + 8 SSE app names / host-to-product map | Keep the two in step |
| `..._threshold_mb` | `10` | MB per `src` per hour |
| `..._customizations` / `..._risk_score` | `search *` | Post-threshold hook; last-pipe score override (max 100) |

### Adding allowlist entries

```
entity_type,entity,provider,scope,expires,owner,reason,enabled,allow_key
group,sales,Tactiq,group,<YYYY-MM-DD>,<your_name>,<justification>,1,sales|tactiq
```

---

## Related Detections

| Detection ID | Name | Relationship |
|---|---|---|
| AI-021 | HDSI AI Browser Extension Activity | Same catalog without the byte requirement; global and usually the collection signal before this one |
| AI-007 | HDSI AI High Volume Upload To AI Service | Upload volume to mainstream AI providers, including their extensions |
| AI-044 | HDSI AI Gradual Data Exfiltration Via AI | Low-and-slow counterpart to a single high-volume hour |
| AI-025 | HDSI AI Copy-Paste Correlation To AI Service | Another collection-phase signal (ad hoc) |
| AI-RISK-003 | HDSI RBA AI Data Collection Kill Chain | Uses this rule as an upload-phase detection |
| AI-RISK-005 | HDSI RBA AI Multi-Vector Risk | Counts this rule in the high-impact `data_exposure` vector |

---

## Data Requirements

| Requirement | Details |
|---|---|
| Data Model | `Web`, from a forward proxy, SWG or SSE (not inbound web server, WAF or load-balancer logs) |
| Required Fields | `Web.src`, `Web.bytes_out` (request bytes, client to server), the destination host in `Web.url_domain` or a domain-style `Web.site` (or an exact SSE app name). `Web.user` is optional and only adds the user risk object |
| Sourcetype Examples | Forward proxy or SWG access logs with byte counts. NGFW URL-filtering logs (for example `pan:threat` URL entries) carry the host but no bytes and cannot work. `Network_Traffic` carries bytes but no host and is not used |
| CIM Compliance | Without `bytes_out` the rule returns nothing (the `tstats` where clause requires `Web.bytes_out>0`) |
| Acceleration | Required (`summariesonly=t`) |
| Lookups | `identity_lookup_expanded`, `asset_lookup_by_str`, `asset_lookup_by_cidr` (ES, optional, for `bunit`); `ai_sanctioned_entities`, `ai_department_sensitivity` (common package, via `ai_unsanctioned_filter(3)` and `ai_risk_multiplier`) |

**Prerequisite check before deploying (ad hoc).** It should return rows with non-zero `mb_out`. Rows with `count` but empty or zero `mb_out` mean the source logs the host but no bytes, so the rule cannot work on that source:

```spl
| tstats summariesonly=t allow_old_summaries=t fillnull_value="-" count sum(Web.bytes_out) as bytes_out from datamodel=Web
    where `hdsi_ai_browser_extension_high_volume_data_transmission_domains(Web.url_domain)` earliest=-7d by sourcetype Web.url_domain
| eval mb_out=round(bytes_out/1048576,3)
| sort - count
```

### Live validation (2026-10-09)

| Tenant | Web egress with host and bytes | Catalogued backends seen (24 h) | Rows (hourly / 24 h) | Notes |
|---|---|---|---|---|
| A | No: NGFW URL logs have hosts but no bytes | Sider, Monica, Wordtune, Brisk, Magical, Liner, Merlin, Glasp (about 195 requests) | 0 / 0 | No data path |
| B | Partly: a small user proxy logs host, user and bytes | Sider marketing site only (about 3 KB) | 0 / 0 | With the threshold set to 0, 2 user-attributed rows: the path works end to end |
| C | SSE app names and bytes, no hosts | None | 0 / 0 | No matching SSE app names |
| D | No (inbound web server logs only) | None | 0 / 0 | Runs cleanly |

The search and its 3 drilldowns parse on all four tenants with no FATAL or ERROR messages. A synthetic test confirmed the logic: 6 + 3 + 2 MB across products on one `src` fired at 11 MB with the single user attributed; 9 MB did not fire; 250 MB with user `unknown` fired at base 50 with no user risk object; a row with no `src` was dropped.

---

## Revision History

| Date | Author | Change |
|---|---|---|
| 2026-02-22 | Brainstorm SOC | Initial production runbook |
| 2026-10-09 | Trevor Mock, Hurricane Labs LLC | 1.1.0: rewritten as the package `hdsi_ai_browser_extension_high_volume_data_transmission` (stanza `Network - HDSI AI Browser Extension High-Volume Data Transmission - Rule`), now **ad hoc**. Detection sums `Web.bytes_out` per `src` per hour to a catalog of extension-first AI backends (hosts or exact SSE app names, `url_domain`/`site` with `fillnull_value`), threshold 10 MB, dynamic score 30/40/50 x multiplier capped at 60. The old `chrome-extension` user-agent logic was removed. Risk-only, hourly. Triage SPL updated to the Risk data model; live and synthetic evidence from Tenant A-D added |
| 2026-10-10 | Trevor Mock, Hurricane Labs LLC | Moved to `saved_searches/incubating/` (not released): only proven with synthetic test events; no validation tenant had the data. Was `docs/runbooks/AI-024.md` |
