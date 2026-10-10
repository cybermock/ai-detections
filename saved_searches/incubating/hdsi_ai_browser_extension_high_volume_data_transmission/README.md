## Architect Notes
---
**Author:** Trevor Mock, Hurricane Labs LLC. Security Operations Architect

> **Incubating — not released.** This package lives in `saved_searches/incubating/` because it has only been proven with synthetic test events; none of the four validation tenants had a forward proxy, SWG or SSE that logs the destination host and request bytes for the catalogued extension backends. Promote it to `saved_searches/packages/` only after it produces real results in a customer environment (see [`saved_searches/incubating/README.md`](../README.md)).

This rule finds a host that sends a large volume of data in one hour to the backend of an extension-first AI assistant. Monica, Sider, MaxAI, Merlin, HARPA, Tactiq, Wordtune and similar products are sold mainly as browser extensions. They read the open page, an uploaded document or a meeting transcript and post it to the vendor's own LLM backend, outside any sanctioned AI provider. The rule adds up `Web.bytes_out` from one `src` to all catalogued backend hosts in the hourly window and fires when the total reaches a threshold (default 10 MB). It creates risk on `src` (system), and on `user` when the proxy attributes the traffic to exactly one user. It does not create a notable. MITRE ATT&CK: T1567 (Exfiltration Over Web Service) and T1176.001 (Software Extensions: Browser Extensions); kill-chain phase `exfiltration`.

Once promoted, the package is **ad hoc** (`deployment_type: adhoc`). It needs a forward proxy, SWG or SSE that writes the destination host **and** the request bytes to the CIM Web model. None of the 4 validation tenants had that for these hosts in volume. The rule parses and runs cleanly everywhere, but it can only fire where that data exists. Deploy it only to tenants that pass the check under [Prerequisites](#prerequisites). It pairs with `hdsi_ai_browser_extension_activity`, which reports any use of the same products from DNS or proxy hosts without needing bytes. This rule adds the volume signal on top.

### Prerequisites
- **CIM `Web`, accelerated, from a forward proxy / SWG / SSE (required):** `Web.src`, `Web.bytes_out` (request bytes, client to server), and the destination host in `Web.url_domain` or a domain-style `Web.site`. `Web.user` is optional and only adds the user risk object. Without `bytes_out` the rule returns nothing, because the `tstats` where clause requires `Web.bytes_out>0`.
  - NGFW URL-filtering logs (for example PAN `pan:threat` URL entries) carry the host but no byte counts. In validation they recorded hundreds of requests a day to these backends, but none of them could be measured.
  - NGFW traffic logs (`Network_Traffic`) carry bytes but no hostname, and no NGFW App-ID exists for these products (only Grammarly had an App-ID in validation). This rule does not use `Network_Traffic`.
  - Inbound web server, WAF and load-balancer logs in the Web model never match these hosts.
  - SSE products that log an app name in `site` instead of a host: the domains macro also accepts a few exact app names (`Monica AI`, `Sider AI`, `MaxAI`, `Merlin AI`, `HARPA AI`, `Tactiq`, `Bardeen AI`, `Wordtune`). None of these names appeared in validation. Confirm the names your SSE uses and add them to both the domains macro and the catalog.
- **Check before deploying.** This should return rows with non-zero `mb_out`:
  ```spl
  | tstats summariesonly=t allow_old_summaries=t fillnull_value="-" count sum(Web.bytes_out) as bytes_out from datamodel=Web
      where `hdsi_ai_browser_extension_high_volume_data_transmission_domains(Web.url_domain)` earliest=-7d by sourcetype Web.url_domain
  | eval mb_out=round(bytes_out/1048576,3) | sort - count
  ```
  Rows with `count` but empty `mb_out` mean the source logs the host but no bytes, so the rule cannot work on that source.
- **ES assets and identities (optional):** `bunit` is resolved from `identity_lookup_expanded` (by `user`), then from `asset_lookup_by_str` (`ip` or `dns` = `src`) and `asset_lookup_by_cidr`. It is used only for `bunit|<product>` allowlist keys.
- **Common package `hdsi_ai_rba_common`:** `ai_unsanctioned_filter(3)` (allowlist `ai_sanctioned_entities`, keys `user|<product>`, `src|<product>`, `bunit|<product>`, all lowercase, `*` for any product) and `ai_risk_multiplier` (identity `bunit` sensitivity from `ai_department_sensitivity`, ×1.25 for privileged or critical identities, capped at 2.0). The rule no longer reads `ai_detection_config` or calls `ai_domains_filter`.

### How it works
- A `tstats` search of `Web` over the hourly window (`-65m@m` to `-5m@m`) selects requests with `Web.bytes_out>0` whose `url_domain` or `site` matches `hdsi_ai_browser_extension_high_volume_data_transmission_domains(1)`. It groups by `user`, `src`, `url_domain` and `site`. `fillnull_value="-"` keeps rows where the proxy leaves `site` or `user` empty. Without it, `tstats` silently drops those rows.
- `hdsi_ai_browser_extension_high_volume_data_transmission_catalog` maps each host or app name to a product. Rows with no product are dropped.
- The search nulls `unknown`, `-` and IP-shaped users, and drops rows without a `src`. No risk object is ever the literal `unknown`.
- It resolves `bunit` and applies `ai_unsanctioned_filter(user,src,provider)` for each product.
- Rows are summed **per `src`** across every product, host and user, and the threshold is applied to that total. The old rule applied it to each `(user, src, host, user agent)` row, so traffic split across hosts never fired. `user` is set only when exactly one real user was seen. Otherwise only the system gets risk, and `user_display` lists up to 5 users.
- **Scoring:**
  - The base score depends on volume relative to the threshold: 30 at the threshold or above, 40 at 5× or above, 50 at 20× or above.
  - The base is multiplied by `risk_multiplier` and capped at 60. The result is written to `risk_score`, which ES applies to every risk object in the row.
  - The literal `_risk` scores (30 for `src` and for `user`) are only the fallback.
- **Suppression:** 24 h per `src` and `user`. The first hour over the threshold is the signal, and repeats the same day add no new evidence for RBA.

### Tuning macros
| Macro | Ships as | Purpose |
|---|---|---|
| `hdsi_ai_browser_extension_high_volume_data_transmission_filter` | `()` | Exclusions inline in the `tstats` where clause (Web field names), e.g. `NOT Web.src IN ("192.0.2.10")` for a proxy egress or NAT address that aggregates many users. |
| `hdsi_ai_browser_extension_high_volume_data_transmission_domains(1)` | 20 vendor domains + 8 app names | Backend hosts and SSE app names of extension-first AI products. Add a host here **and** in the catalog. |
| `hdsi_ai_browser_extension_high_volume_data_transmission_catalog` | eval/case | Maps a host or app name to its product. Keep it in step with the domains macro. |
| `hdsi_ai_browser_extension_high_volume_data_transmission_threshold_mb` | `10` | Minimum MB per `src` per hour, summed over all catalogued backends. |
| `hdsi_ai_browser_extension_high_volume_data_transmission_customizations` | `search *` | Post-threshold hook. Fields: `src`, `user`, `user_display`, `bunit`, `ext_products`, `ext_product_list`, `ext_domain_list`, `request_count`, `total_mb`, `mb_in`, `threshold_mb`, `base_score`, `risk_multiplier`, `risk_score`. |
| `hdsi_ai_browser_extension_high_volume_data_transmission_risk_score` | `search *` | Last pipe. Overrides `risk_score` (max 100) for the row. |

Grammarly and QuillBot are not in the catalog. They are high-volume and usually licensed. In validation, one tenant's NGFW recorded about 1.5 GB in 4 hours to the Grammarly App-ID, and QuillBot hosts appeared from about 90 sources a day. Mainstream providers' extensions (ChatGPT, Claude, Copilot, Gemini, Perplexity) use the same hosts as their web apps, so they cannot be told apart by host. Their upload volume is covered by `hdsi_ai_high_volume_upload_to_ai_service`. To monitor QuillBot here, add `quillbot.com` and `*.quillbot.com` to the domains macro and a matching `case` branch to the catalog, then allowlist licensed users in `ai_sanctioned_entities`.

### Threshold
The default of 10 MB per `src` per hour is a starting floor, not a measured fleet value. These products mostly send page or meeting text, which amounts to kilobytes per request. Ten megabytes in an hour means document uploads or bulk page capture. Before enabling, profile 7 days of hourly per-`src` totals in the tenant:

```spl
| tstats summariesonly=t allow_old_summaries=t fillnull_value="-" sum(Web.bytes_out) as bytes_out from datamodel=Web
    where Web.bytes_out>0 (`hdsi_ai_browser_extension_high_volume_data_transmission_domains(Web.url_domain)` OR `hdsi_ai_browser_extension_high_volume_data_transmission_domains(Web.site)`) earliest=-7d@h latest=@h
    by _time span=1h Web.src
| eval mb=bytes_out/1048576
| stats count as src_hours dc(Web.src) as srcs perc95(mb) as p95_mb perc99(mb) as p99_mb max(mb) as max_mb count(eval(mb>=10)) as hours_over_10
```

Set the threshold to `max(10, 3 * p99_mb)` so the rule fires a few times a week at most. If the same `src` dominates `max_mb`, check whether it is a proxy egress or shared host and exclude it in the filter macro instead of raising the threshold.

### Known false positives / Limitations
- **No byte counts, no detection.** This is the main limitation. In validation, Tenant A's NGFW URL logs recorded requests to Sider, Monica, Wordtune (`chromium-extension.wordtune.com`), Brisk, Liner, Glasp and Merlin hosts, with no bytes. Tenant B's user proxy logged bytes but saw only a few KB of Sider marketing-site traffic. Tenant C's SSE logs app names and recorded none of these products.
- **Extension or web app.** Hosts such as `api.monica.im` and `api2.sider.ai` also serve the vendor's own web app. A finding means "data sent to this product's backend", not proof that the extension is installed.
- **Request bytes only.** `bytes_out` counts the request side, which is the data leaving. Some proxies log only `bytes` (total) or swap the two directions. Check `mb_out` against `mb_in` in the drilldown before trusting a finding.
- **Shared sources.** A NAT, VDI or terminal-server `src` sums many users' traffic. Exclude it in the filter macro, or rely on the user risk object where the proxy attributes users.
- **Approved products.** Brisk (education), Tactiq and Bardeen (sales) may be approved. Allowlist them in `ai_sanctioned_entities` (`bunit|brisk`, `user|tactiq`, `src|bardeen`).
- **Old version.** The previous logic treated any request with a `chrome-extension` user agent to any domain as "Browser Extension" risk. It counted ordinary Copilot web use (`copilot.microsoft.com`) and matched two hosts that do not exist (`extensions.chat.openai.com`, `browser.claude.ai`). Browser extensions do not put `chrome-extension` in the User-Agent; they send it in the `Origin` header, which no validation proxy logged. A broad user-agent match on `*extension*` returned millions of inbound WAF events in one tenant.

### Validation
Read-only live tests on 2026-10-09 across 4 production ES tenants:

| Tenant | Web egress with host + bytes | Catalogued backends seen (24 h) | Parses (search + 3 drilldowns) | Rows: own hourly window / 24 h | Notes |
|---|---|---|---|---|---|
| A | No. NGFW URL logs have hosts but no bytes. NGFW traffic logs have bytes but no hosts; the only matching App-ID is Grammarly | Yes: Sider, Monica, Wordtune, Brisk, Magical, Liner, Merlin, Glasp (about 195 requests, mostly with no user) | OK | 0 / 0 | No data path. The old rule also scanned about 258 M Web events for a 4 h window. |
| B | Partly: a small user proxy logs host, user and bytes. The rest of the Web model is inbound LB/WAF | Sider marketing site only (3 requests, about 3 KB) | OK | 0 / 0 | With the threshold set to 0, the 24 h run returned 2 user-attributed `src` rows (Sider, 0.00 MB). This shows the path works end to end. |
| C | SSE with app names in `site` and bytes, but no hosts | None (no matching SSE app names; NGFW App-ID only for Grammarly) | OK | 0 / 0 | A wildcard app-name test (for example `*Monica*`, `*Sider*`, `*Liner*`) matched only unrelated retail and news sites, so the macro uses exact names only. |
| D | No (inbound web server logs only) | None | OK | 0 / 0 | Runs cleanly. |

A synthetic test (6 rows piped through the full search after `tstats`) confirmed the logic:
- A `src` with 6 MB + 3 MB + 2 MB across Monica, Sider and an SSE app-name row fired at 11 MB, with the single real user attributed.
- A 9 MB `src` did not fire.
- A 250 MB `src` with user `unknown` fired at base 50 with no user risk object.
- A row with no `src` was dropped.

Runtimes: 6 s / 5 s / 2.5 s / 2.6 s over the hourly dispatch window and 15 s / 66 s / 2.6 s / 2.4 s over 24 h in Tenants A to D. In Tenant B nearly all of that time goes on scanning inbound LB/WAF events in the Web model. No run returned a FATAL or ERROR message. The previous version returned 0 rows in every tenant. Its web-activity drilldown also hit the 300 s search limit in Tenant B and took 269 s in Tenant A, because it filtered on `user`/`src` after an unfiltered `tstats`. The new drilldowns filter on `Web.src` inside `tstats`.

### Deployment
The package is configured with `enable_alerting: false` and `deployment_type: adhoc`, the type it takes once promoted to `saved_searches/packages/`. Before enabling it for a tenant:
- Run the prerequisite check and confirm that a forward proxy logs host **and** `bytes_out` for these vendors.
- Derive the threshold from the 7-day profile.
- Exclude proxy egress or shared `src` addresses in the filter macro.
- Allowlist approved products in `ai_sanctioned_entities`.

The rule is risk-only. Enabling it must be one separately approved change.
