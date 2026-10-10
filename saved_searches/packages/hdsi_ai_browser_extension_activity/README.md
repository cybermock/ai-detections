## Architect Notes
---
**Author:** Trevor Mock, Hurricane Labs LLC. Security Operations Architect

This rule finds endpoints using extension-first AI assistants. Monica, Sider, MaxAI, Merlin, HARPA, Bardeen, Tactiq, Wordtune and similar tools are sold mainly as extensions. They read the page the user is viewing, or capture meeting audio and transcripts, and send that content to the vendor's own LLM backend instead of the organisation's sanctioned AI provider. The rule matches DNS lookups and proxy requests to those vendors' backend hosts. Several of those hosts also serve the vendor's own web, desktop or mobile app, so a match proves the product was used from that `src` (extension or web app), not that the extension is installed. It also matches proxy-logged views of AI extension listings in the Chrome, Edge and Firefox extension stores. It creates risk on `src` (system), and on `user` when the proxy attributes the activity to exactly one user. It does not create a notable. MITRE ATT&CK: T1176.001 (Software Extensions: Browser Extensions) and T1588.007 (Obtain Capabilities: Artificial Intelligence); the risk is page, document or meeting content leaving to an unsanctioned LLM backend, so the kill-chain phase is `collection`.

### Prerequisites
- **CIM `Network_Resolution` (DNS dataset), accelerated:** `DNS.src` and `DNS.query`. This is the most portable path. Lookups made through a local resolver or forwarder record that server, not the endpoint, as `src`. Endpoint-level DNS (Windows DNS debug, Sysmon 22, an EDR, or a cloud DNS security service with internal client IPs) gives the best attribution.
- **CIM `Web`, accelerated (optional second leg):** `Web.url_domain` or `Web.site`, `Web.src`, `Web.user`, `Web.url`. Matching vendor hosts needs only `url_domain` or a domain-style `site`. Matching store listing views needs full URL paths, which means a proxy or NGFW with TLS inspection. SSE products that log the app name in `site` (for example "Chrome Web Store") without a path can't support the store leg. Inbound web server, WAF or load-balancer logs in the Web model never match.
- Either data model is enough (`data_prereqs` op OR). The search runs and returns nothing when one of them is absent.
- **ES assets and identities (optional, for business-unit allowlisting):** before the allowlist, the search resolves `bunit` from `identity_lookup_expanded` (`identity` = `user`), then from `asset_lookup_by_str` (`asset` = `src`; `asset` is the merged ES key covering ip, dns, nt_host and mac) and `asset_lookup_by_cidr` (`ip` = `src`). Placeholder values (`unknown`, `n/a`, `none`, `null`, `-`, empty) are discarded and the rest lowercased and de-duplicated. A `bunit` is used only when exactly one real value is left. When an IP matches several asset records with different business units (shared or reused addresses), no `bunit` is used for allowlisting and the row carries `bunit_note` ("ambiguous asset or identity bunit (N values)") for the analyst. Without a single `bunit`, only the per-user, per-src and organisation-wide allowlist keys can match. Validation results for this are in the Validation section.
- **Common package `hdsi_ai_rba_common`:** `ai_unsanctioned_filter(3)` and `ai_risk_multiplier`. `ai_unsanctioned_filter` checks the allowlist `ai_sanctioned_entities` for these keys, all lowercase with `*` for any product: `user|<product>`, `src|<product>`, `<bunit>|<product>`, and the organisation-wide `*|<product>`. If this search supplies no `bunit`, the macro tries the ES identity `bunit` of the user itself, first by the raw value and then by the bare name. `ai_risk_multiplier` uses the ES `identity_lookup_expanded` bunit with `ai_department_sensitivity`, and is 1.0 when there is no user.

### How it works
- **DNS leg:** a `tstats` search of `Network_Resolution` for the backend domains in `hdsi_ai_browser_extension_activity_domains(1)`, grouped by `DNS.src` and `DNS.query`. The patterns cover subdomains and the trailing dot that some DNS sources log.
- **Web leg (`append maxtime=240`):** a `tstats` search of `Web` for the same domains in `url_domain` or `site`, plus exact matches on the store hosts in `hdsi_ai_browser_extension_activity_store_domains`. The search uses `fillnull_value="-"` so that rows with an empty `user` or `site` are kept. The old leading-wildcard `Web.url` scan has been removed.
- `hdsi_ai_browser_extension_activity_catalog` maps each host to a product and a tier:
  - `capture`: meeting capture or browser automation (Tactiq, HARPA AI, Bardeen).
  - `page_reader`: a sidebar assistant that sends page content to its own LLM backend.
  - `writer`: a writing assistant.
  - `vendor_site`: only the bare or `www.` marketing host was reached. This is weaker evidence.
- A store URL counts only when `hdsi_ai_browser_extension_activity_store_ai_regex` finds an AI term in the extension's detail page slug. These rows get the tier `store_view`.
- The search drops `unknown`, `-` and IP-shaped users, and rows without a `src`. It resolves a single `bunit` (identity bunit for the user, else asset bunit for the `src`, placeholders and ambiguous multi-matches discarded). It then applies `ai_unsanctioned_filter(user,src,provider)` to each product, so `user|`, `src|`, `<bunit>|` and `*|` allowlist keys all work.
- Rows are aggregated by `src`. `user` is set only when exactly one real user was seen. Otherwise the user risk object is left empty and only the system receives risk. `user_display` names the users in the message.
- **Scoring:**
  - The base score is the highest tier score: capture 30, page_reader 20, writer 10, store_view or vendor_site 5. Each extra product that hit a backend host adds 5 (vendor marketing sites and store listing views do not count toward the bonus). The base is capped at 60.
  - The base is multiplied by `risk_multiplier` from `ai_risk_multiplier`, which is 1.0 when there is no user, and capped at 60 again. The result is written to `risk_score`, which ES uses for every risk object in the row.
  - The literal `_risk` scores (20 each) are only a fallback.
- **Schedule:** hourly (`7 * * * *`, `-65m@m` to `-5m@m`). Suppression is 24 h per `src` and `user`, because extension use is a persistent state rather than an event that needs alerting each time. `user` is part of the key so that a later proxy row naming a user is not suppressed by an earlier DNS-only row for the same `src`; the cost is at most one extra system risk event for that `src` per day.

### Tuning macros
| Macro | Ships as | Purpose |
|---|---|---|
| `hdsi_ai_browser_extension_activity_filter` | `()` | DNS-leg exclusions inline in the `tstats` where clause (DNS field names), e.g. `NOT DNS.src IN ("192.0.2.53")` for resolvers or forwarders. |
| `hdsi_ai_browser_extension_activity_web_filter` | `()` | Web-leg exclusions inline in the `tstats` where clause (Web field names). |
| `hdsi_ai_browser_extension_activity_domains(1)` | 20 vendor domains | Backend domains of extension-first AI products. Add a domain here **and** in the catalog. |
| `hdsi_ai_browser_extension_activity_catalog` | eval/case | Maps a domain to its product and tier. Keep it in step with the domains macro. |
| `hdsi_ai_browser_extension_activity_store_domains` | Chrome, Edge, Firefox stores | Store hosts matched exactly in `Web.url_domain`. |
| `hdsi_ai_browser_extension_activity_store_ai_regex` | AI-term regex | Decides which store detail page slugs count as AI extensions. |
| `hdsi_ai_browser_extension_activity_tier_scores` | 30/20/10/5 | Base risk per tier. |
| `hdsi_ai_browser_extension_activity_customizations` | `search *` | Post-aggregation hook. Fields: `src`, `user`, `user_display`, `bunit`, `bunit_note`, `ext_products`, `ext_tiers`, `ext_domain_list`, `store_listings`, `evidence`, `event_count`, `product_count`, `backend_product_count`, `base_score`, `risk_multiplier`, `risk_score`. |
| `hdsi_ai_browser_extension_activity_risk_score` | `search *` | Last pipe. Overrides `risk_score` (max 100). |

Grammarly and QuillBot are deliberately left out of the domain list. In validation, 61, 851 and 336 distinct DNS sources a day resolved them in Tenants A, B and C (0 in D), and they are usually licensed. To monitor them, add `grammarly.com`, `grammarly.io` and `quillbot.com` to both the domains macro and the catalog with tier `writer`, and allowlist the licensed population in `ai_sanctioned_entities`.

### Threshold
There is no count threshold. A single lookup of a catalogued backend host (for example `api.monica.im`) is enough evidence that the product was used from that `src`, either as the extension or through the vendor's web app. Only a few hosts are extension-specific (for example `chromium-extension.wordtune.com`). The tier scores are the tuning surface. To see what the rule would emit in your tenant before you enable it, profile the matches per source over 7 days:

```spl
| tstats summariesonly=t allow_old_summaries=t count dc(DNS.query) as hosts from datamodel=Network_Resolution
    where `hdsi_ai_browser_extension_activity_domains(DNS.query)` earliest=-7d@d by DNS.src DNS.query
| rename DNS.* as * | eval ext_domain=query | `hdsi_ai_browser_extension_activity_catalog`
| stats sum(count) as lookups dc(ext_product) as products values(ext_product) as ext_products values(ext_tier) as tiers by src
| sort - lookups
```

A `src` that resolves many different products, with high counts, is likely a resolver or forwarder rather than an endpoint. Exclude it in `hdsi_ai_browser_extension_activity_filter`.

### Known false positives / Limitations
- **Marketing-site visits:** someone who visits a vendor's website (for example `www.getmerlin.in`) without installing the extension matches as `vendor_site` at score 5. This was the most common low-value match in validation.
- **Extension or web app:** hosts such as `api.monica.im`, `assets.monica.im`, `api2.sider.ai`, `app.wordtune.com` and `api.briskteaching.com` were matched in validation and also serve the vendor's web app. The rule therefore reports "extension or web app". Both send content to the same unsanctioned LLM backend, so the risk is the same, but an analyst should not assume an installed extension.
- **Approved use:** Brisk, Tactiq and Bardeen are also used on managed education and sales devices where they may be approved. Allowlist them in `ai_sanctioned_entities` with `allow_key` `<bunit>|<product>`, `<user>|<product>` or `<src>|<product>`, all lowercase. For example, `education|brisk` needs a single real `bunit` of `education` on the ES identity or asset. To approve a product for the whole organisation, use the organisation-wide key `*|<product>`, for example `*|brisk`. The `<product>` part is the lowercased `ext_product`. A store listing view uses the product `ai extension store listing`. In validation, every DNS-only finding had no user, and no source resolved a single real asset `bunit` in Tenants B and C. In those tenants, only the per-src key and the organisation-wide key work. To stop monitoring a product completely, rather than allowlisting it, remove its domain from both the domains macro and the catalog.
- **Ambiguous asset business units:** in Tenant C, the asset records that matched a source IP listed the placeholder `unknown` together with several different sites. The asset data maps one IP to several locations. The search does not guess a business unit in that case. It sets `bunit_note`, and `<bunit>|<product>` keys do not apply. To fix this, clean up the overlapping asset records, or allowlist by `src`.
- **No user attribution from DNS:** DNS data rarely carries a user. In validation, every DNS-only finding carried system risk only. Proxy data supplied a user for a small share of findings in two tenants: 2 of 29 sources in Tenant A and 2 of 16 to 24 sources in Tenant B. Many vendor-host requests in the proxy were logged with an empty or `unknown` user and are attributed to the system.
- **Store listing views are weak evidence:** a view is not an install. The search sees the listing only when the proxy logs full URL paths. Installed-extension inventories need endpoint or browser-management data, which this rule does not use. Chrome's `clients2.google.com/service/update2/crx` requests list installed extension IDs, but this rule does not ship an ID catalog.
- **Catalog coverage:** the catalog covers only products whose main delivery is an extension. Extensions from mainstream providers (ChatGPT, Claude, Copilot, Gemini, Perplexity) talk to the same hosts as those providers' web apps. They can't be told apart by domain and are covered by the AI web and DNS rules.
- **Volume in large tenants:** run over its own hourly window (`-65m@m` to `-5m@m`), the rule took 16 s / 8 s / 4 s / 4 s in Tenants A to D. A 24 h run took about 105 s in Tenant A, almost all of it the Web leg. `append maxtime=240` stops the subsearch from being cut off silently at the default 60 s.

### Validation
Read-only live tests on 2026-10-09 across 4 production ES tenants (hourly rule run over 24 h for the row counts):

| Tenant | DNS data | Web data | Parses (search + 3 drilldowns) | Rows / 24 h (distinct src) | Notes |
|---|---|---|---|---|---|
| A | Yes, but no catalog lookups in 24 h (7 d: 6 lookups from 3 sources, 2 distinct hosts) | NGFW URL logs with TLS-decrypted paths | OK | 29 | All rows came from the Web leg: Sider, Monica, MaxAI, Merlin, Liner, Glasp, Brisk, Wordtune and Magical hosts, plus 1 user-attributed AI store listing view. 2 rows had a user. 2 sources resolved a single real asset `bunit`, so `<bunit>|<product>` keys work for them. 14 rows scored 10 or less (vendor site or writer only); max score 20. Before the `fillnull_value` fix, the Web leg returned 0 rows here because `Web.site` is empty. |
| B | Yes; cloud DNS security service with a trailing dot | Small user proxy plus inbound LB/WAF | OK | 24 (16 in a later 24 h run) | Sider, Monica, Merlin, AIPRM, Wordtune, Glasp, Tactiq. 2 sources also matched the proxy and gained a user. None of the 16 DNS sources matched an asset record, so no `bunit` was resolved. 9 rows scored 10 or less; max score 25. Inbound logs produced no matches. |
| C | Yes | SSE with app names in `site`, no URL paths | OK | 7 (6 in a later 24 h run) | Sider, Bardeen, Brisk and Wordtune, all from DNS. No row had a user. 2 of 6 sources matched asset records, but each IP mapped to `unknown` plus several different sites (2 and 8 real values). Both rows carry `bunit_note` and no `bunit`, so only `<src>|<product>` and `*|<product>` allowlisting works here. The previous version took the first value, which was the literal `unknown`. Max score 30. The SSE logs "Chrome Web Store" visits as an app name with no path, so the store leg is not applicable. |
| D | Little relevant DNS | Inbound web server logs only | OK | 0 | No extension-first AI traffic. The rule runs cleanly with no matches. |

Run over its own hourly dispatch window (`-65m@m` to `-5m@m`), the rule returned 2 / 1 / 2 / 0 rows in Tenants A to D, with runtimes of 16 s / 8 s / 4 s / 4 s. After the `bunit` change, a run over the last 4 h returned 2 / 1 / 0 / 0 rows in 24 s / 12 s / 4 s / 5 s. A 24 h run in Tenants B and C returned 16 and 6 rows in 58 s and 7 s. No run returned a FATAL or ERROR message, and the search and all 3 drilldowns parse in every tenant. The DNS and web-activity drilldowns returned the matching rows when run for a concrete `src` from those results. The web-activity drilldown is now limited to the catalogued vendor hosts and the store hosts, so it no longer lists unrelated Web traffic for the `src`. The risk drilldown returned 0 rows because the rule is not deployed.

The previous version returned 0 rows in every tenant. It matched two hostnames that don't exist (`extensions.chat.openai.com`, `browser.claude.ai`) and retired `chrome.google.com/webstore` URL patterns, using expensive leading-wildcard `Web.url` matches.

### Deployment
The package ships with `enable_alerting: false`. Before enablement:
- Confirm that the tenant's DNS `src` values are endpoints, not resolvers.
- Exclude any resolvers or forwarders in the filter macro.
- Review the 7-day profile above.
- Allowlist approved extensions in `ai_sanctioned_entities`. Use `<bunit>|<product>` where identities or assets carry a single clean `bunit`. Otherwise use `<src>|<product>`, or `*|<product>` for products approved for the whole organisation.

The rule is risk-only. Enabling it must be one separately approved change.
