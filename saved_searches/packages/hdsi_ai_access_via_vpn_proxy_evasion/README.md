## Architect Notes
---
**Author:** Trevor Mock, Hurricane Labs LLC. Security Operations Architect

This rule finds hosts that use **Tor, a consumer anonymising VPN (NordVPN, ExpressVPN, Hotspot Shield, Surfshark, Proton VPN and others) or a proxy-avoidance service in the same hour as AI service activity**. The pairing matters because a tunnel hides the AI traffic itself from the proxy, the CASB and DLP. When AI was blocked and the evasion tool then got through, it is a policy bypass attempt. The rule creates risk on `src` (system) and, when exactly one firewall or proxy user is seen for that source, on `user`. It creates no notable.

v1.0 matched AI web traffic whose source had an ES asset `category` containing `vpn|proxy|tor|anonymizer`, or whose user agent contained `tunnel|proxy|vpn|tor`. None of the four validation tenants has such an asset category. The unanchored `tor` matched asset categories such as `monitoring` and `routeeditor`, and user agents containing words such as `Editor`. Rows matched only by user agent had an empty `evasion_methods`. Rows without a user were given the risk object `unknown`. v1.0 returned 0 rows on all four tenants. v1.1 uses the places where evasion tools are actually identified: firewall App-ID, web gateway URL categories and VPN client DNS names.

### Prerequisites
Any one evasion data path plus any one AI data path is enough. The six branches are chained `tstats prestats=t append=t` calls, so a missing data model only empties its own branch (`data_prereqs` op `OR`). No branch runs as a subsearch, so the 50,000-row subsearch limit does not apply.

| Data | Fields used | Evasion evidence | AI evidence | If absent |
|---|---|---|---|---|
| `Network_Traffic` (accelerated) from an NGFW with application identification (PAN-OS App-ID or equivalent) | `app`, `src`, `user`, `action` | `tor`, `hotspot-shield`, `nordvpn`, `expressvpn`, `hola-unblocker`... (`..._evasion_app_ids`) | `openai-chatgpt`, `claude-base`, `google-gemini`... (`..._ai_app_ids`) | No proof that a tunnel was established. Firewalls that put only protocol or port in `app` contribute nothing |
| `Web` (accelerated) from a forward proxy or SWG that sets `category` | `category`, `url_domain`, `site`, `src`, `user`, `action` | Anonymizer / proxy-avoidance categories (`..._anonymizer_categories`). The host is `url_domain`, or `site` on SSE/CASB data without a domain | AI hostnames or SSE app names (`..._ai_web_names`) | Inbound web server or load-balancer logs in `Web` add nothing, because they never carry these categories or AI hosts as destinations |
| `Network_Resolution` (accelerated) from client-facing DNS | `query`, `src` | VPN, anonymizer and Tor client hostnames (`..._evasion_dns`) | AI hostnames (`..._ai_dns_names`) | DNS evidence cannot say whether a connection was allowed, so DNS-only evidence with allowed AI scores 10 and is not emitted by default (see Threshold). Tor names seen only in DNS do not add the Tor bonus |

- `src` must be the **client**. Add DNS forwarders, explicit proxies and NAT addresses that appear as the client to the `..._dns_filter`, `..._web_filter` or `..._filter` macros. Public IPv4 sources without a user are dropped by `..._unreliable_src`.
- Depends on `hdsi_ai_rba_common`. `ai_domains_filter` (`ai_provider_domains`, `ai_provider_apps`) resolves AI evidence to a provider and drops disabled rows. It also returns `ai_traffic_class`, used to ignore background AI hosts. `ai_unsanctioned_filter(3)` applies `ai_sanctioned_entities` approvals and looks up the user's ES identity `bunit` itself for group approvals. `ai_risk_multiplier` applies the identity `bunit` sensitivity. The rule reads the ES lookup `identity_lookup_expanded` only through these two common macros. It does not use `asset_lookup_by_str`.

### How it works
- **Evasion branches:** `tstats` over `Network_Traffic` (evasion App-IDs), `Web` (anonymizer categories, minus `..._web_exclusions`) and `Network_Resolution` (evasion DNS names). Every branch is filtered inside the `tstats` where clause. Evidence is recorded as `app:<App-ID>`, `web:<url_domain or site>` or `dns:<name>`.
- **AI branches:** `tstats` over the same three models, prefiltered by `..._ai_app_ids`, `..._ai_web_names` and `..._ai_dns_names`. The prefilters only keep `tstats` cheap.
- **One pipeline, no subsearches:** all six branches are chained with `tstats prestats=t append=t` (every branch uses `fillnull_value="unknown"`, so rows without a user, domain or site are kept), labelled evasion or AI, and merged with one `stats`. v1.1 first used `append` subsearches. The AI App-ID branch on Tenant A produces 45,000 to 74,000 rows per hour to four hours, which hit the default 50,000-row subsearch limit and silently dropped sources late in the sort order. The chained form has no such limit.
- **Correlation:** placeholder users (`unknown`, `-`, empty) are nulled. Only sources with both an evasion row and an AI row in the window are kept. AI rows are then resolved by `ai_domains_filter`: hostnames as `dns`/`host`, SSE app names and App-IDs as `app`. A PAN App-ID is tried as-is, then without its sub-function suffix (`-base`, `-post`, `-upload`...), then by its first token. For example, `claude-base` resolves through `claude`. Values that do not resolve are dropped. AI hosts that the registry marks `traffic_class=background` (for example `ab.chatgpt.com`, `bzr.openai.com`, `auth.openai.com`, Copilot telemetry) do not count as AI use, because an idle desktop app contacts them without anyone using AI. Providers in `..._sanctioned_providers` and entities approved in `ai_sanctioned_entities` are removed, and the both-sides check is repeated.
- **Risk objects:** results are aggregated to **one row per `src`**. `user` is set only when exactly one user was seen. A source with more users than `..._max_users_per_src` is treated as shared egress and dropped. A source without a user is dropped when it matches `..._unreliable_src` (public IPv4 by default). A source without a user that matches `..._dynamic_src` (remote-access VPN pools and CGNAT, `100.64.0.0/10` by default) is dropped unless it reaches the 40 tier, because the next person given that address would inherit the risk. No row carries an `unknown` risk object.
- **Scoring (base):** 40 when AI was blocked and an evasion tool passed. 25 when an evasion tool passed alongside allowed AI use. 20 when AI was blocked and the evasion attempt was blocked, DNS-only or an attempt host (below). 10 when AI was allowed and the evasion attempt was blocked, DNS-only or an attempt host. +10 when Tor traffic got through: an allowed `tor` App-ID session, or an allowed Tor Browser host (`check`, `bridges`, `aus1`/`aus2.torproject.org`, `snowflake-broker.torproject.net`) or SSE app named Tor on the web. Blocked Tor, Tor names seen only in DNS, and Tor project web pages (www, support, GitLab, forum) do not add it, so an attempt with allowed AI stays at 10 and is not emitted by default.
- **What "passed" means:** an App-ID session, or a Web anonymizer-category event, that was not blocked. An allowed Web event whose host matches `..._web_attempt_hosts` counts as an attempt, not as the tool passing: apex and `www` vendor sites (`expressvpn.com`), wildcard SNI values (`*.nordvpn.com`), events with no host, and installer or update hosts (`downloads.*`, `updates.*`, any host containing `cdn` such as `downloads.nordcdn.com`). Other hosts (API, relay and node hosts such as `api.tunnelbear.com`) and SSE app names count as passing. Rows below `..._min_base_score` (20) are not emitted. `risk_score = min(60, round(base x risk_multiplier))` applies to both `src` and `user`. The `_risk` literal fallbacks are 25 and 25.
- `ai_outcome` says "AI blocked, then evasion tool allowed" when the last allowed evasion session came after the first blocked AI session in the window (`bypass_after_block=1`). The 25 tier is labelled "AI allowed, evasion tool allowed (co-occurrence)": both were seen from the host in the same hour, which is not proof that the AI traffic went through the tunnel.
- **Cadence:** hourly at :05 over `-65m@m` to `-5m@m`, suppressed 24 h per `src`. A host that keeps a VPN up all day yields one event per day.
- **Context fields:** `mitre_attack="T1090,T1090.003,T1588.007"` (the same IDs as the annotation) and `ai_kill_chain_phase="initial_access"` (reaching a blocked or unsanctioned AI service through an evasion tool; nothing is collected or staged). The multi-vector aggregator lists this rule explicitly under `risky_access`, so the phase does not change its vector.

### Tuning macros
| Macro | Ships as | Purpose |
|---|---|---|
| `hdsi_ai_access_via_vpn_proxy_evasion_filter` | `()` | Exclusions inside both `Network_Traffic` where clauses (`All_Traffic.*`), e.g. an approved lab subnet |
| `hdsi_ai_access_via_vpn_proxy_evasion_web_filter` | `()` | Exclusions inside both `Web` where clauses (`Web.*`), e.g. an explicit proxy that appears as `src` |
| `hdsi_ai_access_via_vpn_proxy_evasion_dns_filter` | `()` | Exclusions inside both `Network_Resolution` where clauses (`DNS.*`). Add internal resolvers/forwarders |
| `hdsi_ai_access_via_vpn_proxy_evasion_evasion_app_ids` | Tor, Psiphon, Ultrasurf, Lantern, Hotspot Shield, NordVPN, ExpressVPN, CyberGhost, TunnelBear, Hola, Betternet, Windscribe, Proton VPN, Surfshark, PIA, IPVanish and other consumer VPN/proxy App-IDs | Evasion App-IDs. Enterprise VPNs (`ike`, `ipsec-*`, `open-vpn`, `wireguard`, `tailscale-*`, `zerotier`, `cloudflare-warp`) are deliberately absent |
| `hdsi_ai_access_via_vpn_proxy_evasion_anonymizer_categories` | `proxy-avoidance-and-anonymizers`, `Proxy Avoidance*`, `*Anonymizer*`... | Gateway URL categories that mean an anonymizer or VPN service |
| `hdsi_ai_access_via_vpn_proxy_evasion_web_attempt_hosts` | Regex: apex/`www` hosts, `*.` wildcard SNI, no host, `downloads`/`dl`/`static`/`assets`/`updates`/`install*` hosts, any host containing `cdn` | Allowed anonymizer-category hosts that are scored as an attempt (site visit or installer download), not as the tool passing |
| `hdsi_ai_access_via_vpn_proxy_evasion_web_exclusions` | iCloud Private Relay (`mask*.icloud.com`, `mask.apple-dns.net`, `*.fastly-masque.net`) | Hosts in the anonymizer category that are OS privacy relays, not evasion tools |
| `hdsi_ai_access_via_vpn_proxy_evasion_evasion_dns` | API/server-list/telemetry names of the same VPN vendors plus the hosts Tor Browser itself contacts (`aus1`/`aus2`/`check`/`bridges`/`dist.torproject.org`, `snowflake-broker.torproject.net`), with and without trailing dot, `www.*` excluded | Evasion DNS names. Tor blog, forum, support and GitLab pages are not listed |
| `hdsi_ai_access_via_vpn_proxy_evasion_ai_app_ids` | `openai*`, `claude*`, `anthropic*`, `google-gemini*`, `perplexity*`, `deepseek*`, `github-copilot*`... | AI App-ID prefilter |
| `hdsi_ai_access_via_vpn_proxy_evasion_ai_dns_names` | 38 general-purpose AI chat/API bases (OpenAI, Anthropic, Gemini, Copilot, Perplexity, DeepSeek, Mistral, xAI, Meta AI, Qwen, Kimi, Manus, Poe, OpenRouter, Hugging Face, DeepL, QuillBot...) | AI DNS prefilter. Add a base to correlate another `ai_provider_domains` provider |
| `hdsi_ai_access_via_vpn_proxy_evasion_ai_web_names` | Same bases, plus SSE app names (`ChatGPT*`, `Claude*`, `Google Gemini*`...) | AI web prefilter |
| `hdsi_ai_access_via_vpn_proxy_evasion_sanctioned_providers` | `"__none__"` | Providers licensed for everyone (e.g. `"Google Gemini","Microsoft Copilot"`). Their activity does not count as the AI half |
| `hdsi_ai_access_via_vpn_proxy_evasion_max_users_per_src` | `3` | Shared-egress guard (see Threshold) |
| `hdsi_ai_access_via_vpn_proxy_evasion_unreliable_src` | public IPv4 | Sources that are not one host. Rows matching it with no user are dropped. `false()` keeps everything |
| `hdsi_ai_access_via_vpn_proxy_evasion_dynamic_src` | `cidrmatch("100.64.0.0/10",src)` | Addresses reassigned between people (remote-access VPN pools, CGNAT). Rows matching it with no user are dropped below the 40 tier. Add your pool ranges, or `false()` to keep them |
| `hdsi_ai_access_via_vpn_proxy_evasion_min_base_score` | `20` | Lowest base score emitted (see Threshold) |
| `hdsi_ai_access_via_vpn_proxy_evasion_customizations` | `search *` | Post-aggregation hook (fields: `src`, `user`, `users`, `user_display`, `evasion_methods`, `evasion_list`, `evasion_allowed`, `tor_seen`, `providers`, `provider`, `provider_list`, `ai_evidence`, `ai_blocked`, `ai_outcome`, `bypass_after_block`, `evasion_count`, `ai_count`, `base_score`, `risk_multiplier`, `risk_score`) |
| `hdsi_ai_access_via_vpn_proxy_evasion_risk_score` | `search *` | Last pipe. Override `risk_score` (≤100) here |

Per-user, per-host and per-group approvals go in `ai_sanctioned_entities` (common package), keyed `<user, src or bunit>|<provider>` or `<entity>|*`. An entity approved for `*` also suppresses its evasion rows.

### Threshold
**`..._min_base_score` (default 20).** The 10 tier (AI allowed, evasion attempt blocked by the gateway, seen only in DNS, a vendor site visit or an installer download) proves that a VPN client is installed or being looked at. It does not prove that traffic left through it. On the tenant whose gateway blocks the anonymizer category, the 10 tier was 125 of 180 sources in 8 hours, about one event per host with a VPN client installed. On DNS-only tenants it is the only tier reachable. Lower it to 10 where DNS is the only evasion source and the daily volume is acceptable (10 sources a day on Tenant B). Measure the tier mix first by setting the macro to 10 and running the rule over a window:

```spl
| savedsearch "Network - HDSI AI Access Via VPN/Proxy Evasion - Rule"
| stats count as sources by base_score ai_outcome
```

Use the last 24 hours on small and mid-size tenants (20 to 110 s on Tenants B to D). On a large NGFW tenant use 4 to 8 hours: 8 hours took 219 s on Tenant A and 24 hours ran past 300 s. Over a long window the correlation is looser than the hourly schedule, so treat the result as an upper bound.

**`..._max_users_per_src` (default 3).** This only matters when the firewall or proxy supplies a user. A workstation shows one user an hour. An explicit proxy, NAT pool, VDI host or terminal server shows many. Set the value just below the first user count that belongs to known shared infrastructure:

```spl
| tstats summariesonly=t allow_old_summaries=t dc(All_Traffic.user) as users from datamodel=Network_Traffic
    where `hdsi_ai_access_via_vpn_proxy_evasion_ai_app_ids` All_Traffic.user=* NOT All_Traffic.user="unknown"
    by All_Traffic.src _time span=1h
| stats max(users) as max_users_per_hour by All_Traffic.src
| stats count as srcs by max_users_per_hour
| sort max_users_per_hour
```

### Known false positives / Limitations
- **Personal VPN clients on corporate laptops are common.** Most rows are "VPN installed and connecting, AI used the same hour". That is a governance finding, not proof of an AI policy bypass. The 40 tier ("AI blocked, then evasion tool allowed") is the strongest signal. It appeared for 2 of 180 correlated sources in an 8-hour window on Tenant A.
- **Co-occurrence, not proven tunnelling.** In the 25 tier the AI traffic was identified natively by the firewall or resolver, so it did not itself go through the tunnel. The rule shows the host ran an evasion tool and used AI in the same hour. On Tenant A every row in six consecutive hourly runs was at 25 except two at 40 and one at 20. Treat the 25 tier as a governance finding that adds context in the aggregator, not as a bypass.
- **Vendor site visits and installer downloads.** A web gateway that categorises VPN vendor sites as anonymizers would make reading `expressvpn.com` or downloading an installer from `downloads.nordcdn.com` look like using the tool. Hosts matching `..._web_attempt_hosts` are therefore scored as attempts. A web proxy service used directly at its apex host (for example a browser-based proxy site) is also scored as an attempt unless App-ID sees it. On Tenant A every anonymizer-category event in 24 hours was blocked (about 140,000 non-apex and 11,000 apex events, iCloud relays excluded), so this rule changes no emitted row there today. It matters on a gateway that allows the category.
- **Tor project pages.** Tenant A logged visits to `www`, `support`, `gitlab` and `bridges.torproject.org` over 7 days, all blocked in the anonymizer category. None of them add the Tor bonus: blocked Tor events never do, and when allowed only the Tor Browser hosts listed under Scoring count.
- **No user on most rows.** On the App-ID tenant, consumer-VPN App-ID sessions carried no User-ID, and anonymizer-category web events had no user. All validated rows raise system risk only. Map User-ID for VPN sessions, or correlate `src` to a user in the aggregator.
- **Reassigned addresses.** In a 4-hour Tenant A window, 7 of the 11 correlated sources were user-less addresses in `100.64.0.0/10` (a remote-access pool). They are now dropped by `..._dynamic_src` below the 40 tier. Add your own pool ranges to that macro. DHCP leases on office networks (RFC 1918) are kept. They usually last a day or more, which the 24-hour suppression matches, but a 7-day aggregator can still join two people who held the same lease.
- **iCloud Private Relay** is in the PAN-OS `proxy-avoidance-and-anonymizers` category. It was 86% of those events on Tenant A (about 34,000 sources a day) and is excluded by `..._web_exclusions`. Other built-in privacy relays (for example Chrome IP Protection or Edge Secure Network) belong there too, if your gateway categorises them as anonymizers.
- **Residential-proxy SDKs and VPN client CDNs** (random-looking domains in the anonymizer category, white-label VPN API hosts) show up as `web:` evidence. They are real anonymizer infrastructure, but they may come from a free app or SDK rather than from the user choosing to tunnel.
- **Enterprise VPN and mesh tools are not evasion here.** `open-vpn`, `tailscale-*`, `wireguard`, `zerotier`, `ike`/`ipsec` and `cloudflare-warp` made up most VPN App-ID traffic on Tenants A and C, and are often sanctioned. Add any of them to `..._evasion_app_ids` only after confirming they are unsanctioned.
- **A full tunnel hides AI traffic.** When the VPN carries everything, the AI half of the correlation is only seen before or after the tunnel, or through split tunnelling. The rule therefore under-reports successful evasion by design. It reports hosts where both are visible.
- **Public sources:** on Tenant C, DNS correlation hit public egress addresses with no user (NAT for many clients). They are dropped by `..._unreliable_src`. Roaming DNS clients on home networks (`192.168.x.x`) are kept, and different laptops can share one such address.
- **App-ID coverage of AI:** an AI App-ID that resolves neither as-is, nor without its suffix, nor by its first token through `ai_provider_apps` is dropped. The common registry now lists the PAN App-IDs seen in validation (`claude-*`, `openai-base`, `google-bard-base`, `character-ai-base`, `openrouter`, `deepseek-*`...). The DNS branch still catches services whose App-ID is missing, where DNS is logged.

### Validation
Read-only tests on 4 production ES tenants, 2026-10-09. The search and its 4 drilldowns parse on all four. The figures are from the chained-`tstats` version and carry no subsearch truncation. The "earlier runs" column predates the reassigned-address guard (`..._dynamic_src`), the installer/CDN attempt hosts and the background-host filter.

| Tenant | Data paths present | v1.0 rows | Final run (4 h window) | Earlier runs | Notes |
|---|---|---|---|---|---|
| A | NGFW App-ID with consumer-VPN and AI App-IDs; PAN URL categories in `Web` (anonymizer category always blocked); DNS | 0 (4 h) | 5 rows, 97 s, all 25 (co-occurrence), no user. A tier breakdown of the same window: 11 correlated sources, 7 dropped as user-less `100.64.0.0/10` pool addresses; the background-host filter, attempt hosts and Tor rule removed none | Six consecutive hourly runs: 8 to 12 rows each (58 to 82 s), 57 at 25, 2 at 40, 1 at 20. 8 h at threshold 10: 180 sources (125 at 10, 3 at 20, 50 at 25, 2 at 40), 219 s | NordVPN, ExpressVPN and TunnelBear App-IDs with OpenAI, Gemini, xAI and OpenRouter. The AI App-ID branch alone is 39,000 to 74,000 rows per hour to four hours |
| B | DNS only (roaming DNS security service, trailing-dot names). `Web` is inbound load-balancer logs; `Network_Traffic` has no consumer-VPN App-IDs | 0 (4 h) | 0, 23 s | 24 h at threshold 10: 10 sources, all at the 10 tier (DNS-only VPN names with AI), 109 s | Lower `..._min_base_score` to 10 to report them |
| C | SSE `Web` (app names, no anonymizer category seen), DNS, small App-ID | 0 (4 h) | 0, 13 s | 24 h at threshold 10: 3 sources at 10. An earlier 24 h window had 2 at 25 (NordVPN, ExpressVPN + Hola App-IDs); 4 public NAT sources were removed by the public-address guard | Consumer-VPN App-ID sessions occur a few times a day; most do not coincide with AI use in the same hour |
| D | No App-ID, no egress web, little AI DNS | 0 (4 h) | 0, 19 s | 4 h and 24 h: 0 | No data path. Expected silence |

No FATAL or ERROR messages and no subsearch truncation messages on any tenant.

Drilldowns, run on Tenant A with a literal `src` from an emitted row over the 4-hour window: firewall sessions 3 rows (10 s), anonymizer and AI web activity 5 rows (7 s), VPN and AI DNS queries 0 rows (5 s; that host's evidence came from App-ID and web, and no DNS was logged with it as the client). The firewall and web drilldowns use `fillnull_value="unknown"`. Without it, `tstats` drops every event that lacks one of the `by` fields, and the earlier web drilldown returned 0 rows for the same Tenant A host. The same `tstats` shape returned 0 events on Tenant A (where `site` is always empty) and on Tenant C (where `url_domain` is empty). The web and DNS drilldowns are limited to the anonymizer, evasion and AI names this rule looks for.

Expected daily volume at the default threshold (one event per source per day, 20 to 60 points): Tenant A about 15 to 30 (an estimate: the earlier 40 to 80 minus the roughly 60% of user-less pool sources the pool guard now drops), B none (about 10 at threshold 10), C 0 to 2, D none.

### Deployment
The package ships with `enable_alerting: false`. Before enablement:

1. Confirm that at least one evasion path exists: run `..._evasion_app_ids`, `..._anonymizer_categories` or `..._evasion_dns` alone over a day.
2. Set `..._sanctioned_providers` to the AI services everyone is licensed for. Add enterprise VPN App-IDs that are unsanctioned in your environment to `..._evasion_app_ids`.
3. Add forwarders, proxies and NAT addresses that appear as `src` to the filter macros. Check `..._unreliable_src` against your address plan, and add your remote-access VPN pools to `..._dynamic_src`. Derive `..._max_users_per_src`, and decide on `..._min_base_score` from the tier-mix SPL above.
4. Run the search over its scheduled window several times and confirm the expected daily risk volume.

The rule is risk-only (no notable). Enabling it is a separately approved change.
