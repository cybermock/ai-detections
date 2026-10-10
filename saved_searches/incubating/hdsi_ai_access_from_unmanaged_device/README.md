## Architect Notes
---
**Author:** Trevor Mock, Hurricane Labs LLC. Security Operations Architect

> **Incubating — not released.** This package lives in `saved_searches/incubating/` because it has only been proven with synthetic test events; none of the four validation tenants had both on-network DNS and registered guest/BYOD address blocks (or an inventory-gap subnet that met the gates), so it produced no real results anywhere. Promote it to `saved_searches/packages/` only after it produces real results in a customer environment (see [`saved_searches/incubating/README.md`](../README.md)).

This rule finds **devices on the corporate network that use AI services while the organisation does not manage them**. Evidence is DNS resolution of AI provider domains (`Network_Resolution`) as seen by on-network resolvers. A device counts as unmanaged in one of two ways:
- It is registered as BYOD, guest or unmanaged in ES assets. Either its own asset entry or the address block (CIDR asset) it sits in carries a matching category.
- It is missing from the asset inventory while at least 90% of at least 10 other AI-active hosts in its /24 are in it.

Data typed into an AI service from a personal or rogue device is outside DLP, EDR and browser controls. Each finding raises low risk on the device address (`src`, system). The rule creates no notable.

**Deployment type: ad hoc.** The rule only works with two inputs. The first is DNS logged where unmanaged devices are visible, meaning on-network resolvers or sensors, not cloud DNS roaming agents. The second is an asset inventory that either tracks client IPs or registers guest/BYOD address blocks. Only one of the four validation tenants had on-network DNS, and none had registered guest/BYOD blocks, so the rule is not part of the global baseline.

v1.0 read the `Web` model and could not work:
- It looked assets up with a field that does not identify them.
- Its asset-coverage guard (`eventstats max(if(...))` without `eval`) silently produced nothing.
- It therefore flagged only assets with `is_expected=false`. That is the default for most managed assets on one tenant.
- Its `Web` source data was inbound server logs or public SSE egress addresses, never internal clients.

v1.1 moves to on-network DNS. It also adds address-block categories, a subnet coverage test, and exclusion of roaming-agent DNS feeds and home-router ranges. Risk goes on the device only.

### Prerequisites
| Data | Fields used | If absent or poor |
|---|---|---|
| `Network_Resolution.DNS` (accelerated) from **on-network** resolvers or sensors (Windows DNS, Infoblox, BIND, Stream/Zeek on the resolver segment) | `src` (client IP), `query`, `sourcetype` | No on-network DNS means no rule. If `src` is a forwarder rather than the client, exclude it in `..._filter` |
| ES `asset_lookup_by_str` (match type `asset`) | `asset` (match key), `nt_host`, `category` | An empty inventory makes the inventory-gap path silent by design. This happened on one tenant |
| ES `asset_lookup_by_cidr` (match type `CIDR(asset)`) | `asset` (CIDR match key), `category` | Without category-tagged guest/BYOD blocks, the registered path can only use per-device categories |

- **DNS must come from where unmanaged devices are visible.** Cloud DNS-security feeds (Cisco Umbrella / Secure Access) report an internal client address only through their roaming agent or agent-reported user identity. Those agents run only on managed laptops. Office traffic from network identities arrives as the public egress address. So an unmanaged device cannot appear in such a feed under its own internal address, and every inventory-gap result on those feeds is a managed laptop by construction. In validation:
  - On one tenant, 100% of internal-address events came from the roaming client.
  - On another, 99.9% of internal-address events were roaming-client or AD-user identities, and 58% of those events came from home-router ranges, which means the agents were off-network.
  - `..._dns_sources` therefore excludes these sourcetypes. Remove one only if its internal-address events come from on-network virtual appliances. Check with the source search under Threshold.
- **Registered path (preferred).** Tag guest, BYOD and unmanaged Wi-Fi/LAN pools as CIDR assets with a category such as `byod` or `guest network`, or tag individual assets. Set `..._unmanaged_categories` to your names. The CIDR lookup is matched with `asset as src`, which is the ES match key. An `ip as src` lookup never matches a CIDR entry. Block categories are used only for the registered path. A matching block never marks an address as inventoried, because many inventories hold broad generic RFC 1918 blocks: on one tenant every AI-active client matched such a block.
- **Inventory-gap path.** The inventory's `ip` values must be current for client subnets. Typical feeds are DHCP leases, NAC, or an EDR/MDM export refreshed at least daily. Run the Threshold search. An `inventory_ip_coverage` of 0.9 or more is usable.
- Common package `hdsi_ai_rba_common`: `ai_domains_filter` (provider resolution from `ai_provider_domains`) and `ai_unsanctioned_filter(3)` (allow-list).

### How it works
- **Prefilter (`..._dns_scope`, inside `tstats`):** every domain base from `ai_provider_domains` as `name*` and `*.name*`, plus the cloud AI endpoint patterns. The trailing `*` keeps resolvers that log the root dot (`chatgpt.com.`). One hour of DNS on the busiest tenant took 35 s with the prefilter and 147 s without it.
- **Source scope (`..._dns_sources`, inside `tstats`):** excludes cloud DNS roaming-agent sourcetypes (see Prerequisites).
- **Client scope:** `src` must be in `..._client_ranges` (RFC 1918 plus 100.64.0.0/10) and outside `..._home_network_ranges`. The home ranges are consumer router defaults, a second safeguard for VPN split DNS and any remaining agent feed.
- **Provider resolution:** `ai_domain=query`, `ai_input_type="dns"`, then `ai_domains_filter`. Only enabled providers survive.
- **Inventory:**
  - `lookup asset_lookup_by_str asset as src` sets `src_inventoried` and returns `src_nt_host` and `src_category`.
  - `lookup asset_lookup_by_cidr asset as src` returns `src_block_category` and affects only the registered path.
- **Subnet coverage:** per IPv4 /24, `subnet_ai_hosts` counts the distinct AI-active addresses in the window and `subnet_inventoried_hosts` counts the inventoried ones. For an uninventoried device, `subnet_other_hosts = subnet_ai_hosts - 1` and `subnet_coverage = subnet_inventoried_hosts / subnet_other_hosts`, so the device itself is not counted. Coverage is computed before the allow-list, so allow-listed devices still count as evidence of the subnet's inventory quality.
- **Allow-list:** `ai_unsanctioned_filter(device_name,src,provider)` drops pairs approved in `ai_sanctioned_entities`. The keys are:
  - the asset's `nt_host` (`device_name`);
  - the device address;
  - the first asset or block category, as the group key.
- **Decision.** A row is kept when the address made at least `..._min_queries` AI queries and one of these holds:
  - `registered_asset`: inventoried, and the asset category matches `..._unmanaged_categories`.
  - `registered_address_block`: not inventoried, and its CIDR block category matches. An address that the inventory knows as a different, non-BYOD asset is treated as managed.
  - `inventory_gap`: not inventoried, IPv4, `subnet_other_hosts >= ..._min_subnet_hosts` (10) and `subnet_coverage >= ..._min_subnet_coverage` (0.9).
- **Scoring (dynamic, one risk object):**
  - Base 30 for the registered paths and 20 for `inventory_gap`, multiplied by the highest provider `severity_weight` (0.4–1.2).
  - `risk_score = min(60, max(5, round(base × weight)))`.
  - The literal `_risk` score (20) is the fallback.
  - There is no identity multiplier, because there is no user.
- **Output:** one row per device address. Fields:
  - `unmanaged_basis` and `unmanaged_reason` (plain-language basis with category or coverage figures);
  - `provider_list`, `dns_query_count`, `ai_domain_sample`, `usage_types`;
  - `src_subnet`, `src_nt_host`, `src_category`, `src_block_category`;
  - `mitre_attack` (T1200 Hardware Additions, T1588.007 AI).
- **Cadence and suppression:** hourly (`-65m@m` to `-5m@m`), suppressed for 24 h per `src`. One device produces at most one risk event a day.

### Tuning macros
| Macro | Ships as | Purpose |
|---|---|---|
| `hdsi_ai_access_from_unmanaged_device_filter` | `()` | Exclusions inside the `tstats` where clause (`DNS.*` names, CIDR values work). Examples: `NOT DNS.src IN ("10.0.0.53")` for forwarders, or an approved BYOD pool `NOT DNS.src="10.50.0.0/16"` |
| `hdsi_ai_access_from_unmanaged_device_dns_scope` | Generated from `ai_provider_domains` (279 terms) | AI-name prefilter. Regenerate it when domains are added to the common lookup: every row's registrable base as `"base*","*.base*"` |
| `hdsi_ai_access_from_unmanaged_device_dns_sources` | `NOT sourcetype IN ("cisco:umbrella:dns","cisco:cloud_security:dns","opendns:dnslogs")` | Excludes cloud DNS roaming-agent feeds. Add other agent-based DNS sourcetypes. Remove one only after the source check below |
| `hdsi_ai_access_from_unmanaged_device_client_ranges` | RFC 1918 + 100.64.0.0/10 | Eval condition for on-network client addresses. Narrow it to your LAN, Wi-Fi and VPN pools |
| `hdsi_ai_access_from_unmanaged_device_home_network_ranges` | 12 consumer router default ranges | Eval condition for addresses to ignore. Remove a range only if it is a real corporate LAN |
| `hdsi_ai_access_from_unmanaged_device_unmanaged_categories` | `byod`, `unmanaged`, `guest device/network/wifi`, `personal device`, `non-corporate` (word-bounded regex) | Asset and address-block categories that register a device as unmanaged |
| `hdsi_ai_access_from_unmanaged_device_min_subnet_hosts` | `10` | Other AI-active hosts (excluding the device) a /24 needs in the hour before its coverage is trusted |
| `hdsi_ai_access_from_unmanaged_device_min_subnet_coverage` | `0.9` | Share of those other hosts that must be inventoried. Set to `2` to switch the inventory-gap path off |
| `hdsi_ai_access_from_unmanaged_device_min_queries` | `5` | AI DNS queries per device per hour |
| `hdsi_ai_access_from_unmanaged_device_customizations` | `search *` | Post-aggregation hook (fields listed in the macro description), e.g. `search NOT src_block_category="approved-byod-ai"` |
| `hdsi_ai_access_from_unmanaged_device_risk_score` | `search *` | Last pipe. Rescale or override `risk_score` |

**Approved unmanaged use.** DHCP addresses change, so do not allow-list a BYOD device by IP. Use one of these stable keys instead:
- The pool's CIDR in `..._filter`.
- A distinct block category, removed in `..._customizations`.
- A common `ai_sanctioned_entities` entry keyed on the category (`<category>|*` or `<category>|<provider>`). The group key is the first asset or block category.
- For an inventoried device, its `nt_host` (`<nt_host>|<provider>`).

### Threshold
**1. Source check.** Run this over 4 h. Every in-scope sourcetype should be an on-network resolver or sensor:

```spl
| tstats summariesonly=t allow_old_summaries=t count dc(DNS.src) as clients from datamodel=Network_Resolution
    where `hdsi_ai_access_from_unmanaged_device_dns_scope` `hdsi_ai_access_from_unmanaged_device_dns_sources` earliest=-4h@h latest=@h
    by sourcetype DNS.vendor_product
```

If you consider removing a cloud DNS sourcetype from `..._dns_sources`, first check which identities report internal addresses. The identity field name varies by add-on version:

```spl
index=* sourcetype IN ("cisco:umbrella:dns","cisco:cloud_security:dns") earliest=-1h
| where cidrmatch("10.0.0.0/8",src) OR cidrmatch("172.16.0.0/12",src) OR cidrmatch("192.168.0.0/16",src)
| eval identity=coalesce(granular_identity_type, identity_type, identity_types, "(none)")
| stats count dc(src) as clients by identity
```

Roaming-client or user identities are managed endpoints and do not qualify. Only network, site or virtual-appliance identities do.

**2. Gate sizing.** Run this over a normal working day (24 h). Each `devices_*` column is the number of distinct devices that the gate would report in that day, after `..._min_queries`. With 24 h suppression per `src`, that is the expected number of risk events per day:

```spl
| tstats summariesonly=t allow_old_summaries=t count from datamodel=Network_Resolution
    where `hdsi_ai_access_from_unmanaged_device_dns_scope` `hdsi_ai_access_from_unmanaged_device_dns_sources` `hdsi_ai_access_from_unmanaged_device_filter` earliest=-24h@h latest=@h
    by _time span=1h DNS.src DNS.query
| rename DNS.* as *
| where `hdsi_ai_access_from_unmanaged_device_client_ranges` AND NOT `hdsi_ai_access_from_unmanaged_device_home_network_ranges`
| eval ai_domain=query, ai_input_type="dns"
| `ai_domains_filter`
| stats sum(count) as queries by _time src
| lookup asset_lookup_by_str asset as src OUTPUT asset as inv
| eval inventoried=if(isnotnull(inv),1,0), subnet=replace(src,"\.\d+$",".0/24")
| eventstats dc(src) as hosts sum(inventoried) as inv_hosts by _time subnet
| eval others=hosts-1, coverage=if(others>0,round(inv_hosts/others,2),0), busy=if(queries>=`hdsi_ai_access_from_unmanaged_device_min_queries`,1,0)
| stats count as host_hours sum(inventoried) as inventoried_host_hours dc(src) as ai_clients
        dc(eval(if(inventoried=0,src,null()))) as unknown_clients
        p50(eval(if(inventoried=0,queries,null()))) as p50_unknown_queries
        dc(eval(if(inventoried=0 AND busy=1 AND others>=10 AND coverage>=0.9,src,null()))) as devices_10_090
        dc(eval(if(inventoried=0 AND busy=1 AND others>=5 AND coverage>=0.8,src,null()))) as devices_5_080
        dc(eval(if(inventoried=0 AND busy=1 AND others>=20 AND coverage>=0.95,src,null()))) as devices_20_095
| eval inventory_ip_coverage=round(inventoried_host_hours/host_hours,2)
```

- `inventory_ip_coverage` is the share of AI-active client hours whose address resolves in `asset_lookup_by_str`. Below about 0.8, the inventory does not track client IPs well. In that case, keep the shipped gate or switch the path off (`..._min_subnet_coverage` = `2`) and rely on registered categories.
- Choose the gate whose `devices_*` count you can review each day. Do not go below 5 other hosts or 0.8 coverage, because below that DHCP churn on managed laptops dominates.
- `unknown_clients` far above every `devices_*` column means most unknown devices are in subnets that the inventory does not track at all, such as guest Wi-Fi or OT/IoT. The inventory-gap path never reports those. Register those blocks with a category instead.
- Set `..._min_queries` near `p50_unknown_queries` if single background lookups are the bulk of what you would review.

### Known false positives / Limitations
- **Stale inventory IPs.** A managed laptop that gets a new DHCP lease is "not in the inventory" until the inventory refreshes. The subnet coverage gate exists for this case, but a 0.9 gate still lets through the odd laptop in an otherwise well-covered subnet. Check the device with drilldown 2. Its DNS names (domain controllers, EDR and MDM endpoints, corporate update servers) usually reveal a managed laptop.
- **Roaming-agent DNS is not evidence of an unmanaged device.** With the cloud DNS feeds included, one tenant produced 6 inventory-gap devices in 24 h. All 6 came from the vendor's roaming client, so all were managed laptops. `..._dns_sources` removes them. Earlier, before that exclusion existed, home-router ranges had caused 14 of 17 such results on that tenant and all 6 on another. `..._home_network_ranges` stays as a second safeguard. A corporate LAN that uses one of these ranges is invisible to this rule unless you remove that range from the macro.
- **Whole untracked subnets are not covered by the inventory-gap path.** On the tenant with on-network DNS, 4 h of unknown AI clients split three ways:
  - 25 in 4 /24s that the inventory hardly tracks (coverage under 0.2);
  - 27 alone in their /24;
  - 12 in well-covered /24s with fewer than 10 other AI-active hosts.

  None of them can pass the coverage gate. Guest, BYOD and OT networks are reportable only through registered address-block categories.
- **Generic block categories.** Inventories often hold broad RFC 1918 or site blocks. Those categories never mark an address as inventoried. They report a device only if they match `..._unmanaged_categories`, so keep that regex specific.
- **No user.** DNS has no user, so risk goes to the device address only. DHCP can move an address to another device within the 24 h suppression window. Use the risk event's time and drilldown 2 to identify the device.
- **Forwarders and NAT.** A DNS forwarder, proxy or NAT gateway that appears as `src` represents many devices. Exclude it in `..._filter`.
- **IPv4 only for the inventory-gap path.** IPv6 addresses never pass the coverage test, because they have no /24. They can still match the registered paths if `..._client_ranges` is widened to IPv6.
- **Categories are tenant-defined.** On the validation tenants, `visitor`, `patient`, `kiosk` and `personal computer` asset categories and generic `rfc1918` block tags all described managed devices or corporate ranges. That is why the default regex is narrow.
- **Web/SSE data is not used.** In validation, every `Web` source was either inbound server logs or an SSE service that reports the public egress address. Neither identifies an internal device. SSE products that report device posture (managed/unmanaged) are a stronger signal, but they are not in CIM.

### Validation
Read-only tests on 4 production ES tenants on 2026-10-09. Coverage and day figures come from the Threshold search over the last full 24 h. "Emulated" means the rule run as 24 hourly windows, with the first hit per `src` kept (equivalent to 24 h suppression).

| Tenant | DNS source with AI queries | In scope after `..._dns_sources` | AI-active on-network clients / day | Inventory IP coverage | Parses (rule + 2 drilldowns) | Rows: 4 h run (runtime) | Emulated 24 h, shipped | Emulated 24 h, cloud DNS included | Notes |
|---|---|---|---|---|---|---|---|---|---|
| A | On-prem resolver logs + wire DNS sensor | Yes | 2,193 (206 unknown) | 0.90 | OK | 0 (51 s) | 0 | 0 | No unknown client sat in a /24 with 10 or more other AI-active hosts (0 devices at 5/0.8 either). The registered address-block path fired correctly when the regex was pointed at a block category present on the tenant: 15 devices in 1 h, scores 15–36 |
| B | Cloud DNS-security (roaming client only) | No | 0 (1,471 before scope) | 0.44 before scope | OK | 0 (8 s) | 0 | 6 | All 6 were roaming-client events, so all were managed laptops. The source scope removes them |
| C | Cloud DNS-security (roaming client + agent-reported AD users) | No | 0 (1,391 before scope) | 0.28 before scope | OK | 0 (6 s) | 0 | 0 | 44% of AI-active internal addresses were on home-router ranges |
| D | No AI DNS in the window | n/a | 0 | n/a (empty inventory) | OK | 0 (9 s) | 0 | 0 | Silent by design |

- `asset_lookup_by_cidr` is defined as `CIDR(asset)` on all four tenants. In a self-test on one tenant, `lookup asset_lookup_by_cidr asset as <ip>` matched 20 of 20 test addresses inside known blocks, and `ip as <ip>` matched 0 of 20. With `asset as src`, every AI-active client on that tenant matched at least one block in a 1 h sample (224 of 224). That is why block matches never set the inventoried flag.
- No tenant has BYOD, guest or unmanaged asset or block categories, so the registered paths produced nothing anywhere with the shipped regex.
- The inventory-gap output shape was checked on Tenant A with a relaxed gate (2 other hosts, 0.5 coverage). `unmanaged_reason`, `provider_list`, `ai_domain_sample`, `dns_query_count`, `subnet_other_hosts`, `subnet_coverage` and `risk_score` were populated on every row.
- A synthetic check of `..._unmanaged_categories` matched `byod`, `guest wifi`, `guest-network`, `unmanaged devices`, `personal_device` and `non-corporate`. It did not match `personal computer`, `visitorcare`, `guest services` or `corp laptops`.
- v1.0 baseline on the same tenants: parses, 0 rows everywhere. Its `Web` sources carry no internal clients, and its coverage guard evaluated to null. The `Web` drilldown scanned the whole model and hit the 300 s limit on two tenants.
- All runs completed with no FATAL or ERROR message.

### Deployment
The package is configured with `enable_alerting: false` and `deployment_type: adhoc`, the type it takes once promoted to `saved_searches/packages/`. Before enablement:
1. Run the source check. The tenant needs on-network DNS with client addresses.
2. Register guest/BYOD/unmanaged address blocks as CIDR assets with a category, and set `..._unmanaged_categories`. Alternatively, confirm `inventory_ip_coverage` of 0.9 or more with the Threshold search.
3. Narrow `..._client_ranges` to corporate LAN, Wi-Fi and VPN pools, and review `..._home_network_ranges` against your addressing plan.
4. Measure a day of volume with the Threshold search (`devices_*`).

The rule is risk-only (system object, no notable). Enabling it is a separately approved change.
