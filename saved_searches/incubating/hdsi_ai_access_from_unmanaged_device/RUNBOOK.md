# AI-023 - HDSI AI Access From Unmanaged Device

> **Incubating — not released.** This package lives in `saved_searches/incubating/` because it has only been proven with synthetic test events; none of the four validation tenants had both on-network DNS and registered guest/BYOD address blocks (or an inventory-gap subnet that met the gates), so it produced no real results anywhere. Promote it to `saved_searches/packages/` only after it produces real results in a customer environment (see [`saved_searches/incubating/README.md`](../README.md)).

> **AD HOC DETECTION. This rule is not part of the global baseline.** Once promoted, the package deploys as `deployment_type: adhoc`. It works only where the tenant has (1) DNS logged by **on-network** resolvers or sensors and (2) an asset inventory that either tracks client IPs or registers guest/BYOD address blocks with a category. Of the 4 production ES tenants used for validation, only one had on-network DNS and none had registered guest/BYOD blocks. Do not enable it until the checks under [Data Requirements](#data-requirements) pass.

> **Detection ID:** AI-023 (runbook ID; results carry `detection_id=hdsi_ai_access_from_unmanaged_device`)
> **Search name:** `Network - HDSI AI Access From Unmanaged Device - Rule`
> **Package:** `hdsi_ai_access_from_unmanaged_device` v1.1.0 (`deployment_type: adhoc`, `enable_alerting: false`)
> **Status:** Incubating (not released). Ad hoc deployment only once promoted
> **Output:** Risk only (`action.notable = 0`). Aggregators raise the notable.
> **Risk Score:** system (`src`) only, dynamic 5 to 60: base 30 (registered BYOD/guest) or 20 (inventory gap) × highest provider `severity_weight`. Literal `_risk` fallback 20. No user object.
> **MITRE ATT&CK:** T1200 - Hardware Additions (Initial Access); T1588.007 - Obtain Capabilities: Artificial Intelligence (Resource Development)
> **Data Model:** `Network_Resolution` (DNS from on-network resolvers) + ES `asset_lookup_by_str` / `asset_lookup_by_cidr`
> **Schedule:** `11 * * * *` (hourly at :11)
> **Lookback Window:** `-65m@m` to `-5m@m`
> **Suppression:** 24 h (`86400s`) per `src`
> **Kill Chain Phase:** `initial_access` (multi-vector aggregator vector: `risky_access`)
> **Last Updated:** 2026-10-09

---

## Overview

This detection finds a **device on the corporate network that resolves AI provider domains while the organisation does not manage it**. Evidence is DNS resolution of AI provider domains (`Network_Resolution`) as logged by an on-network resolver or sensor. A device counts as unmanaged in one of two ways:

- **Registered as unmanaged:** its own ES asset entry, or the CIDR address block it sits in, carries a category matching `hdsi_ai_access_from_unmanaged_device_unmanaged_categories` (`byod`, `unmanaged`, `guest network/wifi/device`, `personal device`, `non-corporate`).
- **Inventory gap:** it is missing from the asset inventory while at least 90% of at least 10 *other* AI-active hosts in the same /24 are inventoried.

Data typed into an AI service from a personal or rogue device is outside DLP, EDR and browser controls, so the organisation cannot see what was shared. The actor is usually an employee or contractor on a personal laptop or phone, a visitor on a guest network, or an unregistered shadow-IT system. Each finding raises low risk on the device address (`src`, system). DNS has no user, so there is no user risk object.

Cloud DNS-security feeds (Cisco Umbrella / Secure Access) are excluded by default. Their internal-address events come from the vendor's roaming agent, which runs only on managed laptops, so every "unmanaged" result on those feeds is a managed laptop by construction.

---

## MITRE ATT&CK Mapping

| Field | Value |
|---|---|
| Technique ID | T1200, T1588.007 |
| Technique Name | Hardware Additions; Obtain Capabilities: Artificial Intelligence |
| Tactic | Initial Access; Resource Development |
| Sub-technique | T1588.007 (Artificial Intelligence) |

The annotation is `{"mitre_attack": ["T1200", "T1588.007"]}`, and the search sets the same IDs in `mitre_attack`.

---

## Detection Logic

### Plain English

1. Query `Network_Resolution` with `tstats` for DNS queries that match the AI-domain prefilter (`..._dns_scope`, generated from every `ai_provider_domains` row, with a trailing `*` so `chatgpt.com.` matches). Cloud DNS roaming-agent sourcetypes are excluded inside the same where clause (`..._dns_sources`).
2. Keep client addresses inside `..._client_ranges` (RFC 1918 and 100.64.0.0/10) and outside `..._home_network_ranges` (consumer router defaults).
3. Resolve each query to a provider with the common `ai_domains_filter`. Only enabled providers survive.
4. Look up the address in `asset_lookup_by_str` (`asset as src`): this sets "inventoried" and returns `nt_host` and `category`. Look it up in `asset_lookup_by_cidr` (`asset as src`, the ES CIDR match key): this returns the address-block category. A block match never marks an address as inventoried.
5. Per /24, count the AI-active hosts and how many of them are inventoried (computed before the allow-list).
6. Remove approved devices with `ai_unsanctioned_filter(device_name,src,provider)`. Keys: asset `nt_host`, the address, and the first asset or block category as the group key.
7. Keep the device if it made at least `..._min_queries` (5) AI queries in the hour **and** it is `registered_asset`, `registered_address_block`, or `inventory_gap` (10 other hosts, 0.9 coverage).
8. Score: `risk_score = min(60, max(5, round(base × max severity_weight)))`, base 30 for the registered paths and 20 for the inventory gap. The score lands on `src` only.

### Key Fields

| Field | Description | Example Value |
|---|---|---|
| `src` | Device address (the risk object) | `10.20.30.41` |
| `unmanaged_basis` | `registered_asset`, `registered_address_block` or `inventory_gap` | `inventory_gap` |
| `unmanaged_reason` | Plain-language basis with the category or coverage figures | `not in the asset inventory, while 18 of the 19 other AI-active hosts in 10.20.30.0/24 are` |
| `src_nt_host` / `src_category` / `src_block_category` | Asset name, asset category and CIDR block category | `byod` |
| `src_subnet`, `subnet_other_hosts`, `subnet_inventoried_hosts`, `subnet_coverage` | Subnet coverage evidence | `10.20.30.0/24`, `19`, `18`, `0.95` |
| `provider_list`, `ai_domain_sample`, `usage_types` | AI providers and sample domains resolved | `OpenAI, Anthropic` |
| `dns_query_count` | AI DNS queries in the hour | `37` |
| `base_score`, `max_weight`, `risk_score` | Scoring inputs and result | `20`, `1.0`, `20` |

### Thresholds

| Parameter | Default | Macro | Notes |
|---|---|---|---|
| Minimum AI DNS queries per device per hour | 5 | `hdsi_ai_access_from_unmanaged_device_min_queries` | Lower values add single background lookups |
| Other AI-active hosts in the /24 | 10 | `hdsi_ai_access_from_unmanaged_device_min_subnet_hosts` | The device itself is not counted |
| Inventoried share of those hosts | 0.9 | `hdsi_ai_access_from_unmanaged_device_min_subnet_coverage` | Set to `2` to switch the inventory-gap path off |
| Unmanaged categories | word-bounded regex | `hdsi_ai_access_from_unmanaged_device_unmanaged_categories` | Replace with your own category names |

---

## Triage Steps

> **Estimated triage time:** 10 to 20 minutes. Replace `<src>`, `<src_subnet>`, `<nt_host>` and `<category>` with the values from the risk event. Run each search over the time of the risk event (time picker), unless stated otherwise.

### Step 1: Validate the risk event

```spl
| from datamodel:"Risk.All_Risk"
| search source="Network - HDSI AI Access From Unmanaged Device - Rule" risk_object="<src>"
| table _time, source, risk_object, risk_object_type, risk_score, unmanaged_basis, unmanaged_reason, risk_message
| sort - _time
```

- Note `unmanaged_basis`. `registered_asset` and `registered_address_block` mean the inventory itself says the device or network is unmanaged. `inventory_gap` is an inference and needs Step 3.
- One event per device per day is expected (24 h suppression). DHCP can hand the same address to another device within that day, so always work from the event time.

### Step 2: Identify the device and its network

```spl
| makeresults
| eval src="<src>"
| lookup asset_lookup_by_str asset as src OUTPUT nt_host, category, owner, bunit, priority
| lookup asset_lookup_by_cidr asset as src OUTPUT category as block_category, bunit as block_bunit
| table src, nt_host, category, owner, bunit, priority, block_category, block_bunit
```

- A guest, BYOD or visitor block category tells you which network the device was on.
- If DHCP is in CIM, find the device MAC and hostname that held the lease at the event time:

```spl
| tstats summariesonly=t allow_old_summaries=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Sessions where nodename=All_Sessions.DHCP All_Sessions.src_ip="<src>" by All_Sessions.src_ip All_Sessions.src_mac All_Sessions.src_nt_host
| rename All_Sessions.* as *
| convert ctime(firstTime) ctime(lastTime)
```

Otherwise use the NAC, wireless controller or DHCP server console for the lease holder.

### Step 3: Review the DNS fingerprint (managed laptop or not?)

This is the rule's second drilldown:

```spl
| tstats summariesonly=t allow_old_summaries=t count min(_time) as firstTime max(_time) as lastTime values(DNS.record_type) as record_type from datamodel=Network_Resolution where DNS.src="<src>" by DNS.src DNS.query
| rename DNS.* as *
| sort - count
| head 500
| convert ctime(firstTime) ctime(lastTime)
| table firstTime, lastTime, src, query, record_type, count
```

- Queries for your domain controllers, EDR and MDM endpoints, corporate update servers or internal application names usually mean a **managed laptop with a stale inventory IP** (false positive; see Tuning).
- Consumer-only names (phone vendor services, game consoles, personal cloud storage, smart-TV services) and no corporate names point to a personal device.

For an `inventory_gap` result, re-check the subnet coverage that justified it:

```spl
| tstats summariesonly=t allow_old_summaries=t count from datamodel=Network_Resolution where DNS.src="<src_subnet>" `hdsi_ai_access_from_unmanaged_device_dns_scope` `hdsi_ai_access_from_unmanaged_device_dns_sources` by DNS.src
| rename DNS.src as src
| lookup asset_lookup_by_str asset as src OUTPUT asset as inv_asset, nt_host
| eval inventoried=if(isnotnull(inv_asset),1,0)
| stats dc(src) as ai_active_hosts sum(inventoried) as inventoried_hosts values(eval(if(inventoried=0,src,null()))) as not_inventoried
```

Several uninventoried addresses in the same subnet at once usually mean the inventory feed is behind, not that several unmanaged devices appeared.

### Step 4: Check for related risk on the device

```spl
| from datamodel:"Risk.All_Risk"
| search risk_object="<src>" OR risk_object="<nt_host>"
| stats sum(risk_score) as total_risk dc(source) as detections values(source) as sources values(risk_object_type) as risk_object_types by risk_object
| sort - total_risk
```

- This rule maps to the `risky_access` vector of `Threat - HDSI RBA AI Multi-Vector Risk - Rule`. Uploads or data-exposure detections on the same address are the combination that matters.
- The device has no user, so the user threshold aggregators (`Threat - HDSI RBA AI User Risk Threshold Exceeded - Rule`, medium 60, and `... User Critical Risk Threshold Exceeded - Rule`, 90) never count this event. Correlate the address to a person with Step 2 if you need that view.

### Step 5: Determine sanctioned status

```spl
| inputlookup ai_sanctioned_entities
| search enabled=1 (entity="<src>" OR entity="<nt_host>" OR entity="<category>")
| table entity_type, entity, provider, scope, expires, owner, reason, allow_key
```

- An approved BYOD programme should be allow-listed by a stable key (pool CIDR, block category or `nt_host`), never by a DHCP address.

### Step 6: Make a determination

- **True Positive:** a personal or unregistered device on a corporate network used AI services, against policy.
- **Benign True Positive:** the device is unmanaged but its AI use is approved (for example a sanctioned BYOD programme or a guest network where AI use is allowed). Tune with a stable allow-list key.
- **False Positive:** the device is managed (stale inventory IP, roaming DNS agent, DNS forwarder or NAT appearing as `src`). Fix the inventory or the scope macros.

---

## True Positive Indicators

- `unmanaged_basis` is `registered_asset` or `registered_address_block` and the category is a guest or BYOD pool.
- The DNS fingerprint has no corporate names (no domain controller, EDR, MDM or internal application lookups).
- The DHCP/NAC record shows a consumer device MAC vendor or a hostname that is not in your naming scheme.
- The same address also carries upload or data-exposure risk from other HDSI AI detections.
- High-weight providers (general-purpose chat, file-upload capable services) rather than a single background lookup.

---

## False Positive Scenarios

Evidence from the 2026-10-09 validation on 4 production ES tenants (package README):

| Scenario | Likelihood | Mitigation |
|---|---|---|
| Managed laptop with a new DHCP lease that the inventory has not picked up yet | Medium (where the inventory-gap path is on) | Refresh the inventory feed (DHCP, NAC, EDR/MDM export at least daily). Raise `..._min_subnet_coverage`, or set it to `2` to switch the path off |
| Cloud DNS roaming agent (Umbrella / Secure Access) reporting an internal or home address | High if those sourcetypes are put back in scope | Keep them in `..._dns_sources`. With them included, one tenant produced 6 devices in 24 h, all roaming-client managed laptops |
| Laptop at home on a consumer router range reached through VPN split DNS | Medium | `..._home_network_ranges` drops 12 common router ranges. In validation 44% to 54% of AI-active internal addresses on roaming feeds were in those ranges |
| DNS forwarder, proxy or NAT gateway appearing as `src` | Low to Medium | Exclude it in `hdsi_ai_access_from_unmanaged_device_filter` (`NOT DNS.src IN ("10.0.0.53")`) |
| Generic block categories (`rfc1918`, site tags) or categories such as `visitor`, `patient`, `kiosk`, `personal computer` that describe managed devices | Medium | Keep `..._unmanaged_categories` narrow. On one tenant every AI-active client matched a generic RFC 1918 block (224 of 224), which is why block matches never set "inventoried" |
| Approved BYOD pool | Depends on policy | Exclude the pool CIDR in `..._filter`, give it a distinct block category and drop it in `..._customizations`, or allow-list `<category>|*` |

---

## Response Actions

### If confirmed True Positive

1. **Contain:** move the device to the guest/quarantine VLAN through NAC, or block AI provider categories for that network segment at the proxy/firewall.
2. **Notify:** the device owner (from DHCP/NAC/wireless records) and their manager. Remind them of the acceptable-use and BYOD policy.
3. **Investigate:** check Step 4 for upload, DLP or personal-account risk from the same address in the same period. Ask the owner what was shared with the AI service.
4. **Remediate:** enrol the device in MDM, or register the network as a guest/BYOD block with a category so future use is reported on the registered path.
5. **Document:** record the device, owner, providers and decision in the case.

### If Benign True Positive

1. Add a stable key to `ai_sanctioned_entities` (common package): `<category>|*`, `<category>|<provider>` or `<nt_host>|<provider>` (lower case). Never key on a DHCP address.
2. Put the business justification in `reason` and set `expires`.
3. Close the related aggregator notable (if any) as benign.

---

## Tuning Guidance

### Reducing false positives

- Fix inventory freshness first: `inventory_ip_coverage` of 0.9 or more is needed for the inventory-gap path.
- Narrow `hdsi_ai_access_from_unmanaged_device_client_ranges` to corporate LAN, Wi-Fi and VPN pools.
- Register guest/BYOD blocks as CIDR assets with a category: that path is precise and does not depend on coverage.
- Use `hdsi_ai_access_from_unmanaged_device_customizations` for post-scoring exclusions (`search NOT src_block_category="approved-byod-ai"`).
- Use `hdsi_ai_access_from_unmanaged_device_risk_score` (last pipe) to rescale `risk_score`.

### Adjusting thresholds

Source check (4 h). Every in-scope sourcetype should be an on-network resolver or sensor:

```spl
| tstats summariesonly=t allow_old_summaries=t count dc(DNS.src) as clients from datamodel=Network_Resolution where `hdsi_ai_access_from_unmanaged_device_dns_scope` `hdsi_ai_access_from_unmanaged_device_dns_sources` earliest=-4h@h latest=@h by sourcetype DNS.vendor_product
```

Gate sizing (24 h): the `devices_*` columns are distinct devices per day that each gate would report, which is the expected daily risk volume under 24 h suppression. The full search is in the package README, section *Threshold*. Do not go below 5 other hosts or 0.8 coverage.

### Adding allowlist entries

`ai_sanctioned_entities.csv` in `hdsi_ai_rba_common`:

```
entity_type,entity,provider,scope,expires,owner,reason,enabled,allow_key
group,guest network,*,group,<YYYY-MM-DD>,<your_name>,<justification>,1,guest network|*
system,lab-byod-07,OpenAI,provider,<YYYY-MM-DD>,<your_name>,<justification>,1,lab-byod-07|openai
```

---

## Related Detections

| Detection ID | Name | Relationship |
|---|---|---|
| AI-012 | `Network - HDSI AI DNS Queries To AI Domains - Rule` | Same DNS evidence on managed and unmanaged hosts alike |
| AI-022 | `Network - HDSI AI Access Via VPN/Proxy Evasion - Rule` | Same `risky_access` vector; evasion from the same network |
| AI-026 | `Identity - HDSI AI Usage From Personal Account / OAuth Mismatch - Rule` (incubating: not released; see [`saved_searches/incubating/hdsi_ai_usage_from_personal_account_oauth_mismatch/`](../hdsi_ai_usage_from_personal_account_oauth_mismatch/RUNBOOK.md)) | Personal accounts often go with personal devices |
| AI-RISK-005 | `Threat - HDSI RBA AI Multi-Vector Risk - Rule` | Counts this rule as `risky_access` and raises the notable |

---

## Data Requirements

| Requirement | Details |
|---|---|
| Data Model | `Network_Resolution.DNS`, accelerated, from **on-network** resolvers or sensors (Windows DNS, Infoblox, BIND, Stream/Zeek on the resolver segment) |
| Required Fields | `DNS.src` (the client, not a forwarder), `DNS.query`, `sourcetype` |
| Sourcetype Examples | `MSAD:NT6:DNS`, `infoblox:dns`, `isc:bind:query`, `stream:dns`, `bro:dns:json`. Not `cisco:umbrella:dns`, `cisco:cloud_security:dns`, `opendns:dnslogs` (excluded) |
| CIM Compliance | `src` and `query` mapped in `Network_Resolution` |
| Acceleration | Required (`summariesonly=t`) |
| Lookups | ES `asset_lookup_by_str` (match key `asset`: `nt_host`, `category`), ES `asset_lookup_by_cidr` (`CIDR(asset)`: `category`), common `ai_provider_domains` (via `ai_domains_filter`), `ai_sanctioned_entities` (via `ai_unsanctioned_filter(3)`) |
| Common package | `hdsi_ai_rba_common` |

Validation summary (read-only, 2026-10-09, 4 production ES tenants): the rule and both drilldowns parse on Tenants A to D, and a 4 h run returned 0 rows everywhere with no errors. Tenant A was the only tenant with on-network DNS (inventory IP coverage 0.90, 206 unknown AI clients a day, all in untracked or sparse /24s, so 0 inventory-gap results). Tenants B and C log DNS only through a cloud DNS-security roaming agent and are out of scope. Tenant D had no AI DNS and an empty inventory. With the category regex pointed at a block category present on Tenant A, the registered address-block path reported 15 devices in 1 h at scores 15 to 36.

---

## Revision History

| Date | Author | Change |
|---|---|---|
| 2026-02-22 | Brainstorm SOC | Initial production runbook |
| 2026-10-09 | Trevor Mock, Hurricane Labs | 1.1.0: rewritten for v1.1.0. Rule moved from `Web` to on-network DNS (`Network_Resolution`); registered asset/address-block categories and subnet inventory coverage replace `is_expected`; cloud DNS roaming-agent feeds and home-router ranges excluded; risk on the device (`src`) only, dynamic 5 to 60; MITRE T1200 + T1588.007; ad hoc deployment; triage SPL uses the Risk data model and current search name |
| 2026-10-10 | Trevor Mock, Hurricane Labs LLC | Moved to `saved_searches/incubating/` (not released): only proven with synthetic test events; no validation tenant had the data. Was `docs/runbooks/AI-023.md` |
