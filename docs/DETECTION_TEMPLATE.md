# Detection Template

Use this template when adding a new detection to `default/savedsearches.conf`. Replace all placeholder values in angle brackets (`<...>`) with actual values.

## savedsearches.conf Stanza

```ini
# --------------------------------------------------------------------------
# <AI-XXX> - <Detection Name>
# Description: <One sentence describing what this detection identifies>
# MITRE: <TXXXX>
# Risk: user=<XX>, system=<XX>
# Data Model: <Web | Endpoint.Processes | Network_Traffic | Network_Resolution | Data_Loss_Prevention>
# --------------------------------------------------------------------------
[AI RBA - <Detection Name>]
# A one-line description including the MITRE technique ID.
description = <Describe what is detected and why it matters>. MITRE: <TXXXX>

# The SPL search (must be a single line in the conf file).
# Structure:
#   1. tstats query against CIM data model
#   2. Field normalization (rename, coalesce)
#   3. Enrichment macros (ai_domains_filter or ai_process_filter)
#   4. Threshold/filtering logic
#   5. Allowlist filter (ai_unsanctioned_filter) - MUST be last
#   6. Metadata tagging (ai_activity, detection_id, mitre_attack)
search = <your SPL search here>

# Schedule: how often the search runs.
# Use */5 for real-time detections, */15 for longer lookbacks, daily for baselines.
cron_schedule = */5 * * * *

# Time window: how far back each run looks.
# Use -15m@m for 5-min schedule, -30d@d for baseline detections.
dispatch.earliest_time = -15m@m
dispatch.latest_time = now

# Suppression: prevent duplicate alerts for the same entity.
alert.suppress = 1
alert.suppress.period = 1h
# Fields to deduplicate on. Common: user,provider or user,src,process_name
alert.suppress.fields = <field1>,<field2>

# Risk action: assign risk scores to users and systems.
# This is the primary output of individual detections.
action.risk = 1
# risk_score values: see CONTRIBUTING.md for scoring guidelines
# risk_object_type: "user" or "system"
# risk_object_field: the field name containing the entity value
action.risk.param._risk = [{"risk_object_field":"user","risk_object_type":"user","risk_score":"<XX>"},{"risk_object_field":"src","risk_object_type":"system","risk_score":"<XX>"}]
# Use $field$ tokens to include dynamic values in the risk message.
action.risk.param._risk_message = <Descriptive message about what happened>. User: $user$, Source: $src$.

# Notable: individual detections should NOT create notables (set to 0).
# Only risk aggregation rules (AI-RISK-*) create notables.
action.notable = 0
```

## Field Reference

| Field | Required | Description |
|---|---|---|
| `description` | Yes | One-line description with MITRE technique ID |
| `search` | Yes | The SPL search (single line) |
| `cron_schedule` | Yes | Cron expression for scheduling |
| `dispatch.earliest_time` | Yes | Lookback start time |
| `dispatch.latest_time` | Yes | Lookback end time (usually `now`) |
| `alert.suppress` | Yes | Set to `1` to enable suppression |
| `alert.suppress.period` | Yes | How long to suppress duplicates |
| `alert.suppress.fields` | Yes | Fields to deduplicate on |
| `action.risk` | Yes | Set to `1` to enable risk scoring |
| `action.risk.param._risk` | Yes | JSON array of risk object definitions |
| `action.risk.param._risk_message` | Yes | Human-readable risk message with $field$ tokens |
| `action.notable` | Yes | Set to `0` for individual detections |

## Risk Object Types

```json
// User risk object (most detections)
{"risk_object_field":"user","risk_object_type":"user","risk_score":"25"}

// System risk object (endpoint/IP-based detections)
{"risk_object_field":"src","risk_object_type":"system","risk_score":"15"}

// Dynamic risk score (for tiered detections like AI-007)
{"risk_object_field":"user","risk_object_type":"user","risk_score":"$risk_score$"}
```

## Example: Completed Detection

Below is a complete example of a detection that monitors for AI service access from VPN connections:

```ini
[AI RBA - AI Service Access Via VPN]
description = Detect AI service access from VPN-connected endpoints. VPN users accessing AI services may be remote workers exfiltrating data outside the corporate network perimeter. MITRE: T1567
search = | tstats summariesonly=t allow_old_summaries=t count sum(Web.bytes_out) as bytes_out min(_time) as firstTime max(_time) as lastTime values(Web.http_user_agent) as http_user_agent from datamodel=Web where Web.url_domain=* by Web.user Web.src Web.url_domain | rename Web.* as * | eval user=coalesce(user,"unknown"), src=coalesce(src,"unknown"), ai_domain=lower(url_domain) | `ai_domains_filter` | lookup asset_lookup_by_str ip as src OUTPUTNEW category as src_category | where lower(src_category)="vpn" | stats sum(count) as request_count sum(bytes_out) as total_bytes values(ai_domain) as ai_domains min(firstTime) as firstTime max(lastTime) as lastTime by user src provider | eval mb_out=round(total_bytes/1024/1024,2) | `ai_unsanctioned_filter(user,src,provider)` | eval ai_activity="vpn_ai_access", detection_id="AI-050", mitre_attack="T1567"
cron_schedule = */5 * * * *
dispatch.earliest_time = -15m@m
dispatch.latest_time = now
alert.suppress = 1
alert.suppress.period = 1h
alert.suppress.fields = user,provider
action.risk = 1
action.risk.param._risk = [{"risk_object_field":"user","risk_object_type":"user","risk_score":"20"},{"risk_object_field":"src","risk_object_type":"system","risk_score":"12"}]
action.risk.param._risk_message = AI service access via VPN by $user$ from $src$ to $provider$ ($request_count$ requests, $mb_out$ MB uploaded).
action.notable = 0
```

## Checklist Before Adding

- [ ] Detection ID is unique and follows the numbering convention
- [ ] Search uses CIM data models (not raw sourcetypes)
- [ ] Search includes `ai_unsanctioned_filter` as the last filtering step
- [ ] Risk scores follow the scoring guidelines in CONTRIBUTING.md
- [ ] Suppress fields prevent duplicate alerts for the same entity
- [ ] `action.notable = 0` (only risk aggregation rules create notables)
- [ ] Description includes the MITRE technique ID
- [ ] ai_mitre_mapping.csv updated with the new detection ID
- [ ] Runbook created at `docs/runbooks/AI-XXX.md`
