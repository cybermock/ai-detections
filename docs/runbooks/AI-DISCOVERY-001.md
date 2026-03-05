# AI-DISCOVERY-001 - Unknown High-Volume External API Discovery

> **Detection ID:** AI-DISCOVERY-001
> **Status:** Disabled
> **Risk Score:** None
> **MITRE ATT&CK:** N/A
> **Data Model:** Web
> **Schedule:** `0 2 * * *`
> **Lookback Window:** `-24h@h to now`
> **Kill Chain Phase:** recon
> **Last Updated:** 2026-02-19

---

## Overview

Discovery-only hunt for high-volume unknown external APIs not mapped in provider lookup.

This runbook provides a rapid triage flow, false-positive guidance, and response recommendations for SOC analysts.

---

## Detection Logic

### Plain English

1. Search the configured data models/sources for activity matching this use case.
2. Apply AI provider/tool enrichment and threshold logic.
3. Apply sanctioned-entity filtering (`ai_unsanctioned_filter`).
4. Write risk event metadata (`detection_id`, `mitre_attack`, `ai_kill_chain_phase`) for correlation.

### Analyst Validation SPL (starter)

```spl
index=risk earliest=-24h search_name="AI RBA -*" detection_id="AI-DISCOVERY-001"
| stats sum(risk_score) as total_risk values(search_name) as detections values(risk_message) as risk_messages by risk_object risk_object_type
| sort - total_risk
```

---

## Triage Steps

1. Validate the detection fired in expected timeframe and scope.
2. Confirm user/system identity quality (user, src, host, asset, identity enrichment).
3. Review destination/provider/tool context and volume/count metrics.
4. Correlate with adjacent detections in prior 24h (especially AI-RISK rules).
5. Check allowlist intent vs current sanctioned entries and expiration.
6. Decide: true positive, benign-but-unsanctioned, or false positive/tuning issue.

---

## True Positive Indicators

- Repeated or high-volume behavior aligned with this detection's threat model.
- Corroborating detections across different telemetry planes (web + endpoint + DLP + risk).
- Clear policy mismatch (unsanctioned entity/provider) with meaningful business data exposure risk.

## False Positive Scenarios

- Incomplete/incorrect identity or asset enrichment causes misclassification.
- Provider/domain/process overlap with non-AI services in local telemetry.
- Logging artifacts (proxy retries, scanner activity, synthetic testing) inflate volume/count fields.

---

## Response Actions

### If confirmed true positive

1. Escalate to IR/SOC lead according to severity and data sensitivity.
2. Contain exposure path (identity/session controls, endpoint restrictions, egress controls).
3. Preserve evidence (raw events, timeline, affected entities, lookup states).
4. Execute policy/user remediation and document risk outcome in Incident Review.

### If benign or expected

1. Add/adjust sanctioned entry with provider scope and expiration.
2. Tune threshold/logic only after validating data quality and business context.
3. Document disposition reason and expected future behavior pattern.

---

## Related Detections

- AI-RISK-001 (medium threshold aggregation)
- AI-RISK-002 (high threshold aggregation)
- AI-RISK-003/004/005 (advanced correlation rules)

---

## Data Requirements

- Source(s) mapped to relevant CIM models listed above.
- Lookups: `ai_provider_domains.csv`, `ai_sanctioned_entities.csv`, and `ai_detection_config.csv`.
- Risk framework enabled and writing events to `index=risk` for downstream correlation.

---

## Revision History

| Date | Author | Notes |
|---|---|---|
| 2026-02-19 | Codex | Initial runbook added for AI-DISCOVERY-001. |
