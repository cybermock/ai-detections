# P2R Saved Search Conformance Report

- Generated: 2026-10-10 11:51:22Z
- Scope: `/Users/tmock/Projects/splunk-es-ai-rba/saved_searches/packages`
- Regex engine: grep -E
- Total searches audited: 46
- Fully conformant searches: 46

## Summary

| Check | Passed | Total |
|---|---:|---:|
| action.notable matches role (detection 0, aggregator 1, health/hunting exempt) | 46 | 46 |
| action.risk matches role (detection 1, aggregator 0, health/hunting exempt) | 46 | 46 |
| notable rule_description present | 46 | 46 |
| risk message present (when action.risk = 1) | 46 | 46 |
| risk objects present (when action.risk = 1) | 46 | 46 |
| drilldown searches present | 46 | 46 |
| drilldown dashboards line present | 46 | 46 |
| drilldown keys use earliest_offset/latest_offset | 46 | 46 |
| search enabled by default (disabled = 0) | 46 | 46 |
| risk_object_type in {user,system} | 46 | 46 |
| `<pkg>_filter` referenced inline, never piped | 46 | 46 |
| `<pkg>_risk_score` is the last pipe (when action.risk = 1) | 46 | 46 |

## Nonconformant Packages

| Package | Role | Issues |
|---|---|---|
| _None_ | | _All searches conform_ |
