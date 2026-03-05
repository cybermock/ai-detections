# Contributing Guide

This guide covers development setup, project structure, and the process for adding new detections, lookups, and documentation to the AI RBA Starter Pack.

## Development Environment Setup

### Prerequisites

- Git
- Python 3.9+
- Access to a Splunk ES development instance (for testing)
- A text editor with SPL syntax highlighting (recommended: VS Code with Splunk Extension)

### Clone and Install

```bash
git clone <repository-url>
cd splunk-es-ai-rba

# Install Python dependencies for testing
pip install -r requirements.txt
```

### Project Structure

```
splunk-es-ai-rba/
├── default/
│   ├── app.conf                 # Splunk app metadata
│   ├── savedsearches.conf       # All detection definitions
│   ├── macros.conf              # Reusable SPL macros
│   └── transforms.conf          # CSV lookup definitions
├── lookups/
│   ├── ai_provider_domains.csv  # AI domain catalog (52 domains)
│   ├── ai_tool_processes.csv    # AI process catalog (80+ entries)
│   ├── ai_sanctioned_entities.csv # Allowlist
│   ├── ai_detection_config.csv  # Tunable thresholds
│   ├── ai_mitre_mapping.csv     # MITRE ATT&CK mappings
│   ├── ai_prompt_injection_patterns.csv
│   ├── ai_department_sensitivity.csv
│   └── ai_deepfake_tools.csv
├── metadata/
│   └── default.meta             # Splunk permissions metadata
├── docs/
│   ├── ARCHITECTURE.md          # System architecture with Mermaid diagrams
│   ├── TUNING_GUIDE.md          # Threshold calibration guidance
│   ├── CONTRIBUTING.md          # This file
│   ├── DETECTION_TEMPLATE.md    # Template for new detections
│   └── runbooks/
│       ├── _runbook_template.md # Template for analyst runbooks
│       └── AI-*.md              # Individual detection runbooks
├── tests/
│   └── __init__.py
├── CHANGELOG.md
└── README.md
```

## Adding a New Detection

### Step 1: Choose a detection ID

Detection IDs follow the format `AI-XXX` where XXX is a zero-padded sequential number. IDs are organized by category:

| Range | Category | Examples |
|---|---|---|
| AI-001 to AI-027 | Shadow AI (original set) | Web access, CLI, desktop, upload |
| AI-028 to AI-039 | Shadow AI (consolidated/new) | Consolidated web access |
| AI-040 to AI-049 | UEBA / Behavioral | Baseline anomaly detections |
| AI-050+ | Adversarial AI | Prompt injection, deepfake, abuse |
| AI-RISK-XXX | Risk Aggregation | Threshold correlation rules |

Check the current highest ID in `savedsearches.conf` and `ai_mitre_mapping.csv` before assigning a new one.

### Important: tstats Hardcoding Limitation

**When adding new AI domains or process names, you must update BOTH the lookup CSV AND the hardcoded lists in detection searches.**

Splunk's `tstats` command does not support runtime lookup joins in its `WHERE` clause. This means detections that use `tstats` must hardcode domain names and process names directly in the search. When you add a new entry to a lookup CSV (e.g., a new domain to `ai_provider_domains.csv` or a new process to `ai_tool_processes.csv`), you must also update the corresponding hardcoded lists in these detection searches:

| Detection | Hardcoded Field | Lookup Used Post-tstats |
|---|---|---|
| AI-004 | `Processes.process_name IN (...)` | `ai_tool_processes` via `ai_process_filter` |
| AI-005 | `Processes.process_name=*` (uses lookup after) | `ai_tool_processes` |
| AI-008 | `Processes.process_name IN (...)` | `ai_tool_processes` via `ai_process_filter` |
| AI-011 | `Processes.process_name IN (...)` | `ai_tool_processes` via `ai_process_filter` |
| AI-012 | `DNS.query IN (...)` | `ai_provider_domains` via `ai_domains_filter` |
| AI-014 | `All_Traffic.dest_port IN (...)` | N/A (port-based) |
| AI-035 | `Processes.process_name IN (...)` | `ai_tool_processes` |

**Failure to update both will cause drift** where the lookup recognizes a new tool/domain but the `tstats` query never finds events for it. Always grep for existing hardcoded values in `savedsearches.conf` to find all places that need updating.

### Step 2: Write the SPL search

Follow these conventions:

**Search structure:**
1. Start with `| tstats` or `| datamodel` for CIM-compliant data model queries.
2. Use `summariesonly=t allow_old_summaries=t` for tstats performance.
3. Rename data model fields: `| rename Web.* as *` or `| rename Processes.* as *`.
4. Normalize key fields: `| eval user=coalesce(user,"unknown"), src=coalesce(src,dest)`.
5. Apply domain/process enrichment macros: `` `ai_domains_filter` `` or `` `ai_process_filter` ``.
6. Apply threshold logic from `ai_detection_config.csv` if applicable.
7. Apply allowlist filter last: `` `ai_unsanctioned_filter(user,src,provider)` ``.
8. Set metadata fields: `| eval ai_activity="...", detection_id="AI-XXX", mitre_attack="T..."`.

**SPL formatting guidelines:**
- Use pipes (`|`) at the start of new lines for readability in the conf file, but join them on one line in `savedsearches.conf` (Splunk requires single-line search values).
- Use lowercase for field names.
- Use double quotes for string values in eval.
- Use backticks for macro invocations.

### Step 3: Add to savedsearches.conf

Use the template from `docs/DETECTION_TEMPLATE.md`. Required fields:

```ini
[AI RBA - Your Detection Name]
description = One-line description. MITRE: TXXXX
search = <your SPL search on one line>
cron_schedule = */5 * * * *
dispatch.earliest_time = -15m@m
dispatch.latest_time = now
alert.suppress = 1
alert.suppress.period = 1h
alert.suppress.fields = user,provider
action.risk = 1
action.risk.param._risk = [{"risk_object_field":"user","risk_object_type":"user","risk_score":"XX"},{"risk_object_field":"src","risk_object_type":"system","risk_score":"XX"}]
action.risk.param._risk_message = Descriptive message with $field$ tokens.
action.notable = 0
```

**Naming convention:** `AI RBA - <Detection Name>` (title case, descriptive).

### Step 4: Add to ai_mitre_mapping.csv

Add a row mapping the new detection ID to its MITRE ATT&CK technique:

```csv
AI-XXX,T1234.001,Technique Name,Tactic Name
```

### Step 5: Create a runbook

Copy `docs/runbooks/_runbook_template.md` to `docs/runbooks/AI-XXX.md` and fill in all sections. At minimum:

- Overview: What and why
- Detection Logic: Plain English steps
- Triage Steps: Numbered analyst workflow with SPL queries
- True Positive / False Positive guidance
- Response Actions
- Data Requirements

### Step 6: Update README.md

Add a row to the detection set table in README.md:

```markdown
| AI-XXX | Your detection name | XX+XX | T1234 | Data Model |
```

### Step 7: Run tests

```bash
python -m pytest tests/ -v
```

All tests must pass before submitting a pull request.

## Adding a New Lookup

### Step 1: Create the CSV file

Create the CSV in `lookups/` with a header row. Follow these conventions:

- Use lowercase column names with underscores.
- Include an `enabled` column (1/0) for rows that can be toggled.
- Do not include trailing commas or empty rows.
- Use UTF-8 encoding without BOM.

### Step 2: Add a transform in transforms.conf

```ini
[your_lookup_name]
filename = your_lookup_name.csv
case_sensitive_match = false
```

### Step 3: Add a schema test

If a test suite for CSV schema validation exists (e.g., `test_csv_schema.py`), add a test that validates:

- Required columns are present.
- No duplicate keys.
- Data types are correct (e.g., `enabled` is 0 or 1).
- No empty required fields.

### Step 4: Reference in documentation

Update ARCHITECTURE.md to include the new lookup in the lookup relationship diagram and component descriptions.

## Pull Request Checklist

Before submitting a PR, verify:

- [ ] **Tests pass:** `python -m pytest tests/ -v` completes with no failures.
- [ ] **Lint passes:** No syntax errors in .conf files; CSV files are valid.
- [ ] **Runbook exists:** Every new detection has a corresponding `docs/runbooks/AI-XXX.md`.
- [ ] **README updated:** Detection set table includes the new detection.
- [ ] **MITRE mapping added:** `ai_mitre_mapping.csv` includes the new detection ID.
- [ ] **CHANGELOG updated:** New entries added under the appropriate version section.
- [ ] **No hardcoded thresholds:** Configurable values use `ai_detection_config.csv` lookup.
- [ ] **Allowlist filter applied:** Detection search ends with `ai_unsanctioned_filter` macro.
- [ ] **Risk scoring documented:** Risk scores are justified (higher for higher-confidence/higher-impact detections).
- [ ] **Suppress fields set:** `alert.suppress.fields` includes the appropriate dedup fields.

## Naming Conventions

### Detection IDs

- Format: `AI-XXX` (zero-padded three-digit number)
- Risk rules: `AI-RISK-XXX`
- Sequential within category ranges (see table above)

### Stanza Names

- Format: `AI RBA - <Detection Name>`
- Title case
- Descriptive but concise (under 60 characters)

### Macro Names

- Lowercase with underscores
- Prefix with `ai_`
- Include argument count in parentheses: `ai_unsanctioned_filter(3)`

### Lookup File Names

- Lowercase with underscores
- Prefix with `ai_`
- Extension: `.csv`

### Field Names

- Lowercase with underscores
- Follow CIM naming where applicable (`user`, `src`, `dest`, `process_name`)
- Custom fields: `ai_activity`, `detection_id`, `provider`, `upload_tier`

## Code Style

### SPL Formatting

In savedsearches.conf, searches must be on a single line. For readability during development, format with pipes on new lines:

```spl
| tstats summariesonly=t allow_old_summaries=t count
    from datamodel=Web
    where Web.url_domain=*
    by Web.user Web.src Web.url_domain
| rename Web.* as *
| eval user=coalesce(user,"unknown"),
       src=coalesce(src,"unknown")
| `ai_domains_filter`
| `ai_unsanctioned_filter(user,src,provider)`
| eval ai_activity="your_activity",
       detection_id="AI-XXX",
       mitre_attack="T1234"
```

Then collapse to a single line before adding to savedsearches.conf.

### CSV Formatting

- No spaces after commas in data values.
- No trailing newlines or carriage returns.
- Quote values containing commas: `"value, with comma"`.
- Empty optional fields: leave blank (no quotes).

### Risk Score Guidelines

| Confidence Level | User Risk | System Risk | Total | Examples |
|---|---|---|---|---|
| Low (informational) | 10-15 | 8-12 | 18-27 | DNS queries, first-seen, browser extensions |
| Medium (suspicious) | 18-25 | 10-15 | 28-40 | CLI execution, burst activity, desktop apps |
| High (concerning) | 30-40 | 15-20 | 45-60 | Scripted invocation, model downloads, privileged usage |
| Critical (confirmed threat) | 50-80 | 20-30 | 70-110 | DLP violations, high-tier uploads |
