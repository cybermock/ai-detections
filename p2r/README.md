# P2R Packages

P2R (Package-to-Release) structures each detection as an independently deployable, versioned package. This format enables selective deployment, per-package version control, and granular dependency tracking.

## Why Modular Packaging Matters

- **Selective deployment** -- Deploy only the detections your data sources support. No DLP? Skip those 4 packages.
- **Independent versioning** -- Update a single detection without touching the rest.
- **Explicit dependencies** -- Each package declares its prerequisites in `package.yml`.
- **Per-package tuning hooks** -- Every package ships `_filter` and `_customizations` macros for local overrides without editing SPL.

## Package Structure

```
p2r/packages/
  hdsi_ai_rba_common/           # DEPLOY FIRST -- shared macros, lookups, transforms
    confs/macros.conf            #   7 shared macros
    confs/transforms.conf        #   Lookup definitions
    lookups/                     #   9 CSV lookup files
    package.yml

  hdsi_ai_<name>/               # Detection package (45 packages)
    confs/savedsearches.conf     #   The correlation search
    confs/macros.conf            #   _filter + _customizations macros
    package.yml                  #   Metadata, dependencies, data prereqs
    README.md

  hdsi_rba_ai_<name>/           # RBA correlation package (5 packages)
    confs/savedsearches.conf     #   Risk threshold / kill chain search
    confs/macros.conf
    package.yml
    README.md
```

51 packages total: 1 common + 45 detection + 5 RBA correlation.

## Deployment Order

1. **`hdsi_ai_rba_common`** -- All packages depend on its shared macros and lookups. Deploy this first.
2. **Detection packages** (`hdsi_ai_*`) -- Deploy in any order. Each declares `hdsi_ai_rba_common` as a prerequisite.
3. **RBA correlation packages** (`hdsi_rba_ai_*`) -- Deploy after detections are generating risk events in the risk index.

> [!WARNING]
> Deploying detection packages without `hdsi_ai_rba_common` will cause macro resolution failures. Every detection references at least `ai_unsanctioned_filter` and `ai_domains_filter` or `ai_process_filter`.

## Per-Package Customization Hooks

Every detection package ships two empty macros for local overrides:

| Macro | Default | Purpose |
|---|---|---|
| `hdsi_ai_<name>_filter` | `()` | Add `WHERE` clauses to exclude users, hosts, or patterns |
| `hdsi_ai_<name>_customizations` | `search *` | Append post-processing (field overrides, enrichments) |

These macros are applied within the search SPL, so your customizations take effect without modifying `savedsearches.conf`.

**Example -- exclude a service account from DNS detection:**
```
[hdsi_ai_dns_queries_to_ai_domains_filter]
definition = (src!="10.0.0.1")
```

## Conformance Audit

All 50 searches pass a 10-check conformance audit:

| Check | Result |
|---|---|
| `action.notable = 1` | 50/50 |
| `action.risk = 1` | 50/50 |
| Notable description present | 50/50 |
| Risk message present | 50/50 |
| Risk object present | 50/50 |
| Drilldown searches present | 50/50 |
| Drilldown key schema (`earliest_offset`/`latest_offset`) | 50/50 |
| Enabled by default (`disabled=0`) | 50/50 |
| Risk object type (`user` or `system`) | 50/50 |

Run the audit yourself: `p2r/tools/audit_savedsearch_conformance.sh`

## Related Documentation

- [Main README](../README.md) -- Detection inventory, risk scoring, quick start
- [Architecture](../docs/ARCHITECTURE.md) -- Data flow, macro relationships
- [Interactive Dashboard](../docs/dashboard.html) -- Filterable detection explorer
- [Tuning Guide](../docs/TUNING_GUIDE.md) -- Threshold calibration
