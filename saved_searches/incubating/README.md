# Incubating detections (not released)

**Author:** Trevor Mock, Hurricane Labs LLC. Security Operations Architect

This folder holds detections that are **kept but not released**. Each one parses and runs on all four validation tenants (Tenants A–D), and its logic passed synthetic tests run through the real search in Splunk. None of the tenants had the data it needs, though, so none of them has fired on real activity. Until one does, they stay here, outside `saved_searches/packages/`, so they cannot be shipped or deployed by mistake.

| Package | Search | What it needs before it can be proven |
|---|---|---|
| `hdsi_ai_access_from_unmanaged_device` | `Network - HDSI AI Access From Unmanaged Device - Rule` | On-network DNS (resolvers or sensors, not cloud roaming agents) plus an asset inventory of client IPs or registered guest/BYOD address blocks |
| `hdsi_ai_browser_extension_high_volume_data_transmission` | `Network - HDSI AI Browser Extension High-Volume Data Transmission - Rule` | A forward proxy, SWG or SSE that writes destination host and request bytes to CIM Web |
| `hdsi_ai_dlp_violation_on_service_upload` | `Audit - HDSI AI DLP Violation On Service Upload - Rule` | An egress DLP/CASB incident feed in the CIM `DLP` model (`DLP_Incidents`) that names the AI destination |
| `hdsi_ai_usage_from_personal_account_oauth_mismatch` | `Identity - HDSI AI Usage From Personal Account / OAuth Mismatch - Rule` | AI traffic attributed to users plus corporate SSO sign-ins to the same provider |

Each folder has the normal package layout (`package.yml`, `confs/`, `README.md`) plus its analyst runbook as `RUNBOOK.md`. The package README's **Validation** section records what was tested.

## How this folder is kept separate

- `validate.py`, `deploy.py`, `tools/audit_savedsearch_conformance.sh` and the release tests only read `packages/`, so nothing here is validated as release content or deployed.
- No released package depends on an incubating one. `tests/test_incubating.py` enforces this and checks that every incubating package still renders cleanly against the current common package.
- The common `ai_mitre_mapping.csv` lists released detections only. The rows for these four are under [Promotion checklist](#promotion-checklist).
- The `hdsi_rba_ai_multi_vector_risk` vector map and the `hdsi_rba_ai_data_collection_kill_chain` upload list still name these detection IDs. A detection that is not deployed writes no risk, so this has no effect until one is promoted, and then it is counted correctly.

## Testing one against a customer environment

Render it to self-contained SPL and run it read-only on a search head that has the data:

```bash
python3 saved_searches/tools/render_live_spl.py hdsi_ai_dlp_violation_on_service_upload --drilldowns
```

Run the README's prerequisite and threshold SPL first. A package is ready for promotion when it returns real, reviewed results (true positives, or clearly explainable benign activity at an acceptable volume) on at least one tenant.

## Promotion checklist

1. Move the folder: `saved_searches/incubating/<package>/` to `saved_searches/packages/<package>/`.
2. Move `RUNBOOK.md` to `docs/runbooks/` under its runbook ID (`AI-020` DLP upload, `AI-023` unmanaged device, `AI-024` extension high volume, `AI-026` OAuth mismatch).
3. Keep `deployment_type: adhoc` unless its data turns out to be common.
4. Add its rows back to `saved_searches/packages/hdsi_ai_rba_common/lookups/ai_mitre_mapping.csv`:

   ```
   hdsi_ai_access_from_unmanaged_device,T1200,Hardware Additions,Initial Access
   hdsi_ai_access_from_unmanaged_device,T1588.007,Obtain Capabilities: Artificial Intelligence,Resource Development
   hdsi_ai_browser_extension_high_volume_data_transmission,T1567,Exfiltration Over Web Service,Exfiltration
   hdsi_ai_browser_extension_high_volume_data_transmission,T1176.001,Software Extensions: Browser Extensions,Persistence
   hdsi_ai_dlp_violation_on_service_upload,T1567,Exfiltration Over Web Service,Exfiltration
   hdsi_ai_usage_from_personal_account_oauth_mismatch,T1588.007,Obtain Capabilities: Artificial Intelligence,Resource Development
   hdsi_ai_usage_from_personal_account_oauth_mismatch,T1567,Exfiltration Over Web Service,Exfiltration
   ```

5. Replace the README's **Incubating** banner and **Validation** table with the real-data results (tenant labels only, no customer identifiers).
6. Move its row from the "Incubating detections" table in the top-level `README.md` into the detection catalogue, and update the counts in `README.md`, `saved_searches/README.md`, `docs/ARCHITECTURE.md` and `CHANGELOG.md`.
7. Run `validate.py`, `pytest tests/` and the conformance audit; all must pass.
