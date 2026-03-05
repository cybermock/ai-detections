"""Validate CSV lookup schemas, value constraints, and uniqueness rules."""

from __future__ import annotations

import re

import pytest

from .conftest import LOOKUPS_DIR, load_csv

# ---------------------------------------------------------------------------
# ai_provider_domains.csv
# ---------------------------------------------------------------------------

PROVIDER_DOMAINS_REQUIRED_COLS = {"provider", "domain", "usage_type", "severity_weight", "enabled", "notes"}
PROVIDER_DOMAINS_USAGE_TYPES = {"web", "api", "ide", "local_llm", "model_registry", "cli"}


class TestProviderDomains:
    def test_required_columns(self, provider_domains):
        assert len(provider_domains) > 0, "ai_provider_domains.csv is empty"
        actual_cols = set(provider_domains[0].keys())
        missing = PROVIDER_DOMAINS_REQUIRED_COLS - actual_cols
        assert not missing, f"Missing columns: {missing}"

    def test_domain_uniqueness(self, provider_domains):
        domains = [r["domain"] for r in provider_domains]
        dupes = [d for d in domains if domains.count(d) > 1]
        assert not dupes, f"Duplicate domains: {set(dupes)}"

    def test_enabled_values(self, provider_domains):
        for row in provider_domains:
            assert row["enabled"] in ("0", "1"), (
                f"Invalid enabled value '{row['enabled']}' for domain {row['domain']}"
            )

    def test_usage_type_values(self, provider_domains):
        for row in provider_domains:
            assert row["usage_type"] in PROVIDER_DOMAINS_USAGE_TYPES, (
                f"Invalid usage_type '{row['usage_type']}' for domain {row['domain']}; "
                f"expected one of {PROVIDER_DOMAINS_USAGE_TYPES}"
            )

    def test_severity_weight_numeric(self, provider_domains):
        for row in provider_domains:
            try:
                float(row["severity_weight"])
            except ValueError:
                pytest.fail(f"severity_weight '{row['severity_weight']}' is not numeric for domain {row['domain']}")

    def test_provider_not_empty(self, provider_domains):
        for row in provider_domains:
            assert row["provider"].strip(), f"Empty provider for domain {row['domain']}"

    def test_domain_not_empty(self, provider_domains):
        for row in provider_domains:
            assert row["domain"].strip(), f"Empty domain in row with provider {row['provider']}"


# ---------------------------------------------------------------------------
# ai_tool_processes.csv
# ---------------------------------------------------------------------------

TOOL_PROCESSES_REQUIRED_COLS = {
    "tool_name" if "tool_name" in {} else "tool",  # handle either name
    "provider",
    "process_name_lc",
    "original_file_name_lc",
    "platform",
    "usage_type",
    "enabled",
    "notes",
}


class TestToolProcesses:
    def test_required_columns(self, tool_processes):
        assert len(tool_processes) > 0, "ai_tool_processes.csv is empty"
        actual_cols = set(tool_processes[0].keys())
        # Accept either "tool" or "tool_name" as the tool column
        has_tool_col = "tool" in actual_cols or "tool_name" in actual_cols
        assert has_tool_col, "Missing tool/tool_name column"
        required_others = {
            "provider", "process_name_lc", "original_file_name_lc", "platform", "usage_type", "enabled", "notes",
        }
        missing = required_others - actual_cols
        assert not missing, f"Missing columns: {missing}"

    def test_process_name_uniqueness_per_platform_and_type(self, tool_processes):
        seen: dict[tuple[str, str, str], str] = {}
        dupes = []
        for row in tool_processes:
            key = (row["process_name_lc"], row["platform"], row.get("usage_type", ""))
            if key in seen:
                dupes.append(f"{row['process_name_lc']} on {row['platform']} ({row.get('usage_type', '')})")
            seen[key] = row.get("tool", row.get("tool_name", ""))
        assert not dupes, f"Duplicate process_name per platform+usage_type: {dupes}"

    def test_enabled_values(self, tool_processes):
        for row in tool_processes:
            assert row["enabled"] in ("0", "1"), (
                f"Invalid enabled value '{row['enabled']}' for process {row['process_name_lc']}"
            )

    def test_platform_not_empty(self, tool_processes):
        for row in tool_processes:
            assert row["platform"].strip(), f"Empty platform for process {row['process_name_lc']}"


# ---------------------------------------------------------------------------
# ai_sanctioned_entities.csv
# ---------------------------------------------------------------------------

SANCTIONED_ENTITY_TYPES = {"user", "system", "group"}
SANCTIONED_SCOPES = {"global", "provider", "subnet", "group"}
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


class TestSanctionedEntities:
    def test_required_columns(self, sanctioned_entities):
        assert len(sanctioned_entities) > 0, "ai_sanctioned_entities.csv is empty"
        actual_cols = set(sanctioned_entities[0].keys())
        required = {"entity_type", "entity", "provider", "scope", "expires", "enabled"}
        missing = required - actual_cols
        assert not missing, f"Missing columns: {missing}"

    def test_entity_type_values(self, sanctioned_entities):
        for row in sanctioned_entities:
            assert row["entity_type"] in SANCTIONED_ENTITY_TYPES, (
                f"Invalid entity_type '{row['entity_type']}' for entity {row['entity']}"
            )

    def test_scope_values(self, sanctioned_entities):
        for row in sanctioned_entities:
            assert row["scope"] in SANCTIONED_SCOPES, (
                f"Invalid scope '{row['scope']}' for entity {row['entity']}"
            )

    def test_enabled_values(self, sanctioned_entities):
        for row in sanctioned_entities:
            assert row["enabled"] in ("0", "1"), (
                f"Invalid enabled value '{row['enabled']}' for entity {row['entity']}"
            )

    def test_expires_format(self, sanctioned_entities):
        for row in sanctioned_entities:
            val = row["expires"].strip()
            if val:  # Allow empty (never expires)
                assert DATE_RE.match(val), (
                    f"Invalid date format '{val}' for entity {row['entity']}; expected YYYY-MM-DD"
                )


# ---------------------------------------------------------------------------
# ai_detection_config.csv
# ---------------------------------------------------------------------------

DETECTION_CONFIG_REQUIRED_COLS = {"control_name", "value", "notes"}
# Accept both "value" and "default_value" since the task mentions either
DETECTION_CONFIG_VALUE_COL_ALTERNATIVES = {"value", "default_value"}
DETECTION_CONFIG_NON_NUMERIC_CONTROLS = {"alert_email_to"}


class TestDetectionConfig:
    def test_required_columns(self, detection_config):
        assert len(detection_config) > 0, "ai_detection_config.csv is empty"
        actual_cols = set(detection_config[0].keys())
        assert "control_name" in actual_cols, "Missing control_name column"
        has_value_col = bool(DETECTION_CONFIG_VALUE_COL_ALTERNATIVES & actual_cols)
        assert has_value_col, f"Missing value/default_value column; have {actual_cols}"

    def test_control_name_uniqueness(self, detection_config):
        names = [r["control_name"] for r in detection_config]
        dupes = [n for n in names if names.count(n) > 1]
        assert not dupes, f"Duplicate control_name: {set(dupes)}"

    def test_value_is_numeric(self, detection_config):
        value_col = "value" if "value" in detection_config[0] else "default_value"
        for row in detection_config:
            control_name = row["control_name"].strip()
            val = row[value_col]
            if control_name in DETECTION_CONFIG_NON_NUMERIC_CONTROLS:
                assert val.strip(), f"Control '{control_name}' must not be empty"
                continue
            try:
                float(val)
            except ValueError:
                pytest.fail(f"Non-numeric value '{val}' for control {row['control_name']}")

    def test_control_name_not_empty(self, detection_config):
        for row in detection_config:
            assert row["control_name"].strip(), "Empty control_name found"

    def test_health_alert_email_control_present(self, detection_config):
        value_col = "value" if "value" in detection_config[0] else "default_value"
        matches = [row for row in detection_config if row["control_name"].strip() == "alert_email_to"]
        assert matches, "Missing required control 'alert_email_to' in ai_detection_config.csv"
        assert matches[0][value_col].strip(), "Control 'alert_email_to' must contain a non-empty email value"


# ---------------------------------------------------------------------------
# ai_mitre_mapping.csv
# ---------------------------------------------------------------------------

MITRE_MAPPING_REQUIRED_COLS = {"detection_id", "mitre_technique_id", "mitre_tactic", "mitre_technique_name"}
MITRE_TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


class TestMitreMapping:
    def test_required_columns(self, mitre_mapping):
        assert len(mitre_mapping) > 0, "ai_mitre_mapping.csv is empty"
        actual_cols = set(mitre_mapping[0].keys())
        missing = MITRE_MAPPING_REQUIRED_COLS - actual_cols
        assert not missing, f"Missing columns: {missing}"

    def test_detection_id_uniqueness(self, mitre_mapping):
        ids = [r["detection_id"] for r in mitre_mapping]
        dupes = [d for d in ids if ids.count(d) > 1]
        assert not dupes, f"Duplicate detection_id: {set(dupes)}"

    def test_technique_id_format(self, mitre_mapping):
        for row in mitre_mapping:
            tid = row["mitre_technique_id"]
            assert MITRE_TECHNIQUE_RE.match(tid), (
                f"Invalid MITRE technique ID '{tid}' for detection {row['detection_id']}; "
                f"expected T####  or T####.###"
            )

    def test_detection_id_format(self, mitre_mapping):
        for row in mitre_mapping:
            assert re.match(r"^AI-\d{3,}$", row["detection_id"]), (
                f"Invalid detection_id format '{row['detection_id']}'"
            )

    def test_tactic_not_empty(self, mitre_mapping):
        for row in mitre_mapping:
            assert row["mitre_tactic"].strip(), (
                f"Empty mitre_tactic for detection {row['detection_id']}"
            )


# ---------------------------------------------------------------------------
# Dynamic tests for any additional CSV lookups
# ---------------------------------------------------------------------------


class TestAdditionalCsvLookups:
    """Validate structural integrity of any CSV file in lookups/."""

    def test_all_csvs_are_loadable(self, all_csv_files):
        """Every CSV in lookups/ must parse without error and have at least a header."""
        for name, rows in all_csv_files.items():
            # A CSV with only a header and no data rows is acceptable,
            # but we should be able to read the header columns.
            if rows:
                assert len(rows[0].keys()) > 0, f"{name} has rows but no columns"

    def test_no_empty_headers(self, all_csv_files):
        """No CSV should have blank column names."""
        for name, rows in all_csv_files.items():
            if rows:
                for col in rows[0].keys():
                    assert col.strip(), f"{name} has an empty column header"

    def test_enabled_column_if_present(self, all_csv_files):
        """If a CSV has an 'enabled' column, values must be 0 or 1."""
        for name, rows in all_csv_files.items():
            if rows and "enabled" in rows[0]:
                for i, row in enumerate(rows):
                    assert row["enabled"] in ("0", "1"), (
                        f"{name} row {i}: invalid enabled value '{row['enabled']}'"
                    )

    # --- Optional new lookups that detection-engineer may add ---

    def _get_csv_if_exists(self, filename: str) -> list[dict[str, str]] | None:
        path = LOOKUPS_DIR / filename
        if path.exists():
            return load_csv(path)
        return None

    def test_department_sensitivity_schema(self):
        rows = self._get_csv_if_exists("ai_department_sensitivity.csv")
        if rows is None:
            pytest.skip("ai_department_sensitivity.csv not yet created")
        assert len(rows) > 0
        cols = set(rows[0].keys())
        assert "department" in cols or "dept" in cols, f"Missing department column in {cols}"

    def test_prompt_injection_patterns_schema(self):
        rows = self._get_csv_if_exists("ai_prompt_injection_patterns.csv")
        if rows is None:
            pytest.skip("ai_prompt_injection_patterns.csv not yet created")
        assert len(rows) > 0

    def test_deepfake_tools_schema(self):
        rows = self._get_csv_if_exists("ai_deepfake_tools.csv")
        if rows is None:
            pytest.skip("ai_deepfake_tools.csv not yet created")
        assert len(rows) > 0

    def test_api_key_patterns_schema(self):
        rows = self._get_csv_if_exists("ai_api_key_patterns.csv")
        if rows is None:
            pytest.skip("ai_api_key_patterns.csv not yet created")
        assert len(rows) > 0


# ---------------------------------------------------------------------------
# KV Store collections.conf validation
# ---------------------------------------------------------------------------


class TestKvStoreCollections:
    """Validate collections.conf and KV Store transforms exist and are consistent."""

    def _load_collections(self):
        from .conftest import DEFAULT_DIR, parse_conf
        path = DEFAULT_DIR / "collections.conf"
        if not path.exists():
            pytest.skip("collections.conf not yet created")
        return parse_conf(path)

    def _load_transforms(self):
        from .conftest import DEFAULT_DIR, parse_conf
        return parse_conf(DEFAULT_DIR / "transforms.conf")

    def test_collections_conf_exists(self):
        from .conftest import DEFAULT_DIR
        assert (DEFAULT_DIR / "collections.conf").exists(), "collections.conf not found"

    def test_operational_csv_lookups_have_kvstore_collection(self):
        """Operational CSV-based transforms should have corresponding KV Store collections.

        Only operational lookups (those likely to grow or be frequently updated)
        need KV Store alternatives. Reference-only lookups (mitre_mapping,
        department_sensitivity, prompt_injection_patterns, deepfake_tools) are
        excluded as they are small and rarely change.
        """
        transforms = self._load_transforms()
        operational_csv_transforms = [
            "ai_sanctioned_entities", "ai_detection_config",
            "ai_provider_domains", "ai_tool_processes", "ai_api_key_patterns",
        ]
        for csv_name in operational_csv_transforms:
            assert csv_name in transforms, f"CSV transform '{csv_name}' not found"
            kvstore_name = f"{csv_name}_kvstore"
            assert kvstore_name in transforms, (
                f"CSV transform '{csv_name}' has no KV Store alternative '{kvstore_name}'"
            )

    def test_kvstore_transforms_reference_valid_collections(self):
        """Every KV Store transform must reference a collection defined in collections.conf."""
        transforms = self._load_transforms()
        collections = self._load_collections()
        collection_stanzas = {
            name for name in collections if name != "default"
        }
        for name, props in transforms.items():
            if props.get("external_type") == "kvstore":
                coll = props.get("collection", "")
                assert coll in collection_stanzas, (
                    f"KV Store transform '{name}' references undefined collection '{coll}'"
                )

    def test_collections_have_enforced_types(self):
        """All collections should have enforceTypes = true."""
        collections = self._load_collections()
        for name, props in collections.items():
            if name == "default":
                continue
            assert props.get("enforceTypes") == "true", (
                f"Collection '{name}' missing enforceTypes = true"
            )
