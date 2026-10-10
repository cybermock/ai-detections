"""Lookup CSV schemas, discovered through each package's transforms.conf.

Core columns are required; extra columns (e.g. match_subdomains) and extra lookup
files (e.g. ai_provider_apps.csv) are tolerated as long as they are well formed.
"""

from __future__ import annotations

import csv
import re

import pytest

from .conftest import (
    PACKAGES_DIR,
    PROJECT_ROOT,
    csv_header,
    load_csv,
    lookup_rows,
    transforms_csv_lookups,
)

# transforms stanza -> core columns that the detections depend on
CORE_COLUMNS = {
    "ai_provider_domains": {"provider", "domain", "usage_type", "severity_weight", "enabled"},
    "ai_tool_processes": {"tool", "provider", "process_name_lc", "original_file_name_lc", "platform",
                          "usage_type", "enabled"},
    "ai_sanctioned_entities": {"entity_type", "entity", "provider", "scope", "expires", "enabled", "allow_key"},
    "ai_detection_config": {"control_name", "value"},
    "ai_mitre_mapping": {"detection_id", "mitre_technique_id", "mitre_tactic", "mitre_technique_name"},
    "ai_department_sensitivity": {"department", "risk_multiplier"},
    "ai_prompt_injection_patterns": {"pattern_id", "pattern", "enabled"},
    "ai_deepfake_tools": {"tool_name", "process_name", "category", "enabled"},
    "ai_api_key_patterns": {"pattern_id", "provider", "regex_pattern", "enabled"},
}

DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
MITRE_TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")

LOOKUPS = transforms_csv_lookups()
LOOKUP_IDS = [f"{pkg}:{stanza}" for pkg, stanza, _ in LOOKUPS]


# ---------------------------------------------------------------------------
# Generic structure, for every transforms-defined CSV
# ---------------------------------------------------------------------------


def test_core_lookups_defined():
    defined = {stanza for _, stanza, _ in LOOKUPS}
    missing = sorted(set(CORE_COLUMNS) - defined)
    assert not missing, f"transforms.conf no longer defines core lookup(s): {missing}"


def test_every_csv_has_transforms_stanza():
    referenced = {path.resolve() for _, _, path in LOOKUPS}
    orphans = [
        str(p.relative_to(PROJECT_ROOT))
        for p in sorted(PACKAGES_DIR.glob("*/lookups/*.csv"))
        if p.resolve() not in referenced
    ]
    assert not orphans, f"CSV lookup(s) without a transforms.conf filename stanza: {orphans}"


@pytest.mark.parametrize(("package", "stanza", "path"), LOOKUPS, ids=LOOKUP_IDS)
def test_csv_well_formed(package, stanza, path):
    assert path.exists(), f"{package} transforms [{stanza}] -> missing {path.relative_to(PROJECT_ROOT)}"
    with open(path, newline="", encoding="utf-8") as f:
        rows = list(csv.reader(f))
    assert rows, f"{path.name} is empty"
    header = rows[0]
    assert all(h.strip() for h in header), f"{path.name} has a blank column header: {header}"
    dupes = sorted({h for h in header if header.count(h) > 1})
    assert not dupes, f"{path.name} has duplicate column(s) {dupes}"
    ragged = [i + 1 for i, r in enumerate(rows[1:], start=1) if r and len(r) != len(header)]
    assert not ragged, f"{path.name} rows with wrong column count (line numbers): {ragged[:20]}"
    assert len(rows) > 1, f"{path.name} has a header but no rows"


@pytest.mark.parametrize(("package", "stanza", "path"), LOOKUPS, ids=LOOKUP_IDS)
def test_core_columns_present(package, stanza, path):
    if stanza not in CORE_COLUMNS:
        pytest.skip(f"{stanza} has no core schema (extra lookup)")
    missing = sorted(CORE_COLUMNS[stanza] - set(csv_header(path)))
    assert not missing, f"{path.name} missing core column(s) {missing}"


@pytest.mark.parametrize(("package", "stanza", "path"), LOOKUPS, ids=LOOKUP_IDS)
def test_enabled_column_values(package, stanza, path):
    if "enabled" not in csv_header(path):
        pytest.skip("no enabled column")
    bad = [(i + 2, r["enabled"]) for i, r in enumerate(load_csv(path)) if r["enabled"] not in ("0", "1")]
    assert not bad, f"{path.name} enabled must be 0/1; bad (line, value): {bad[:20]}"


# ---------------------------------------------------------------------------
# Per-lookup value rules
# ---------------------------------------------------------------------------

PROVIDER_DOMAINS_USAGE_TYPES = {"web", "api", "ide", "local_llm", "model_registry", "cli"}


class TestProviderDomains:
    def test_domain_unique(self, provider_domains):
        domains = [r["domain"].lower() for r in provider_domains]
        dupes = sorted({d for d in domains if domains.count(d) > 1})
        assert not dupes, f"Duplicate domains (lookup key) in ai_provider_domains.csv: {dupes}"

    def test_domain_and_provider_not_empty(self, provider_domains):
        bad = [r for r in provider_domains if not r["domain"].strip() or not r["provider"].strip()]
        assert not bad, f"Rows with empty domain/provider: {bad[:5]}"

    def test_usage_type_values(self, provider_domains):
        bad = sorted({(r["domain"], r["usage_type"]) for r in provider_domains
                      if r["usage_type"] not in PROVIDER_DOMAINS_USAGE_TYPES})
        assert not bad, f"usage_type must be one of {sorted(PROVIDER_DOMAINS_USAGE_TYPES)}: {bad}"

    def test_severity_weight_numeric(self, provider_domains):
        bad = []
        for r in provider_domains:
            try:
                float(r["severity_weight"])
            except ValueError:
                bad.append((r["domain"], r["severity_weight"]))
        assert not bad, f"Non-numeric severity_weight: {bad}"


class TestToolProcesses:
    def test_unique_per_platform_and_usage_type(self, tool_processes):
        seen, dupes = set(), []
        for r in tool_processes:
            key = (r["process_name_lc"].lower(), r["platform"], r["usage_type"])
            if key in seen:
                dupes.append(key)
            seen.add(key)
        assert not dupes, f"Duplicate process_name_lc per platform+usage_type: {dupes}"

    def test_platform_not_empty(self, tool_processes):
        bad = [r["process_name_lc"] for r in tool_processes if not r["platform"].strip()]
        assert not bad, f"Empty platform for: {bad}"


class TestSanctionedEntities:
    def test_entity_type_values(self, sanctioned_entities):
        bad = [(r["entity"], r["entity_type"]) for r in sanctioned_entities
               if r["entity_type"] not in {"user", "system", "group"}]
        assert not bad, f"Invalid entity_type: {bad}"

    def test_scope_values(self, sanctioned_entities):
        bad = [(r["entity"], r["scope"]) for r in sanctioned_entities
               if r["scope"] not in {"global", "provider", "subnet", "group"}]
        assert not bad, f"Invalid scope: {bad}"

    def test_expires_format(self, sanctioned_entities):
        bad = [(r["entity"], r["expires"]) for r in sanctioned_entities
               if r["expires"].strip() and not DATE_RE.match(r["expires"].strip())]
        assert not bad, f"expires must be YYYY-MM-DD or empty: {bad}"

    def test_allow_key_format(self, sanctioned_entities):
        bad = [(r["entity"], r["allow_key"]) for r in sanctioned_entities
               if r["allow_key"] and r["allow_key"].count("|") != 1]
        assert not bad, f"allow_key must be '<entity>|<provider or *>': {bad}"


class TestDetectionConfig:
    NON_NUMERIC = {"alert_email_to"}

    def test_control_name_unique(self, detection_config):
        names = [r["control_name"].strip() for r in detection_config]
        dupes = sorted({n for n in names if names.count(n) > 1})
        assert not dupes, f"Duplicate control_name: {dupes}"
        assert all(names), "Empty control_name found"

    def test_values_numeric(self, detection_config):
        bad = []
        for r in detection_config:
            name = r["control_name"].strip()
            if name in self.NON_NUMERIC:
                continue
            try:
                float(r["value"])
            except ValueError:
                bad.append((name, r["value"]))
        assert not bad, f"Non-numeric control values: {bad}"

    def test_alert_email_control_present(self, detection_config):
        # The control must exist; it ships empty because health checks send no email by default.
        rows = [r for r in detection_config if r["control_name"].strip() == "alert_email_to"]
        assert rows, "ai_detection_config.csv needs an alert_email_to control (may be empty)"


class TestMitreMappingFormat:
    def test_technique_id_format(self, mitre_mapping):
        bad = [(r["detection_id"], r["mitre_technique_id"]) for r in mitre_mapping
               if not MITRE_TECHNIQUE_RE.match(r["mitre_technique_id"])]
        assert not bad, f"Invalid MITRE technique IDs: {bad}"

    def test_tactic_not_empty(self, mitre_mapping):
        bad = [r["detection_id"] for r in mitre_mapping if not r["mitre_tactic"].strip()]
        assert not bad, f"Empty mitre_tactic for: {bad}"

    def test_no_duplicate_rows(self, mitre_mapping):
        keys = [(r["detection_id"], r["mitre_technique_id"]) for r in mitre_mapping]
        dupes = sorted({k for k in keys if keys.count(k) > 1})
        assert not dupes, f"Duplicate (detection_id, technique) rows: {dupes}"


class TestDeepfakeTools:
    def test_categories_valid(self):
        valid = {"face_swap", "voice_clone", "lip_sync", "avatar_generation", "image_generation"}
        bad = [(r["tool_name"], r["category"]) for r in lookup_rows("ai_deepfake_tools") if r["category"] not in valid]
        assert not bad, f"Invalid deepfake tool categories: {bad}"
