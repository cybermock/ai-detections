"""ai_mitre_mapping.csv is keyed by package name and covers every detection package."""

from __future__ import annotations

import json

import pytest

from .conftest import all_packages, packages_with_role, savedsearches


def test_mapping_ids_are_existing_packages(mitre_mapping):
    existing = set(all_packages())
    unknown = sorted({r["detection_id"] for r in mitre_mapping} - existing)
    assert not unknown, f"ai_mitre_mapping.csv detection_id values that are not packages: {unknown}"


@pytest.mark.parametrize("package", packages_with_role("detection", "hunting"))
def test_detection_has_mapping_row(package, mitre_mapping):
    assert any(r["detection_id"] == package for r in mitre_mapping), (
        f"{package}: no row in hdsi_ai_rba_common/lookups/ai_mitre_mapping.csv"
    )


@pytest.mark.parametrize("package", packages_with_role("detection", "hunting"))
def test_mapping_agrees_with_annotations(package, mitre_mapping):
    """Every technique mapped in the CSV should also be in the search's annotations.mitre_attack."""
    mapped = {r["mitre_technique_id"] for r in mitre_mapping if r["detection_id"] == package}
    if not mapped:
        pytest.skip("no CSV mapping (reported by test_detection_has_mapping_row)")
    annotated: set[str] = set()
    for kv in savedsearches(package).values():
        try:
            annotated.update(json.loads(kv.get("action.correlationsearch.annotations", "{}")).get("mitre_attack", []))
        except (json.JSONDecodeError, AttributeError):
            pytest.skip("annotations unparsable (reported by test_annotations)")
    missing = sorted(mapped - annotated)
    assert not missing, (
        f"{package}: ai_mitre_mapping.csv maps {sorted(mapped)} but annotations.mitre_attack is {sorted(annotated)}"
    )
