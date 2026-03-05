"""Validate MITRE ATT&CK coverage and cross-references."""

from __future__ import annotations

import re

from .conftest import extract_detection_id

MITRE_TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
# Matches mitre_attack="T####.###" or mitre_attack="T####" in SPL eval
SPL_MITRE_RE = re.compile(r'mitre_attack\s*=\s*"(T\d{4}(?:\.\d{3})?)"')


class TestMitreMappingCoverage:
    """Every detection must have a MITRE mapping entry."""

    def test_all_detections_have_mitre_entry(self, detection_stanzas, mitre_mapping):
        mapped_ids = {r["detection_id"] for r in mitre_mapping}
        errors = []
        for name, props in detection_stanzas.items():
            det_id = extract_detection_id(props.get("search", ""))
            if det_id and det_id not in mapped_ids:
                errors.append(f"[{name}] detection_id={det_id} has no MITRE mapping")
        assert not errors, "Detections missing MITRE mapping:\n" + "\n".join(errors)

    def test_no_orphan_mitre_entries(self, detection_stanzas, mitre_mapping):
        """Every detection_id in the MITRE mapping should correspond to a real detection."""
        spl_ids = set()
        for name, props in detection_stanzas.items():
            det_id = extract_detection_id(props.get("search", ""))
            if det_id:
                spl_ids.add(det_id)
        orphans = []
        for row in mitre_mapping:
            if row["detection_id"] not in spl_ids:
                orphans.append(row["detection_id"])
        assert not orphans, f"MITRE mapping has entries for non-existent detections: {orphans}"


class TestMitreTechniqueFormat:
    """All MITRE technique IDs must match the ATT&CK format."""

    def test_csv_technique_ids(self, mitre_mapping):
        errors = []
        for row in mitre_mapping:
            tid = row["mitre_technique_id"]
            if not MITRE_TECHNIQUE_RE.match(tid):
                errors.append(f"{row['detection_id']}: invalid technique '{tid}'")
        assert not errors, "Invalid MITRE technique IDs:\n" + "\n".join(errors)


class TestMitreCrossValidation:
    """MITRE technique IDs in SPL eval statements must match the CSV mapping."""

    def test_spl_mitre_matches_csv(self, detection_stanzas, mitre_mapping):
        # Build lookup: detection_id -> technique_id from CSV
        csv_map: dict[str, str] = {}
        for row in mitre_mapping:
            csv_map[row["detection_id"]] = row["mitre_technique_id"]

        errors = []
        for name, props in detection_stanzas.items():
            search = props.get("search", "")
            det_id = extract_detection_id(search)
            if not det_id:
                continue
            spl_match = SPL_MITRE_RE.search(search)
            if not spl_match:
                continue
            spl_technique = spl_match.group(1)
            csv_technique = csv_map.get(det_id)
            if csv_technique and spl_technique != csv_technique:
                errors.append(
                    f"[{name}] detection_id={det_id}: SPL has mitre_attack=\"{spl_technique}\" "
                    f"but CSV has \"{csv_technique}\""
                )
        assert not errors, "MITRE cross-validation mismatches:\n" + "\n".join(errors)


class TestMitreDescriptionConsistency:
    """MITRE technique mentioned in detection description should match the mapping."""

    def test_description_technique_matches(self, detection_stanzas, mitre_mapping):
        csv_map: dict[str, str] = {}
        for row in mitre_mapping:
            csv_map[row["detection_id"]] = row["mitre_technique_id"]

        errors = []
        for name, props in detection_stanzas.items():
            desc = props.get("description", "")
            search = props.get("search", "")
            det_id = extract_detection_id(search)
            if not det_id:
                continue
            # Extract technique from description (e.g. "MITRE: T1071.001")
            desc_match = re.search(r"MITRE:\s*(T\d{4}(?:\.\d{3})?)", desc)
            if not desc_match:
                continue
            desc_technique = desc_match.group(1)
            csv_technique = csv_map.get(det_id)
            if csv_technique and desc_technique != csv_technique:
                errors.append(
                    f"[{name}] description says MITRE: {desc_technique} "
                    f"but CSV maps {det_id} to {csv_technique}"
                )
        assert not errors, "Description/CSV MITRE mismatches:\n" + "\n".join(errors)
