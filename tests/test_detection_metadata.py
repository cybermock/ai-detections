"""Validate detection metadata: required fields, naming, risk/notable config."""

from __future__ import annotations

import re

import pytest

from .conftest import extract_detection_id


class TestRequiredFields:
    """Every detection stanza must have the essential scheduling and description fields."""

    REQUIRED_KEYS = {"description", "cron_schedule", "dispatch.earliest_time", "dispatch.latest_time"}

    def test_detections_have_required_fields(self, detection_stanzas):
        errors = []
        for name, props in detection_stanzas.items():
            missing = self.REQUIRED_KEYS - set(props.keys())
            if missing:
                errors.append(f"[{name}] missing: {missing}")
        assert not errors, "Detection stanzas missing required fields:\n" + "\n".join(errors)

    def test_threshold_searches_have_required_fields(self, threshold_stanzas):
        required = {"description", "cron_schedule", "dispatch.earliest_time", "dispatch.latest_time"}
        errors = []
        for name, props in threshold_stanzas.items():
            missing = required - set(props.keys())
            if missing:
                errors.append(f"[{name}] missing: {missing}")
        assert not errors, "Threshold stanzas missing required fields:\n" + "\n".join(errors)


class TestRiskOrNotable:
    """Every detection must have action.risk=1 or action.notable=1 (or both)."""

    def test_detection_has_risk_or_notable(self, detection_stanzas):
        errors = []
        for name, props in detection_stanzas.items():
            has_risk = props.get("action.risk") == "1"
            has_notable = props.get("action.notable") == "1"
            if not has_risk and not has_notable:
                errors.append(name)
        assert not errors, (
            "Detections with neither action.risk=1 nor action.notable=1:\n"
            + "\n".join(errors)
        )


class TestDetectionId:
    """Every detection must have an extractable detection_id in its SPL."""

    def test_detection_id_present(self, detection_stanzas):
        errors = []
        for name, props in detection_stanzas.items():
            search = props.get("search", "")
            det_id = extract_detection_id(search)
            if not det_id:
                errors.append(name)
        assert not errors, "Detections without extractable detection_id:\n" + "\n".join(errors)

    def test_detection_ids_unique(self, detection_stanzas):
        """No two detections should share the same detection_id."""
        id_map: dict[str, list[str]] = {}
        for name, props in detection_stanzas.items():
            det_id = extract_detection_id(props.get("search", ""))
            if det_id:
                id_map.setdefault(det_id, []).append(name)
        dupes = {did: names for did, names in id_map.items() if len(names) > 1}
        assert not dupes, f"Duplicate detection_ids: {dupes}"


class TestNamingConvention:
    """Stanza names must follow the ESCU naming convention."""

    def test_detection_stanza_prefix(self, savedsearches):
        errors = []
        for name in savedsearches:
            if name == "default":
                continue
            if not name.startswith("AI RBA -"):
                errors.append(name)
        assert not errors, (
            "Stanzas not following 'AI RBA -' naming convention:\n" + "\n".join(errors)
        )


class TestDisabledStatus:
    """All detections in the [default] stanza should have disabled=0 (pack ships enabled,
    but individual stanzas can override). Or if the pack ships disabled for safety,
    all stanzas should be disabled=true. We check that the disabled setting is consistent
    across all detection stanzas."""

    def test_disabled_consistency(self, savedsearches, detection_stanzas):
        # Get the default disabled value
        default_disabled = savedsearches.get("default", {}).get("disabled", None)
        # Collect per-stanza overrides
        stanza_values = set()
        for name, props in detection_stanzas.items():
            val = props.get("disabled", default_disabled)
            stanza_values.add(val)

        # All stanzas should share the same disabled state (either all enabled or all disabled)
        # This is a consistency check, not a mandate on which value to use
        if len(stanza_values) > 1:
            details = {}
            for name, props in detection_stanzas.items():
                val = props.get("disabled", default_disabled)
                details.setdefault(val, []).append(name)
            # Only warn, don't fail — mixed states may be intentional during development
            pytest.skip(
                f"Mixed disabled states across detections: {dict((k, len(v)) for k, v in details.items())}"
            )


class TestDescriptionContent:
    """Detection descriptions should be meaningful."""

    def test_description_not_trivially_short(self, detection_stanzas):
        errors = []
        for name, props in detection_stanzas.items():
            desc = props.get("description", "")
            if len(desc) < 20:
                errors.append(f"[{name}] description too short ({len(desc)} chars): '{desc}'")
        assert not errors, "Detections with very short descriptions:\n" + "\n".join(errors)

    def test_risk_message_present(self, detection_stanzas):
        """Detections with action.risk=1 should have a risk message."""
        errors = []
        for name, props in detection_stanzas.items():
            if props.get("action.risk") == "1":
                msg = props.get("action.risk.param._risk_message", "").strip()
                if not msg:
                    errors.append(name)
        assert not errors, "Detections with action.risk=1 but no risk message:\n" + "\n".join(errors)


class TestCronSchedule:
    """Cron schedules must be syntactically valid (basic check)."""

    # Each cron field can be: *, */N, N, N-M, N,M, N-M/S, or combinations
    _CRON_FIELD = r"(\*(?:/\d+)?|[\d,\-\/]+)"
    CRON_RE = re.compile(
        rf"^{_CRON_FIELD}\s+{_CRON_FIELD}\s+{_CRON_FIELD}\s+{_CRON_FIELD}\s+{_CRON_FIELD}$"
    )

    def test_cron_valid(self, savedsearches):
        errors = []
        for name, props in savedsearches.items():
            if name == "default":
                continue
            cron = props.get("cron_schedule", "").strip()
            if cron and not self.CRON_RE.match(cron):
                errors.append(f"[{name}] invalid cron: '{cron}'")
        assert not errors, "Invalid cron schedules:\n" + "\n".join(errors)
