"""Validate runbook coverage for detections."""

from __future__ import annotations

import re
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RUNBOOKS_DIR = PROJECT_ROOT / "docs" / "runbooks"

DETECTION_ID_RE = re.compile(r'detection_id\s*=\s*"(AI-[\w-]+\d+)"')


class TestRunbookCoverage:
    def test_every_detection_id_has_runbook(self, savedsearches):
        detection_ids: set[str] = set()
        for name, props in savedsearches.items():
            if name == "default":
                continue
            search = props.get("search", "")
            if not search:
                continue
            for match in DETECTION_ID_RE.finditer(search):
                detection_ids.add(match.group(1))

        missing = [did for did in sorted(detection_ids) if not (RUNBOOKS_DIR / f"{did}.md").exists()]
        assert not missing, f"Missing runbook(s) for detection IDs: {missing}"

    def test_runbooks_are_not_empty(self):
        # Exclude template/deprecated aggregate helper docs from the size check.
        excluded = {"_runbook_template.md", "AI-001-002-003.md"}
        tiny = []
        for runbook in RUNBOOKS_DIR.glob("AI-*.md"):
            if runbook.name in excluded:
                continue
            if runbook.stat().st_size < 500:
                tiny.append(runbook.name)
        assert not tiny, f"Runbook files appear incomplete/suspiciously small: {tiny}"

    def test_advanced_risk_runbooks_exist(self):
        required = ["AI-RISK-003.md", "AI-RISK-004.md", "AI-RISK-005.md"]
        missing = [name for name in required if not (RUNBOOKS_DIR / name).exists()]
        assert not missing, f"Missing advanced correlation runbook(s): {missing}"
