"""Every detection and risk aggregator has an analyst runbook under docs/runbooks/."""

from __future__ import annotations

from functools import lru_cache

import pytest

from .conftest import RUNBOOKS_DIR, packages_with_role, savedsearches


@lru_cache(maxsize=None)
def _runbook_text() -> str:
    return "\n".join(p.read_text(encoding="utf-8", errors="ignore") for p in sorted(RUNBOOKS_DIR.glob("*.md")))


@pytest.mark.parametrize("package", packages_with_role("detection", "hunting", "aggregator"))
def test_package_has_runbook(package):
    text = _runbook_text()
    names = {package}
    for stanza, kv in savedsearches(package).items():
        names.add(stanza)
        if kv.get("action.correlationsearch.label"):
            names.add(kv["action.correlationsearch.label"])
    assert any(n in text for n in names), (
        f"{package}: not referenced by package name, stanza or label in any docs/runbooks/*.md"
    )
