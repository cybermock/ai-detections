"""Shared helpers for the splunk-es-ai-rba test suite.

The release target is the soc-search-repo style package tree under
``saved_searches/packages/``. Conf parsing, macro expansion, the prereq closure and
lookup loading are reused from ``saved_searches/tools/render_live_spl.py`` so the
tests and the live-render tool agree on what a package means.

Package roles (by name):

- ``hdsi_ai_rba_common``  -- shared macros, transforms and lookups (no saved search)
- ``hdsi_ai_health_*``    -- platform health checks
- ``hdsi_rba_ai_*``       -- risk aggregators (raise notables from the risk index)
- ``hdsi_ai_*`` with ``deployment_type: adhoc`` and ``action.risk = 0`` -- hunting/discovery
- every other ``hdsi_ai_*`` -- detections (risk-only, no notable)
"""

from __future__ import annotations

import csv
import importlib.util
import json
import re
import sys
from functools import lru_cache
from pathlib import Path

import pytest
import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SAVED_SEARCHES_DIR = PROJECT_ROOT / "saved_searches"
PACKAGES_DIR = SAVED_SEARCHES_DIR / "packages"
TOOLS_DIR = SAVED_SEARCHES_DIR / "tools"
DOCS_DIR = PROJECT_ROOT / "docs"
RUNBOOKS_DIR = DOCS_DIR / "runbooks"
PACKAGE_TAGS_CSV = SAVED_SEARCHES_DIR / "package_tags.csv"

COMMON_PACKAGE = "hdsi_ai_rba_common"
COMMON_DIR = PACKAGES_DIR / COMMON_PACKAGE
COMMON_LOOKUPS_DIR = COMMON_DIR / "lookups"

RELEASE_VERSION = "1.1.0"


def _load_render_module():
    spec = importlib.util.spec_from_file_location("render_live_spl", TOOLS_DIR / "render_live_spl.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["render_live_spl"] = module
    spec.loader.exec_module(module)
    return module


rls = _load_render_module()
read_conf = rls.read_conf
package_closure = rls.package_closure
load_macros = rls.load_macros
load_lookups = rls.load_lookups
expand_macros = rls.expand_macros
render = rls.render
split_args = rls.split_args
parse_outputs = rls.parse_outputs
MACRO_RE = rls.MACRO_RE


# ---------------------------------------------------------------------------
# Package discovery and metadata
# ---------------------------------------------------------------------------


def all_packages() -> list[str]:
    return sorted(p.name for p in PACKAGES_DIR.iterdir() if p.is_dir() and (p / "package.yml").exists())


@lru_cache(maxsize=None)
def package_meta(package: str) -> dict:
    data = yaml.safe_load((PACKAGES_DIR / package / "package.yml").read_text(encoding="utf-8"))
    return data or {}


@lru_cache(maxsize=None)
def savedsearches(package: str) -> dict[str, dict[str, str]]:
    return read_conf(PACKAGES_DIR / package / "confs" / "savedsearches.conf")


@lru_cache(maxsize=None)
def package_macro_stanzas(package: str) -> dict[str, dict[str, str]]:
    return read_conf(PACKAGES_DIR / package / "confs" / "macros.conf")


@lru_cache(maxsize=None)
def closure_macros(package: str) -> dict[str, tuple[list[str], str]]:
    return load_macros(package_closure(package))


def role(package: str) -> str:
    """Return common | health | aggregator | hunting | detection."""
    if package == COMMON_PACKAGE:
        return "common"
    if package.startswith("hdsi_ai_health_"):
        return "health"
    if package.startswith("hdsi_rba_ai_"):
        return "aggregator"
    if package_meta(package).get("deployment_type") == "adhoc" and all(
        kv.get("action.risk", "0").strip() == "0" for kv in savedsearches(package).values()
    ):
        return "hunting"
    return "detection"


def packages_with_role(*roles: str) -> list[str]:
    return [p for p in all_packages() if role(p) in roles]


def search_packages() -> list[str]:
    """Packages that ship a saved search (everything except the common package)."""
    return [p for p in all_packages() if p != COMMON_PACKAGE]


def risk_enabled(kv: dict[str, str]) -> bool:
    return kv.get("action.risk", "0").strip() == "1"


def drilldowns(kv: dict[str, str]) -> list[dict]:
    """Parsed drilldown searches; raises ValueError/JSONDecodeError on malformed JSON."""
    raw = kv.get("action.notable.param.drilldown_searches", "").strip()
    if not raw:
        return []
    parsed = json.loads(raw)
    if not isinstance(parsed, list):
        raise ValueError("drilldown_searches is not a JSON list")
    return parsed


def drilldown_searches_text(kv: dict[str, str]) -> list[str]:
    """Drilldown search strings, or [] when the JSON does not parse (covered by its own test)."""
    try:
        return [d.get("search", "") for d in drilldowns(kv) if isinstance(d, dict)]
    except (ValueError, json.JSONDecodeError):
        return []


@lru_cache(maxsize=None)
def repo_macro_names() -> frozenset[str]:
    """Every macro name (without arity) defined by any package in the repo."""
    names = set()
    for pkg in all_packages():
        for stanza in package_macro_stanzas(pkg):
            names.add(re.sub(r"\(\d+\)$", "", stanza))
    return frozenset(names)


# ---------------------------------------------------------------------------
# Lookups (discovered through transforms.conf)
# ---------------------------------------------------------------------------


def load_csv(path: Path) -> list[dict[str, str]]:
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def csv_header(path: Path) -> list[str]:
    with open(path, newline="", encoding="utf-8") as f:
        return next(csv.reader(f), [])


@lru_cache(maxsize=None)
def transforms_csv_lookups() -> tuple[tuple[str, str, Path], ...]:
    """(package, transforms stanza, CSV path) for every file-based lookup definition."""
    found = []
    for pkg in all_packages():
        for stanza, kv in read_conf(PACKAGES_DIR / pkg / "confs" / "transforms.conf").items():
            filename = kv.get("filename")
            if filename:
                found.append((pkg, stanza, PACKAGES_DIR / pkg / "lookups" / filename))
    return tuple(found)


def lookup_path(name: str) -> Path:
    """CSV path for a transforms stanza name, e.g. ``ai_provider_domains``."""
    for _, stanza, path in transforms_csv_lookups():
        if stanza == name:
            return path
    raise KeyError(f"no transforms.conf stanza named {name!r} with a filename")


def lookup_rows(name: str) -> list[dict[str, str]]:
    path = lookup_path(name)
    if not path.exists():
        pytest.fail(f"transforms.conf stanza [{name}] points at missing file {path.relative_to(PROJECT_ROOT)}")
    return load_csv(path)


@pytest.fixture(scope="session")
def provider_domains() -> list[dict[str, str]]:
    return lookup_rows("ai_provider_domains")


@pytest.fixture(scope="session")
def tool_processes() -> list[dict[str, str]]:
    return lookup_rows("ai_tool_processes")


@pytest.fixture(scope="session")
def sanctioned_entities() -> list[dict[str, str]]:
    return lookup_rows("ai_sanctioned_entities")


@pytest.fixture(scope="session")
def detection_config() -> list[dict[str, str]]:
    return lookup_rows("ai_detection_config")


@pytest.fixture(scope="session")
def mitre_mapping() -> list[dict[str, str]]:
    return lookup_rows("ai_mitre_mapping")


def search_of(package: str) -> str:
    """The (single) saved search SPL of a package, or '' if none."""
    for kv in savedsearches(package).values():
        if "search" in kv:
            return kv["search"]
    return ""
