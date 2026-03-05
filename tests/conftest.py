"""
Shared fixtures and helpers for splunk-es-ai-rba test suite.

Provides:
- Splunk .conf parser that handles multi-line values, stanza headers, key=value pairs
- Fixtures for loading savedsearches.conf, macros.conf, transforms.conf
- Fixtures for loading all CSV lookups
- Helpers for extracting macro and lookup references from SPL
"""

from __future__ import annotations

import csv
import re
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DIR = PROJECT_ROOT / "default"
LOOKUPS_DIR = PROJECT_ROOT / "lookups"


# ---------------------------------------------------------------------------
# Splunk .conf parser
# ---------------------------------------------------------------------------


def parse_conf(path: Path) -> dict[str, dict[str, str]]:
    """Parse a Splunk .conf file into {stanza: {key: value}}.

    Handles:
    - Stanza headers: [stanza_name]
    - Key=value pairs (first ``=`` is the separator)
    - Multi-line values via ``\\`` continuation at end of line
    - Continuation lines that start with leading whitespace (appended to
      the previous key's value)
    - Comment lines starting with ``#`` or ``;``
    - Blank lines (ignored)
    """
    stanzas: dict[str, dict[str, str]] = {}
    current_stanza = "default"
    stanzas[current_stanza] = {}
    current_key: str | None = None

    lines = path.read_text(encoding="utf-8").splitlines()
    i = 0
    while i < len(lines):
        raw = lines[i]
        stripped = raw.strip()

        # Skip blank and comment lines
        if not stripped or stripped.startswith("#") or stripped.startswith(";"):
            current_key = None
            i += 1
            continue

        # Stanza header
        if stripped.startswith("[") and stripped.endswith("]"):
            current_stanza = stripped[1:-1]
            stanzas.setdefault(current_stanza, {})
            current_key = None
            i += 1
            continue

        # Continuation line (starts with whitespace, no ``=`` before content)
        # Only valid when we already have a current_key
        if raw[0] in (" ", "\t") and current_key is not None:
            stanzas[current_stanza][current_key] += " " + stripped
            i += 1
            continue

        # Key = value
        if "=" in stripped:
            key, _, value = stripped.partition("=")
            key = key.strip()
            value = value.strip()

            # Handle backslash continuation
            while value.endswith("\\") and i + 1 < len(lines):
                value = value[:-1].rstrip()
                i += 1
                value += " " + lines[i].strip()

            stanzas[current_stanza][key] = value
            current_key = key
            i += 1
            continue

        # Anything else — treat as continuation of prior value
        if current_key is not None:
            stanzas[current_stanza][current_key] += " " + stripped

        i += 1

    return stanzas


# ---------------------------------------------------------------------------
# CSV loader
# ---------------------------------------------------------------------------


def load_csv(path: Path) -> list[dict[str, str]]:
    """Load a CSV lookup file and return list of row dicts."""
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        return list(reader)


# ---------------------------------------------------------------------------
# SPL helpers
# ---------------------------------------------------------------------------

# Matches backtick-wrapped macro references:  `macro_name`  or  `macro_name(arg1,arg2)`
_MACRO_RE = re.compile(r"`([a-zA-Z_][a-zA-Z0-9_]*(?:\([^)]*\))?)`")

# Matches ``| lookup <transform_name>`` in SPL (the word after ``lookup``)
_LOOKUP_RE = re.compile(r"\|\s*lookup\s+([a-zA-Z_][a-zA-Z0-9_]*)")


def extract_macro_refs(spl: str) -> list[str]:
    """Return macro references found in SPL, e.g. ['ai_domains_filter', 'ai_unsanctioned_filter(3)'].

    The returned names include arity notation: ``name`` for 0-arg macros,
    ``name(N)`` for N-arg macros (matching Splunk's macros.conf stanza naming).
    """
    refs = []
    for m in _MACRO_RE.finditer(spl):
        raw = m.group(1)
        if "(" in raw:
            name_part = raw[: raw.index("(")]
            args_part = raw[raw.index("(") + 1 : raw.rindex(")")]
            arg_count = len([a.strip() for a in args_part.split(",") if a.strip()])
            refs.append(f"{name_part}({arg_count})")
        else:
            refs.append(raw)
    return refs


def extract_lookup_refs(spl: str) -> list[str]:
    """Return lookup transform names referenced via ``| lookup`` in SPL."""
    return _LOOKUP_RE.findall(spl)


# ---------------------------------------------------------------------------
# Detection helpers
# ---------------------------------------------------------------------------

# Matches detection_id="AI-NNN" or "AI-RISK-NNN" or "AI-DISCOVERY-NNN" in SPL eval statements
_DETECTION_ID_RE = re.compile(r'detection_id\s*=\s*"(AI-[\w-]+\d+)"')


def extract_detection_id(spl: str) -> str | None:
    """Extract detection_id from SPL (e.g. 'AI-001')."""
    m = _DETECTION_ID_RE.search(spl)
    return m.group(1) if m else None


def is_detection_stanza(name: str) -> bool:
    """Return True if stanza name looks like a detection (not a threshold/aggregate/health/discovery search)."""
    return (
        name.startswith("AI RBA -")
        and "Risk Threshold" not in name
        and "Health -" not in name
        and "AI-RISK-" not in name
        and "AI-DISCOVERY-" not in name
    )


def is_threshold_stanza(name: str) -> bool:
    """Return True if stanza is a risk threshold/notable search."""
    return name.startswith("AI RBA -") and "Risk Threshold" in name


# ---------------------------------------------------------------------------
# Fixtures — .conf files
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def savedsearches() -> dict[str, dict[str, str]]:
    return parse_conf(DEFAULT_DIR / "savedsearches.conf")


@pytest.fixture(scope="session")
def macros() -> dict[str, dict[str, str]]:
    return parse_conf(DEFAULT_DIR / "macros.conf")


@pytest.fixture(scope="session")
def transforms() -> dict[str, dict[str, str]]:
    return parse_conf(DEFAULT_DIR / "transforms.conf")


# ---------------------------------------------------------------------------
# Fixtures — CSV lookups
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def provider_domains() -> list[dict[str, str]]:
    return load_csv(LOOKUPS_DIR / "ai_provider_domains.csv")


@pytest.fixture(scope="session")
def tool_processes() -> list[dict[str, str]]:
    return load_csv(LOOKUPS_DIR / "ai_tool_processes.csv")


@pytest.fixture(scope="session")
def sanctioned_entities() -> list[dict[str, str]]:
    return load_csv(LOOKUPS_DIR / "ai_sanctioned_entities.csv")


@pytest.fixture(scope="session")
def detection_config() -> list[dict[str, str]]:
    return load_csv(LOOKUPS_DIR / "ai_detection_config.csv")


@pytest.fixture(scope="session")
def mitre_mapping() -> list[dict[str, str]]:
    return load_csv(LOOKUPS_DIR / "ai_mitre_mapping.csv")


@pytest.fixture(scope="session")
def all_csv_files() -> dict[str, list[dict[str, str]]]:
    """Load every CSV in the lookups directory, keyed by filename."""
    result = {}
    for csv_path in sorted(LOOKUPS_DIR.glob("*.csv")):
        result[csv_path.name] = load_csv(csv_path)
    return result


# ---------------------------------------------------------------------------
# Derived fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def detection_stanzas(savedsearches):
    """Return {stanza_name: props} for detection searches only (not thresholds)."""
    return {
        name: props
        for name, props in savedsearches.items()
        if name != "default" and is_detection_stanza(name)
    }


@pytest.fixture(scope="session")
def threshold_stanzas(savedsearches):
    """Return {stanza_name: props} for risk threshold searches."""
    return {
        name: props
        for name, props in savedsearches.items()
        if name != "default" and is_threshold_stanza(name)
    }
