"""Repository hygiene: no customer identifiers, no resurrected legacy app."""

from __future__ import annotations

import hashlib
import re

import pytest

from .conftest import DOCS_DIR, PROJECT_ROOT, SAVED_SEARCHES_DIR

# SHA-256 of lowercase customer identifiers (tenant names, hostnames, the cloud stack domain).
# Stored hashed so the test itself does not ship the names it guards against.
CUSTOMER_IDENTIFIER_HASHES = frozenset({
    "b016e59ff922942cab669678a714963c674565d58a8f5cf35447f96e0a8a9b11",
    "1c665b3f4399a3cca7b3407217e9d9bd1560b18ca5fa4f653163bddf7b4061e4",
    "155ed80576e9a933dfca8b709277439647b78539e25e7e6219ca5a9f8d831f73",
    "4d9aa1401d05693abc67d1acc84e80cd4ff74b917af7db55db475df04dbef585",
    "0fb704f83c72849da18c89bfb421abae35cd2670c4a456633128c169e89c2312",
    "f1113cd4f17fc530c6dc666091254c96ccdb4809f78862213b990ee3b32fbd27",
    "34e794c2627ee7339ec637ae66ca51f1585f0fd70defa3e10746147754209f2d",
})
TOKEN_RE = re.compile(r"[a-z0-9]+")
JOINERS = ("", " ", "-", ".")
SKIP_DIRS = {"__pycache__", ".pytest_cache", ".ruff_cache"}
SKIP_SUFFIXES = {".pyc", ".png", ".jpg", ".jpeg", ".gif", ".spl", ".tgz", ".gz", ".zip", ".pdf"}


def _candidates(line):
    """Single tokens plus adjacent token pairs joined the ways identifiers appear (es-chi, x.com, two words)."""
    tokens = TOKEN_RE.findall(line.lower())
    yield from tokens
    for a, b in zip(tokens, tokens[1:]):
        for joiner in JOINERS:
            yield f"{a}{joiner}{b}"


def _text_files(root):
    if root.is_file():
        yield root
        return
    for path in sorted(root.rglob("*")):
        if path.is_file() and not SKIP_DIRS & set(path.parts) and path.suffix.lower() not in SKIP_SUFFIXES:
            yield path


@pytest.mark.parametrize(
    "root",
    [SAVED_SEARCHES_DIR, DOCS_DIR, PROJECT_ROOT / "README.md", PROJECT_ROOT / "CHANGELOG.md"],
    ids=["saved_searches", "docs", "README.md", "CHANGELOG.md"],
)
def test_no_customer_identifiers(root):
    hits = []
    for path in _text_files(root):
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        for lineno, line in enumerate(lines, start=1):
            for candidate in _candidates(line):
                if hashlib.sha256(candidate.encode()).hexdigest() in CUSTOMER_IDENTIFIER_HASHES:
                    hits.append(f"{path.relative_to(PROJECT_ROOT)}:{lineno} contains a customer identifier")
                    break
    assert not hits, f"{len(hits)} customer identifier hit(s):\n" + "\n".join(hits[:200])


@pytest.mark.parametrize("legacy", ["default", "lookups"])
def test_legacy_app_retired(legacy):
    assert not (PROJECT_ROOT / legacy).exists(), (
        f"top-level {legacy}/ belongs to the retired monolithic app; saved_searches/packages/ is the source of truth"
    )
