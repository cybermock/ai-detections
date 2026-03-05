#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# ///
"""Fail fast when required SOC repo-bones files are missing."""

from __future__ import annotations

import sys
from pathlib import Path


REQUIRED_PATHS = [
    ".gitlab-ci.yml",
    "validate.py",
    "deploy.py",
    "to_hec.py",
    "extract_risk_params.py",
    "package-schema.yml",
    "package_tags.csv",
    "requirements.txt",
    "templates/template_package/package.yml",
    "templates/template_package/README.md",
    "templates/template_package/confs/macros.conf",
    "templates/template_package/confs/savedsearches.conf",
    "tools/collect_tags.py",
    "tools/delete_splunk_package.py",
]


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    missing = [path for path in REQUIRED_PATHS if not (repo_root / path).exists()]

    packages_dir = repo_root / "packages"
    has_packages = packages_dir.exists() and any(
        entry.is_dir() and (entry / "package.yml").exists() for entry in packages_dir.iterdir()
    )
    if not has_packages:
        missing.append("packages/*/package.yml")

    if missing:
        print("ERROR: p2r is missing required repo-bones paths:", file=sys.stderr)
        for path in missing:
            print(f"- {path}", file=sys.stderr)
        return 1

    print("Repo-bones check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
