#!/usr/bin/env python3
"""
Collect unique tags from each package.yml under packages/* and write them
as a CSV file at the repository root (package_tags.csv).

Usage:
  python3 tools/collect_tags.py

The output CSV will have two columns: "tag,count".
"""

import csv
import glob
import os
import sys
from typing import Dict, Iterable, List, Set, Tuple

try:
	import yaml  # type: ignore
except Exception as exc:  # pragma: no cover
	print("ERROR: This script requires PyYAML. Install with: pip install pyyaml", file=sys.stderr)
	raise


def find_repo_root(script_path: str) -> str:
	"""Return the absolute path to the repository root.

	Assumes this script lives in <repo_root>/tools/.
	"""
	tools_dir = os.path.dirname(os.path.abspath(script_path))
	repo_root = os.path.abspath(os.path.join(tools_dir, os.pardir))
	return repo_root


def ordered_dedupe(values: Iterable[str]) -> List[str]:
	"""Deduplicate while preserving first-seen order, ignoring empty strings."""
	seen: Set[str] = set()
	result: List[str] = []
	for value in values:
		if not value:
			continue
		if value not in seen:
			seen.add(value)
			result.append(value)
	return result


def collect_all_tags_with_counts(packages_dir: str) -> Tuple[List[str], Dict[str, int]]:
	"""Collect tags from package.yml files, returning ordered unique tags and counts.

	The first list preserves the first-seen order of tags across all packages.
	The dict maps tag -> total count of occurrences across packages.
	"""
	pattern = os.path.join(packages_dir, '*/package.yml')
	package_files = sorted(glob.glob(pattern))

	all_tags: List[str] = []
	for pkg_file in package_files:
		try:
			with open(pkg_file, 'r', encoding='utf-8') as f:
				data = yaml.safe_load(f) or {}
		except Exception as exc:
			print(f"WARN: Failed to read {pkg_file}: {exc}", file=sys.stderr)
			continue

		tags = data.get('tags', [])
		if isinstance(tags, list):
			for tag in tags:
				# Normalize to strings, strip whitespace
				if isinstance(tag, str):
					normalized = tag.strip()
				else:
					normalized = str(tag).strip()
				if normalized:
					all_tags.append(normalized)
		else:
			print(f"WARN: 'tags' in {pkg_file} is not a list; skipping", file=sys.stderr)

	# Compute counts and ordered unique list
	counts: Dict[str, int] = {}
	for tag in all_tags:
		counts[tag] = counts.get(tag, 0) + 1
	ordered_unique = ordered_dedupe(all_tags)
	return ordered_unique, counts


def write_csv(output_path: str, ordered_tags: List[str], counts: Dict[str, int]) -> None:
	"""Write tags and counts to a CSV with headers 'tag,count'."""
	with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
		writer = csv.writer(csvfile)
		writer.writerow(['tag', 'count'])
		for tag in ordered_tags:
			writer.writerow([tag, counts.get(tag, 0)])


def main() -> int:
	repo_root = find_repo_root(__file__)
	packages_dir = os.path.join(repo_root, 'packages')
	if not os.path.isdir(packages_dir):
		print(f"ERROR: Packages directory not found: {packages_dir}", file=sys.stderr)
		return 1

	ordered_tags, counts = collect_all_tags_with_counts(packages_dir)
	output_csv = os.path.join(repo_root, 'package_tags.csv')
	write_csv(output_csv, ordered_tags, counts)

	print(f"Wrote {len(ordered_tags)} unique tags to {output_csv}")
	return 0


if __name__ == '__main__':
	sys.exit(main())

