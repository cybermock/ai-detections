#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# ///
"""Render a package's saved search into self-contained SPL for read-only live testing.

The rendered search runs on any ES search head without deploying the package:

- Macros are expanded from the package's own macros.conf and its prereq_packages
  (argument macros included). Macros not defined in the repo (cim_*, ES macros)
  are left for the search head to expand.
- Repo lookups (any lookup with a CSV under a package's lookups/ directory) are
  inlined. ``| lookup X key [AS f] OUTPUT|OUTPUTNEW ...`` becomes a case-insensitive
  left join against ``| makeresults format=csv data="..."``, and ``| inputlookup X``
  becomes the makeresults itself. ES lookups such as identity_lookup_expanded and
  asset_lookup_by_str are left untouched.

Nothing is written to Splunk. Paste the output into the search bar, or emit a JSON
batch for a scripted runner.

Examples:
    tools/render_live_spl.py hdsi_ai_unsanctioned_web_access
    tools/render_live_spl.py hdsi_ai_unsanctioned_web_access --drilldowns
    tools/render_live_spl.py --all --json --earliest -24h --latest now > batch.json
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import re
import sys
from pathlib import Path

PACKAGES_DIR = Path(__file__).resolve().parent.parent / "packages"
INCUBATING_DIR = Path(__file__).resolve().parent.parent / "incubating"
MACRO_RE = re.compile(r"`([A-Za-z0-9_]+)(?:\(([^`]*)\))?`")
LOOKUP_RE = re.compile(
    r"\blookup\s+(?P<name>[A-Za-z0-9_]+?)(?:\.csv)?\s+(?P<key>[A-Za-z0-9_]+)"
    r"(?:\s+as\s+(?P<field>[A-Za-z0-9_]+))?"
    r"\s+(?P<mode>OUTPUTNEW|OUTPUT)\s+(?P<outputs>.*?)(?=\s*(?:\||\]|$))",
    re.IGNORECASE | re.DOTALL,
)
INPUTLOOKUP_RE = re.compile(r"\binputlookup\s+(?P<name>[A-Za-z0-9_]+?)(?:\.csv)?\b")


def read_conf(path: Path) -> dict[str, dict[str, str]]:
    """Minimal .conf reader: stanzas, key = value, backslash line continuation."""
    stanzas: dict[str, dict[str, str]] = {}
    if not path.exists():
        return stanzas
    current: dict[str, str] | None = None
    key = None
    for raw in path.read_text(encoding="utf-8").splitlines():
        if key is not None and current is not None:
            current[key] += "\n" + raw
            if not raw.endswith("\\"):
                current[key] = current[key].replace("\\\n", "\n")
                key = None
            continue
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = stanzas.setdefault(line[1:-1], {})
            continue
        if current is None or "=" not in raw:
            continue
        k, v = raw.split("=", 1)
        k, v = k.strip(), v.strip()
        current[k] = v
        if v.endswith("\\"):
            key = k
    return stanzas


def package_dir(package: str) -> Path:
    """Shipped packages first; incubating packages (not released) can still be rendered."""
    shipped = PACKAGES_DIR / package
    return shipped if shipped.is_dir() or not (INCUBATING_DIR / package).is_dir() else INCUBATING_DIR / package


def prereqs(package: str) -> list[str]:
    yml = package_dir(package) / "package.yml"
    found: list[str] = []
    in_block = False
    for line in yml.read_text(encoding="utf-8").splitlines():
        if re.match(r"^prereq_packages\s*:", line):
            in_block = True
            continue
        if in_block:
            m = re.match(r"^\s*-\s*(\S+)", line)
            if m:
                found.append(m.group(1).strip("'\""))
            elif line.strip() and not line.startswith(" "):
                in_block = False
    return found


def package_closure(package: str) -> list[str]:
    seen: list[str] = []
    stack = [package]
    while stack:
        pkg = stack.pop()
        if pkg in seen or not package_dir(pkg).is_dir():
            continue
        seen.append(pkg)
        stack.extend(prereqs(pkg))
    return seen


def load_macros(packages: list[str]) -> dict[str, tuple[list[str], str]]:
    macros: dict[str, tuple[list[str], str]] = {}
    for pkg in packages:
        for stanza, kv in read_conf(package_dir(pkg) / "confs" / "macros.conf").items():
            m = re.match(r"^([A-Za-z0-9_]+)(?:\((\d+)\))?$", stanza)
            if not m or "definition" not in kv:
                continue
            nargs = int(m.group(2) or 0)
            args = [a.strip() for a in kv.get("args", "").split(",") if a.strip()]
            macros[f"{m.group(1)}/{nargs}"] = (args, kv["definition"])
    return macros


def load_lookups(packages: list[str]) -> dict[str, str]:
    """Map lookup name -> CSV text, via transforms.conf filename or the CSV stem."""
    lookups: dict[str, str] = {}
    for pkg in packages:
        lookup_dir = package_dir(pkg) / "lookups"
        if not lookup_dir.is_dir():
            continue
        files = {p.name: p for p in lookup_dir.glob("*.csv")}
        for stanza, kv in read_conf(package_dir(pkg) / "confs" / "transforms.conf").items():
            if kv.get("filename") in files:
                lookups[stanza] = files[kv["filename"]].read_text(encoding="utf-8")
        for name, path in files.items():
            lookups.setdefault(Path(name).stem, path.read_text(encoding="utf-8"))
    return lookups


def split_args(text: str) -> list[str]:
    """Split macro call arguments on top-level commas, respecting quotes and parens."""
    args, depth, quote, buf = [], 0, False, ""
    for ch in text:
        if ch == '"':
            quote = not quote
        elif not quote and ch == "(":
            depth += 1
        elif not quote and ch == ")":
            depth -= 1
        if ch == "," and depth == 0 and not quote:
            args.append(buf.strip())
            buf = ""
            continue
        buf += ch
    if buf.strip() or args:
        args.append(buf.strip())
    return args


def expand_macros(spl: str, macros: dict[str, tuple[list[str], str]], depth: int = 0) -> str:
    if depth > 20:
        raise RecursionError("macro expansion exceeded 20 levels")

    def repl(m: re.Match[str]) -> str:
        name, argtext = m.group(1), m.group(2)
        values = split_args(argtext) if argtext is not None else []
        entry = macros.get(f"{name}/{len(values)}")
        if entry is None:
            return m.group(0)
        argnames, body = entry
        for argname, value in zip(argnames, values):
            body = body.replace(f"${argname}$", value)
        return expand_macros(body, macros, depth + 1)

    return MACRO_RE.sub(repl, spl)


def spl_csv(text: str, columns: list[str] | None = None) -> str:
    """CSV text as an SPL double-quoted string literal, optionally pruned to columns."""
    rows = [r for r in csv.reader(io.StringIO(text)) if r]
    if columns and rows:
        idx = [i for i, h in enumerate(rows[0]) if h in columns]
        rows = [[r[i] if i < len(r) else "" for i in idx] for r in rows]
    out = io.StringIO()
    csv.writer(out, lineterminator="\n").writerows(r for r in rows if r)
    body = out.getvalue().rstrip("\n").replace("\\", "\\\\").replace('"', '\\"')
    return f'"{body}"'


def parse_outputs(text: str) -> list[tuple[str, str]]:
    tokens = [t for t in re.split(r"[\s,]+", text.strip()) if t]
    pairs: list[tuple[str, str]] = []
    i = 0
    while i < len(tokens):
        src = tokens[i]
        if i + 2 < len(tokens) and tokens[i + 1].lower() == "as":
            pairs.append((src, tokens[i + 2]))
            i += 3
        else:
            pairs.append((src, src))
            i += 1
    return pairs


def inline_lookups(spl: str, lookups: dict[str, str]) -> str:
    counter = iter(range(10_000))

    def lookup_repl(m: re.Match[str]) -> str:
        name = m.group("name")
        if name not in lookups:
            return m.group(0)
        n = next(counter)
        # temp fields must not start with "_": join drops underscore fields from the subsearch
        jk = f"zzjk{n}"
        key, field = m.group("key"), m.group("field") or m.group("key")
        overwrite = "false" if m.group("mode").upper() == "OUTPUTNEW" else "true"
        outs = parse_outputs(m.group("outputs"))
        renames = " ".join(
            f"| rename {src} as zzlk{n}_{dst}" for src, dst in outs
        )
        restore = ", ".join(
            f"{dst}=coalesce('{dst}', 'zzlk{n}_{dst}')" if overwrite == "false"
            else f"{dst}=if(isnotnull('zzlk{n}_{dst}'), 'zzlk{n}_{dst}', '{dst}')"
            for _, dst in outs
        )
        keep = " ".join(f"zzlk{n}_{dst}" for _, dst in outs)
        data = spl_csv(lookups[name], [key] + [src for src, _ in outs])
        return (
            f"eval {jk}=lower('{field}') "
            f"| join type=left max=1 {jk} [| makeresults format=csv data={data} "
            f"| eval {jk}=lower('{key}') {renames} | fields {jk} {keep}] "
            f"| eval {restore} | fields - {jk} zzlk{n}_*"
        )

    def inputlookup_repl(m: re.Match[str]) -> str:
        name = m.group("name")
        if name not in lookups:
            return m.group(0)
        return f"makeresults format=csv data={spl_csv(lookups[name])}"

    spl = LOOKUP_RE.sub(lookup_repl, spl)
    return INPUTLOOKUP_RE.sub(inputlookup_repl, spl)


def render(package: str, *, drilldowns: bool = False) -> list[dict]:
    closure = package_closure(package)
    macros = load_macros(closure)
    lookups = load_lookups(closure)
    rendered = []
    for stanza, kv in read_conf(package_dir(package) / "confs" / "savedsearches.conf").items():
        if "search" not in kv:
            continue
        spl = re.sub(r"\s*\n\s*", " ", expand_macros(kv["search"], macros)).strip()
        spl = inline_lookups(spl, lookups)
        rendered.append(
            {
                "package": package,
                "stanza": stanza,
                "kind": "search",
                "earliest": kv.get("dispatch.earliest_time", "-24h"),
                "latest": kv.get("dispatch.latest_time", "now"),
                "spl": spl,
            }
        )
        if drilldowns and kv.get("action.notable.param.drilldown_searches"):
            for dd in json.loads(kv["action.notable.param.drilldown_searches"]):
                rendered.append(
                    {
                        "package": package,
                        "stanza": stanza,
                        "kind": f"drilldown:{dd.get('name', '')}",
                        "earliest": "-24h",
                        "latest": "now",
                        "spl": inline_lookups(expand_macros(dd["search"], macros), lookups),
                    }
                )
    return rendered


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("package", nargs="?", help="package directory name under packages/ (or incubating/)")
    parser.add_argument("--all", action="store_true", help="render every released package with a saved search")
    parser.add_argument("--json", action="store_true", help="emit a JSON list instead of plain SPL")
    parser.add_argument("--drilldowns", action="store_true", help="also render notable drilldown searches")
    parser.add_argument("--earliest", help="override dispatch.earliest_time in JSON output")
    parser.add_argument("--latest", help="override dispatch.latest_time in JSON output")
    args = parser.parse_args()

    if args.all:
        packages = sorted(p.name for p in PACKAGES_DIR.iterdir() if (p / "confs" / "savedsearches.conf").exists())
    elif args.package:
        packages = [args.package]
    else:
        parser.error("give a package name or --all")

    results = []
    for pkg in packages:
        if not package_dir(pkg).is_dir():
            print(f"ERROR: no such package: {pkg}", file=sys.stderr)
            return 1
        results.extend(render(pkg, drilldowns=args.drilldowns))
    for r in results:
        if args.earliest:
            r["earliest"] = args.earliest
        if args.latest:
            r["latest"] = args.latest

    if args.json:
        json.dump(results, sys.stdout, indent=1)
        print()
    else:
        for r in results:
            print(f"### {r['stanza']} [{r['kind']}] earliest={r['earliest']} latest={r['latest']}")
            print(r["spl"])
            print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
