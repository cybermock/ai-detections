#!/usr/bin/env python3
"""Apply convention compliance fixes to all saved_searches detection packages.

Addresses findings from the soc-search-repo pipeline audit:
1. enable_alerting: False -> false (all package.yml)
2. Add app_context: HurricaneLabsContentUpdates (all package.yml)
3. alert.suppress.period -> seconds format (all savedsearches.conf)
4. Add cron schedule offsets (all savedsearches.conf)
5. Static risk scores: strings -> integers (affected savedsearches.conf)
6. Break single-line SPL into multi-line (all savedsearches.conf)
7. Add common_dependencies where applicable (most package.yml)
8. Add description/disabled to shared macros (hdsi_ai_rba_common macros.conf)
9. Add dynamic field token to rule_title (all savedsearches.conf)
"""

import os
import re
import sys

BASE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "packages")

# Time period to seconds conversion
TIME_TO_SECONDS = {
    "1h": "3600s",
    "2h": "7200s",
    "4h": "14400s",
    "24h": "86400s",
    "7d": "604800s",
}

# Shared macros defined in hdsi_ai_rba_common
SHARED_MACROS = [
    "ai_domains_filter",
    "ai_unsanctioned_filter",
    "ai_risk_multiplier",
    "ai_process_filter",
    "ai_prompt_injection_patterns_enabled",
    "ai_api_key_patterns_enabled",
    "ai_risk_defaults",
]


def get_packages():
    """Get all package directories sorted alphabetically."""
    return sorted([
        d for d in os.listdir(BASE_DIR)
        if os.path.isdir(os.path.join(BASE_DIR, d))
    ])


def detect_shared_macros(savedsearch_path):
    """Scan savedsearches.conf for references to shared macros."""
    if not os.path.exists(savedsearch_path):
        return []
    with open(savedsearch_path) as f:
        content = f.read()
    found = []
    for macro in SHARED_MACROS:
        # Match backtick-wrapped macros: `macro_name` or `macro_name(args)`
        if re.search(r'`' + re.escape(macro) + r'[\(`]', content) or \
           re.search(r'`' + re.escape(macro) + r'`', content):
            found.append(macro)
    return sorted(found)


def fix_package_yml(filepath, shared_macros_used):
    """Fix package.yml: enable_alerting, app_context, common_dependencies."""
    with open(filepath) as f:
        content = f.read()

    original = content

    # 1. Fix enable_alerting: False -> false
    content = content.replace("enable_alerting: False", "enable_alerting: false")

    # 2. Add app_context if missing (after enable_alerting line)
    if "app_context:" not in content:
        content = content.replace(
            "enable_alerting: false\n",
            "enable_alerting: false\napp_context: HurricaneLabsContentUpdates\n"
        )

    # 3. Add common_dependencies if macros are used and not already present
    if shared_macros_used and "common_dependencies:" not in content:
        deps_lines = "\n".join(f"  - macros:{m}" for m in shared_macros_used)
        deps_block = f"common_dependencies:\n{deps_lines}\n"
        # Add before tags: line
        if "tags:" in content:
            content = content.replace("tags:\n", f"{deps_block}tags:\n")
        else:
            # Fallback: add before deployment_type
            content = content.replace("deployment_type:", f"{deps_block}deployment_type:")

    changed = content != original
    with open(filepath, 'w') as f:
        f.write(content)
    return changed


def fix_macros_conf(filepath):
    """Add description and disabled to each macro stanza in hdsi_ai_rba_common."""
    with open(filepath) as f:
        content = f.read()

    original = content

    # Process each stanza: add description and disabled after iseval line
    # Pattern: find "iseval = 0\n" followed by blank line or EOF
    # Add "description = v1.0\ndisabled = False\n" after iseval
    content = re.sub(
        r'(iseval = 0)\n(\n|\Z)',
        r'\1\ndescription = v1.0\ndisabled = False\n\2',
        content
    )

    changed = content != original
    with open(filepath, 'w') as f:
        f.write(content)
    return changed


def get_suppress_fields(content):
    """Extract alert.suppress.fields from savedsearches.conf content."""
    m = re.search(r'alert\.suppress\.fields\s*=\s*(.+)', content)
    if m:
        return [f.strip() for f in m.group(1).split(',')]
    return []


def get_dynamic_field(content):
    """Determine the best dynamic field for rule_title based on suppress fields."""
    fields = get_suppress_fields(content)
    if not fields:
        return None
    # Prefer user, then src, then first field
    if 'user' in fields:
        return 'user'
    if 'src' in fields:
        return 'src'
    return fields[0]


def fix_rule_title(content):
    """Add dynamic field token to rule_title if not already present."""
    dynamic_field = get_dynamic_field(content)
    if not dynamic_field:
        return content

    pattern = r'(action\.notable\.param\.rule_title\s*=\s*)(.+)'
    match = re.search(pattern, content)
    if match:
        title = match.group(2).strip()
        token = f"(${dynamic_field}$)"
        # Only add if no dynamic token already present
        if '$' not in title:
            new_title = f"{title} {token}"
            content = content.replace(
                match.group(0),
                f"{match.group(1)}{new_title}"
            )
    return content


def fix_suppress_period(content):
    """Convert human-readable suppress periods to seconds."""
    for human, seconds in TIME_TO_SECONDS.items():
        content = content.replace(
            f"alert.suppress.period = {human}",
            f"alert.suppress.period = {seconds}"
        )
    return content


def fix_cron_schedule(content, offset_5, offset_15):
    """Add offset to */N cron schedules."""
    if "cron_schedule = */5 * * * *" in content:
        new_cron = f"cron_schedule = {offset_5}-59/5 * * * *"
        content = content.replace("cron_schedule = */5 * * * *", new_cron)
    elif "cron_schedule = */15 * * * *" in content:
        new_cron = f"cron_schedule = {offset_15}-59/15 * * * *"
        content = content.replace("cron_schedule = */15 * * * *", new_cron)
    return content


def fix_risk_scores(content):
    """Convert static risk_score strings to integers in _risk JSON."""
    # Match "risk_score":"<digits>" and convert to "risk_score": <digits>
    # Don't touch "risk_score":"$variable$" patterns (Splunk token substitution)
    content = re.sub(
        r'"risk_score"\s*:\s*"(\d+)"',
        lambda m: f'"risk_score": {m.group(1)}',
        content
    )
    return content


def collect_search_value(lines, start_idx):
    """Collect the full search value spanning continuation lines.

    Returns (search_string, end_idx) where end_idx is the index of the
    last line that is part of the search value.
    """
    search_lines = []
    i = start_idx
    while i < len(lines):
        line = lines[i]
        search_lines.append(line)
        # Check if this line continues (ends with \)
        if line.rstrip().endswith('\\'):
            i += 1
        else:
            break
    return search_lines, i


def reformat_spl_multiline(content):
    """Reformat single-line SPL search to multi-line with \\ continuation."""
    lines = content.split('\n')
    new_lines = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith('search = '):
            # Collect the full search value (including continuation lines)
            search_lines, end_idx = collect_search_value(lines, i)

            # Join into one string, stripping continuation markers
            parts = []
            for sl in search_lines:
                stripped = sl.rstrip()
                if stripped.endswith('\\'):
                    stripped = stripped[:-1].rstrip()
                # Remove leading whitespace from continuation lines
                if sl != search_lines[0]:
                    stripped = stripped.lstrip('\t ')
                parts.append(stripped)

            full_search = ' '.join(p for p in parts if p)

            # Remove the "search = " prefix to get raw SPL
            spl = full_search[len("search = "):]

            # Split on " | " to get pipe-separated commands
            segments = re.split(r' \| ', spl)

            if len(segments) <= 1:
                # No pipes to split on, keep as-is
                new_lines.append(full_search)
            else:
                # First segment: "search = <first_command> \"
                new_lines.append(f"search = {segments[0]} \\")
                # Middle segments: "\t| <command> \"
                for j in range(1, len(segments) - 1):
                    new_lines.append(f"\t| {segments[j]} \\")
                # Last segment: "\t| <command>" (no trailing \)
                new_lines.append(f"\t| {segments[-1]}")

            i = end_idx + 1
        else:
            new_lines.append(line)
            i += 1

    return '\n'.join(new_lines)


def fix_savedsearches_conf(filepath, offset_5, offset_15):
    """Apply all fixes to a savedsearches.conf file."""
    with open(filepath) as f:
        content = f.read()

    original = content

    # 1. Fix suppress period (human-readable -> seconds)
    content = fix_suppress_period(content)

    # 2. Fix cron schedule (add offsets)
    content = fix_cron_schedule(content, offset_5, offset_15)

    # 3. Fix static risk scores (strings -> integers)
    content = fix_risk_scores(content)

    # 4. Fix rule_title (add dynamic field token)
    content = fix_rule_title(content)

    # 5. Reformat SPL to multi-line
    content = reformat_spl_multiline(content)

    changed = content != original
    with open(filepath, 'w') as f:
        f.write(content)
    return changed


def main():
    packages = get_packages()
    print(f"Processing {len(packages)} packages...\n")

    stats = {
        "package_yml_fixed": 0,
        "macros_conf_fixed": 0,
        "savedsearches_fixed": 0,
        "common_deps_added": 0,
    }

    # Counters for distributing cron offsets
    five_min_counter = 0
    fifteen_min_counter = 0

    for pkg in packages:
        pkg_dir = os.path.join(BASE_DIR, pkg)
        pkg_yml = os.path.join(pkg_dir, "package.yml")
        saved_search = os.path.join(pkg_dir, "confs", "savedsearches.conf")
        macros_conf = os.path.join(pkg_dir, "confs", "macros.conf")

        print(f"--- {pkg} ---")

        # Detect shared macros used (skip for hdsi_ai_rba_common itself)
        shared_macros = []
        if pkg != "hdsi_ai_rba_common":
            shared_macros = detect_shared_macros(saved_search)
            if shared_macros:
                print(f"  Shared macros: {', '.join(shared_macros)}")

        # Fix package.yml
        if os.path.exists(pkg_yml):
            changed = fix_package_yml(pkg_yml, shared_macros)
            if changed:
                stats["package_yml_fixed"] += 1
                print(f"  Fixed package.yml")
                if shared_macros:
                    stats["common_deps_added"] += 1

        # Fix macros.conf (only for hdsi_ai_rba_common)
        if pkg == "hdsi_ai_rba_common" and os.path.exists(macros_conf):
            changed = fix_macros_conf(macros_conf)
            if changed:
                stats["macros_conf_fixed"] += 1
                print(f"  Fixed macros.conf")

        # Fix savedsearches.conf
        if os.path.exists(saved_search):
            # Read to determine cron type and calculate offset
            with open(saved_search) as f:
                ss_content = f.read()

            if "*/5 * * * *" in ss_content:
                offset_5 = five_min_counter % 5
                offset_15 = 0
                five_min_counter += 1
            elif "*/15 * * * *" in ss_content:
                offset_5 = 0
                offset_15 = (fifteen_min_counter % 5) * 3
                fifteen_min_counter += 1
            else:
                offset_5 = 0
                offset_15 = 0

            changed = fix_savedsearches_conf(saved_search, offset_5, offset_15)
            if changed:
                stats["savedsearches_fixed"] += 1
                if "*/5 * * * *" in ss_content:
                    print(f"  Fixed savedsearches.conf (cron offset: {offset_5})")
                elif "*/15 * * * *" in ss_content:
                    print(f"  Fixed savedsearches.conf (cron offset: {offset_15})")
                else:
                    print(f"  Fixed savedsearches.conf")

    print(f"\n=== Summary ===")
    print(f"package.yml files fixed: {stats['package_yml_fixed']}")
    print(f"macros.conf files fixed: {stats['macros_conf_fixed']}")
    print(f"savedsearches.conf files fixed: {stats['savedsearches_fixed']}")
    print(f"common_dependencies added: {stats['common_deps_added']}")
    print(f"*/5 cron offsets distributed across {five_min_counter} packages (offsets 0-4)")
    print(f"*/15 cron offsets distributed across {fifteen_min_counter} packages (offsets 0,3,6,9,12)")


if __name__ == "__main__":
    main()
