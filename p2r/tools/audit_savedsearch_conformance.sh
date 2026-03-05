#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
P2R_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
PACKAGES_DIR="${P2R_DIR}/packages"
OUT_DIR="${1:-${P2R_DIR}/reports}"

mkdir -p "${OUT_DIR}"

JSON_OUT="${OUT_DIR}/p2r_savedsearch_conformance.json"
MD_OUT="${OUT_DIR}/p2r_savedsearch_conformance.md"

FILES="$(find "${PACKAGES_DIR}" -maxdepth 3 -type f -name 'savedsearches.conf' | sort)"

if [[ -z "${FILES}" ]]; then
  echo "No savedsearches.conf files found under ${PACKAGES_DIR}" >&2
  exit 1
fi

total=0
pass_all=0

total_notable=0
total_risk=0
total_notable_desc=0
total_risk_msg=0
total_risk_obj=0
total_drill=0
total_dashboards=0
total_drill_key_schema=0
total_enabled=0
total_risk_type_schema=0

{
  echo "["

  first=1
  for f in ${FILES}; do
    pkg="$(basename "$(dirname "$(dirname "${f}")")")"

    notable=0
    risk=0
    notable_desc=0
    risk_msg=0
    risk_obj=0
    drill=0
    dashboards=0
    drill_key_schema=0
    enabled=0
    risk_type_schema=0

    rg -q '^action\.notable\s*=\s*1\b' "${f}" && notable=1
    rg -q '^action\.risk\s*=\s*1\b' "${f}" && risk=1
    rg -q '^action\.notable\.param\.rule_description\s*=' "${f}" && notable_desc=1
    rg -q '^action\.risk\.param\._risk_message\s*=' "${f}" && risk_msg=1
    rg -q '^action\.risk\.param\._risk\s*=\s*\[' "${f}" && risk_obj=1
    rg -q '^action\.notable\.param\.drilldown_searches\s*=\s*\[' "${f}" && drill=1
    rg -q '^action\.notable\.param\.drilldown_dashboards\s*=\s*\[\]' "${f}" && dashboards=1
    rg -q '^disabled\s*=\s*0\b' "${f}" && enabled=1

    has_bad_drill_keys=0
    rg -q '"earliest"\s*:|"latest"\s*:' "${f}" && has_bad_drill_keys=1
    if [[ "${has_bad_drill_keys}" -eq 0 ]]; then
      drill_key_schema=1
    fi

    invalid_types="$(rg -o 'risk_object_type\"\\s*:\\s*\"[^\"]+\"' "${f}" | sed -E 's/.*\"([^\"]+)\"$/\1/' | sort -u | rg -v '^(user|system)$' || true)"
    if [[ -z "${invalid_types}" ]]; then
      risk_type_schema=1
      invalid_json="[]"
    else
      invalid_json="$(
        printf '%s\n' "${invalid_types}" | awk 'BEGIN{printf "["} {if(NR>1)printf ","; gsub(/"/,"\\\"",$0); printf "\""$0"\""} END{printf "]"}'
      )"
    fi

    ((total += 1))
    ((total_notable += notable))
    ((total_risk += risk))
    ((total_notable_desc += notable_desc))
    ((total_risk_msg += risk_msg))
    ((total_risk_obj += risk_obj))
    ((total_drill += drill))
    ((total_dashboards += dashboards))
    ((total_drill_key_schema += drill_key_schema))
    ((total_enabled += enabled))
    ((total_risk_type_schema += risk_type_schema))

    all_pass=0
    if [[ "${notable}" -eq 1 && "${risk}" -eq 1 && "${notable_desc}" -eq 1 && "${risk_msg}" -eq 1 && "${risk_obj}" -eq 1 && "${drill}" -eq 1 && "${dashboards}" -eq 1 && "${drill_key_schema}" -eq 1 && "${enabled}" -eq 1 && "${risk_type_schema}" -eq 1 ]]; then
      all_pass=1
      ((pass_all += 1))
    fi

    if [[ "${first}" -eq 0 ]]; then
      echo ","
    fi
    first=0

    printf '  {"package":"%s","file":"%s","checks":{"notable_enabled":%s,"risk_enabled":%s,"notable_description_present":%s,"risk_message_present":%s,"risk_object_present":%s,"drilldown_present":%s,"drilldown_dashboards_present":%s,"drilldown_key_schema_ok":%s,"enabled_by_default":%s,"risk_object_type_schema_ok":%s},"invalid_risk_object_types":%s,"all_pass":%s}' \
      "${pkg}" "${f}" "${notable}" "${risk}" "${notable_desc}" "${risk_msg}" "${risk_obj}" "${drill}" "${dashboards}" "${drill_key_schema}" "${enabled}" "${risk_type_schema}" "${invalid_json}" "${all_pass}"
  done

  echo
  echo "]"
} > "${JSON_OUT}"

{
  echo "# P2R Saved Search Conformance Report"
  echo
  echo "- Generated: $(date -u '+%Y-%m-%d %H:%M:%SZ')"
  echo "- Scope: \`${PACKAGES_DIR}\`"
  echo "- Total searches audited: ${total}"
  echo "- Fully conformant searches: ${pass_all}"
  echo
  echo "## Summary"
  echo
  echo "| Check | Passed | Total |"
  echo "|---|---:|---:|"
  echo "| action.notable = 1 | ${total_notable} | ${total} |"
  echo "| action.risk = 1 | ${total_risk} | ${total} |"
  echo "| notable description present | ${total_notable_desc} | ${total} |"
  echo "| risk message present | ${total_risk_msg} | ${total} |"
  echo "| risk object present | ${total_risk_obj} | ${total} |"
  echo "| drilldown searches present | ${total_drill} | ${total} |"
  echo "| drilldown dashboards line present | ${total_dashboards} | ${total} |"
  echo "| drilldown keys use earliest_offset/latest_offset | ${total_drill_key_schema} | ${total} |"
  echo "| search enabled by default (disabled=0) | ${total_enabled} | ${total} |"
  echo "| risk_object_type in {user,system} | ${total_risk_type_schema} | ${total} |"
  echo
  echo "## Nonconformant Packages"
  echo
  echo "| Package | Issues |"
  echo "|---|---|"

  any_issues=0
  while IFS= read -r line; do
    pkg="$(echo "${line}" | cut -d'|' -f1)"
    issues="$(echo "${line}" | cut -d'|' -f2-)"
    echo "| ${pkg} | ${issues} |"
    any_issues=1
  done < <(
    for f in ${FILES}; do
      pkg="$(basename "$(dirname "$(dirname "${f}")")")"
      issues=()
      rg -q '^action\.notable\s*=\s*1\b' "${f}" || issues+=("notable_disabled")
      rg -q '^action\.risk\s*=\s*1\b' "${f}" || issues+=("risk_disabled")
      rg -q '^action\.notable\.param\.rule_description\s*=' "${f}" || issues+=("missing_notable_description")
      rg -q '^action\.risk\.param\._risk_message\s*=' "${f}" || issues+=("missing_risk_message")
      rg -q '^action\.risk\.param\._risk\s*=\s*\[' "${f}" || issues+=("missing_risk_object")
      rg -q '^action\.notable\.param\.drilldown_searches\s*=\s*\[' "${f}" || issues+=("missing_drilldown")
      rg -q '^action\.notable\.param\.drilldown_dashboards\s*=\s*\[\]' "${f}" || issues+=("missing_drilldown_dashboards")
      rg -q '"earliest"\s*:|"latest"\s*:' "${f}" && issues+=("legacy_drilldown_keys")
      rg -q '^disabled\s*=\s*0\b' "${f}" || issues+=("disabled_by_default")
      bad_types="$(rg -o 'risk_object_type\"\\s*:\\s*\"[^\"]+\"' "${f}" | sed -E 's/.*\"([^\"]+)\"$/\1/' | sort -u | rg -v '^(user|system)$' || true)"
      [[ -n "${bad_types}" ]] && issues+=("invalid_risk_object_type")

      if [[ "${#issues[@]}" -gt 0 ]]; then
        printf '%s|%s\n' "${pkg}" "$(IFS=', '; echo "${issues[*]}")"
      fi
    done
  )

  if [[ "${any_issues}" -eq 0 ]]; then
    echo "| _None_ | _All searches conform_ |"
  fi
} > "${MD_OUT}"

echo "Wrote ${JSON_OUT}"
echo "Wrote ${MD_OUT}"

if [[ "${pass_all}" -ne "${total}" ]]; then
  exit 1
fi
