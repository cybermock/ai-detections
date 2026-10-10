#!/usr/bin/env bash
# Audit every package saved search against the release conventions.
#
# Policy by package role (from the package name / package.yml):
#   detection   hdsi_ai_*            action.notable = 0, action.risk = 1
#   aggregator  hdsi_rba_ai_*        action.notable = 1, action.risk = 0
#   health      hdsi_ai_health_*     exempt from the notable/risk policy
#   hunting     hdsi_ai_* with deployment_type adhoc and action.risk = 0: exempt
# Every search: `<pkg>_filter` is referenced but never piped; when action.risk = 1 the
# last pipe is `<pkg>_risk_score` and risk message / risk objects are present.
#
# Usage: audit_savedsearch_conformance.sh [OUT_DIR]   (default: saved_searches/reports)
# Exit 0 when every search conforms, 1 otherwise.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
P2R_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
PACKAGES_DIR="${P2R_DIR}/packages"
OUT_DIR="${1:-${P2R_DIR}/reports}"

# Regex engine: a real ripgrep binary when present, otherwise POSIX grep -E.
# Patterns below stick to ERE syntax ([[:space:]], no \s or \b) so both engines agree.
if RG_BIN="$(type -P rg)" && [[ -n "${RG_BIN}" ]]; then
  ENGINE="rg"
elif command -v grep >/dev/null 2>&1; then
  ENGINE="grep -E"
  echo "NOTE: ripgrep (rg) not found on PATH; falling back to grep -E" >&2
else
  echo "ERROR: neither rg nor grep is available; cannot audit" >&2
  exit 2
fi

# re_q PATTERN FILE -> exit 0 if PATTERN matches a line of FILE
re_q() {
  if [[ "${ENGINE}" == "rg" ]]; then "${RG_BIN}" -q -e "$1" -- "$2"; else grep -Eq -e "$1" -- "$2"; fi
}
# re_o PATTERN FILE -> print each match (never fails)
re_o() {
  if [[ "${ENGINE}" == "rg" ]]; then "${RG_BIN}" -o -e "$1" -- "$2" || true; else grep -Eo -e "$1" -- "$2" || true; fi
}
# re_s PATTERN STRING -> exit 0 if PATTERN matches a line of STRING
re_s() {
  if [[ "${ENGINE}" == "rg" ]]; then "${RG_BIN}" -q -e "$1" <<<"$2"; else grep -Eq -e "$1" <<<"$2"; fi
}

# conf_value FILE KEY -> value of KEY (first stanza), backslash continuations joined with newlines
conf_value() {
  awk -v key="$2" '
    function trim(s) { sub(/^[ \t]+/, "", s); sub(/[ \t]+$/, "", s); return s }
    cont {
      line = $0; more = (line ~ /\\$/); if (more) sub(/\\$/, "", line)
      val = val "\n" line
      if (!more) { print val; exit }
      next
    }
    index($0, "=") > 0 {
      k = trim(substr($0, 1, index($0, "=") - 1))
      if (k != key) next
      val = trim(substr($0, index($0, "=") + 1)); more = (val ~ /\\$/); if (more) sub(/\\$/, "", val)
      if (!more) { print val; exit }
      cont = 1
    }
    END { if (cont) print val }
  ' "$1"
}

mkdir -p "${OUT_DIR}"
JSON_OUT="${OUT_DIR}/savedsearch_conformance.json"
MD_OUT="${OUT_DIR}/savedsearch_conformance.md"

FILES="$(find "${PACKAGES_DIR}" -mindepth 3 -maxdepth 3 -type f -name 'savedsearches.conf' | sort)"
if [[ -z "${FILES}" ]]; then
  echo "No savedsearches.conf files found under ${PACKAGES_DIR}" >&2
  exit 1
fi

# Parallel arrays (bash 3.2 compatible): check id, report label, issue name.
CHECKS=(notable_policy risk_policy notable_description risk_message risk_object drilldown drilldown_dashboards
        drilldown_key_schema enabled risk_object_type_schema filter_not_piped risk_score_last)
LABELS=(
  "action.notable matches role (detection 0, aggregator 1, health/hunting exempt)"
  "action.risk matches role (detection 1, aggregator 0, health/hunting exempt)"
  "notable rule_description present"
  "risk message present (when action.risk = 1)"
  "risk objects present (when action.risk = 1)"
  "drilldown searches present"
  "drilldown dashboards line present"
  "drilldown keys use earliest_offset/latest_offset"
  "search enabled by default (disabled = 0)"
  "risk_object_type in {user,system}"
  "\`<pkg>_filter\` referenced inline, never piped"
  "\`<pkg>_risk_score\` is the last pipe (when action.risk = 1)"
)
ISSUE_NAMES=(notable_policy_violation risk_policy_violation missing_notable_description missing_risk_message
             missing_risk_object missing_drilldown missing_drilldown_dashboards legacy_drilldown_keys
             disabled_by_default invalid_risk_object_type filter_missing_or_piped risk_score_not_last_pipe)
NCHECKS=${#CHECKS[@]}
TOTALS=()
for ((i = 0; i < NCHECKS; i++)); do TOTALS[i]=0; done

# check index lookup (bash 3.2 has no associative arrays)
idx() {
  local i
  for ((i = 0; i < NCHECKS; i++)); do [[ "${CHECKS[i]}" == "$1" ]] && { echo "$i"; return; }; done
  echo "unknown check $1" >&2; exit 2
}
pass() { OK[$(idx "$1")]=1; }

total=0
pass_all=0
ISSUE_ROWS=()

{
  echo "["
  first=1
  for f in ${FILES}; do
    pkg_dir="$(dirname "$(dirname "${f}")")"
    pkg="$(basename "${pkg_dir}")"
    OK=()
    for ((i = 0; i < NCHECKS; i++)); do OK[i]=0; done

    notable="$(conf_value "${f}" action.notable)"
    risk="$(conf_value "${f}" action.risk)"
    search="$(conf_value "${f}" search)"

    if [[ "${pkg}" == hdsi_ai_health_* ]]; then
      role="health"
    elif [[ "${pkg}" == hdsi_rba_ai_* ]]; then
      role="aggregator"
    elif [[ "${risk}" != "1" ]] && re_q '^deployment_type:[[:space:]]*["'"'"']?adhoc' "${pkg_dir}/package.yml"; then
      role="hunting"
    else
      role="detection"
    fi

    case "${role}" in
      detection)  [[ "${notable}" == "0" ]] && pass notable_policy; [[ "${risk}" == "1" ]] && pass risk_policy ;;
      aggregator) [[ "${notable}" == "1" ]] && pass notable_policy; [[ "${risk}" == "0" ]] && pass risk_policy ;;
      *)          pass notable_policy; pass risk_policy ;;
    esac

    re_q '^action\.notable\.param\.rule_description[[:space:]]*=' "${f}" && pass notable_description
    if [[ "${risk}" == "1" ]]; then
      re_q '^action\.risk\.param\._risk_message[[:space:]]*=[[:space:]]*[^[:space:]]' "${f}" && pass risk_message
      re_q '^action\.risk\.param\._risk[[:space:]]*=[[:space:]]*\[' "${f}" && pass risk_object
    else
      pass risk_message
      pass risk_object
    fi
    re_q '^action\.notable\.param\.drilldown_searches[[:space:]]*=[[:space:]]*\[' "${f}" && pass drilldown
    re_q '^action\.notable\.param\.drilldown_dashboards[[:space:]]*=[[:space:]]*\[\]' "${f}" && pass drilldown_dashboards
    re_q '"(earliest|latest)"[[:space:]]*:' "${f}" || pass drilldown_key_schema
    re_q '^disabled[[:space:]]*=[[:space:]]*(0|false|False)[[:space:]]*$' "${f}" && pass enabled

    invalid_types="$(re_o 'risk_object_type"[[:space:]]*:[[:space:]]*"[^"]+"' "${f}" \
      | sed -E 's/.*"([^"]+)"$/\1/' | sort -u | grep -Ev '^(user|system)$' || true)"
    if [[ -z "${invalid_types}" ]]; then
      pass risk_object_type_schema
      invalid_json="[]"
    else
      invalid_json="$(printf '%s\n' "${invalid_types}" \
        | awk 'BEGIN{printf "["} {if(NR>1)printf ","; gsub(/"/,"\\\"",$0); printf "\""$0"\""} END{printf "]"}')"
    fi

    filter_macro='`'"${pkg}"'_filter'
    if re_s "${filter_macro}" "${search}" && ! re_s '\|[[:space:]]*'"${filter_macro}" "${search}"; then
      pass filter_not_piped
    fi

    if [[ "${risk}" == "1" ]]; then
      last_line="$(printf '%s\n' "${search}" | awk 'NF {l=$0} END {print l}')"
      re_s '\|[[:space:]]*`'"${pkg}"'_risk_score`[[:space:]]*$' "${last_line}" && pass risk_score_last
    else
      pass risk_score_last
    fi

    ((total += 1))
    all_pass=1
    issues=()
    checks_json=""
    for ((i = 0; i < NCHECKS; i++)); do
      TOTALS[i]=$((TOTALS[i] + OK[i]))
      checks_json="${checks_json}${checks_json:+,}\"${CHECKS[i]}\":${OK[i]}"
      if [[ "${OK[i]}" -ne 1 ]]; then
        all_pass=0
        issues+=("${ISSUE_NAMES[i]}")
      fi
    done
    if [[ "${all_pass}" -eq 1 ]]; then
      ((pass_all += 1))
    else
      ISSUE_ROWS+=("${pkg}|${role}|$(IFS=','; echo "${issues[*]}" | sed 's/,/, /g')")
    fi

    [[ "${first}" -eq 0 ]] && echo ","
    first=0
    printf '  {"package":"%s","file":"%s","role":"%s","action_notable":"%s","action_risk":"%s","checks":{%s},"invalid_risk_object_types":%s,"all_pass":%s}' \
      "${pkg}" "${f}" "${role}" "${notable}" "${risk}" "${checks_json}" "${invalid_json}" "${all_pass}"
  done
  echo
  echo "]"
} > "${JSON_OUT}"

{
  echo "# P2R Saved Search Conformance Report"
  echo
  echo "- Generated: $(date -u '+%Y-%m-%d %H:%M:%SZ')"
  echo "- Scope: \`${PACKAGES_DIR}\`"
  echo "- Regex engine: ${ENGINE}"
  echo "- Total searches audited: ${total}"
  echo "- Fully conformant searches: ${pass_all}"
  echo
  echo "## Summary"
  echo
  echo "| Check | Passed | Total |"
  echo "|---|---:|---:|"
  for ((i = 0; i < NCHECKS; i++)); do
    echo "| ${LABELS[i]} | ${TOTALS[i]} | ${total} |"
  done
  echo
  echo "## Nonconformant Packages"
  echo
  echo "| Package | Role | Issues |"
  echo "|---|---|---|"
  if [[ "${#ISSUE_ROWS[@]}" -eq 0 ]]; then
    echo "| _None_ | | _All searches conform_ |"
  else
    for row in "${ISSUE_ROWS[@]}"; do
      echo "| ${row//|/ | } |"
    done
  fi
} > "${MD_OUT}"

echo "Wrote ${JSON_OUT}"
echo "Wrote ${MD_OUT}"

if [[ "${pass_all}" -ne "${total}" ]]; then
  exit 1
fi
