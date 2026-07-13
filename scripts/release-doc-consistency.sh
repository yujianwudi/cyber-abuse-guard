#!/usr/bin/env bash
set -euo pipefail

root="$(cd "${BASH_SOURCE[0]%/*}/.." && pwd -P)"
# shellcheck source=release-common.sh
source "$root/scripts/release-common.sh"
release_require_commands awk grep sed sha256sum sort

doc_root="${RELEASE_DOC_ROOT:-$root}"
old_ruleset_sha256="5354e9b56c5986ac09b2b231b2750f4a519b8e3a6bfcbd71da7747dd32481cf6"

fail() {
  printf 'release document consistency error: %s\n' "$*" >&2
  exit 1
}

resolve_evaluation_report() {
  local report highest_report="" highest_version=-1 name version

  if [[ -n "${CURRENT_EVALUATION_REPORT:-}" ]]; then
    report="$CURRENT_EVALUATION_REPORT"
    if [[ "$report" != /* ]]; then
      report="$doc_root/$report"
    fi
    [[ -f "$report" ]] || fail "current evaluation report not found: $report"
    printf '%s\n' "$report"
    return 0
  fi

  shopt -s nullglob
  local reports=("$doc_root"/docs/reports/EVALUATION_V*_REPORT.md)
  shopt -u nullglob
  for report in "${reports[@]}"; do
    [[ -f "$report" ]] || continue
    name="${report##*/}"
    if [[ "$name" =~ ^EVALUATION_V([0-9]+)_REPORT\.md$ ]]; then
      version="${BASH_REMATCH[1]}"
      if ((10#$version > highest_version)); then
        highest_version=$((10#$version))
        highest_report="$report"
      fi
    fi
  done
  [[ -n "$highest_report" ]] || \
    fail "no numeric EVALUATION_VN_REPORT.md found under $doc_root/docs/reports"
  printf '%s\n' "$highest_report"
}

current_report="$(resolve_evaluation_report)"
mapfile -t evaluation_statuses < <(grep -E '^[[:space:]]*Status:' "$current_report" || true)
if ((${#evaluation_statuses[@]} != 1)) || \
  [[ ! "${evaluation_statuses[0]}" =~ ^[[:space:]]*Status:[[:space:]]*\*\*CONSUMED[[:space:]]*/[[:space:]]*PASS\*\*[[:space:]]*$ ]]; then
  fail "${current_report##*/} must explicitly declare Status: **CONSUMED / PASS**"
fi

current_ruleset_sha256="${CURRENT_RULESET_SHA256:-$(release_ruleset_hash)}"
[[ "$current_ruleset_sha256" =~ ^[0-9a-f]{64}$ ]] || \
  fail "current ruleset SHA-256 is not a lowercase 64-character digest"

current_release_version="${CURRENT_RELEASE_VERSION:-}"
if [[ -z "$current_release_version" ]]; then
  current_release_version="$(sed -nE \
    's/^[[:space:]]*Version[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' \
    "$root/internal/buildinfo/buildinfo.go" | sed -n '1p')"
fi
[[ "$current_release_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || \
  fail "cannot determine the current semantic release version"

documents=(
  README.md
  README_CN.md
  CHANGELOG.md
  docs/AUDIT_HANDOFF.md
  docs/LIMITATIONS.md
  docs/INSTALL_DOCKER.md
  docs/reports/RELEASE_EVIDENCE.md
  docs/reports/TEST_REPORT.md
  docs/reports/CORPUS_REPORT.md
)

for relative in "${documents[@]}"; do
  document="$doc_root/$relative"
  [[ -f "$document" ]] || fail "required current release document is missing: $relative"

  if grep -nFq "$old_ruleset_sha256" "$document"; then
    fail "$relative contains obsolete canonical ruleset SHA-256 $old_ruleset_sha256"
  fi
  if grep -niEq 'unreleased[[:space:]-]+candidate|candidate' "$document" || \
    LC_ALL=C grep -nFq $'\xe5\x80\x99\xe9\x80\x89' "$document"; then
    fail "$relative still describes the current release as a candidate"
  fi
  if grep -nEq '(^|[^[:alnum:]_])PENDING([^[:alnum:]_]|$)' "$document"; then
    fail "$relative contains an unresolved PENDING release marker"
  fi
  if grep -niE \
    '(release|gate|tag|artifact|commit|evidence|hash|test|result|decision).{0,80}pending|pending.{0,80}(release|gate|tag|artifact|commit|evidence|hash|test|result|decision)' \
    "$document" >/dev/null; then
    fail "$relative contains a pending release result"
  fi
  if grep -niE 'v3.*pending|pending.*v3' "$document" >/dev/null; then
    fail "$relative contains the obsolete v3 pending release status"
  fi
  if grep -niEq \
    'not[[:space:]-]+(yet[[:space:]-]+)?release-eligible|not[[:space:]-]+yet[[:space:]-]+production-ready|do not install a formal' \
    "$document"; then
    fail "$relative contains an obsolete release-blocking status"
  fi
done

changelog="$doc_root/CHANGELOG.md"
em_dash=$'\xe2\x80\x94'
if ! grep -Eq \
  "^##[[:space:]]+v?${current_release_version//./\\.}[[:space:]]+(-|$em_dash)[[:space:]]+[0-9]{4}-[0-9]{2}-[0-9]{2}[[:space:]]*$" \
  "$changelog"; then
  fail "CHANGELOG.md must date the $current_release_version heading as YYYY-MM-DD"
fi

current_reports=(
  docs/reports/RELEASE_EVIDENCE.md
  docs/reports/TEST_REPORT.md
  docs/reports/CORPUS_REPORT.md
)
for relative in "${current_reports[@]}"; do
  report="$doc_root/$relative"
  mapfile -t declared_hashes < <(sed -nE \
    's/^[[:space:]]*ruleset_sha256:[[:space:]]*`?([0-9a-f]{64})`?[[:space:]]*$/\1/p' \
    "$report")
  ((${#declared_hashes[@]} == 1)) || \
    fail "$relative must declare exactly one concrete ruleset_sha256"
  [[ "${declared_hashes[0]}" == "$current_ruleset_sha256" ]] || \
    fail "$relative ruleset_sha256 ${declared_hashes[0]} does not match current $current_ruleset_sha256"
done

printf 'release document consistency passed: %s, ruleset %s\n' \
  "${current_report##*/}" "$current_ruleset_sha256"
