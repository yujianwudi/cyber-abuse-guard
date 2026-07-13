#!/usr/bin/env bash
set -euo pipefail

root="$(cd "${BASH_SOURCE[0]%/*}/.." && pwd -P)"
gate="$root/scripts/release-doc-consistency.sh"
ruleset_sha256="a9bbfb2ed76d55cca02f83390e3fe10532dc7cb3fb389c440b0b130a0b2d1642"
old_ruleset_sha256="5354e9b56c5986ac09b2b231b2750f4a519b8e3a6bfcbd71da7747dd32481cf6"
work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT

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

make_fixture() {
  local fixture="$1" relative
  mkdir -p "$fixture/docs/reports"
  for relative in "${documents[@]}"; do
    mkdir -p "$(dirname "$fixture/$relative")"
    if [[ "$relative" == CHANGELOG.md ]]; then
      printf '# Changelog\n\n## 0.1.2 - 2026-07-13\n\nReleased.\n' >"$fixture/$relative"
    else
      printf '# Final release document\n\nRelease evidence is complete.\n' >"$fixture/$relative"
    fi
  done
  for relative in \
    docs/reports/RELEASE_EVIDENCE.md \
    docs/reports/TEST_REPORT.md \
    docs/reports/CORPUS_REPORT.md; do
    printf '\nruleset_sha256: %s\n' "$ruleset_sha256" >>"$fixture/$relative"
  done
  printf '# Historical evaluation\n\nStatus: **CONSUMED / FAIL**\n' \
    >"$fixture/docs/reports/EVALUATION_V6_REPORT.md"
  printf '# Current evaluation\n\nStatus: **CONSUMED / PASS**\n' \
    >"$fixture/docs/reports/EVALUATION_V7_REPORT.md"
}

run_gate() {
  local fixture="$1" evaluation_report="${2:-}"
  local environment=(
    "RELEASE_DOC_ROOT=$fixture"
    "CURRENT_RELEASE_VERSION=0.1.2"
    "CURRENT_RULESET_SHA256=$ruleset_sha256"
  )
  if [[ -n "$evaluation_report" ]]; then
    environment+=("CURRENT_EVALUATION_REPORT=$evaluation_report")
  fi
  env "${environment[@]}" "$gate"
}

must_fail() {
  local name="$1" fixture="$2"
  if run_gate "$fixture" >"$work/$name.log" 2>&1; then
    printf 'release document consistency fixture unexpectedly passed: %s\n' "$name" >&2
    exit 1
  fi
  printf 'release document consistency fixture rejected as expected: %s\n' "$name"
}

make_fixture "$work/pass"
run_gate "$work/pass"

cp -a "$work/pass" "$work/stale-document"
printf '\n## 0.1.2 - Unreleased candidate\n' >>"$work/stale-document/README.md"
must_fail stale-document "$work/stale-document"

cp -a "$work/pass" "$work/fail-report"
sed -i 's/CONSUMED \/ PASS/CONSUMED \/ FAIL/' \
  "$work/fail-report/docs/reports/EVALUATION_V7_REPORT.md"
must_fail fail-report "$work/fail-report"

cp -a "$work/pass" "$work/higher-fail-report"
printf '# Newest evaluation\n\nStatus: **CONSUMED / FAIL**\n' \
  >"$work/higher-fail-report/docs/reports/EVALUATION_V8_REPORT.md"
must_fail higher-fail-report "$work/higher-fail-report"
run_gate "$work/higher-fail-report" docs/reports/EVALUATION_V7_REPORT.md

cp -a "$work/pass" "$work/old-hash"
sed -i "s/$ruleset_sha256/$old_ruleset_sha256/" \
  "$work/old-hash/docs/reports/TEST_REPORT.md"
must_fail old-hash "$work/old-hash"

printf 'all release document consistency fixtures passed\n'
