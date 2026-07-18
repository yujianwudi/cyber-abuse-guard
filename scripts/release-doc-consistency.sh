#!/usr/bin/env bash
set -euo pipefail

root="$(cd "${BASH_SOURCE[0]%/*}/.." && pwd -P)"
# shellcheck source=release-common.sh
source "$root/scripts/release-common.sh"
release_require_commands awk grep sed sha256sum sort

doc_root="${RELEASE_DOC_ROOT:-$root}"

fail() {
  printf 'release document consistency error: %s\n' "$*" >&2
  exit 1
}

current_ruleset_sha256="${CURRENT_RULESET_SHA256:-$(release_ruleset_hash)}"
[[ "$current_ruleset_sha256" =~ ^[0-9a-f]{64}$ ]] || \
  fail "current ruleset SHA-256 is not a lowercase 64-character digest"

current_release_version="${CURRENT_RELEASE_VERSION:-}"
if [[ -z "$current_release_version" ]]; then
  current_release_version="$(sed -nE \
    's/^[[:space:]]*Version[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' \
    "$root/internal/buildinfo/buildinfo.go" | sed -n '1p')"
fi
[[ "$current_release_version" =~ ^[0-9]+\.[0-9]+$ ]] || \
  fail "cannot determine the exact two-component release version"

documents=(
  README.md
  README_CN.md
  CHANGELOG.md
  docs/AUDIT_HANDOFF.md
  docs/LIMITATIONS.md
  docs/INSTALL_DOCKER.md
  docs/RELEASE_POLICY.md
  docs/reports/RELEASE_EVIDENCE.md
  docs/reports/TEST_REPORT.md
)

for relative in "${documents[@]}"; do
  document="$doc_root/$relative"
  [[ -f "$document" ]] || fail "required current release document is missing: $relative"
done

historical_corpus="$doc_root/docs/reports/CORPUS_REPORT.md"
[[ -f "$historical_corpus" ]] || \
  fail "required historical corpus report is missing: docs/reports/CORPUS_REPORT.md"
grep -Eq '^# Historical .*v0\.1\.2 candidate[[:space:]]*$' "$historical_corpus" || \
  fail "docs/reports/CORPUS_REPORT.md must be explicitly labeled as historical v0.1.2 evidence"

policy="$doc_root/docs/RELEASE_POLICY.md"
required_policy_lines=(
  "release_version: $current_release_version"
  "formal_tag: v$current_release_version"
  "version_alias_policy: reject-v0.15.0"
  "platform: linux-amd64"
  "candidate_workflow: .github/workflows/candidate.yml"
  "candidate_attestation: candidate-manifest.json"
  "attested_prerelease_workflow: .github/workflows/attested-prerelease.yml"
  "rc_workflow_archive: docs/archive/workflows/release-rc-v0.15-rc.2.yml"
  "host_audit_attestation: round6-prerelease-attestation.json"
  "formal_gate_attestation: formal-release-attestation.json"
  "promotion_workflow: .github/workflows/release-promote.yml"
  "host_matrix: v7.2.88"
  "host_matrix_commit: 93d74a890a44802f656d7f39a573916b2611896e"
  "host_attestation_schema: 2"
  "host_evidence_fields: cpa_version,cpa_commit,cpa_host_sha256"
  "upstream_version_policy: no-automatic-follow"
  "external_admission: required"
  "minimum_independent_evaluation: evaluation-v11"
  "independent_evaluation_required_status: CONSUMED/PASS"
  "historical_evaluation_v10_policy: immutable-consumed-fail-not-formal-input"
  "formal_bundle_content_policy: exclude-evaluation-holdout-consumed-private-blind-retired"
)
for line in "${required_policy_lines[@]}"; do
  key="${line%%:*}"
  [[ "$(grep -Ec "^${key}:" "$policy")" == 1 ]] || \
    fail "docs/RELEASE_POLICY.md must contain exactly one policy key: $key"
  [[ "$(grep -Fxc "$line" "$policy")" == 1 ]] || \
    fail "docs/RELEASE_POLICY.md must contain exactly one policy line: $line"
done

for relative in README.md README_CN.md CHANGELOG.md docs/ROUND6_RELEASE_GATE.md; do
  document="$doc_root/$relative"
  [[ -f "$document" ]] || fail "required release-facing document is missing: $relative"
  grep -Fq 'round6-prerelease-attestation.json' "$document" || \
    fail "$relative must point readers to the Host/audit attestation"
  grep -Fq 'formal-release-attestation.json' "$document" || \
    fail "$relative must point readers to the formal gate attestation"
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
)
for relative in "${current_reports[@]}"; do
  report="$doc_root/$relative"
  mapfile -t declared_hashes < <(sed -nE \
    's/^[[:space:]]*ruleset_sha256:[[:space:]]*`?([0-9a-f]{64})`?[[:space:]]*$/\1/p' \
    "$report")
  ((${#declared_hashes[@]} >= 1)) || \
    fail "$relative must declare a concrete ruleset_sha256"
  latest_declared_hash="${declared_hashes[${#declared_hashes[@]}-1]}"
  [[ "$latest_declared_hash" == "$current_ruleset_sha256" ]] || \
    fail "$relative latest ruleset_sha256 $latest_declared_hash does not match current $current_ruleset_sha256"
done

printf 'release document consistency passed: version %s, ruleset %s\n' \
  "$current_release_version" "$current_ruleset_sha256"
