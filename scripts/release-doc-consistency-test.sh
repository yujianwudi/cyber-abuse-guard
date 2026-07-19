#!/usr/bin/env bash
set -euo pipefail

root="$(cd "${BASH_SOURCE[0]%/*}/.." && pwd -P)"
gate="$root/scripts/release-doc-consistency.sh"
ruleset_sha256="a9bbfb2ed76d55cca02f83390e3fe10532dc7cb3fb389c440b0b130a0b2d1642"
old_ruleset_sha256="5354e9b56c5986ac09b2b231b2750f4a519b8e3a6bfcbd71da7747dd32481cf6"
classifier_policy_version="classifier-policy-v5"
classifier_policy_sha256="42d48af7a854b19d29c956a6f99b9027189ce4ae7b19a1d92a83955639d0916e"
old_classifier_policy_sha256="fd7627f1ac9c4e08d1e073ecfb4b8afd395a10e713d5e98fddbfe6a380edb59d"
work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT

documents=(
  README.md
  README_CN.md
  CHANGELOG.md
  docs/AUDIT_HANDOFF.md
  docs/DESIGN.md
  docs/LIMITATIONS.md
  docs/INSTALL_DOCKER.md
  docs/RELEASE_POLICY.md
  docs/ROUND6_DEVELOPMENT_HANDOFF.md
  docs/ROUND6_LIMITATIONS.md
  docs/ROUND6_RELEASE_GATE.md
  docs/ROUND6_STREAMING_SCANNER_DESIGN.md
  docs/RULES.md
  docs/THREAT_MODEL.md
  docs/reports/PROMPT_INJECTION_REVIEW.md
  docs/reports/RELEASE_EVIDENCE.md
  docs/reports/TEST_REPORT.md
  docs/reports/CORPUS_REPORT.md
)

make_fixture() {
  local fixture="$1" relative
  mkdir -p "$fixture/docs/reports"
  for relative in "${documents[@]}"; do
    mkdir -p "$(dirname "$fixture/$relative")"
    if [[ "$relative" == docs/RELEASE_POLICY.md ]]; then
      printf '%s\n' \
        '# Release policy' \
        'release_version: 0.15' \
        'formal_tag: v0.15' \
        'version_alias_policy: reject-v0.15.0' \
        'platform: linux-amd64' \
        'candidate_workflow: .github/workflows/candidate.yml' \
        'candidate_attestation: candidate-manifest.json' \
        'attested_prerelease_workflow: .github/workflows/attested-prerelease.yml' \
        'rc_workflow_archive: docs/archive/workflows/release-rc-v0.15-rc.2.yml' \
        'host_audit_attestation: round6-prerelease-attestation.json' \
        'formal_gate_attestation: formal-release-attestation.json' \
        'promotion_workflow: .github/workflows/release-promote.yml' \
        'host_matrix: v7.2.88' \
        'host_matrix_commit: 93d74a890a44802f656d7f39a573916b2611896e' \
        'host_attestation_schema: 2' \
        'host_evidence_fields: cpa_version,cpa_commit,cpa_host_sha256' \
        'upstream_version_policy: no-automatic-follow' \
        'external_admission: required' \
        'minimum_independent_evaluation: evaluation-v11' \
        'independent_evaluation_required_status: CONSUMED/PASS' \
        'historical_evaluation_v10_policy: immutable-consumed-fail-not-formal-input' \
        'formal_bundle_content_policy: exclude-evaluation-holdout-consumed-private-blind-retired' \
        >"$fixture/$relative"
    elif [[ "$relative" == CHANGELOG.md ]]; then
      printf '# Changelog\n\n## 0.15 - 2026-07-17\n\nround6-prerelease-attestation.json\nformal-release-attestation.json\n' >"$fixture/$relative"
    elif [[ "$relative" == docs/reports/CORPUS_REPORT.md ]]; then
      printf '# Historical project regression corpus report - v0.1.2 candidate\n' >"$fixture/$relative"
    else
      printf '# Final release document\n\nRelease evidence is complete.\n' >"$fixture/$relative"
    fi
  done
  for relative in README.md README_CN.md docs/ROUND6_RELEASE_GATE.md; do
    printf '\nround6-prerelease-attestation.json\nformal-release-attestation.json\n' \
      >>"$fixture/$relative"
  done
  for relative in \
    README.md \
    README_CN.md \
    CHANGELOG.md \
    docs/AUDIT_HANDOFF.md \
    docs/DESIGN.md \
    docs/INSTALL_DOCKER.md \
    docs/LIMITATIONS.md \
    docs/ROUND6_DEVELOPMENT_HANDOFF.md \
    docs/ROUND6_LIMITATIONS.md \
    docs/ROUND6_RELEASE_GATE.md \
    docs/ROUND6_STREAMING_SCANNER_DESIGN.md \
    docs/RULES.md \
    docs/THREAT_MODEL.md \
    docs/reports/PROMPT_INJECTION_REVIEW.md \
    docs/reports/RELEASE_EVIDENCE.md \
    docs/reports/TEST_REPORT.md; do
    printf '\nclassifier_policy: %s\nclassifier_policy_sha256: %s\n' \
      "$classifier_policy_version" "$classifier_policy_sha256" >>"$fixture/$relative"
  done
  for relative in \
    docs/reports/RELEASE_EVIDENCE.md \
    docs/reports/TEST_REPORT.md; do
    printf '\nruleset_sha256: %s\n' "$ruleset_sha256" >>"$fixture/$relative"
  done
}

run_gate() {
  local fixture="$1"
  local environment=(
    "RELEASE_DOC_ROOT=$fixture"
    "CURRENT_RELEASE_VERSION=0.15"
    "CURRENT_RULESET_SHA256=$ruleset_sha256"
    "CURRENT_CLASSIFIER_POLICY_VERSION=$classifier_policy_version"
    "CURRENT_CLASSIFIER_POLICY_SHA256=$classifier_policy_sha256"
  )
  env "${environment[@]}" "$gate"
}

must_fail() {
  local name="$1" fixture="$2" expected_diagnostic="$3"
  if run_gate "$fixture" >"$work/$name.log" 2>&1; then
    printf 'release document consistency fixture unexpectedly passed: %s\n' "$name" >&2
    exit 1
  fi
  if ! grep -Fq -- "$expected_diagnostic" "$work/$name.log"; then
    printf 'release document consistency fixture emitted the wrong diagnostic: %s\n' "$name" >&2
    exit 1
  fi
  printf 'release document consistency fixture rejected as expected: %s\n' "$name"
}

make_fixture "$work/pass"
run_gate "$work/pass"

cp -a "$work/pass" "$work/historical-hash"
sed -i "/ruleset_sha256:/i ruleset_sha256: $old_ruleset_sha256" \
  "$work/historical-hash/docs/reports/RELEASE_EVIDENCE.md"
run_gate "$work/historical-hash"

cp -a "$work/pass" "$work/stale-document"
sed -i '/formal-release-attestation.json/d' "$work/stale-document/README.md"
must_fail stale-document "$work/stale-document" \
  'README.md must point readers to the formal gate attestation'

cp -a "$work/pass" "$work/alias-policy"
sed -i 's/version_alias_policy: reject-v0.15.0/version_alias_policy: allow-v0.15.0/' \
  "$work/alias-policy/docs/RELEASE_POLICY.md"
must_fail alias-policy "$work/alias-policy" \
  'docs/RELEASE_POLICY.md must contain exactly one policy line: version_alias_policy: reject-v0.15.0'

policy_keys=(
  host_matrix_commit
  host_attestation_schema
  host_evidence_fields
  upstream_version_policy
)
policy_values=(
  93d74a890a44802f656d7f39a573916b2611896e
  2
  cpa_version,cpa_commit,cpa_host_sha256
  no-automatic-follow
)
policy_bad_values=(
  0000000000000000000000000000000000000000
  1
  cpa_version,cpa_commit
  automatic-follow
)
for index in "${!policy_keys[@]}"; do
  key="${policy_keys[$index]}"
  value="${policy_values[$index]}"
  bad_value="${policy_bad_values[$index]}"

  cp -a "$work/pass" "$work/${key}-missing"
  sed -i "\|^${key}: ${value}$|d" \
    "$work/${key}-missing/docs/RELEASE_POLICY.md"
  must_fail "${key}-missing" "$work/${key}-missing" \
    "docs/RELEASE_POLICY.md must contain exactly one policy key: $key"

  cp -a "$work/pass" "$work/${key}-changed"
  sed -i "s|^${key}: ${value}$|${key}: ${bad_value}|" \
    "$work/${key}-changed/docs/RELEASE_POLICY.md"
  must_fail "${key}-changed" "$work/${key}-changed" \
    "docs/RELEASE_POLICY.md must contain exactly one policy line: ${key}: ${value}"
done

cp -a "$work/pass" "$work/duplicate-policy-key"
printf '%s\n' 'version_alias_policy: allow-v0.15.0' \
  >>"$work/duplicate-policy-key/docs/RELEASE_POLICY.md"
must_fail duplicate-policy-key "$work/duplicate-policy-key" \
  'docs/RELEASE_POLICY.md must contain exactly one policy key: version_alias_policy'

cp -a "$work/pass" "$work/unlabeled-historical-corpus"
sed -i 's/^# Historical /# /' \
  "$work/unlabeled-historical-corpus/docs/reports/CORPUS_REPORT.md"
must_fail unlabeled-historical-corpus "$work/unlabeled-historical-corpus" \
  'docs/reports/CORPUS_REPORT.md must be explicitly labeled as historical v0.1.2 evidence'

cp -a "$work/pass" "$work/old-hash"
sed -i "s/$ruleset_sha256/$old_ruleset_sha256/" \
  "$work/old-hash/docs/reports/TEST_REPORT.md"
must_fail old-hash "$work/old-hash" \
  'docs/reports/TEST_REPORT.md latest ruleset_sha256'

cp -a "$work/pass" "$work/old-classifier-hash"
sed -i "s/$classifier_policy_sha256/$old_classifier_policy_sha256/" \
  "$work/old-classifier-hash/docs/reports/TEST_REPORT.md"
must_fail old-classifier-hash "$work/old-classifier-hash" \
  "docs/reports/TEST_REPORT.md must declare current classifier policy SHA-256 $classifier_policy_sha256"

printf 'all release document consistency fixtures passed\n'
