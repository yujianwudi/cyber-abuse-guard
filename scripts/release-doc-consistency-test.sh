#!/usr/bin/env bash
set -euo pipefail

root="$(cd "${BASH_SOURCE[0]%/*}/.." && pwd -P)"
gate="$root/scripts/release-doc-consistency.sh"
ruleset_sha256="a9bbfb2ed76d55cca02f83390e3fe10532dc7cb3fb389c440b0b130a0b2d1642"
old_ruleset_sha256="5354e9b56c5986ac09b2b231b2750f4a519b8e3a6bfcbd71da7747dd32481cf6"
classifier_policy_version="classifier-policy-v5"
classifier_policy_sha256="0e114d98862282d2492fb62e4300297b4746eeaf8165339603d02c48d11bd60b"
old_classifier_policy_version="classifier-policy-v4"
old_classifier_policy_sha256="2763f10e2565dce2ffcf700f5d6566e9fbac68f3fedd08fcce20bceff450b4c8"
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
  docs/README.md
  docs/RELEASE_POLICY.md
  docs/ROUND6_CONFIG_MIGRATION.md
  docs/ROUND6_DEVELOPMENT_HANDOFF.md
  docs/ROUND6_LIMITATIONS.md
  docs/ROUND6_RELEASE_GATE.md
  docs/ROUND6_STREAMING_SCANNER_DESIGN.md
  docs/RULES.md
  docs/THREAT_MODEL.md
  docs/reports/CPA_INTEGRATION.md
  docs/reports/PERFORMANCE.md
  docs/reports/PHASE0_CPA_CONTRACT.md
  docs/reports/PRIVACY.md
  docs/reports/PUBLIC_JAILBREAK_REPOSITORY_REVIEW.md
  docs/reports/PROMPT_INJECTION_REVIEW.md
  docs/reports/RELEASE_EVIDENCE.md
  docs/reports/TEST_REPORT.md
  docs/reports/CORPUS_REPORT.md
)

classifier_identity_documents=(
  README.md
  README_CN.md
  CHANGELOG.md
  docs/AUDIT_HANDOFF.md
  docs/DESIGN.md
  docs/INSTALL_DOCKER.md
  docs/LIMITATIONS.md
  docs/README.md
  docs/RELEASE_POLICY.md
  docs/ROUND6_CONFIG_MIGRATION.md
  docs/ROUND6_DEVELOPMENT_HANDOFF.md
  docs/ROUND6_LIMITATIONS.md
  docs/ROUND6_RELEASE_GATE.md
  docs/ROUND6_STREAMING_SCANNER_DESIGN.md
  docs/RULES.md
  docs/THREAT_MODEL.md
  docs/reports/CPA_INTEGRATION.md
  docs/reports/PERFORMANCE.md
  docs/reports/PHASE0_CPA_CONTRACT.md
  docs/reports/PRIVACY.md
  docs/reports/PUBLIC_JAILBREAK_REPOSITORY_REVIEW.md
  docs/reports/PROMPT_INJECTION_REVIEW.md
  docs/reports/RELEASE_EVIDENCE.md
  docs/reports/TEST_REPORT.md
)

make_fixture() {
  local fixture="$1" relative
  mkdir -p "$fixture/docs/reports"
  for relative in "${documents[@]}"; do
    mkdir -p "$(dirname "$fixture/$relative")"
    if [[ "$relative" == docs/RELEASE_POLICY.md ]]; then
      printf '%s\n' \
        '# Release policy' \
        '' \
        'release_version: 0.16' \
        'formal_tag: v0.16' \
        'version_alias_policy: reject-v0.16.0' \
        'platform: linux-amd64' \
        'local_rc_artifact_version: 0.16-rc.1' \
        'local_rc_artifact_scope: local-linux-amd64-core-package' \
        'local_rc_evidence_policy: not-github-release-actions-or-host-evidence' \
        'candidate_workflow: .github/workflows/candidate.yml' \
        'candidate_attestation: candidate-manifest.json' \
        'attested_prerelease_workflow: .github/workflows/attested-prerelease.yml' \
        'rc_workflow: .github/workflows/release-rc.yml' \
        'rc_workflow_archive: docs/archive/workflows/release-rc-v0.15-rc.2.yml' \
        'rc_artifact_version: 0.15-rc.4' \
        'rc_artifact_history: historical-v0.15-rc4-only' \
        'rc_status: internal-gates-required-sandbox-only-not-formal-not-round6-candidate' \
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
      printf '# Changelog\n\n## 0.16 - 2026-07-21\n\nround6-prerelease-attestation.json\nformal-release-attestation.json\n' >"$fixture/$relative"
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
  for relative in "${classifier_identity_documents[@]}"; do
    staged="$fixture/.classifier-prologue"
    {
      sed -n '1p' "$fixture/$relative"
      printf '\n```text\ncurrent_classifier_policy_version: %s\ncurrent_classifier_policy_sha256: %s\n```\n' \
        "$classifier_policy_version" "$classifier_policy_sha256"
      sed -n '3,$p' "$fixture/$relative"
    } >"$staged"
    mv -f -- "$staged" "$fixture/$relative"
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
    "RELEASE_DOC_FIXTURE_MODE=1"
    "CURRENT_RELEASE_VERSION=0.16"
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

if CURRENT_CLASSIFIER_POLICY_VERSION="$old_classifier_policy_version" "$gate" \
  >"$work/source-classifier-override.log" 2>&1; then
  echo 'release document consistency source-tree classifier override unexpectedly passed' >&2
  exit 1
fi
grep -Fq \
  'source-tree release document verification forbids document-root and CURRENT_* overrides' \
  "$work/source-classifier-override.log" || {
  echo 'release document consistency source-tree classifier override emitted the wrong diagnostic' >&2
  exit 1
}
printf 'release document consistency source-tree classifier override rejected as expected\n'

if RELEASE_DOC_ROOT="$work/pass" \
  CURRENT_RELEASE_VERSION=0.16 \
  CURRENT_RULESET_SHA256="$ruleset_sha256" \
  CURRENT_CLASSIFIER_POLICY_VERSION="$classifier_policy_version" \
  CURRENT_CLASSIFIER_POLICY_SHA256="$classifier_policy_sha256" \
  "$gate" >"$work/external-root-without-fixture-mode.log" 2>&1; then
  echo 'release document consistency external root without fixture mode unexpectedly passed' >&2
  exit 1
fi
grep -Fq \
  'external release document roots are allowed only with RELEASE_DOC_FIXTURE_MODE=1' \
  "$work/external-root-without-fixture-mode.log" || {
  echo 'release document consistency external root without fixture mode emitted the wrong diagnostic' >&2
  exit 1
}
printf 'release document consistency external root without fixture mode rejected as expected\n'

cp -a "$work/pass" "$work/historical-hash"
sed -i "/ruleset_sha256:/i ruleset_sha256: $old_ruleset_sha256" \
  "$work/historical-hash/docs/reports/RELEASE_EVIDENCE.md"
run_gate "$work/historical-hash"

cp -a "$work/pass" "$work/stale-document"
sed -i '/formal-release-attestation.json/d' "$work/stale-document/README.md"
must_fail stale-document "$work/stale-document" \
  'README.md must point readers to the formal gate attestation'

cp -a "$work/pass" "$work/alias-policy"
sed -i 's/version_alias_policy: reject-v0.16.0/version_alias_policy: allow-v0.16.0/' \
  "$work/alias-policy/docs/RELEASE_POLICY.md"
must_fail alias-policy "$work/alias-policy" \
  'docs/RELEASE_POLICY.md must contain exactly one policy line: version_alias_policy: reject-v0.16.0'

policy_keys=(
  local_rc_artifact_version
  local_rc_artifact_scope
  local_rc_evidence_policy
  rc_workflow
  rc_artifact_version
  rc_artifact_history
  rc_status
  host_matrix_commit
  host_attestation_schema
  host_evidence_fields
  upstream_version_policy
)
policy_values=(
  0.16-rc.1
  local-linux-amd64-core-package
  not-github-release-actions-or-host-evidence
  .github/workflows/release-rc.yml
  0.15-rc.4
  historical-v0.15-rc4-only
  internal-gates-required-sandbox-only-not-formal-not-round6-candidate
  93d74a890a44802f656d7f39a573916b2611896e
  2
  cpa_version,cpa_commit,cpa_host_sha256
  no-automatic-follow
)
policy_bad_values=(
  0.16-rc.2
  github-release
  github-release-evidence
  docs/archive/workflows/release-rc-v0.15-rc.2.yml
  0.15-rc.2
  active-v0.15-rc4
  sandbox-only-not-formal-not-round6-candidate
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
printf '%s\n' 'version_alias_policy: allow-v0.16.0' \
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
  'docs/reports/TEST_REPORT.md must place the exact visible classifier policy prologue on lines 2-6'

cp -a "$work/pass" "$work/old-classifier-version"
sed -i "s/$classifier_policy_version/$old_classifier_policy_version/" \
  "$work/old-classifier-version/docs/reports/TEST_REPORT.md"
must_fail old-classifier-version "$work/old-classifier-version" \
  'docs/reports/TEST_REPORT.md must place the exact visible classifier policy prologue on lines 2-6'

cp -a "$work/pass" "$work/conflicting-classifier-version"
printf '%s\n' "current_classifier_policy_version: $old_classifier_policy_version" \
  >>"$work/conflicting-classifier-version/docs/reports/TEST_REPORT.md"
must_fail conflicting-classifier-version "$work/conflicting-classifier-version" \
  'docs/reports/TEST_REPORT.md must contain exactly one canonical classifier policy version key: current_classifier_policy_version'

cp -a "$work/pass" "$work/conflicting-classifier-hash"
printf '%s\n' "current_classifier_policy_sha256: $old_classifier_policy_sha256" \
  >>"$work/conflicting-classifier-hash/docs/reports/TEST_REPORT.md"
must_fail conflicting-classifier-hash "$work/conflicting-classifier-hash" \
  'docs/reports/TEST_REPORT.md must contain exactly one canonical classifier policy SHA-256 key: current_classifier_policy_sha256'

cp -a "$work/pass" "$work/quoted-conflicting-classifier-version"
printf '%s\n' "\"current_classifier_policy_version\": \"$old_classifier_policy_version\"" \
  >>"$work/quoted-conflicting-classifier-version/docs/reports/TEST_REPORT.md"
must_fail quoted-conflicting-classifier-version "$work/quoted-conflicting-classifier-version" \
  'docs/reports/TEST_REPORT.md must contain exactly one canonical classifier policy version key: current_classifier_policy_version'

cp -a "$work/pass" "$work/same-line-conflicting-classifier-version"
printf '%s\n' \
  "current_classifier_policy_version: $old_classifier_policy_version current_classifier_policy_version: $classifier_policy_version" \
  >>"$work/same-line-conflicting-classifier-version/docs/reports/TEST_REPORT.md"
must_fail same-line-conflicting-classifier-version "$work/same-line-conflicting-classifier-version" \
  'docs/reports/TEST_REPORT.md must contain exactly one canonical classifier policy version key: current_classifier_policy_version'

cp -a "$work/pass" "$work/duplicate-current-classifier-identity"
printf '%s\n%s\n' \
  "current_classifier_policy_version: $classifier_policy_version" \
  "current_classifier_policy_sha256: $classifier_policy_sha256" \
  >>"$work/duplicate-current-classifier-identity/docs/reports/TEST_REPORT.md"
must_fail duplicate-current-classifier-identity "$work/duplicate-current-classifier-identity" \
  'docs/reports/TEST_REPORT.md must contain exactly one canonical classifier policy version key: current_classifier_policy_version'

cp -a "$work/pass" "$work/legacy-plus-current-classifier-identity"
printf '%s\n%s\n' \
  "classifier_policy: $old_classifier_policy_version" \
  "classifier_policy_sha256: $old_classifier_policy_sha256" \
  >>"$work/legacy-plus-current-classifier-identity/docs/reports/TEST_REPORT.md"
must_fail legacy-plus-current-classifier-identity "$work/legacy-plus-current-classifier-identity" \
  'docs/reports/TEST_REPORT.md must not contain unlabeled legacy classifier policy keys; use current_ or historical_ prefixes'

cp -a "$work/pass" "$work/spaced-legacy-classifier-identity"
printf '%s\n' "classifier_policy : $old_classifier_policy_version" \
  >>"$work/spaced-legacy-classifier-identity/docs/reports/TEST_REPORT.md"
must_fail spaced-legacy-classifier-identity "$work/spaced-legacy-classifier-identity" \
  'docs/reports/TEST_REPORT.md must not contain unlabeled legacy classifier policy keys; use current_ or historical_ prefixes'

quoted_legacy_index=0
for quoted_key in \
  '"classifier_policy"' \
  "'classifier_policy'" \
  '`classifier_policy`'; do
  fixture_name="quoted-legacy-$quoted_legacy_index"
  quoted_legacy_index=$((quoted_legacy_index + 1))
  cp -a "$work/pass" "$work/$fixture_name"
  printf '%s: %s\n' "$quoted_key" "$old_classifier_policy_version" \
    >>"$work/$fixture_name/docs/reports/TEST_REPORT.md"
  must_fail "$fixture_name" "$work/$fixture_name" \
    'docs/reports/TEST_REPORT.md must not contain unlabeled legacy classifier policy keys; use current_ or historical_ prefixes'
done

cp -a "$work/pass" "$work/moved-classifier-prologue"
sed -i '2,6d' "$work/moved-classifier-prologue/docs/reports/TEST_REPORT.md"
printf '\n```text\ncurrent_classifier_policy_version: %s\ncurrent_classifier_policy_sha256: %s\n```\n' \
  "$classifier_policy_version" "$classifier_policy_sha256" \
  >>"$work/moved-classifier-prologue/docs/reports/TEST_REPORT.md"
must_fail moved-classifier-prologue "$work/moved-classifier-prologue" \
  'docs/reports/TEST_REPORT.md must place the exact visible classifier policy prologue on lines 2-6'

cp -a "$work/pass" "$work/hidden-classifier-prologue"
sed -i '3s/^```text$/<!--/; 6s/^```$/-->/' \
  "$work/hidden-classifier-prologue/docs/reports/TEST_REPORT.md"
must_fail hidden-classifier-prologue "$work/hidden-classifier-prologue" \
  'docs/reports/TEST_REPORT.md must place the exact visible classifier policy prologue on lines 2-6'

cp -a "$work/pass" "$work/html-wrapped-classifier-prologue"
sed -i '1c<!--' "$work/html-wrapped-classifier-prologue/docs/reports/TEST_REPORT.md"
sed -i '7i-->' "$work/html-wrapped-classifier-prologue/docs/reports/TEST_REPORT.md"
must_fail html-wrapped-classifier-prologue "$work/html-wrapped-classifier-prologue" \
  'docs/reports/TEST_REPORT.md must start with one visible top-level Markdown heading'

cp -a "$work/pass" "$work/frontmatter-wrapped-classifier-prologue"
sed -i '1c---' "$work/frontmatter-wrapped-classifier-prologue/docs/reports/TEST_REPORT.md"
must_fail frontmatter-wrapped-classifier-prologue "$work/frontmatter-wrapped-classifier-prologue" \
  'docs/reports/TEST_REPORT.md must start with one visible top-level Markdown heading'

cp -a "$work/pass" "$work/reordered-classifier-prologue"
awk 'NR == 4 { first = $0; next } NR == 5 { print; print first; next } { print }' \
  "$work/reordered-classifier-prologue/docs/reports/TEST_REPORT.md" \
  >"$work/reordered-classifier-prologue/docs/reports/TEST_REPORT.md.tmp"
mv -f -- \
  "$work/reordered-classifier-prologue/docs/reports/TEST_REPORT.md.tmp" \
  "$work/reordered-classifier-prologue/docs/reports/TEST_REPORT.md"
must_fail reordered-classifier-prologue "$work/reordered-classifier-prologue" \
  'docs/reports/TEST_REPORT.md must place the exact visible classifier policy prologue on lines 2-6'

cp -a "$work/pass" "$work/labeled-historical-classifier-identity"
printf '%s\n%s\n' \
  "historical_classifier_policy_version: $old_classifier_policy_version" \
  "historical_classifier_policy_sha256: $old_classifier_policy_sha256" \
  >>"$work/labeled-historical-classifier-identity/docs/reports/TEST_REPORT.md"
run_gate "$work/labeled-historical-classifier-identity"

printf 'all release document consistency fixtures passed\n'
