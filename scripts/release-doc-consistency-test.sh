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
  SECURITY.md
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
  docs/ROUND8_HOST_RUNNER.md
  docs/RULES.md
  docs/THREAT_MODEL.md
  docs/reports/CPA_INTEGRATION.md
  docs/reports/PERFORMANCE.md
  docs/reports/PHASE0_CPA_CONTRACT.md
  docs/reports/PRIVACY.md
  docs/reports/PUBLIC_JAILBREAK_REPOSITORY_REVIEW.md
  docs/reports/PROMPT_INJECTION_REVIEW.md
  docs/reports/RELEASE_EVIDENCE.md
  docs/reports/ROUND8_CALIBRATION.md
  docs/reports/ROUND8_RELEASE_READINESS.md
  docs/reports/TEST_REPORT.md
  docs/reports/CORPUS_REPORT.md
)

classifier_identity_documents=(
  README.md
  README_CN.md
  CHANGELOG.md
  SECURITY.md
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
  docs/ROUND8_HOST_RUNNER.md
  docs/RULES.md
  docs/THREAT_MODEL.md
  docs/reports/CPA_INTEGRATION.md
  docs/reports/PERFORMANCE.md
  docs/reports/PHASE0_CPA_CONTRACT.md
  docs/reports/PRIVACY.md
  docs/reports/PUBLIC_JAILBREAK_REPOSITORY_REVIEW.md
  docs/reports/PROMPT_INJECTION_REVIEW.md
  docs/reports/RELEASE_EVIDENCE.md
  docs/reports/ROUND8_CALIBRATION.md
  docs/reports/ROUND8_RELEASE_READINESS.md
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
        'local_rc_artifact_version: 0.16-rc.2' \
        'local_rc_artifact_scope: two-stage-linux-amd64-private-candidate-or-prerelease' \
        'local_rc_evidence_policy: phase1-no-host-evidence-phase2-strict-counted-mock-evidence' \
        'candidate_workflow: .github/workflows/candidate.yml' \
        'candidate_attestation: candidate-manifest.json' \
        'attested_prerelease_workflow: .github/workflows/attested-prerelease.yml' \
        'rc_workflow: .github/workflows/release-rc.yml' \
        'rc_workflow_archive: docs/archive/workflows/release-rc-v0.15-rc.2.yml' \
        'rc_artifact_version: 0.16-rc.2' \
        'rc_artifact_history: active-v0.16-rc2-prerelease-only' \
        'rc_status: two-stage-private-candidate-or-counted-mock-verified-prerelease-independent-audit-required-production-not-approved' \
        'rc_manifest_schema: 4' \
        'rc_candidate_asset_count: 17' \
        'rc_publish_asset_count: 19' \
        'rc_publish_host_evidence: round8-host-evidence.json' \
        'rc_publish_host_evidence_sidecar: round8-host-evidence.json.sha256' \
        'immutable_published_rc_identity_verification: release-object,tag=v0.16-rc.2,annotated-tag-target=exact-commit,target-commitish=exact-commit,title=exact,body=exact,prerelease=true,latest=false,draft=false,immutable=true' \
        'immutable_published_rc_asset_verification: exact-count=19,download-count=19,byte-compare-each=rebuilt-candidate,release-digest-and-attestation-check=each' \
        'immutable_published_rc_recovery: same-run-re-run-failed-or-admission-read-only-verifier' \
        'immutable_published_rc_new_dispatch_or_rerun_all: admission-already-public-skip-write-capable-build-and-publish' \
        'immutable_published_rc_recovery_access_policy: read-only-no-state-mutation' \
        'immutable_published_rc_forbidden_mutations: release-create,release-edit,release-upload,release-delete,artifact-upload,attestation-write,cache-write' \
        'immutable_published_rc_latest_release: v0.15' \
        'immutable_published_rc_mismatch_policy: fail-only-no-automatic-repair' \
        'host_audit_attestation: round6-prerelease-attestation.json' \
        'formal_gate_attestation: formal-release-attestation.json' \
        'promotion_workflow: .github/workflows/release-promote.yml' \
        'host_matrix: v7.2.95' \
        'host_matrix_commit: f71ec0eb6776854457892452cf28c47f0d658251' \
        'candidate_manifest_schema: 3' \
        'host_attestation_schema: 2' \
        'host_evidence_fields: schema_version,validation_scope,candidate,cpa,mock,safety' \
        'upstream_version_policy: no-automatic-follow' \
        'independent_audit_status: required-not-provided' \
        'production_approval_status: not-granted' \
        'stable_v0.16_status: not-released' \
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
    elif [[ "$relative" == docs/reports/ROUND8_RELEASE_READINESS.md ]]; then
      printf '%s\n' \
        '# Round 8 release readiness' \
        '' \
        '```json' \
        '{' \
        '  "validation_scope": "CPA_HOST_COUNTED_MOCK_ONLY",' \
        '  "cpa": {' \
        '    "primary": {' \
        '      "host_results": {' \
        '        "database": {' \
        '          "schema_version": 5,' \
        '          "migration_versions": [1, 2, 3, 4, 5]' \
        '        }' \
        '      }' \
        '    }' \
        '  }' \
        '}' \
        '```' \
        >"$fixture/$relative"
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

cp -a "$work/pass" "$work/stale-round8-security-identity"
sed -i 's/current_classifier_policy_version: classifier-policy-v5/current_classifier_policy_version: classifier-policy-v4/' \
  "$work/stale-round8-security-identity/SECURITY.md"
must_fail stale-round8-security-identity "$work/stale-round8-security-identity" \
  'SECURITY.md must place the exact visible classifier policy prologue on lines 2-6'

cp -a "$work/pass" "$work/stale-active-classifier-key"
printf '\ncurrent_release_classifier_policy_version: %s\ncurrent_release_classifier_policy_sha256: %s\n' \
  "$classifier_policy_version" "$old_classifier_policy_sha256" \
  >>"$work/stale-active-classifier-key/docs/RULES.md"
must_fail stale-active-classifier-key "$work/stale-active-classifier-key" \
  'current release documents must not contain stale active classifier identities'

cp -a "$work/pass" "$work/stale-json-active-classifier-key"
printf '\n{"current_release_classifier_policy_sha256":"%s"}\n' \
  "$old_classifier_policy_sha256" \
  >>"$work/stale-json-active-classifier-key/docs/RULES.md"
must_fail stale-json-active-classifier-key "$work/stale-json-active-classifier-key" \
  'current release documents must not contain stale active classifier identities'

cp -a "$work/pass" "$work/stale-backtick-active-classifier-key"
printf '\n`round8_classifier_policy_sha256`: `%s`\n' \
  "$old_classifier_policy_sha256" \
  >>"$work/stale-backtick-active-classifier-key/docs/reports/RELEASE_EVIDENCE.md"
must_fail stale-backtick-active-classifier-key "$work/stale-backtick-active-classifier-key" \
  'current release documents must not contain stale active classifier identities'

cp -a "$work/pass" "$work/stale-inline-classifier-identity"
printf '\n| Classifier policy | `%s` / `%s` |\n' \
  "$classifier_policy_version" "$old_classifier_policy_sha256" \
  >>"$work/stale-inline-classifier-identity/docs/reports/TEST_REPORT.md"
must_fail stale-inline-classifier-identity "$work/stale-inline-classifier-identity" \
  'current release documents must not contain stale active classifier identities'

cp -a "$work/pass" "$work/stale-adjacent-classifier-identity"
printf '\nActive classifier: `%s`\nActive classifier policy digest: `%s`\n' \
  "$classifier_policy_version" "$old_classifier_policy_sha256" \
  >>"$work/stale-adjacent-classifier-identity/docs/DESIGN.md"
must_fail stale-adjacent-classifier-identity "$work/stale-adjacent-classifier-identity" \
  'current release documents must not contain stale active classifier identities'

cp -a "$work/pass" "$work/stale-three-line-classifier-identity"
printf '\nActive classifier: `%s`\nSHA-256\n`%s`\n' \
  "$classifier_policy_version" "$old_classifier_policy_sha256" \
  >>"$work/stale-three-line-classifier-identity/docs/DESIGN.md"
must_fail stale-three-line-classifier-identity "$work/stale-three-line-classifier-identity" \
  'current release documents must not contain stale active classifier identities'

cp -a "$work/pass" "$work/ruleset-before-current-classifier"
printf '\n| Ruleset SHA-256 | `%s` |\n| Classifier policy | `%s` / `%s` |\n' \
  "$ruleset_sha256" "$classifier_policy_version" "$classifier_policy_sha256" \
  >>"$work/ruleset-before-current-classifier/docs/reports/TEST_REPORT.md"
run_gate "$work/ruleset-before-current-classifier"
printf 'release document consistency allowed a distinct ruleset hash immediately before the correct classifier identity\n'

cp -a "$work/pass" "$work/quoted-current-active-classifier"
printf '\n{"current_release_classifier_policy_sha256":"%s"}\n' \
  "$classifier_policy_sha256" \
  >>"$work/quoted-current-active-classifier/docs/RULES.md"
run_gate "$work/quoted-current-active-classifier"
printf 'release document consistency allowed a quoted JSON active classifier identity when it is current\n'

cp -a "$work/pass" "$work/round8-database-same-lane-duplicate"
awk '
  $0 == "          \"schema_version\": 5," {
    schema_count++
    if (schema_count == 1) {
      print
    }
    next
  }
  $0 == "          \"migration_versions\": [1, 2, 3, 4, 5]" {
    migration_count++
    if (migration_count == 1) {
      print $0 ","
      print "          \"schema_version\": 5,"
      print
    }
    next
  }
  { print }
' "$work/round8-database-same-lane-duplicate/docs/reports/ROUND8_RELEASE_READINESS.md" \
  >"$work/round8-database-same-lane-duplicate/docs/reports/ROUND8_RELEASE_READINESS.md.tmp"
mv -f -- \
  "$work/round8-database-same-lane-duplicate/docs/reports/ROUND8_RELEASE_READINESS.md.tmp" \
  "$work/round8-database-same-lane-duplicate/docs/reports/ROUND8_RELEASE_READINESS.md"
must_fail round8-database-same-lane-duplicate \
  "$work/round8-database-same-lane-duplicate" \
  'docs/reports/ROUND8_RELEASE_READINESS.md must show the exact database schema and migration history in each named CPA lane'

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
  rc_manifest_schema
  rc_candidate_asset_count
  rc_publish_asset_count
  rc_publish_host_evidence
  rc_publish_host_evidence_sidecar
  immutable_published_rc_identity_verification
  immutable_published_rc_asset_verification
  immutable_published_rc_recovery
  immutable_published_rc_new_dispatch_or_rerun_all
  immutable_published_rc_recovery_access_policy
  immutable_published_rc_forbidden_mutations
  immutable_published_rc_latest_release
  immutable_published_rc_mismatch_policy
  host_matrix_commit
  candidate_manifest_schema
  host_attestation_schema
  host_evidence_fields
  upstream_version_policy
  independent_audit_status
  production_approval_status
  stable_v0.16_status
)
policy_values=(
  0.16-rc.2
  two-stage-linux-amd64-private-candidate-or-prerelease
  phase1-no-host-evidence-phase2-strict-counted-mock-evidence
  .github/workflows/release-rc.yml
  0.16-rc.2
  active-v0.16-rc2-prerelease-only
  two-stage-private-candidate-or-counted-mock-verified-prerelease-independent-audit-required-production-not-approved
  4
  17
  19
  round8-host-evidence.json
  round8-host-evidence.json.sha256
  release-object,tag=v0.16-rc.2,annotated-tag-target=exact-commit,target-commitish=exact-commit,title=exact,body=exact,prerelease=true,latest=false,draft=false,immutable=true
  exact-count=19,download-count=19,byte-compare-each=rebuilt-candidate,release-digest-and-attestation-check=each
  same-run-re-run-failed-or-admission-read-only-verifier
  admission-already-public-skip-write-capable-build-and-publish
  read-only-no-state-mutation
  release-create,release-edit,release-upload,release-delete,artifact-upload,attestation-write,cache-write
  v0.15
  fail-only-no-automatic-repair
  f71ec0eb6776854457892452cf28c47f0d658251
  3
  2
  schema_version,validation_scope,candidate,cpa,mock,safety
  no-automatic-follow
  required-not-provided
  not-granted
  not-released
)
policy_bad_values=(
  0.16-rc.1
  github-release
  github-release-evidence
  docs/archive/workflows/release-rc-v0.15-rc.2.yml
  0.15-rc.4
  historical-v0.15-rc4-only
  production-approved
  3
  16
  18
  unreviewed-host-evidence.json
  round8-host-evidence.sha256
  release-object,tag=v0.16-rc.1,annotated-tag-target=branch-head,target-commitish=branch-head,title=unchecked,body=unchecked,prerelease=false,latest=true,draft=true
  exact-count=18,download-count=0,byte-compare-each=skipped
  new-dispatch
  allow-build
  GET,POST
  mutation-allowed
  v0.16-rc.2
  automatic-repair
  0000000000000000000000000000000000000000
  2
  1
  cpa_version,cpa_commit
  automatic-follow
  pass
  granted
  released
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
