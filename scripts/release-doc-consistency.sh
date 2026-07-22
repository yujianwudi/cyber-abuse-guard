#!/usr/bin/env bash
set -euo pipefail

root="$(cd "${BASH_SOURCE[0]%/*}/.." && pwd -P)"
# shellcheck source=release-common.sh
source "$root/scripts/release-common.sh"
release_require_commands awk grep sed sha256sum sort tr wc python3

doc_root="${RELEASE_DOC_ROOT:-$root}"
fixture_mode="${RELEASE_DOC_FIXTURE_MODE:-0}"

fail() {
  printf 'release document consistency error: %s\n' "$*" >&2
  exit 1
}

[[ -d "$doc_root" ]] || fail "release document root is not a directory: $doc_root"
doc_root="$(cd "$doc_root" && pwd -P)"
[[ "$fixture_mode" == 0 || "$fixture_mode" == 1 ]] || \
  fail "RELEASE_DOC_FIXTURE_MODE must be 0 or 1"
if [[ "$doc_root" == "$root" ]]; then
  if [[ -n "${RELEASE_DOC_ROOT+x}" || -n "${RELEASE_DOC_FIXTURE_MODE+x}" ||
    -n "${CURRENT_RELEASE_VERSION+x}" || -n "${CURRENT_RULESET_SHA256+x}" ||
    -n "${CURRENT_CLASSIFIER_POLICY_VERSION+x}" || -n "${CURRENT_CLASSIFIER_POLICY_SHA256+x}" ]]; then
    fail "source-tree release document verification forbids document-root and CURRENT_* overrides"
  fi
elif [[ "$fixture_mode" != 1 ]]; then
  fail "external release document roots are allowed only with RELEASE_DOC_FIXTURE_MODE=1"
fi

current_ruleset_sha256="${CURRENT_RULESET_SHA256:-$(release_ruleset_hash)}"
[[ "$current_ruleset_sha256" =~ ^[0-9a-f]{64}$ ]] || \
  fail "current ruleset SHA-256 is not a lowercase 64-character digest"

current_classifier_policy_version="${CURRENT_CLASSIFIER_POLICY_VERSION:-}"
if [[ -z "$current_classifier_policy_version" ]]; then
  current_classifier_policy_version="$(sed -nE \
    's/^const ClassifierPolicyVersion = "([^"]+)"/\1/p' \
    "$root/internal/classifier/policy_identity.go" | sed -n '1p')"
fi
[[ "$current_classifier_policy_version" =~ ^classifier-policy-v[0-9]+$ ]] || \
  fail "cannot determine the current classifier policy version"

current_classifier_policy_sha256="${CURRENT_CLASSIFIER_POLICY_SHA256:-}"
if [[ -z "$current_classifier_policy_sha256" ]]; then
  current_classifier_policy_sha256="$(sed -nE \
    's/^const ClassifierPolicySHA256 = "([0-9a-f]{64})"/\1/p' \
    "$root/internal/classifier/policy_identity.go" | sed -n '1p')"
fi
[[ "$current_classifier_policy_sha256" =~ ^[0-9a-f]{64}$ ]] || \
  fail "cannot determine the current classifier policy SHA-256"

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
)

for relative in "${documents[@]}"; do
  document="$doc_root/$relative"
  [[ -f "$document" && ! -L "$document" ]] || fail "required current release document must be a regular non-symlink file: $relative"
done

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
canonical_classifier_version_key="current_classifier_policy_version"
canonical_classifier_sha256_key="current_classifier_policy_sha256"
normalized_policy_keys() {
  LC_ALL=C tr -d "\"'\`" <"$1"
}
count_policy_key() {
  local document="$1" key="$2"
  normalized_policy_keys "$document" |
    { grep -Eo "(^|[^[:alnum:]_])${key}[[:space:]]*:" || true; } |
    wc -l | tr -d '[:space:]'
}
for relative in "${classifier_identity_documents[@]}"; do
  document="$doc_root/$relative"
  canonical_version_line="${canonical_classifier_version_key}: ${current_classifier_policy_version}"
  canonical_sha256_line="${canonical_classifier_sha256_key}: ${current_classifier_policy_sha256}"

  first_line="$(sed -n '1p' "$document")"
  first_title="${first_line#\# }"
  [[ "$first_line" == '# '* && -n "$first_title" && "$first_title" != \#* &&
    "$first_line" != *'<'* && "$first_line" != *'>'* ]] || \
    fail "$relative must start with one visible top-level Markdown heading"

  # Historical sections may retain explicitly historical identities, but every
  # current release document starts with one visible, fixed canonical prologue.
  # A stale/hidden declaration plus an appended current value fails closed.
  [[ "$(sed -n '2p' "$document")" == "" &&
    "$(sed -n '3p' "$document")" == '```text' &&
    "$(sed -n '4p' "$document")" == "$canonical_version_line" &&
    "$(sed -n '5p' "$document")" == "$canonical_sha256_line" &&
    "$(sed -n '6p' "$document")" == '```' ]] || \
    fail "$relative must place the exact visible classifier policy prologue on lines 2-6"

  [[ "$(count_policy_key "$document" "$canonical_classifier_version_key")" == 1 ]] || \
    fail "$relative must contain exactly one canonical classifier policy version key: $canonical_classifier_version_key"
  [[ "$(count_policy_key "$document" "$canonical_classifier_sha256_key")" == 1 ]] || \
    fail "$relative must contain exactly one canonical classifier policy SHA-256 key: $canonical_classifier_sha256_key"
  if normalized_policy_keys "$document" |
    grep -Eq '(^|[^[:alnum:]_])classifier_policy(_version|_sha256)?[[:space:]]*:'; then
    fail "$relative must not contain unlabeled legacy classifier policy keys; use current_ or historical_ prefixes"
  fi
done

if ! python3 -B - \
  "$doc_root" \
  "$current_classifier_policy_version" \
  "$current_classifier_policy_sha256" \
  "${classifier_identity_documents[@]}" <<'PY'
import re
import sys
from pathlib import Path


root = Path(sys.argv[1])
current_version = sys.argv[2]
current_sha256 = sys.argv[3]
documents = sys.argv[4:]
active_key = re.compile(
    r"(?<![A-Za-z0-9_])"
    r"(?P<key>(?:round8|current_release)_classifier_policy_(?:version|sha256))"
    r"\s*:\s*(?P<value>[A-Za-z0-9._-]+)"
)
sha256 = re.compile(r"(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])")

for relative in documents:
    text = (root / relative).read_text(encoding="utf-8")
    normalized = text.translate(str.maketrans("", "", "\"'`"))
    for match in active_key.finditer(normalized):
        expected = current_sha256 if match.group("key").endswith("_sha256") else current_version
        if match.group("value") != expected:
            print(
                f"{relative} contains stale active classifier identity "
                f"{match.group('key')}: {match.group('value')}",
                file=sys.stderr,
            )
            raise SystemExit(1)
    lines = text.splitlines()
    for line_number, line in enumerate(lines, start=1):
        if current_version not in line:
            continue
        hashes = sha256.findall(line)
        if not hashes:
            hashes = sha256.findall("\n".join(lines[line_number : line_number + 2]))
            hashes = hashes[:1]
        if hashes and any(value != current_sha256 for value in hashes):
            print(
                f"{relative}:{line_number} places {current_version} next to a stale SHA-256",
                file=sys.stderr,
            )
            raise SystemExit(1)
PY
then
  fail "current release documents must not contain stale active classifier identities"
fi

historical_corpus="$doc_root/docs/reports/CORPUS_REPORT.md"
[[ -f "$historical_corpus" ]] || \
  fail "required historical corpus report is missing: docs/reports/CORPUS_REPORT.md"
grep -Eq '^# Historical .*v0\.1\.2 candidate[[:space:]]*$' "$historical_corpus" || \
  fail "docs/reports/CORPUS_REPORT.md must be explicitly labeled as historical v0.1.2 evidence"

policy="$doc_root/docs/RELEASE_POLICY.md"
required_policy_lines=(
  "release_version: $current_release_version"
  "formal_tag: v$current_release_version"
  "version_alias_policy: reject-v$current_release_version.0"
  "platform: linux-amd64"
  "local_rc_artifact_version: $current_release_version-rc.2"
  "local_rc_artifact_scope: two-stage-linux-amd64-private-candidate-or-prerelease"
  "local_rc_evidence_policy: phase1-no-host-evidence-phase2-strict-counted-mock-evidence"
  "candidate_workflow: .github/workflows/candidate.yml"
  "candidate_attestation: candidate-manifest.json"
  "attested_prerelease_workflow: .github/workflows/attested-prerelease.yml"
  "rc_workflow: .github/workflows/release-rc.yml"
  "rc_workflow_archive: docs/archive/workflows/release-rc-v0.15-rc.2.yml"
  "rc_artifact_version: 0.16-rc.2"
  "rc_artifact_history: active-v0.16-rc2-prerelease-only"
  "rc_status: two-stage-private-candidate-or-counted-mock-verified-prerelease-independent-audit-required-production-not-approved"
  "rc_manifest_schema: 4"
  "rc_candidate_asset_count: 17"
  "rc_publish_asset_count: 19"
  "rc_publish_host_evidence: round8-host-evidence.json"
  "rc_publish_host_evidence_sidecar: round8-host-evidence.json.sha256"
  "immutable_published_rc_identity_verification: release-object,tag=v$current_release_version-rc.2,annotated-tag-target=exact-commit,target-commitish=exact-commit,title=exact,body=exact,prerelease=true,latest=false,draft=false,immutable=true"
  "immutable_published_rc_asset_verification: exact-count=19,download-count=19,byte-compare-each=rebuilt-candidate,release-digest-and-attestation-check=each"
  "immutable_published_rc_recovery: same-run-re-run-failed-or-admission-read-only-verifier"
  "immutable_published_rc_new_dispatch_or_rerun_all: admission-already-public-skip-write-capable-build-and-publish"
  "immutable_published_rc_recovery_access_policy: read-only-no-state-mutation"
  "immutable_published_rc_forbidden_mutations: release-create,release-edit,release-upload,release-delete,artifact-upload,attestation-write,cache-write"
  "immutable_published_rc_latest_release: v0.15"
  "immutable_published_rc_mismatch_policy: fail-only-no-automatic-repair"
  "host_audit_attestation: round6-prerelease-attestation.json"
  "formal_gate_attestation: formal-release-attestation.json"
  "promotion_workflow: .github/workflows/release-promote.yml"
  "host_matrix: v7.2.95"
  "host_matrix_commit: f71ec0eb6776854457892452cf28c47f0d658251"
  "candidate_manifest_schema: 3"
  "host_attestation_schema: 2"
  "host_evidence_fields: schema_version,validation_scope,candidate,cpa,mock,safety"
  "upstream_version_policy: no-automatic-follow"
  "independent_audit_status: required-not-provided"
  "production_approval_status: not-granted"
  "stable_v0.16_status: not-released"
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

round8_readiness="$doc_root/docs/reports/ROUND8_RELEASE_READINESS.md"
if ! python3 -B - "$round8_readiness" <<'PY'
import json
import re
import sys
from pathlib import Path


def reject_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


text = Path(sys.argv[1]).read_text(encoding="utf-8")
blocks = re.findall(r"(?ms)^```json[ \t]*\n(.*?)^```[ \t]*$", text)
evidence_blocks = []
for raw in blocks:
    try:
        value = json.loads(raw, object_pairs_hook=reject_duplicates)
    except (json.JSONDecodeError, ValueError):
        continue
    if isinstance(value, dict) and value.get("validation_scope") == "CPA_HOST_COUNTED_MOCK_ONLY":
        evidence_blocks.append(value)

if len(evidence_blocks) != 1:
    raise SystemExit(1)

cpa = evidence_blocks[0].get("cpa")
if not isinstance(cpa, dict):
    raise SystemExit(1)
for lane in ("primary",):
    entry = cpa.get(lane)
    if not isinstance(entry, dict):
        raise SystemExit(1)
    host_results = entry.get("host_results")
    if not isinstance(host_results, dict):
        raise SystemExit(1)
    database = host_results.get("database")
    if not isinstance(database, dict):
        raise SystemExit(1)
    schema_version = database.get("schema_version")
    migration_versions = database.get("migration_versions")
    if type(schema_version) is not int or schema_version != 5:
        raise SystemExit(1)
    if (
        not isinstance(migration_versions, list)
        or len(migration_versions) != 5
        or any(type(value) is not int for value in migration_versions)
        or migration_versions != [1, 2, 3, 4, 5]
    ):
        raise SystemExit(1)
PY
then
  fail "docs/reports/ROUND8_RELEASE_READINESS.md must show the exact database schema and migration history in each named CPA lane"
fi
if grep -Fq '"database": {"quick_check": "ok", "wal_checkpoint_passed": true}' \
  "$round8_readiness"; then
  fail "docs/reports/ROUND8_RELEASE_READINESS.md contains the obsolete incomplete database evidence example"
fi

printf 'release document consistency passed: version %s, ruleset %s, classifier %s/%s\n' \
  "$current_release_version" "$current_ruleset_sha256" \
  "$current_classifier_policy_version" "$current_classifier_policy_sha256"
