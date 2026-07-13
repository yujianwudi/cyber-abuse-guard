#!/usr/bin/env bash
set -euo pipefail

root="$(cd "${BASH_SOURCE[0]%/*}/.." && pwd -P)"
# shellcheck source=release-common.sh
source "$root/scripts/release-common.sh"
release_require_commands install zip sha256sum mktemp find touch sort mkdir rm git sed awk cmp
release_init
release_assert_tag

dist="${DIST_DIR:-$root/dist}"
so="cyber-abuse-guard-v${RELEASE_ARTIFACT_VERSION}.so"
zip_name="cyber-abuse-guard_${RELEASE_ARTIFACT_VERSION}_linux_amd64.zip"
source_date_epoch="$RELEASE_SOURCE_DATE_EPOCH"
stage=""
export TZ=UTC

cleanup() {
  if [[ -n "$stage" && -d "$stage" ]]; then
    rm -rf -- "$stage"
  fi
}
trap cleanup EXIT

for required_file in \
  "$dist/$so" \
  "$dist/$so.sha256" \
  "$dist/build-metadata.json" \
  "$dist/ruleset-manifest.json" \
  "$dist/ruleset.sha256" \
  "$dist/sbom.cdx.json" \
  "$root/README.md" \
  "$root/README_CN.md" \
  "$root/LICENSE" \
  "$root/CHANGELOG.md" \
  "$root/THIRD_PARTY_NOTICES.md" \
  "$root/config.example.yaml" \
  "$root/docs/DESIGN.md" \
  "$root/docs/AUDIT_HANDOFF.md" \
  "$root/docs/THREAT_MODEL.md" \
  "$root/docs/INSTALL_DOCKER.md" \
  "$root/docs/LIMITATIONS.md" \
  "$root/docs/NEXT_VERSION.md" \
  "$root/docs/RULES.md" \
  "$root/docs/reports/TEST_REPORT.md" \
  "$root/docs/reports/PERFORMANCE.md" \
  "$root/docs/reports/CORPUS_REPORT.md" \
  "$root/docs/reports/CPA_INTEGRATION.md" \
  "$root/docs/reports/HOLDOUT_REPORT.md" \
  "$root/docs/reports/HOLDOUT_V2_REPORT.md" \
  "$root/docs/reports/HOLDOUT_V3_REPORT.md" \
  "$root/docs/reports/EVALUATION_V4_REPORT.md" \
  "$root/docs/reports/EVALUATION_V5_REPORT.md" \
  "$root/docs/reports/EVALUATION_V6_REPORT.md" \
  "$root/docs/reports/EVALUATION_V7_REPORT.md" \
  "$root/docs/reports/EVALUATION_V8_REPORT.md" \
  "$root/docs/reports/EVALUATION_V9_REPORT.md" \
  "$root/docs/reports/EVALUATION_V10_REPORT.md" \
  "$root/docs/reports/PRIVACY.md" \
  "$root/docs/reports/RELEASE_EVIDENCE.md" \
  "$root/scripts/check-production-health.sh" \
  "$root/scripts/generate-hmac-key.sh"; do
  if [[ ! -f "$required_file" || -L "$required_file" ]]; then
    release_die "required release input must be a regular non-symlink file: $required_file"
  fi
done
(cd "$dist" && sha256sum -c "$so.sha256" && sha256sum -c ruleset.sha256)

stage="$(mktemp -d)"
mkdir -p "$stage/plugins/linux/amd64" "$stage/docs/reports" "$stage/scripts"
find "$stage" -type d -exec chmod 0755 {} +

install -m 0755 "$dist/$so" "$stage/plugins/linux/amd64/$so"
install -m 0644 "$dist/$so.sha256" "$stage/plugins/linux/amd64/$so.sha256"
install -m 0644 "$root/README.md" "$root/README_CN.md" "$root/LICENSE" \
  "$root/CHANGELOG.md" "$root/THIRD_PARTY_NOTICES.md" \
  "$root/config.example.yaml" "$stage/"
install -m 0644 "$root/docs/AUDIT_HANDOFF.md" "$root/docs/DESIGN.md" "$root/docs/THREAT_MODEL.md" \
  "$root/docs/INSTALL_DOCKER.md" "$root/docs/LIMITATIONS.md" \
  "$root/docs/NEXT_VERSION.md" "$root/docs/RULES.md" "$stage/docs/"
install -m 0644 "$root/docs/reports/TEST_REPORT.md" \
  "$root/docs/reports/PERFORMANCE.md" "$root/docs/reports/CORPUS_REPORT.md" \
  "$root/docs/reports/CPA_INTEGRATION.md" "$root/docs/reports/HOLDOUT_REPORT.md" \
  "$root/docs/reports/HOLDOUT_V2_REPORT.md" "$root/docs/reports/HOLDOUT_V3_REPORT.md" \
  "$root/docs/reports/EVALUATION_V4_REPORT.md" "$root/docs/reports/EVALUATION_V5_REPORT.md" \
  "$root/docs/reports/EVALUATION_V6_REPORT.md" "$root/docs/reports/EVALUATION_V7_REPORT.md" \
  "$root/docs/reports/EVALUATION_V8_REPORT.md" \
  "$root/docs/reports/EVALUATION_V9_REPORT.md" \
  "$root/docs/reports/EVALUATION_V10_REPORT.md" \
  "$root/docs/reports/PRIVACY.md" "$root/docs/reports/RELEASE_EVIDENCE.md" \
  "$stage/docs/reports/"
install -m 0755 "$root/scripts/check-production-health.sh" \
  "$root/scripts/generate-hmac-key.sh" "$stage/scripts/"
install -m 0644 "$dist/build-metadata.json" "$dist/ruleset-manifest.json" \
  "$dist/ruleset.sha256" "$dist/sbom.cdx.json" "$stage/"

find "$stage" -exec touch -h -d "@$source_date_epoch" {} +
rm -f "$dist/$zip_name"
(cd "$stage" && find . -mindepth 1 -printf '%P\n' | LC_ALL=C sort | zip -X -q "$dist/$zip_name" -@)

(cd "$dist" && sha256sum \
  "$so" "$so.sha256" "$zip_name" build-metadata.json ruleset-manifest.json \
  ruleset.sha256 sbom.cdx.json \
  >checksums.txt)
DIST_DIR="$dist" "$root/scripts/verify-release.sh"
release_assert_source_unchanged
