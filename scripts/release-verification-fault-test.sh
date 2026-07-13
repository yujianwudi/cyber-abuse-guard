#!/usr/bin/env bash
set -euo pipefail

root="$(cd "${BASH_SOURCE[0]%/*}/.." && pwd -P)"
# shellcheck source=release-common.sh
source "$root/scripts/release-common.sh"
release_require_commands cp mkdir mktemp rm sha256sum zip unzip find chmod env cat git sed awk sort
release_init

dist="${DIST_DIR:-$root/dist}"
verify="$root/scripts/verify-release.sh"
real_cyclonedx="$(command -v "${CYCLONEDX_GOMOD:-cyclonedx-gomod}")"
so="cyber-abuse-guard-v${RELEASE_ARTIFACT_VERSION}.so"
zip_name="cyber-abuse-guard_${RELEASE_ARTIFACT_VERSION}_linux_amd64.zip"
work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT

if ! DIST_DIR="$dist" "$verify" >"$work/baseline.log" 2>&1; then
  echo "baseline release verification must pass before fault injection" >&2
  cat "$work/baseline.log" >&2
  exit 1
fi

run_must_fail() {
  local name="$1"
  shift
  if "$@" >"$work/$name.log" 2>&1; then
    printf 'fault injection unexpectedly passed: %s\n' "$name" >&2
    cat "$work/$name.log" >&2
    exit 1
  fi
  printf 'fault injection rejected as expected: %s\n' "$name"
}

copy_case() {
  local name="$1"
  mkdir -p "$work/$name"
  cp -a "$dist/." "$work/$name/"
}

# A PATH with no verification commands must fail before any positive result.
mkdir -p "$work/empty-path"
run_must_fail missing-command env PATH="$work/empty-path" /bin/bash "$verify"

# A substring such as v11.9.0 must never satisfy the pinned v1.9.0 tool
# identity check. The wrapper is not allowed to reach SBOM generation because
# verification must reject it at the version boundary.
cat >"$work/cyclonedx-wrong-version" <<EOF
#!/usr/bin/env bash
if [[ "\${1:-}" == version ]]; then
  printf 'Version:\tv11.9.0\n'
  exit 0
fi
exec "$real_cyclonedx" "\$@"
EOF
chmod 0755 "$work/cyclonedx-wrong-version"
run_must_fail sbom-tool-version-substring env \
  CYCLONEDX_GOMOD="$work/cyclonedx-wrong-version" DIST_DIR="$dist" "$verify"

copy_case hash-mismatch
printf 'tamper' >>"$work/hash-mismatch/$so"
run_must_fail hash-mismatch env DIST_DIR="$work/hash-mismatch" "$verify"

copy_case architecture-mismatch
printf 'not an ELF shared object\n' >"$work/architecture-mismatch/$so"
(
  cd "$work/architecture-mismatch"
  sha256sum "$so" >"$so.sha256"
  sha256sum "$so" "$so.sha256" "$zip_name" build-metadata.json ruleset-manifest.json \
    ruleset.sha256 sbom.cdx.json >checksums.txt
)
run_must_fail architecture-mismatch env DIST_DIR="$work/architecture-mismatch" "$verify"

copy_case zip-allowlist-mismatch
printf 'forbidden\n' >"$work/zip-allowlist-mismatch/unexpected.txt"
(
  cd "$work/zip-allowlist-mismatch"
  zip -q "$zip_name" unexpected.txt
  rm -f unexpected.txt
  sha256sum "$so" "$so.sha256" "$zip_name" build-metadata.json ruleset-manifest.json \
    ruleset.sha256 sbom.cdx.json >checksums.txt
)
run_must_fail zip-allowlist-mismatch env DIST_DIR="$work/zip-allowlist-mismatch" "$verify"

copy_case zip-readme-content-mismatch
mkdir -p "$work/zip-readme-content-mismatch/repack"
unzip -q "$work/zip-readme-content-mismatch/$zip_name" \
  -d "$work/zip-readme-content-mismatch/repack"
printf '\nTampered release documentation.\n' \
  >>"$work/zip-readme-content-mismatch/repack/README.md"
chmod 0644 "$work/zip-readme-content-mismatch/repack/README.md"
rm -f "$work/zip-readme-content-mismatch/$zip_name"
(
  cd "$work/zip-readme-content-mismatch/repack"
  find . -mindepth 1 -printf '%P\n' | LC_ALL=C sort | \
    zip -X -q "$work/zip-readme-content-mismatch/$zip_name" -@
)
(
  cd "$work/zip-readme-content-mismatch"
  sha256sum "$so" "$so.sha256" "$zip_name" build-metadata.json ruleset-manifest.json \
    ruleset.sha256 sbom.cdx.json >checksums.txt
)
run_must_fail zip-readme-content-mismatch env \
  DIST_DIR="$work/zip-readme-content-mismatch" "$verify"

copy_case zip-script-content-mismatch
mkdir -p "$work/zip-script-content-mismatch/repack"
unzip -q "$work/zip-script-content-mismatch/$zip_name" \
  -d "$work/zip-script-content-mismatch/repack"
printf '\n# Tampered operational script.\n' \
  >>"$work/zip-script-content-mismatch/repack/scripts/check-production-health.sh"
chmod 0755 \
  "$work/zip-script-content-mismatch/repack/scripts/check-production-health.sh"
rm -f "$work/zip-script-content-mismatch/$zip_name"
(
  cd "$work/zip-script-content-mismatch/repack"
  find . -mindepth 1 -printf '%P\n' | LC_ALL=C sort | \
    zip -X -q "$work/zip-script-content-mismatch/$zip_name" -@
)
(
  cd "$work/zip-script-content-mismatch"
  sha256sum "$so" "$so.sha256" "$zip_name" build-metadata.json ruleset-manifest.json \
    ruleset.sha256 sbom.cdx.json >checksums.txt
)
run_must_fail zip-script-content-mismatch env \
  DIST_DIR="$work/zip-script-content-mismatch" "$verify"

copy_case zip-missing-required
(
  cd "$work/zip-missing-required"
  zip -q -d "$zip_name" docs/reports/EVALUATION_V10_REPORT.md
  sha256sum "$so" "$so.sha256" "$zip_name" build-metadata.json ruleset-manifest.json \
    ruleset.sha256 sbom.cdx.json >checksums.txt
)
run_must_fail zip-missing-required env DIST_DIR="$work/zip-missing-required" "$verify"

copy_case zip-missing-v5-history
(
  cd "$work/zip-missing-v5-history"
  zip -q -d "$zip_name" docs/reports/EVALUATION_V5_REPORT.md
  sha256sum "$so" "$so.sha256" "$zip_name" build-metadata.json ruleset-manifest.json \
    ruleset.sha256 sbom.cdx.json >checksums.txt
)
run_must_fail zip-missing-v5-history env DIST_DIR="$work/zip-missing-v5-history" "$verify"

copy_case zip-missing-v4-history
(
  cd "$work/zip-missing-v4-history"
  zip -q -d "$zip_name" docs/reports/EVALUATION_V4_REPORT.md
  sha256sum "$so" "$so.sha256" "$zip_name" build-metadata.json ruleset-manifest.json \
    ruleset.sha256 sbom.cdx.json >checksums.txt
)
run_must_fail zip-missing-v4-history env DIST_DIR="$work/zip-missing-v4-history" "$verify"

copy_case zip-missing-v3-history
(
  cd "$work/zip-missing-v3-history"
  zip -q -d "$zip_name" docs/reports/HOLDOUT_V3_REPORT.md
  sha256sum "$so" "$so.sha256" "$zip_name" build-metadata.json ruleset-manifest.json \
    ruleset.sha256 sbom.cdx.json >checksums.txt
)
run_must_fail zip-missing-v3-history env DIST_DIR="$work/zip-missing-v3-history" "$verify"

copy_case zip-missing-v2-history
(
  cd "$work/zip-missing-v2-history"
  zip -q -d "$zip_name" docs/reports/HOLDOUT_V2_REPORT.md
  sha256sum "$so" "$so.sha256" "$zip_name" build-metadata.json ruleset-manifest.json \
    ruleset.sha256 sbom.cdx.json >checksums.txt
)
run_must_fail zip-missing-v2-history env DIST_DIR="$work/zip-missing-v2-history" "$verify"

copy_case zip-missing-audit-handoff
(
  cd "$work/zip-missing-audit-handoff"
  zip -q -d "$zip_name" docs/AUDIT_HANDOFF.md
  sha256sum "$so" "$so.sha256" "$zip_name" build-metadata.json ruleset-manifest.json \
    ruleset.sha256 sbom.cdx.json >checksums.txt
)
run_must_fail zip-missing-audit-handoff env DIST_DIR="$work/zip-missing-audit-handoff" "$verify"

copy_case zip-mode-mismatch
mkdir -p "$work/zip-mode-mismatch/repack"
unzip -q "$work/zip-mode-mismatch/$zip_name" -d "$work/zip-mode-mismatch/repack"
chmod 0644 "$work/zip-mode-mismatch/repack/scripts/check-production-health.sh"
rm -f "$work/zip-mode-mismatch/$zip_name"
(
  cd "$work/zip-mode-mismatch/repack"
  find . -mindepth 1 -printf '%P\n' | LC_ALL=C sort | \
    zip -X -q "$work/zip-mode-mismatch/$zip_name" -@
)
(
  cd "$work/zip-mode-mismatch"
  sha256sum "$so" "$so.sha256" "$zip_name" build-metadata.json ruleset-manifest.json \
    ruleset.sha256 sbom.cdx.json >checksums.txt
)
run_must_fail zip-mode-mismatch env DIST_DIR="$work/zip-mode-mismatch" "$verify"

copy_case zip-symlink-entry
mkdir -p "$work/zip-symlink-entry/repack"
unzip -q "$work/zip-symlink-entry/$zip_name" -d "$work/zip-symlink-entry/repack"
rm -f "$work/zip-symlink-entry/repack/README.md"
ln -s README_CN.md "$work/zip-symlink-entry/repack/README.md"
rm -f "$work/zip-symlink-entry/$zip_name"
(
  cd "$work/zip-symlink-entry/repack"
  find . -mindepth 1 -printf '%P\n' | LC_ALL=C sort | \
    zip -X -y -q "$work/zip-symlink-entry/$zip_name" -@
)
(
  cd "$work/zip-symlink-entry"
  sha256sum "$so" "$so.sha256" "$zip_name" build-metadata.json ruleset-manifest.json \
    ruleset.sha256 sbom.cdx.json >checksums.txt
)
run_must_fail zip-symlink-entry env DIST_DIR="$work/zip-symlink-entry" "$verify"

copy_case ruleset-mismatch
printf ' ' >>"$work/ruleset-mismatch/ruleset-manifest.json"
(
  cd "$work/ruleset-mismatch"
  sha256sum ruleset-manifest.json >ruleset.sha256
  sha256sum "$so" "$so.sha256" "$zip_name" build-metadata.json ruleset-manifest.json \
    ruleset.sha256 sbom.cdx.json >checksums.txt
)
run_must_fail ruleset-mismatch env DIST_DIR="$work/ruleset-mismatch" "$verify"

copy_case sbom-mismatch
printf ' ' >>"$work/sbom-mismatch/sbom.cdx.json"
(
  cd "$work/sbom-mismatch"
  sha256sum "$so" "$so.sha256" "$zip_name" build-metadata.json ruleset-manifest.json \
    ruleset.sha256 sbom.cdx.json >checksums.txt
)
run_must_fail sbom-mismatch env DIST_DIR="$work/sbom-mismatch" "$verify"

copy_case version-mismatch
run_must_fail version-mismatch env VERSION=9.9.9 DIST_DIR="$work/version-mismatch" "$verify"

echo "all release verification fault injections were rejected"
