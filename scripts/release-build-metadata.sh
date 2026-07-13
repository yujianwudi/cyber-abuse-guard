#!/usr/bin/env bash
set -euo pipefail

root="$(cd "${BASH_SOURCE[0]%/*}/.." && pwd -P)"
# shellcheck source=release-common.sh
source "$root/scripts/release-common.sh"
go_bin="${GO:-go}"
release_require_commands "$go_bin" git sed awk sha256sum sort mkdir mktemp mv rm chmod
release_init

output_dir="${OUTPUT_DIR:-$root/dist}"
mkdir -p "$output_dir"
temporary="$(mktemp "$output_dir/.build-metadata.XXXXXX")"
trap 'rm -f -- "$temporary"' EXIT
go_version="$($go_bin env GOVERSION)"

{
  printf '{\n'
  printf '  "schema_version": 1,\n'
  printf '  "version": "%s",\n' "$RELEASE_ARTIFACT_VERSION"
  printf '  "source_version": "%s",\n' "$RELEASE_SOURCE_VERSION"
  printf '  "commit": "%s",\n' "$RELEASE_GIT_COMMIT"
  printf '  "ruleset_version": "%s",\n' "$RELEASE_RULESET_VERSION"
  printf '  "ruleset_sha256": "%s",\n' "$RELEASE_RULESET_SHA256"
  printf '  "dirty": %s,\n' "$RELEASE_DIRTY"
  printf '  "source_date_epoch": %s,\n' "$RELEASE_SOURCE_DATE_EPOCH"
  printf '  "go_version": "%s",\n' "$go_version"
  printf '  "goos": "linux",\n'
  printf '  "goarch": "amd64",\n'
  printf '  "cgo_enabled": true\n'
  printf '}\n'
} >"$temporary"

mv -f -- "$temporary" "$output_dir/build-metadata.json"
chmod 0644 "$output_dir/build-metadata.json"
trap - EXIT
release_assert_source_unchanged
printf 'build metadata: %s\n' "$output_dir/build-metadata.json"
