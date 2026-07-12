#!/usr/bin/env bash
set -euo pipefail

version="${VERSION:-0.1.1}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dist="$root/dist"
so="cyber-abuse-guard-v${version}.so"
zip_name="cyber-abuse-guard_${version}_linux_amd64.zip"
source_date_epoch="${SOURCE_DATE_EPOCH:-1783814400}"
stage=""
export TZ=UTC

for required in install zip sha256sum mktemp find touch sort; do
  if ! command -v "$required" >/dev/null 2>&1; then
    echo "required packaging command not found: $required" >&2
    exit 127
  fi
done

if [[ ! "$source_date_epoch" =~ ^[0-9]+$ ]] || (( source_date_epoch < 315532800 )); then
  echo "SOURCE_DATE_EPOCH must be an integer at or after 1980-01-01" >&2
  exit 2
fi

cleanup() {
  if [[ -n "$stage" && -d "$stage" ]]; then
    rm -rf -- "$stage"
  fi
}
trap cleanup EXIT

test -f "$dist/$so"
stage="$(mktemp -d)"
mkdir -p "$stage/plugins/linux/amd64" "$stage/docs/reports"
find "$stage" -type d -exec chmod 0755 {} +

install -m 0755 "$dist/$so" "$stage/plugins/linux/amd64/$so"
install -m 0644 "$dist/$so.sha256" "$stage/plugins/linux/amd64/$so.sha256"
install -m 0644 "$root/README.md" "$root/README_CN.md" "$root/LICENSE" \
  "$root/CHANGELOG.md" "$root/THIRD_PARTY_NOTICES.md" \
  "$root/config.example.yaml" "$stage/"
install -m 0644 "$root/docs/DESIGN.md" "$root/docs/THREAT_MODEL.md" \
  "$root/docs/INSTALL_DOCKER.md" "$root/docs/LIMITATIONS.md" \
  "$root/docs/NEXT_VERSION.md" "$root/docs/RULES.md" "$stage/docs/"
install -m 0644 "$root/docs/reports/TEST_REPORT.md" \
  "$root/docs/reports/PERFORMANCE.md" "$root/docs/reports/CORPUS_REPORT.md" \
  "$root/docs/reports/CPA_INTEGRATION.md" "$stage/docs/reports/"

find "$stage" -exec touch -h -d "@$source_date_epoch" {} +
rm -f "$dist/$zip_name"
(cd "$stage" && find . -mindepth 1 -printf '%P\n' | LC_ALL=C sort | zip -X -q "$dist/$zip_name" -@)

(cd "$dist" && sha256sum "$so" "$zip_name" > checksums.txt)
"$root/scripts/verify-release.sh"
