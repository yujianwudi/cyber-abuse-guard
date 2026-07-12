#!/usr/bin/env bash
set -euo pipefail

version="${VERSION:-0.1.0}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dist="$root/dist"
so="cyber-abuse-guard-v${version}.so"
zip_name="cyber-abuse-guard_${version}_linux_amd64.zip"

for required in file sha256sum unzip grep cmp mktemp sort uniq diff stat; do
  if ! command -v "$required" >/dev/null 2>&1; then
    echo "required verification command not found: $required" >&2
    exit 127
  fi
done

cd "$dist"
test -f "$so"
test -f "$so.sha256"
test -f "$zip_name"
test -f checksums.txt

sha256sum -c "$so.sha256"
sha256sum -c checksums.txt
file_output="$(file "$so")"
grep -Fq 'ELF 64-bit' <<<"$file_output"
grep -Fq 'shared object' <<<"$file_output"
grep -Fq 'x86-64' <<<"$file_output"

listing="$(unzip -Z1 "$zip_name")"
expected_listing="$(cat <<EOF
CHANGELOG.md
LICENSE
README.md
README_CN.md
THIRD_PARTY_NOTICES.md
config.example.yaml
docs/
docs/DESIGN.md
docs/INSTALL_DOCKER.md
docs/LIMITATIONS.md
docs/NEXT_VERSION.md
docs/RULES.md
docs/THREAT_MODEL.md
docs/reports/
docs/reports/CORPUS_REPORT.md
docs/reports/CPA_INTEGRATION.md
docs/reports/PERFORMANCE.md
docs/reports/TEST_REPORT.md
plugins/
plugins/linux/
plugins/linux/amd64/
plugins/linux/amd64/$so
plugins/linux/amd64/$so.sha256
EOF
)"

duplicates="$(printf '%s\n' "$listing" | LC_ALL=C sort | uniq -d)"
if [[ -n "$duplicates" ]]; then
  echo "release ZIP contains duplicate entries:" >&2
  printf '%s\n' "$duplicates" >&2
  exit 1
fi
actual_sorted="$(printf '%s\n' "$listing" | LC_ALL=C sort)"
expected_sorted="$(printf '%s\n' "$expected_listing" | LC_ALL=C sort)"
if [[ "$actual_sorted" != "$expected_sorted" ]]; then
  echo "release ZIP content differs from the strict allowlist" >&2
  diff -u <(printf '%s\n' "$expected_sorted") <(printf '%s\n' "$actual_sorted") >&2 || true
  exit 1
fi
if grep -Eiq '(^|/)(\.git|.*\.db($|[-.])|.*secret.*|.*hmac.*|.*\.key|.*\.pem|\.env.*|.*\.log)($|/)' <<<"$listing"; then
  echo "release ZIP contains a forbidden repository, database, or secret-like path" >&2
  exit 1
fi

verify_dir="$(mktemp -d)"
trap 'rm -rf "$verify_dir"' EXIT
(umask 000; unzip -q "$zip_name" -d "$verify_dir")
(cd "$verify_dir/plugins/linux/amd64" && sha256sum -c "$so.sha256")
cmp -s "$so" "$verify_dir/plugins/linux/amd64/$so"

while IFS= read -r entry; do
  if [[ "$entry" == */ ]]; then
    expected_mode=755
    test -d "$verify_dir/$entry"
  elif [[ "$entry" == "plugins/linux/amd64/$so" ]]; then
    expected_mode=755
    test -f "$verify_dir/$entry"
  else
    expected_mode=644
    test -f "$verify_dir/$entry"
  fi
  actual_mode="$(stat -c '%a' "$verify_dir/$entry")"
  if [[ "$actual_mode" != "$expected_mode" ]]; then
    echo "release ZIP mode mismatch for $entry: got $actual_mode, want $expected_mode" >&2
    exit 1
  fi
done <<<"$listing"

echo "release verification passed: $dist/$zip_name"
