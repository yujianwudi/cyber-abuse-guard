#!/usr/bin/env bash
set -euo pipefail

root="$(cd "${BASH_SOURCE[0]%/*}/.." && pwd -P)"
# shellcheck source=release-common.sh
source "$root/scripts/release-common.sh"
release_require_commands git tar grep mktemp rm mkdir

work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT
archive="$work/source.tar"

consumed_paths=(
  cmd/consumed-contract-probe
  cmd/safe/nested-consumed
  cmd/safe/nested-Consumed
  docs/reports/consumed-contract-probe.md
  docs/safe/nested-consumed
  docs/safe/nested-Consumed
  internal/classifier/consumed_contract_probe_test.go
  internal/classifier/safe/nested-consumed
  internal/classifier/safe/nested-Consumed
  testdata/consumed-contract-probe.json
  testdata/safe/nested-consumed
  testdata/safe/nested-Consumed
)
for path in "${consumed_paths[@]}"; do
  [[ "$(git -C "$root" check-attr export-ignore -- "$path")" == \
    "$path: export-ignore: set" ]] || \
    release_die "source archive export-ignore contract does not exclude consumed path: $path"
done

git -C "$root" archive --worktree-attributes --format=tar \
  --output="$archive" HEAD
listing="$(tar -tf "$archive")"

grep -Fxq README.md <<<"$listing" || \
  release_die "source archive exclusion fixture lost a required public source file"
grep -Fxq Dockerfile.test <<<"$listing" || \
  release_die "source archive exclusion fixture lost the tracked Dockerfile.test source"
if grep -Eiq '(^|/)[^/]*(evaluation|holdout|consumed|private|blind|retired)[^/]*($|/)' <<<"$listing"; then
  release_die "source archive export-ignore contract exposed restricted material"
fi

transient_path_pattern='(^|/)(classifier_(candidate|single)_[^/]*|[^/]*\.(cpu|mem|pprof|test\.exe|exe))($|/)'
test_binary_path_pattern='(^|/)[^/]*\.test($|/)'
safe_test_source_pattern='(^|/)Dockerfile\.test($|/)'
backup_binary_archive_path_pattern='(^|/)[^/]*\.(bak|backup|so|dll|zip|tar|tgz|gz)($|/)'
expected_archive_guard="  local backup_binary_archive_path_pattern='$backup_binary_archive_path_pattern'"
grep -Fxq "$expected_archive_guard" "$root/scripts/round6-rc-artifacts.sh" ||
  release_die "source archive production guard lost the reviewed backup/binary/archive pattern"
is_forbidden_source_archive_path() {
  local path="$1"
  grep -Eiq "$backup_binary_archive_path_pattern" <<<"$path" && return 0
  grep -Eiq "$transient_path_pattern" <<<"$path" && return 0
  if grep -Eiq "$test_binary_path_pattern" <<<"$path" &&
    ! grep -Eiq "$safe_test_source_pattern" <<<"$path"; then
    return 0
  fi
  return 1
}
for path in \
  classifier.accept.cpu \
  profiles/classifier.mem \
  profiles/heap.pprof \
  classifier.test \
  classifier.test.exe \
  tools/probe.exe \
  classifier_candidate_exact \
  tmp/classifier_candidate_fixed \
  classifier_single_fixed \
  tmp/classifier_single_tree/member.go \
  audit.db.pre-v5-20260722T000000.000000000Z.bak \
  snapshots/audit.backup \
  plugins/cyber-abuse-guard.so \
  plugins/cyber-abuse-guard.dll \
  release/package.zip \
  release/source.tar \
  release/source.tar.gz \
  release/source.tgz \
  release/transcript.gz; do
  is_forbidden_source_archive_path "cyber-abuse-guard-fixture/$path" || \
    release_die "source archive forbidden-payload guard missed: $path"
done
for path in \
  Dockerfile.test \
  integration/fixture/Dockerfile.test \
  internal/classifier/profile.cpu.go \
  internal/classifier/memory.mem.go \
  internal/classifier/trace.pprof.go \
  internal/classifier/package.test.go \
  internal/classifier/windows.exe.go \
  internal/classifier/classifier_candidate.go \
  internal/classifier/classifier_single.go \
  docs/classifier-candidate-notes.md \
  internal/plugin/cyber-abuse-guard.so.go \
  internal/platform/provider.dll.go \
  internal/audit/migration_backup_test.go \
  docs/archive.zip.md \
  testdata/fixture.tar.json \
  scripts/package-tar-gz.sh; do
  if is_forbidden_source_archive_path "cyber-abuse-guard-fixture/$path"; then
    release_die "source archive forbidden-payload guard rejected safe source: $path"
  fi
done

sparse_fixture="$work/sparse-fixture"
git init --quiet "$sparse_fixture"
restricted_paths=(
  cmd/safe/nested-evaluation/payload.go
  cmd/safe/nested-private/payload.go
  docs/safe/nested-retired/report.md
  internal/classifier/safe/nested-consumed/payload.go
  testdata/safe/nested-blind/payload.json
  cmd/safe/nested-Evaluation/payload.go
  cmd/safe/nested-HoldOut/payload.go
  cmd/safe/nested-Consumed/payload.go
  docs/safe/nested-Private/report.md
  internal/classifier/safe/nested-Blind/payload.go
  testdata/safe/nested-Retired/payload.json
)
mkdir -p "$sparse_fixture/public"
printf 'synthetic safe neighbor\n' >"$sparse_fixture/public/safe.txt"
for path in "${restricted_paths[@]}"; do
  mkdir -p "$sparse_fixture/${path%/*}"
  printf 'synthetic restricted marker\n' >"$sparse_fixture/$path"
done
git -C "$sparse_fixture" add .
git -C "$sparse_fixture" \
  -c user.name='Round6 Contract' \
  -c user.email=round6-contract@example.invalid \
  commit --quiet --message fixture
sparse_patterns=(
  '/*'
  '!/cmd/**/*[Ee][Vv][Aa][Ll][Uu][Aa][Tt][Ii][Oo][Nn]*'
  '!/cmd/**/*[Hh][Oo][Ll][Dd][Oo][Uu][Tt]*'
  '!/cmd/**/*[Cc][Oo][Nn][Ss][Uu][Mm][Ee][Dd]*'
  '!/cmd/**/*[Pp][Rr][Ii][Vv][Aa][Tt][Ee]*'
  '!/cmd/**/*[Bb][Ll][Ii][Nn][Dd]*'
  '!/cmd/**/*[Rr][Ee][Tt][Ii][Rr][Ee][Dd]*'
  '!/docs/**/*[Ee][Vv][Aa][Ll][Uu][Aa][Tt][Ii][Oo][Nn]*'
  '!/docs/**/*[Hh][Oo][Ll][Dd][Oo][Uu][Tt]*'
  '!/docs/**/*[Hh][Oo][Ll][Dd][Oo][Uu][Tt]_[Rr][Ee][Pp][Oo][Rr][Tt].[Mm][Dd]'
  '!/docs/**/*[Cc][Oo][Nn][Ss][Uu][Mm][Ee][Dd]*'
  '!/docs/**/*[Pp][Rr][Ii][Vv][Aa][Tt][Ee]*'
  '!/docs/**/*[Bb][Ll][Ii][Nn][Dd]*'
  '!/docs/**/*[Rr][Ee][Tt][Ii][Rr][Ee][Dd]*'
  '!/internal/classifier/**/*[Ee][Vv][Aa][Ll][Uu][Aa][Tt][Ii][Oo][Nn]*'
  '!/internal/classifier/**/*[Hh][Oo][Ll][Dd][Oo][Uu][Tt]*'
  '!/internal/classifier/**/*[Cc][Oo][Nn][Ss][Uu][Mm][Ee][Dd]*'
  '!/internal/classifier/**/*[Pp][Rr][Ii][Vv][Aa][Tt][Ee]*'
  '!/internal/classifier/**/*[Bb][Ll][Ii][Nn][Dd]*'
  '!/internal/classifier/**/*[Rr][Ee][Tt][Ii][Rr][Ee][Dd]*'
  '!/testdata/**/*[Ee][Vv][Aa][Ll][Uu][Aa][Tt][Ii][Oo][Nn]*'
  '!/testdata/**/*[Hh][Oo][Ll][Dd][Oo][Uu][Tt]*'
  '!/testdata/**/*[Cc][Oo][Nn][Ss][Uu][Mm][Ee][Dd]*'
  '!/testdata/**/*[Pp][Rr][Ii][Vv][Aa][Tt][Ee]*'
  '!/testdata/**/*[Bb][Ll][Ii][Nn][Dd]*'
  '!/testdata/**/*[Rr][Ee][Tt][Ii][Rr][Ee][Dd]*'
)
git -C "$sparse_fixture" sparse-checkout set --no-cone "${sparse_patterns[@]}"
[[ -f "$sparse_fixture/public/safe.txt" ]] || \
  release_die "recursive sparse contract removed a safe neighbor"
for path in "${restricted_paths[@]}"; do
  [[ ! -e "$sparse_fixture/$path" ]] || \
    release_die "recursive sparse contract materialized restricted path: $path"
done

printf 'source release exclusion contract passed\n'
