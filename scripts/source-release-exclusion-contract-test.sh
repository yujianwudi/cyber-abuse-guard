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
if grep -Eiq '(^|/)[^/]*(evaluation|holdout|consumed|private|blind|retired)[^/]*($|/)' <<<"$listing"; then
  release_die "source archive export-ignore contract exposed restricted material"
fi

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
