#!/usr/bin/env bash
set -euo pipefail

root="$(cd "${BASH_SOURCE[0]%/*}/.." && pwd -P)"
# shellcheck source=release-common.sh
source "$root/scripts/release-common.sh"
release_require_commands git tar grep mktemp rm

work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT
archive="$work/source.tar"

git -C "$root" archive --worktree-attributes --format=tar \
  --output="$archive" HEAD
listing="$(tar -tf "$archive")"

grep -Fxq README.md <<<"$listing" || \
  release_die "source archive exclusion fixture lost a required public source file"
if grep -Eiq '(^|/)[^/]*(evaluation|holdout|private|blind|retired)[^/]*($|/)' <<<"$listing"; then
  release_die "source archive export-ignore contract exposed restricted material"
fi

printf 'source release exclusion contract passed\n'
