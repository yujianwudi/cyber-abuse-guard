#!/usr/bin/env bash
set -euo pipefail

root="$(cd "${BASH_SOURCE[0]%/*}/.." && pwd -P)"
# shellcheck source=release-common.sh
source "$root/scripts/release-common.sh"
release_require_commands git tar grep sha256sum mktemp chmod mv rm mkdir basename
release_init
release_assert_tag
release_assert_formal_build

dist="${DIST_DIR:-$root/dist}"
mkdir -p "$dist"
[[ -d "$dist" && ! -L "$dist" ]] || release_die "DIST_DIR must be a real directory"
archive="cyber-abuse-guard-v${RELEASE_SOURCE_VERSION}-source.tar.gz"
temporary="$(mktemp "$dist/.source-release.XXXXXX")"
cleanup() {
  rm -f -- "$temporary"
}
trap cleanup EXIT

archive_pathspecs=(
  .
  ':(exclude)cmd/evaluation-*'
  ':(exclude)cmd/holdout-*'
  ':(exclude)cmd/*private*'
  ':(exclude)cmd/*blind*'
  ':(exclude)cmd/*retired*'
  ':(exclude)docs/reports/EVALUATION_*'
  ':(exclude)docs/reports/HOLDOUT_*'
  ':(exclude)docs/reports/HOLDOUT_REPORT.md'
  ':(exclude)docs/**/*private*'
  ':(exclude)docs/**/*blind*'
  ':(exclude)docs/**/*retired*'
  ':(exclude)internal/classifier/evaluation_*'
  ':(exclude)internal/classifier/holdout_*'
  ':(exclude)internal/classifier/*private*'
  ':(exclude)internal/classifier/*blind*'
  ':(exclude)internal/classifier/*retired*'
  ':(exclude)testdata/evaluation-*'
  ':(exclude)testdata/holdout*'
  ':(exclude)testdata/*private*'
  ':(exclude)testdata/*blind*'
  ':(exclude)testdata/*retired*'
)
git -C "$root" archive --format=tar.gz \
  --prefix="cyber-abuse-guard-v${RELEASE_SOURCE_VERSION}/" \
  --output="$temporary" "$RELEASE_GIT_COMMIT" -- "${archive_pathspecs[@]}"

listing="$(tar -tzf "$temporary")"
[[ -n "$listing" ]] || release_die "source release archive is empty"
if grep -Ev "^cyber-abuse-guard-v${RELEASE_SOURCE_VERSION}/" <<<"$listing" | grep -q .; then
  release_die "source release archive contains an entry outside its fixed prefix"
fi
if grep -Eiq '(^|/)(\.git($|/)|dist($|/)|build($|/)|[^/]*\.(db|sqlite|sqlite3|key|pem|p12|pfx|jks|keystore|log)($|[-.])|\.env($|[./]))' <<<"$listing"; then
  release_die "source release archive contains a forbidden repository, build, database, secret, or log path"
fi
if grep -Eiq '(^|/)[^/]*(evaluation|holdout|private|blind|retired)[^/]*($|/)' <<<"$listing"; then
  release_die "source release archive contains evaluation, holdout, private, blind, or retired material"
fi
if tar -tvzf "$temporary" | grep -Eq '^l'; then
  release_die "source release archive contains a symbolic link"
fi

chmod 0644 "$temporary"
mv -f -- "$temporary" "$dist/$archive"
temporary=""
(cd "$dist" && sha256sum "$archive" >"$archive.sha256" && sha256sum -c "$archive.sha256")
release_assert_source_unchanged
printf 'source release archive generated: %s\n' "$dist/$archive"
