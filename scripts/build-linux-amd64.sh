#!/usr/bin/env bash
set -euo pipefail

root="$(cd "${BASH_SOURCE[0]%/*}/.." && pwd -P)"
# shellcheck source=release-common.sh
source "$root/scripts/release-common.sh"
go_bin="${GO:-go}"
release_require_commands "$go_bin" file sha256sum git sed awk sort mkdir rm basename
release_init
release_assert_tag

dist="${DIST_DIR:-$root/dist}"
artifact="$dist/cyber-abuse-guard-v${RELEASE_ARTIFACT_VERSION}.so"

if [[ "$(uname -s)" != "Linux" || "$(uname -m)" != "x86_64" ]]; then
  echo "build-linux-amd64.sh requires an amd64 Linux environment (native, WSL2, or Docker)." >&2
  exit 1
fi
go_version="$($go_bin env GOVERSION)"
if [[ "$go_version" != go1.26.4 ]]; then
  printf 'build-linux-amd64.sh requires Go go1.26.4, got %s\n' "$go_version" >&2
  exit 1
fi

mkdir -p "$dist"
cd "$root"

ldflags="-s -w -buildid="
ldflags+=" -X github.com/yujianwudi/cyber-abuse-guard/internal/buildinfo.Version=$RELEASE_ARTIFACT_VERSION"
ldflags+=" -X github.com/yujianwudi/cyber-abuse-guard/internal/buildinfo.Commit=$RELEASE_GIT_COMMIT"
ldflags+=" -X github.com/yujianwudi/cyber-abuse-guard/internal/buildinfo.RulesetVersion=$RELEASE_RULESET_VERSION"
ldflags+=" -X github.com/yujianwudi/cyber-abuse-guard/internal/buildinfo.RulesetSHA256=$RELEASE_RULESET_SHA256"
ldflags+=" -X github.com/yujianwudi/cyber-abuse-guard/internal/buildinfo.Dirty=$RELEASE_DIRTY"

export SOURCE_DATE_EPOCH="$RELEASE_SOURCE_DATE_EPOCH"
CGO_ENABLED=1 GOOS=linux GOARCH=amd64 \
  "$go_bin" build -mod=readonly -trimpath -buildvcs=false -buildmode=c-shared \
  -tags=sqlite_omit_load_extension -ldflags="$ldflags" \
  -o "$artifact" ./cmd/cyber-abuse-guard

rm -f "${artifact%.so}.h"
(cd "$dist" && sha256sum "$(basename "$artifact")" > "$(basename "$artifact").sha256")
OUTPUT_DIR="$dist" GO="$go_bin" "$root/scripts/release-ruleset-manifest.sh"
OUTPUT_DIR="$dist" GO="$go_bin" "$root/scripts/release-build-metadata.sh"

file "$artifact"
(cd "$dist" && sha256sum -c "$(basename "$artifact").sha256")
release_assert_source_unchanged
printf 'build identity: version=%s commit=%s ruleset=%s ruleset_sha256=%s dirty=%s\n' \
  "$RELEASE_ARTIFACT_VERSION" "$RELEASE_GIT_COMMIT" "$RELEASE_RULESET_VERSION" \
  "$RELEASE_RULESET_SHA256" "$RELEASE_DIRTY"
