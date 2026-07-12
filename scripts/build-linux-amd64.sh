#!/usr/bin/env bash
set -euo pipefail

version="${VERSION:-0.1.0}"
go_bin="${GO:-go}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dist="$root/dist"
artifact="$dist/cyber-abuse-guard-v${version}.so"

for required in "$go_bin" file sha256sum; do
  if ! command -v "$required" >/dev/null 2>&1; then
    echo "required build command not found: $required" >&2
    exit 127
  fi
done

if [[ "$version" != "0.1.0" ]]; then
  echo "VERSION=$version does not match the compiled plugin metadata (0.1.0). Update the source version before building a new release." >&2
  exit 1
fi

if [[ "$(uname -s)" != "Linux" || "$(uname -m)" != "x86_64" ]]; then
  echo "build-linux-amd64.sh requires an amd64 Linux environment (native, WSL2, or Docker)." >&2
  exit 1
fi

mkdir -p "$dist"
cd "$root"

CGO_ENABLED=1 GOOS=linux GOARCH=amd64 \
  "$go_bin" build -trimpath -buildvcs=false -buildmode=c-shared -tags=sqlite_omit_load_extension \
  -ldflags="-s -w" \
  -o "$artifact" ./cmd/cyber-abuse-guard

rm -f "${artifact%.so}.h"
(cd "$dist" && sha256sum "$(basename "$artifact")" > "$(basename "$artifact").sha256")

file "$artifact"
(cd "$dist" && sha256sum -c "$(basename "$artifact").sha256")
