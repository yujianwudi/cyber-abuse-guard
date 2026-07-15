#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
go_bin="${GO:-go}"
cpa_module='github.com/router-for-me/CLIProxyAPI/v7'
cpa_version='v7.2.79'
cpa_repository='https://github.com/router-for-me/CLIProxyAPI.git'
cpa_commit='b6ce0beecd31dff389d3190f7db6d7a1d4ce0e7e'
cpa_module_sum='h1:/2s9euOTOeKUCIPWjHdCsll9vUHkJ/H2bq25Da3DQrg='
cpa_go_mod_sum='h1:ytvZNWbCv7PrAyR80+RKsDJPODsdL6qxyFaXDBNZdqs='

if [[ "${CPA_LATEST_VERIFY_REMOTE:-0}" == "1" ]]; then
  resolved_tag="$(GIT_TERMINAL_PROMPT=0 timeout 60s git ls-remote --refs "$cpa_repository" "refs/tags/$cpa_version")"
  expected_tag="$(printf '%s\trefs/tags/%s' "$cpa_commit" "$cpa_version")"
  [[ "$resolved_tag" == "$expected_tag" ]] || {
    printf 'latest CPA tag identity mismatch: got %s want %s\n' "$resolved_tag" "$expected_tag" >&2
    exit 1
  }
else
  printf 'CPA latest remote tag check skipped; set CPA_LATEST_VERIFY_REMOTE=1 to require it\n' >&2
fi

work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT
cp "$root/go.mod" "$work/latest-compat.mod"
cp "$root/go.sum" "$work/latest-compat.sum"

"$go_bin" -C "$root" mod edit -modfile="$work/latest-compat.mod" -require="$cpa_module@$cpa_version"
# The latest CPA module may raise indirect dependency floors. Resolve those
# changes only in the temporary modfile, then make the actual probes readonly.
GOWORK=off "$go_bin" -C "$root" mod tidy -modfile="$work/latest-compat.mod"

resolved="$({
  GOWORK=off "$go_bin" -C "$root" list -mod=readonly -modfile="$work/latest-compat.mod" \
    -m -f '{{.Version}} {{.Sum}} {{.GoModSum}}' "$cpa_module"
})"
expected="$cpa_version $cpa_module_sum $cpa_go_mod_sum"
[[ "$resolved" == "$expected" ]] || {
  printf 'latest CPA module identity mismatch: got %s want %s\n' "$resolved" "$expected" >&2
  exit 1
}

(
  cd "$root"
  GOWORK=off CGO_ENABLED=1 "$go_bin" test \
    -mod=readonly -modfile="$work/latest-compat.mod" \
    -tags=sqlite_omit_load_extension -run='^$' -count=1 \
    ./cmd/cyber-abuse-guard ./internal/plugin
  GOWORK=off CGO_ENABLED=1 "$go_bin" test \
    -mod=readonly -modfile="$work/latest-compat.mod" \
    -tags=integration,sqlite_omit_load_extension -run='^$' -count=1 \
    ./integration
  GOWORK=off "$go_bin" -C integration/cpalatestcontract test -count=1 -v \
    -run='^(TestLatestCPAOfficialHostRoutingSourceContract|TestLatestCPAHostFailOpenFixtureContract)$' .
)

printf 'CPA latest source/compile compatibility PASS: %s@%s\n' "$cpa_version" "$cpa_commit"
