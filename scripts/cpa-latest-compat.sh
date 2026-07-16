#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
go_bin="${GO:-go}"
cpa_module='github.com/router-for-me/CLIProxyAPI/v7'
cpa_version='v7.2.80'
cpa_latest_release_api='https://api.github.com/repos/router-for-me/CLIProxyAPI/releases/latest'
cpa_tag_ref_api='https://api.github.com/repos/router-for-me/CLIProxyAPI/git/ref/tags'
cpa_commit='09da52ad509e2c18e7b9540db3b98c2214c280aa'
cpa_module_sum='h1:QIa5T/KYvJACHVPPRzXcRwq/HLpbwWYJYpZAC1eY2WA='
cpa_go_mod_sum='h1:ytvZNWbCv7PrAyR80+RKsDJPODsdL6qxyFaXDBNZdqs='

if [[ "${CPA_LATEST_VERIFY_REMOTE:-0}" == "1" ]]; then
  for required_command in curl jq; do
    command -v "$required_command" >/dev/null 2>&1 || {
      printf '%s is required for latest CPA release identity verification\n' "$required_command" >&2
      exit 1
    }
  done
  release_curl_args=(
    --fail
    --silent
    --show-error
    --location
    --max-time 60
    --header 'Accept: application/vnd.github+json'
    --header 'X-GitHub-Api-Version: 2022-11-28'
  )
  if [[ -n "${GITHUB_TOKEN:-}" ]]; then
    release_curl_args+=(--header "Authorization: Bearer ${GITHUB_TOKEN}")
  fi
  latest_release_json="$(curl "${release_curl_args[@]}" "$cpa_latest_release_api")"
  latest_release_tag="$(printf '%s\n' "$latest_release_json" | jq -er '.tag_name | select(type == "string" and length > 0)')"
  [[ -n "$latest_release_tag" ]] || {
    printf 'latest CPA release response did not contain tag_name\n' >&2
    exit 1
  }
  [[ "$latest_release_tag" == "$cpa_version" ]] || {
    printf 'latest CPA release mismatch: got %s want pinned %s\n' "$latest_release_tag" "$cpa_version" >&2
    exit 1
  }

  tag_ref_json="$(curl "${release_curl_args[@]}" "$cpa_tag_ref_api/$cpa_version")"
  resolved_tag_type="$(printf '%s\n' "$tag_ref_json" | jq -er '.object.type | select(type == "string" and length > 0)')"
  resolved_tag_commit="$(printf '%s\n' "$tag_ref_json" | jq -er '.object.sha | select(type == "string" and length > 0)')"
  [[ "$resolved_tag_type" == "commit" && "$resolved_tag_commit" == "$cpa_commit" ]] || {
    printf 'latest CPA tag identity mismatch: got type=%s commit=%s want type=commit commit=%s\n' \
      "$resolved_tag_type" "$resolved_tag_commit" "$cpa_commit" >&2
    exit 1
  }
else
  printf 'CPA latest release and remote tag checks skipped; set CPA_LATEST_VERIFY_REMOTE=1 to require them\n' >&2
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
    ./cmd/cyber-abuse-guard
  GOWORK=off CGO_ENABLED=1 "$go_bin" test \
    -mod=readonly -modfile="$work/latest-compat.mod" \
    -tags=sqlite_omit_load_extension -count=1 \
    -run='^(TestRegistrationMatchesTargetCPAv7275Contract|TestRouterUsesRoleAwareConversationClassification)$' \
    ./internal/plugin
  GOWORK=off CGO_ENABLED=1 "$go_bin" test \
    -mod=readonly -modfile="$work/latest-compat.mod" \
    -tags=integration,sqlite_omit_load_extension -run='^$' -count=1 \
    ./integration
  # The isolated package contains only bounded source/compile contracts. Run
  # the whole package so newly added CPA compatibility contracts cannot be
  # silently omitted by a stale -run allowlist.
  GOWORK=off "$go_bin" -C integration/cpalatestcontract test -count=1 -v .
)

printf 'CPA latest source/compile compatibility PASS: %s@%s\n' "$cpa_version" "$cpa_commit"
