#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
go_bin="${GO:-go}"
git_identity_dir="$(mktemp -d)"
trap 'rm -rf -- "$git_identity_dir"' EXIT
cpa_module='github.com/router-for-me/CLIProxyAPI/v7'
cpa_origin_url='https://github.com/router-for-me/CLIProxyAPI'
cpa_origin_git_url="${cpa_origin_url}.git"

requested_profile="${CPA_COMPAT_PROFILE:-primary}"
case "$requested_profile" in
  primary)
    profiles=(primary)
    ;;
  *)
    printf 'unsupported CPA_COMPAT_PROFILE=%s; only primary is supported\n' "$requested_profile" >&2
    exit 2
    ;;
esac

verify_remote="${CPA_COMPAT_VERIFY_REMOTE:-0}"
case "$verify_remote" in
  0|1) ;;
  *)
    printf 'CPA_COMPAT_VERIFY_REMOTE must be 0 or 1\n' >&2
    exit 2
    ;;
esac

cpa_version='v7.2.88'
cpa_commit='93d74a890a44802f656d7f39a573916b2611896e'
cpa_module_sum='h1:YfLBYPvkasjqFLzdht+UrEgRLsU3HcM0WDMurNEjIDo='
cpa_go_mod_sum='h1:ytvZNWbCv7PrAyR80+RKsDJPODsdL6qxyFaXDBNZdqs='
cpa_expected_module_identity="$cpa_version $cpa_module_sum $cpa_go_mod_sum"

assert_checked_in_module_identity() {
  local directory="$1"
  local label="$2"
  local resolved

  resolved="$(GOWORK=off "$go_bin" -C "$directory" list -mod=readonly -m \
    -f '{{if .Replace}}REPLACED {{.Replace.Path}} {{.Replace.Version}}{{else}}{{.Version}} {{.Sum}} {{.GoModSum}}{{end}}' \
    "$cpa_module")"
  [[ "$resolved" == "$cpa_expected_module_identity" ]] || {
    printf 'checked-in %s CPA module identity mismatch: got %s want %s\n' \
      "$label" "$resolved" "$cpa_expected_module_identity" >&2
    exit 1
  }
}

resolve_remote_tag_commit() {
  local tag="$1"
  local refs expected

  if ! refs="$(timeout --signal=KILL 60s git -C "$git_identity_dir" \
    -c http.lowSpeedLimit=1 -c http.lowSpeedTime=60 \
    ls-remote --refs "$cpa_origin_git_url" "refs/tags/$tag")"; then
    printf 'CPA tag %s could not be resolved from the official Git origin within 60 seconds\n' \
      "$tag" >&2
    return 1
  fi
  expected="${cpa_commit}"$'\t'"refs/tags/$tag"
  [[ "$refs" == "$expected" ]] || {
    printf 'CPA lightweight tag identity mismatch for %s: got %q want %q\n' \
      "$tag" "$refs" "$expected" >&2
    return 1
  }
  printf '%s\n' "$cpa_commit"
}

command -v jq >/dev/null 2>&1 || {
  printf 'jq is required for CPA module identity verification\n' >&2
  exit 1
}
if [[ "$verify_remote" == 1 ]]; then
  for required_command in git timeout; do
    command -v "$required_command" >/dev/null 2>&1 || {
      printf '%s is required for CPA remote tag verification\n' "$required_command" >&2
      exit 1
    }
  done
else
  printf 'CPA remote tag check skipped; pinned module Origin and sums remain required\n' >&2
fi

assert_checked_in_module_identity "$root" root
assert_checked_in_module_identity "$root/integration/cpalatestcontract" cpalatestcontract
assert_checked_in_module_identity "$root/integration/pluginstorecontract" pluginstorecontract

for profile in "${profiles[@]}"; do
  if [[ "$verify_remote" == 1 ]]; then
    resolved_tag_commit="$(resolve_remote_tag_commit "$cpa_version")"
    [[ "$resolved_tag_commit" == "$cpa_commit" ]] || {
      printf 'CPA tag identity mismatch for %s: got commit=%s want commit=%s\n' \
        "$cpa_version" "$resolved_tag_commit" "$cpa_commit" >&2
      exit 1
    }
  fi

  download_json="$(GOWORK=off "$go_bin" -C "$root" mod download -json "$cpa_module@$cpa_version")"
  download_error="$(printf '%s\n' "$download_json" | jq -er '.Error // ""')"
  [[ -z "$download_error" ]] || {
    printf 'CPA module download metadata error for %s: %s\n' "$cpa_version" "$download_error" >&2
    exit 1
  }
  download_path="$(printf '%s\n' "$download_json" | jq -er '.Path | select(type == "string" and length > 0)')"
  download_version="$(printf '%s\n' "$download_json" | jq -er '.Version | select(type == "string" and length > 0)')"
  download_sum="$(printf '%s\n' "$download_json" | jq -er '.Sum | select(type == "string" and length > 0)')"
  download_go_mod_sum="$(printf '%s\n' "$download_json" | jq -er '.GoModSum | select(type == "string" and length > 0)')"
  download_origin_vcs="$(printf '%s\n' "$download_json" | jq -er '.Origin.VCS | select(type == "string" and length > 0)')"
  download_origin_url="$(printf '%s\n' "$download_json" | jq -er '.Origin.URL | select(type == "string" and length > 0)')"
  download_origin_hash="$(printf '%s\n' "$download_json" | jq -er '.Origin.Hash | select(type == "string" and length > 0)')"
  download_origin_ref="$(printf '%s\n' "$download_json" | jq -er '.Origin.Ref | select(type == "string" and length > 0)')"
  [[ "$download_path" == "$cpa_module" && \
     "$download_version" == "$cpa_version" && \
     "$download_sum" == "$cpa_module_sum" && \
     "$download_go_mod_sum" == "$cpa_go_mod_sum" ]] || {
    printf 'CPA download identity mismatch for %s: got %s@%s sum=%s go_mod_sum=%s\n' \
      "$profile" "$download_path" "$download_version" "$download_sum" "$download_go_mod_sum" >&2
    exit 1
  }
  [[ "$download_origin_vcs" == git && \
     "$download_origin_url" == "$cpa_origin_url" && \
     "$download_origin_hash" == "$cpa_commit" && \
     "$download_origin_ref" == "refs/tags/$cpa_version" ]] || {
    printf 'CPA module Origin mismatch for %s: got vcs=%s url=%s hash=%s ref=%s\n' \
      "$profile" "$download_origin_vcs" "$download_origin_url" \
      "$download_origin_hash" "$download_origin_ref" >&2
    exit 1
  }

  (
    cd "$root"
    GOWORK=off CGO_ENABLED=1 "$go_bin" test \
      -mod=readonly \
      -tags=sqlite_omit_load_extension -run='^$' -count=1 \
      ./cmd/cyber-abuse-guard
    GOWORK=off CGO_ENABLED=1 "$go_bin" test \
      -mod=readonly \
      -tags=sqlite_omit_load_extension -count=1 \
      -run='^(TestRegistrationMatchesTargetCPAContract|TestRouterUsesRoleAwareConversationClassification)$' \
      ./internal/plugin
    GOWORK=off CGO_ENABLED=1 "$go_bin" test \
      -mod=readonly \
      -tags=integration,sqlite_omit_load_extension -run='^$' -count=1 \
      ./integration
    CPA_COMPAT_PROFILE="$profile" \
      CPA_COMPAT_EXPECTED_COMMIT="$cpa_commit" \
      GOWORK=off "$go_bin" -C integration/cpalatestcontract test \
      -mod=readonly -count=1 -v .
  )

  if [[ "$verify_remote" == 1 ]]; then
    printf 'CPA pinned source/compile compatibility PASS: profile=%s %s@%s remote_tag_verified=1\n' \
      "$profile" "$cpa_version" "$cpa_commit"
  else
    printf 'CPA source/compile compatibility PASS: profile=%s %s@%s remote_tag_checks=SKIPPED\n' \
      "$profile" "$cpa_version" "$cpa_commit"
  fi
done

if [[ "$verify_remote" == 1 ]]; then
  printf 'CPA pinned source/compile compatibility PASS: profile=%s %s@%s\n' \
    "${profiles[*]}" "$cpa_version" "$cpa_commit"
else
  printf 'CPA source/compile compatibility PASS: profile=%s remote_tag_checks=SKIPPED\n' "${profiles[*]}"
fi
