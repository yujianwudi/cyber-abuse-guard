#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
go_bin="${GO:-go}"
cpa_module='github.com/router-for-me/CLIProxyAPI/v7'
cpa_latest_release_api='https://api.github.com/repos/router-for-me/CLIProxyAPI/releases/latest'
cpa_tag_ref_api='https://api.github.com/repos/router-for-me/CLIProxyAPI/git/ref/tags'

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

verify_remote="${CPA_COMPAT_VERIFY_REMOTE:-${CPA_LATEST_VERIFY_REMOTE:-0}}"
case "$verify_remote" in
  0|1) ;;
  *)
    printf 'CPA_COMPAT_VERIFY_REMOTE must be 0 or 1\n' >&2
    exit 2
    ;;
esac

select_profile() {
  case "$1" in
    primary)
      cpa_version='v7.2.86'
      cpa_commit='81d70f5d9f3fdb39a6290ed9c917ff0c6f27ca30'
      cpa_module_sum='h1:hngt58VNLMXtQ048U59kXOugcMt2Sw60M4gpmwnj1jA='
      cpa_go_mod_sum='h1:ytvZNWbCv7PrAyR80+RKsDJPODsdL6qxyFaXDBNZdqs='
      cpa_must_be_latest=1
      ;;
    *)
      printf 'internal error: unknown CPA compatibility profile %s\n' "$1" >&2
      exit 2
      ;;
  esac
}

if [[ "$verify_remote" == 1 ]]; then
  for required_command in curl jq; do
    command -v "$required_command" >/dev/null 2>&1 || {
      printf '%s is required for CPA release identity verification\n' "$required_command" >&2
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
else
  printf 'CPA remote release and tag checks skipped; set CPA_COMPAT_VERIFY_REMOTE=1 to require them\n' >&2
fi

work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT

for profile in "${profiles[@]}"; do
  select_profile "$profile"

  if [[ "$verify_remote" == 1 ]]; then
    if [[ "$cpa_must_be_latest" == 1 ]]; then
      latest_release_json="$(curl "${release_curl_args[@]}" "$cpa_latest_release_api")"
      latest_release_tag="$(printf '%s\n' "$latest_release_json" | jq -er '.tag_name | select(type == "string" and length > 0)')"
      [[ "$latest_release_tag" == "$cpa_version" ]] || {
        printf 'primary CPA release mismatch: got latest %s want pinned %s\n' "$latest_release_tag" "$cpa_version" >&2
        exit 1
      }
    fi

    tag_ref_json="$(curl "${release_curl_args[@]}" "$cpa_tag_ref_api/$cpa_version")"
    resolved_tag_type="$(printf '%s\n' "$tag_ref_json" | jq -er '.object.type | select(type == "string" and length > 0)')"
    resolved_tag_commit="$(printf '%s\n' "$tag_ref_json" | jq -er '.object.sha | select(type == "string" and length > 0)')"
    [[ "$resolved_tag_type" == commit && "$resolved_tag_commit" == "$cpa_commit" ]] || {
      printf 'CPA tag identity mismatch for %s: got type=%s commit=%s want type=commit commit=%s\n' \
        "$cpa_version" "$resolved_tag_type" "$resolved_tag_commit" "$cpa_commit" >&2
      exit 1
    }
  fi

  root_modfile="$work/root-$profile.mod"
  root_sumfile="${root_modfile%.mod}.sum"
  cp "$root/go.mod" "$root_modfile"
  cp "$root/go.sum" "$root_sumfile"
  "$go_bin" -C "$root" mod edit -modfile="$root_modfile" -require="$cpa_module@$cpa_version"
  GOWORK=off "$go_bin" -C "$root" mod tidy -modfile="$root_modfile"

  resolved="$({
    GOWORK=off "$go_bin" -C "$root" list -mod=readonly -modfile="$root_modfile" \
      -m -f '{{.Version}} {{.Sum}} {{.GoModSum}}' "$cpa_module"
  })"
  expected="$cpa_version $cpa_module_sum $cpa_go_mod_sum"
  [[ "$resolved" == "$expected" ]] || {
    printf 'root CPA module identity mismatch for %s: got %s want %s\n' "$profile" "$resolved" "$expected" >&2
    exit 1
  }

  contract_modfile="$work/contract-$profile.mod"
  contract_sumfile="${contract_modfile%.mod}.sum"
  cp "$root/integration/cpalatestcontract/go.mod" "$contract_modfile"
  cp "$root/integration/cpalatestcontract/go.sum" "$contract_sumfile"
  "$go_bin" -C "$root/integration/cpalatestcontract" mod edit \
    -modfile="$contract_modfile" -require="$cpa_module@$cpa_version"
  GOWORK=off "$go_bin" -C "$root/integration/cpalatestcontract" mod tidy -modfile="$contract_modfile"

  contract_resolved="$({
    GOWORK=off "$go_bin" -C "$root/integration/cpalatestcontract" list \
      -mod=readonly -modfile="$contract_modfile" -m \
      -f '{{.Version}} {{.Sum}} {{.GoModSum}}' "$cpa_module"
  })"
  [[ "$contract_resolved" == "$expected" ]] || {
    printf 'contract CPA module identity mismatch for %s: got %s want %s\n' \
      "$profile" "$contract_resolved" "$expected" >&2
    exit 1
  }

  (
    cd "$root"
    GOWORK=off CGO_ENABLED=1 "$go_bin" test \
      -mod=readonly -modfile="$root_modfile" \
      -tags=sqlite_omit_load_extension -run='^$' -count=1 \
      ./cmd/cyber-abuse-guard
    GOWORK=off CGO_ENABLED=1 "$go_bin" test \
      -mod=readonly -modfile="$root_modfile" \
      -tags=sqlite_omit_load_extension -count=1 \
      -run='^(TestRegistrationMatchesTargetCPAv7286Contract|TestRouterUsesRoleAwareConversationClassification)$' \
      ./internal/plugin
    GOWORK=off CGO_ENABLED=1 "$go_bin" test \
      -mod=readonly -modfile="$root_modfile" \
      -tags=integration,sqlite_omit_load_extension -run='^$' -count=1 \
      ./integration
    CPA_COMPAT_PROFILE="$profile" \
      CPA_COMPAT_MODFILE="$contract_modfile" \
      CPA_COMPAT_EXPECTED_COMMIT="$cpa_commit" \
      GOWORK=off "$go_bin" -C integration/cpalatestcontract test \
      -mod=readonly -modfile="$contract_modfile" -count=1 -v .
  )

  printf 'CPA source/compile compatibility PASS: profile=%s %s@%s latest_required=%s\n' \
    "$profile" "$cpa_version" "$cpa_commit" "$cpa_must_be_latest"
done

printf 'CPA latest source/compile compatibility PASS: profile=%s\n' "${profiles[*]}"
