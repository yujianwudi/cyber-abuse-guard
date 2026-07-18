#!/usr/bin/env bash
set -euo pipefail

root="$(cd "${BASH_SOURCE[0]%/*}/.." && pwd -P)"
# shellcheck source=release-common.sh
source "$root/scripts/release-common.sh"
release_require_commands make git jq sha256sum awk cmp mktemp mv rm chmod mkdir

[[ "${GITHUB_ACTIONS:-false}" == true ]] || \
  release_die "RC release assets may only be produced by GitHub Actions"
[[ "${GITHUB_EVENT_NAME:-}" == workflow_dispatch ]] || \
  release_die "RC release assets require the dedicated manual workflow"
[[ "${GITHUB_REPOSITORY:-}" == yujianwudi/cyber-abuse-guard ]] || \
  release_die "RC release assets require the canonical repository"
[[ "${GITHUB_RUN_ID:-}" =~ ^[1-9][0-9]*$ ]] || \
  release_die "RC release assets require a numeric GitHub run ID"
[[ "${GITHUB_RUN_ATTEMPT:-}" =~ ^[1-9][0-9]*$ ]] || \
  release_die "RC release assets require a numeric GitHub run attempt"
[[ "${RC_CI_RUN_ID:-}" =~ ^[1-9][0-9]*$ ]] || \
  release_die "RC release assets require the admitted exact-main CI run ID"

release_init
release_assert_tag
release_assert_rc_build
[[ "${GITHUB_REF:-}" == "refs/tags/$RELEASE_RC_TAG" ]] || \
  release_die "RC release assets require the exact annotated tag ref"
[[ "${GITHUB_SHA:-}" == "$RELEASE_GIT_COMMIT" ]] || \
  release_die "GitHub dispatch SHA does not match the RC commit"
[[ "${RELEASE_RC_WORKFLOW_SHA:-}" == "$RELEASE_GIT_COMMIT" ]] || \
  release_die "RC workflow source SHA does not match the RC commit"
[[ "${GITHUB_WORKFLOW_REF:-}" == \
  "${GITHUB_REPOSITORY}/.github/workflows/release-rc.yml@refs/tags/$RELEASE_RC_TAG" ]] || \
  release_die "RC assets require the pinned release-rc workflow ref"

export RELEASE_RC_BUILD RELEASE_RC_TAG RELEASE_RC_EXPECTED_COMMIT RELEASE_RC_EXPECTED_TREE
export ROUND6_SAFE_SPARSE_BUILD=1
export REQUIRE_DIST_ARTIFACTS=1

rm -rf -- "$root/dist"
make -C "$root" -j1 ARTIFACT_VERSION="$RELEASE_ARTIFACT_VERSION" \
  round6-development-artifacts round6-cpa-store-contract artifact-hash

dist="$root/dist"
so="cyber-abuse-guard-v${RELEASE_ARTIFACT_VERSION}.so"
store_zip="cyber-abuse-guard_${RELEASE_ARTIFACT_VERSION}_linux_amd64.zip"
core_artifacts=(
  "$so"
  "$so.sha256"
  "$store_zip"
  build-metadata.json
  checksums.txt
  ruleset-manifest.json
  ruleset.sha256
  sbom.cdx.json
)
for artifact in "${core_artifacts[@]}"; do
  [[ -f "$dist/$artifact" && ! -L "$dist/$artifact" ]] || \
    release_die "RC artifact must be a regular non-symlink file: $dist/$artifact"
done
expected_checksum_files="$(printf '%s\n' \
  "$so" "$so.sha256" "$store_zip" build-metadata.json ruleset-manifest.json \
  ruleset.sha256 sbom.cdx.json | LC_ALL=C sort)"
actual_checksum_files="$(awk '{print $2}' "$dist/checksums.txt" | LC_ALL=C sort)"
[[ "$actual_checksum_files" == "$expected_checksum_files" ]] || \
  release_die "RC checksums.txt does not cover exactly the published core artifacts"
for forbidden in round6-prerelease-attestation.json formal-release-attestation.json; do
  [[ ! -e "$dist/$forbidden" ]] || \
    release_die "RC release must not emit formal evidence asset: $forbidden"
done

jq -e \
  --arg version "$RELEASE_ARTIFACT_VERSION" \
  --arg source_version "$RELEASE_SOURCE_VERSION" \
  --arg commit "$RELEASE_GIT_COMMIT" \
  --arg tree "$RELEASE_GIT_TREE" \
  '.version == $version and .source_version == $source_version and
   .commit == $commit and .tree == $tree and .dirty == false and
   .goos == "linux" and .goarch == "amd64" and .cgo_enabled == true' \
  "$dist/build-metadata.json" >/dev/null || \
  release_die "RC build metadata does not describe the clean exact Linux amd64 source"

work="$(mktemp -d)"
clone_a="$work/source-a"
clone_b="$work/source-b"
cleanup() {
  git -C "$root" worktree remove --force "$clone_a" >/dev/null 2>&1 || true
  git -C "$root" worktree remove --force "$clone_b" >/dev/null 2>&1 || true
  rm -rf -- "$work"
}
trap cleanup EXIT

round6_sparse_worktree() {
  local destination="$1"
  git -C "$root" worktree add --quiet --detach --no-checkout "$destination" "$RELEASE_GIT_COMMIT"
  git -C "$destination" sparse-checkout set --no-cone \
    '/*' \
    '!/cmd/**/*[Ee][Vv][Aa][Ll][Uu][Aa][Tt][Ii][Oo][Nn]*' '!/cmd/**/*[Hh][Oo][Ll][Dd][Oo][Uu][Tt]*' '!/cmd/**/*[Cc][Oo][Nn][Ss][Uu][Mm][Ee][Dd]*' '!/cmd/**/*[Pp][Rr][Ii][Vv][Aa][Tt][Ee]*' '!/cmd/**/*[Bb][Ll][Ii][Nn][Dd]*' '!/cmd/**/*[Rr][Ee][Tt][Ii][Rr][Ee][Dd]*' \
    '!/docs/**/*[Ee][Vv][Aa][Ll][Uu][Aa][Tt][Ii][Oo][Nn]*' '!/docs/**/*[Hh][Oo][Ll][Dd][Oo][Uu][Tt]*' '!/docs/**/*[Hh][Oo][Ll][Dd][Oo][Uu][Tt]_[Rr][Ee][Pp][Oo][Rr][Tt].[Mm][Dd]' \
    '!/docs/**/*[Cc][Oo][Nn][Ss][Uu][Mm][Ee][Dd]*' '!/docs/**/*[Pp][Rr][Ii][Vv][Aa][Tt][Ee]*' '!/docs/**/*[Bb][Ll][Ii][Nn][Dd]*' '!/docs/**/*[Rr][Ee][Tt][Ii][Rr][Ee][Dd]*' \
    '!/internal/classifier/**/*[Ee][Vv][Aa][Ll][Uu][Aa][Tt][Ii][Oo][Nn]*' '!/internal/classifier/**/*[Hh][Oo][Ll][Dd][Oo][Uu][Tt]*' \
    '!/internal/classifier/**/*[Cc][Oo][Nn][Ss][Uu][Mm][Ee][Dd]*' '!/internal/classifier/**/*[Pp][Rr][Ii][Vv][Aa][Tt][Ee]*' '!/internal/classifier/**/*[Bb][Ll][Ii][Nn][Dd]*' '!/internal/classifier/**/*[Rr][Ee][Tt][Ii][Rr][Ee][Dd]*' \
    '!/testdata/**/*[Ee][Vv][Aa][Ll][Uu][Aa][Tt][Ii][Oo][Nn]*' '!/testdata/**/*[Hh][Oo][Ll][Dd][Oo][Uu][Tt]*' '!/testdata/**/*[Cc][Oo][Nn][Ss][Uu][Mm][Ee][Dd]*' '!/testdata/**/*[Pp][Rr][Ii][Vv][Aa][Tt][Ee]*' '!/testdata/**/*[Bb][Ll][Ii][Nn][Dd]*' '!/testdata/**/*[Rr][Ee][Tt][Ii][Rr][Ee][Dd]*'
  git -C "$destination" checkout --quiet "$RELEASE_GIT_COMMIT"
}

round6_sparse_worktree "$clone_a"
round6_sparse_worktree "$clone_b"
go_path="$(command -v "${GO:-go}")"
cyclonedx_path="$(command -v "${CYCLONEDX_GOMOD:-cyclonedx-gomod}")"

for name in a b; do
  clone="$work/source-$name"
  env \
    GO="$go_path" \
    VERSION="$RELEASE_SOURCE_VERSION" \
    SOURCE_DATE_EPOCH="$RELEASE_SOURCE_DATE_EPOCH" \
    RELEASE_RC_BUILD=1 \
    RELEASE_RC_TAG="$RELEASE_RC_TAG" \
    RELEASE_RC_EXPECTED_COMMIT="$RELEASE_GIT_COMMIT" \
    RELEASE_RC_EXPECTED_TREE="$RELEASE_GIT_TREE" \
    ROUND6_SAFE_SPARSE_BUILD=1 \
    REQUIRE_DIST_ARTIFACTS=1 \
    CYCLONEDX_GOMOD="$cyclonedx_path" \
    CYCLONEDX_GOMOD_VERSION="${CYCLONEDX_GOMOD_VERSION:-v1.9.0}" \
    GOCACHE="$work/go-build-cache-$name" \
    make -C "$clone" -j1 ARTIFACT_VERSION="$RELEASE_ARTIFACT_VERSION" \
      round6-development-artifacts round6-cpa-store-contract artifact-hash
  [[ -z "$(git -C "$clone" status --porcelain)" ]] || \
    release_die "RC reproducibility source $name became dirty"
done

for artifact in "${core_artifacts[@]}"; do
  cmp -s "$clone_a/dist/$artifact" "$clone_b/dist/$artifact" || \
    release_die "RC reproducibility clones differ for $artifact"
  cmp -s "$dist/$artifact" "$clone_a/dist/$artifact" || \
    release_die "root RC artifact differs from clean clone for $artifact"
done

hash_file() {
  sha256sum "$1" | awk '{print $1}'
}

manifest="$dist/rc-release-manifest.json"
temporary="$(mktemp "$dist/.rc-release-manifest.XXXXXX")"
jq -n \
  --arg source_version "$RELEASE_SOURCE_VERSION" \
  --arg artifact_version "$RELEASE_ARTIFACT_VERSION" \
  --arg tag "$RELEASE_RC_TAG" \
  --arg commit "$RELEASE_GIT_COMMIT" \
  --arg tree "$RELEASE_GIT_TREE" \
  --argjson source_date_epoch "$RELEASE_SOURCE_DATE_EPOCH" \
  --argjson ci_run_id "$RC_CI_RUN_ID" \
  --arg repository "$GITHUB_REPOSITORY" \
  --arg workflow_ref "$GITHUB_WORKFLOW_REF" \
  --arg workflow_sha "$RELEASE_RC_WORKFLOW_SHA" \
  --arg ref "$GITHUB_REF" \
  --argjson run_id "$GITHUB_RUN_ID" \
  --argjson run_attempt "$GITHUB_RUN_ATTEMPT" \
  --arg so "$so" \
  --arg so_sha256 "$(hash_file "$dist/$so")" \
  --arg store_zip "$store_zip" \
  --arg store_zip_sha256 "$(hash_file "$dist/$store_zip")" \
  --arg build_metadata_sha256 "$(hash_file "$dist/build-metadata.json")" \
  --arg checksums_sha256 "$(hash_file "$dist/checksums.txt")" \
  --arg ruleset_manifest_sha256 "$(hash_file "$dist/ruleset-manifest.json")" \
  --arg ruleset_sha256 "$(hash_file "$dist/ruleset.sha256")" \
  --arg sbom_sha256 "$(hash_file "$dist/sbom.cdx.json")" \
  '{
    schema_version: 1,
    status: "SANDBOX_ONLY / SERVER_VALIDATION_REQUIRED / NOT_FORMAL / NOT_ROUND6_CANDIDATE",
    source_version: $source_version,
    artifact_version: $artifact_version,
    tag: $tag,
    commit: $commit,
    tree: $tree,
    source_date_epoch: $source_date_epoch,
    ci_run_id: $ci_run_id,
    cpa: {
      version: "v7.2.86",
      commit: "81d70f5d9f3fdb39a6290ed9c917ff0c6f27ca30",
      real_host_validation: "NOT_RUN / SERVER_SANDBOX_REQUIRED"
    },
    workflow: {
      repository: $repository,
      ref: $workflow_ref,
      sha: $workflow_sha,
      dispatch_ref: $ref,
      run_id: $run_id,
      run_attempt: $run_attempt
    },
    artifacts: {
      so: {name: $so, sha256: $so_sha256},
      store_zip: {name: $store_zip, sha256: $store_zip_sha256},
      build_metadata_sha256: $build_metadata_sha256,
      checksums_sha256: $checksums_sha256,
      ruleset_manifest_sha256: $ruleset_manifest_sha256,
      ruleset_sha256: $ruleset_sha256,
      sbom_sha256: $sbom_sha256
    }
  }' >"$temporary"

release_assert_no_sensitive_env_values "$temporary" \
  CPA_MANAGEMENT_KEY \
  CYBER_ABUSE_GUARD_HMAC_KEY \
  CYBER_ABUSE_GUARD_HMAC_KEY_FILE \
  GITHUB_TOKEN \
  GH_TOKEN \
  OPENAI_API_KEY \
  ANTHROPIC_API_KEY \
  GOOGLE_API_KEY \
  AZURE_OPENAI_API_KEY \
  AWS_SECRET_ACCESS_KEY \
  DATABASE_URL
chmod 0644 "$temporary"
mv -f -- "$temporary" "$manifest"
(cd "$dist" && sha256sum rc-release-manifest.json >rc-release-manifest.json.sha256 && \
  sha256sum -c rc-release-manifest.json.sha256)

release_assert_source_unchanged
printf 'RC release assets and reproducibility verified: %s\n' "$dist"
