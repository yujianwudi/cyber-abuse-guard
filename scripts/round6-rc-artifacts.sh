#!/usr/bin/env bash
set -euo pipefail

root="$(cd "${BASH_SOURCE[0]%/*}/.." && pwd -P)"
# shellcheck source=release-common.sh
source "$root/scripts/release-common.sh"
release_require_commands make git jq sha256sum awk cmp mktemp mv rm chmod mkdir \
  install find touch zip unzip tar grep wc stat

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
[[ "${RC_CI_RUN_ATTEMPT:-}" =~ ^[1-9][0-9]*$ ]] || \
  release_die "RC release assets require the admitted exact-main CI run attempt"

release_init
release_assert_tag
release_assert_rc_build
release_rc_tag_object="$(git -C "$root" rev-parse "$RELEASE_RC_TAG^{tag}")"
[[ "$release_rc_tag_object" =~ ^[0-9a-f]{40}$ ]] || \
  release_die "RC release requires the exact annotated source tag object"
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

dist="$root/dist"
so="cyber-abuse-guard-v${RELEASE_ARTIFACT_VERSION}.so"
store_zip="cyber-abuse-guard_${RELEASE_ARTIFACT_VERSION}_linux_amd64.zip"
audit_bundle="cyber-abuse-guard-v${RELEASE_ARTIFACT_VERSION}-audit-bundle.zip"
source_archive="cyber-abuse-guard-v${RELEASE_ARTIFACT_VERSION}-source.tar.gz"
test_summary="rc-release-test-summary.txt"
rc_evidence="rc-release-evidence.md"
export TZ=UTC
core_artifacts=(
  "$so"
  "$so.sha256"
  "$store_zip"
  "$audit_bundle"
  build-metadata.json
  ruleset-manifest.json
  ruleset.sha256
  sbom.cdx.json
  checksums.txt
  "$source_archive"
  "$source_archive.sha256"
)

assert_rc_sbom_identity() {
  local sbom_path="$1"
  local component_version="v$RELEASE_ARTIFACT_VERSION"
  local component_ref="pkg:golang/github.com/yujianwudi/cyber-abuse-guard@${component_version}?type=module"
  local component_purl="${component_ref}&goos=linux&goarch=amd64"

  jq -e \
    --arg version "$component_version" \
    --arg ref "$component_ref" \
    --arg purl "$component_purl" \
    '.metadata.component.name == "github.com/yujianwudi/cyber-abuse-guard" and
     .metadata.component.version == $version and
     .metadata.component["bom-ref"] == $ref and
     .metadata.component.purl == $purl and
     ([.dependencies[] | select(.ref == $ref)] | length) == 1' \
    "$sbom_path" >/dev/null || \
    release_die "RC SBOM does not bind the exact versioned main module identity: $sbom_path"
}

normalize_rc_sbom_identity() {
  local sbom_path="$1"
  local old_ref temporary
  local component_version="v$RELEASE_ARTIFACT_VERSION"
  local component_ref="pkg:golang/github.com/yujianwudi/cyber-abuse-guard@${component_version}?type=module"
  local component_purl="${component_ref}&goos=linux&goarch=amd64"

  old_ref="$(jq -er \
    '.metadata.component["bom-ref"] |
     select(type == "string" and length > 0)' "$sbom_path")" || \
    release_die "RC SBOM is missing its generated main component reference: $sbom_path"
  jq -e \
    --arg old_ref "$old_ref" \
    '.metadata.component.name == "github.com/yujianwudi/cyber-abuse-guard" and
     (.metadata.component.version | type == "string") and
     .metadata.component["bom-ref"] == $old_ref and
     ($old_ref | startswith("pkg:golang/github.com/yujianwudi/cyber-abuse-guard@")) and
     ($old_ref | endswith("?type=module")) and
     (.metadata.component.purl | type == "string") and
     (.metadata.component.purl |
       startswith("pkg:golang/github.com/yujianwudi/cyber-abuse-guard@")) and
     (.metadata.component.purl | contains("?type=module")) and
     ([.dependencies[] | select(.ref == $old_ref)] | length) == 1' \
    "$sbom_path" >/dev/null || \
    release_die "RC SBOM generated main component identity is ambiguous: $sbom_path"

  temporary="$(mktemp "${sbom_path%/*}/.sbom-rc-normalized.XXXXXX")"
  if ! jq \
    --arg version "$component_version" \
    --arg ref "$component_ref" \
    --arg purl "$component_purl" \
    '(.metadata.component["bom-ref"]) as $old_ref |
     .metadata.component.version = $version |
     .metadata.component["bom-ref"] = $ref |
     .metadata.component.purl = $purl |
     .dependencies |= map(
       (if .ref == $old_ref then .ref = $ref else . end) |
       (if has("dependsOn") then
          .dependsOn |= map(if . == $old_ref then $ref else . end)
        else . end)
     )' \
    "$sbom_path" >"$temporary"; then
    rm -f -- "$temporary"
    release_die "failed to normalize the exact RC SBOM identity: $sbom_path"
  fi
  chmod 0644 "$temporary"
  mv -f -- "$temporary" "$sbom_path"
  assert_rc_sbom_identity "$sbom_path"
}

write_rc_checksums() {
  local output_dir="$1"
  local temporary
  temporary="$(mktemp "$output_dir/.checksums.XXXXXX")"
  if ! (
    cd "$output_dir"
    sha256sum \
      "$so" \
      "$so.sha256" \
      "$store_zip" \
      "$audit_bundle" \
      build-metadata.json \
      ruleset-manifest.json \
      ruleset.sha256 \
      sbom.cdx.json
  ) >"$temporary"; then
    rm -f -- "$temporary"
    release_die "failed to regenerate checksums for the normalized RC artifacts"
  fi
  chmod 0644 "$temporary"
  mv -f -- "$temporary" "$output_dir/checksums.txt"
}

create_rc_audit_bundle() {
  local source_root="$1"
  local output_dir="$2"
  local stage expected actual verify_dir packaged_mode
  local required_files=(
    README.md
    README_CN.md
    LICENSE
    SECURITY.md
    CHANGELOG.md
    THIRD_PARTY_NOTICES.md
    config.example.yaml
    docs/AUDIT_HANDOFF.md
    docs/DESIGN.md
    docs/THREAT_MODEL.md
    docs/INSTALL_DOCKER.md
    docs/LIMITATIONS.md
    docs/README.md
    docs/archive/v0.1.2/NEXT_VERSION.md
    docs/RELEASE_POLICY.md
    docs/ROUND6_CONFIG_MIGRATION.md
    docs/ROUND6_DEVELOPMENT_HANDOFF.md
    docs/ROUND6_LIMITATIONS.md
    docs/ROUND6_RELEASE_GATE.md
    docs/ROUND6_STREAMING_SCANNER_DESIGN.md
    docs/RULES.md
    docs/reports/TEST_REPORT.md
    docs/reports/PERFORMANCE.md
    docs/reports/CORPUS_REPORT.md
    docs/reports/CPA_INTEGRATION.md
    docs/reports/PHASE0_CPA_CONTRACT.md
    docs/reports/PROMPT_INJECTION_REVIEW.md
    docs/reports/PRIVACY.md
    docs/reports/PUBLIC_JAILBREAK_REPOSITORY_REVIEW.md
    docs/reports/RELEASE_EVIDENCE.md
    scripts/check-production-health.sh
    scripts/generate-hmac-key.sh
  )

  for relative in "${required_files[@]}"; do
    [[ -f "$source_root/$relative" && ! -L "$source_root/$relative" ]] || \
      release_die "RC audit bundle input must be a regular non-symlink file: $source_root/$relative"
  done
  for relative in "$so" "$so.sha256" build-metadata.json ruleset-manifest.json \
    ruleset.sha256 sbom.cdx.json; do
    [[ -f "$output_dir/$relative" && ! -L "$output_dir/$relative" ]] || \
      release_die "RC audit bundle artifact must be a regular non-symlink file: $output_dir/$relative"
  done

  stage="$(mktemp -d)"
  mkdir -p "$stage/plugins/linux/amd64" "$stage/docs/archive/v0.1.2" \
    "$stage/docs/reports" "$stage/scripts"
  install -m 0755 "$output_dir/$so" "$stage/plugins/linux/amd64/$so"
  install -m 0644 "$output_dir/$so.sha256" \
    "$stage/plugins/linux/amd64/$so.sha256"

  for relative in "${required_files[@]}"; do
    if [[ "$relative" == */* ]]; then
      mkdir -p "$stage/${relative%/*}"
    fi
    if [[ "$relative" == scripts/* ]]; then
      install -m 0755 "$source_root/$relative" "$stage/$relative"
    else
      install -m 0644 "$source_root/$relative" "$stage/$relative"
    fi
  done
  install -m 0644 "$output_dir/build-metadata.json" \
    "$output_dir/ruleset-manifest.json" "$output_dir/ruleset.sha256" \
    "$output_dir/sbom.cdx.json" "$stage/"

  while IFS= read -r -d '' staged_path; do
    if [[ -d "$staged_path" ]]; then
      chmod 0755 "$staged_path"
    fi
    touch -h -d "@$RELEASE_SOURCE_DATE_EPOCH" "$staged_path"
  done < <(find "$stage" -print0)
  rm -f -- "$output_dir/$audit_bundle"
  (
    cd "$stage"
    find . -mindepth 1 -printf '%P\n' | LC_ALL=C sort | \
      zip -X -q "$output_dir/$audit_bundle" -@
  )
  expected="$(
    cd "$stage"
    while IFS= read -r -d '' staged_path; do
      relative="${staged_path#./}"
      if [[ -d "$staged_path" ]]; then
        printf '%s/\n' "$relative"
      else
        printf '%s\n' "$relative"
      fi
    done < <(find . -mindepth 1 -print0) | LC_ALL=C sort
  )"
  actual="$(unzip -Z1 "$output_dir/$audit_bundle" | LC_ALL=C sort)"
  [[ "$actual" == "$expected" ]] || \
    release_die "RC audit bundle content differs from its fixed allowlist"
  if unzip -Z -l "$output_dir/$audit_bundle" | awk '$1 ~ /^l/ { found = 1 } END { exit !found }'; then
    release_die "RC audit bundle contains a symbolic-link entry"
  fi
  verify_dir="$(mktemp -d)"
  (umask 000; unzip -q "$output_dir/$audit_bundle" -d "$verify_dir")
  while IFS= read -r -d '' packaged_dir; do
    [[ "$(stat -c '%a' "$packaged_dir")" == 755 ]] || \
      release_die "RC audit bundle directory mode must be 0755: $packaged_dir"
  done < <(find "$verify_dir" -mindepth 1 -type d -print0)
  [[ -f "$verify_dir/plugins/linux/amd64/$so" &&
    ! -L "$verify_dir/plugins/linux/amd64/$so" ]] || \
    release_die "RC audit bundle SO did not extract as a regular file"
  cmp -s "$output_dir/$so" "$verify_dir/plugins/linux/amd64/$so" || \
    release_die "RC audit bundle SO differs from the standalone artifact"
  [[ "$(stat -c '%a' "$verify_dir/plugins/linux/amd64/$so")" == 755 ]] || \
    release_die "RC audit bundle SO mode must be 0755"
  [[ "$(stat -c '%a' "$verify_dir/plugins/linux/amd64/$so.sha256")" == 644 ]] || \
    release_die "RC audit bundle SO checksum mode must be 0644"
  cmp -s "$output_dir/$so.sha256" \
    "$verify_dir/plugins/linux/amd64/$so.sha256" || \
    release_die "RC audit bundle SO checksum differs from the standalone sidecar"
  for relative in "${required_files[@]}"; do
    [[ -f "$verify_dir/$relative" && ! -L "$verify_dir/$relative" ]] || \
      release_die "RC audit bundle entry did not extract as a regular file: $relative"
    cmp -s "$source_root/$relative" "$verify_dir/$relative" || \
      release_die "RC audit bundle source entry differs from exact source: $relative"
    packaged_mode="$(stat -c '%a' "$verify_dir/$relative")"
    if [[ "$relative" == scripts/* ]]; then
      [[ "$packaged_mode" == 755 ]] || \
        release_die "RC audit bundle executable mode must be 0755: $relative"
    else
      [[ "$packaged_mode" == 644 ]] || \
        release_die "RC audit bundle document mode must be 0644: $relative"
    fi
  done
  for relative in build-metadata.json ruleset-manifest.json ruleset.sha256 \
    sbom.cdx.json; do
    [[ -f "$verify_dir/$relative" && ! -L "$verify_dir/$relative" ]] || \
      release_die "RC audit bundle metadata did not extract as a regular file: $relative"
    cmp -s "$output_dir/$relative" "$verify_dir/$relative" || \
      release_die "RC audit bundle metadata differs from standalone artifact: $relative"
    [[ "$(stat -c '%a' "$verify_dir/$relative")" == 644 ]] || \
      release_die "RC audit bundle metadata mode must be 0644: $relative"
  done
  rm -rf -- "$verify_dir"
  rm -rf -- "$stage"
}

create_rc_source_archive() {
  local source_root="$1"
  local output_dir="$2"
  local temporary listing
  local archive_pathspecs=(
    .
    ':(exclude,glob,icase)cmd/**/*evaluation*'
    ':(exclude,glob,icase)cmd/**/*holdout*'
    ':(exclude,glob,icase)cmd/**/*consumed*'
    ':(exclude,glob,icase)cmd/**/*private*'
    ':(exclude,glob,icase)cmd/**/*blind*'
    ':(exclude,glob,icase)cmd/**/*retired*'
    ':(exclude,glob,icase)docs/**/*EVALUATION_*'
    ':(exclude,glob,icase)docs/**/*HOLDOUT_*'
    ':(exclude,glob,icase)docs/**/*HOLDOUT_REPORT.md'
    ':(exclude,glob,icase)docs/**/*consumed*'
    ':(exclude,glob,icase)docs/**/*private*'
    ':(exclude,glob,icase)docs/**/*blind*'
    ':(exclude,glob,icase)docs/**/*retired*'
    ':(exclude,glob,icase)internal/classifier/**/*evaluation*'
    ':(exclude,glob,icase)internal/classifier/**/*holdout*'
    ':(exclude,glob,icase)internal/classifier/**/*consumed*'
    ':(exclude,glob,icase)internal/classifier/**/*private*'
    ':(exclude,glob,icase)internal/classifier/**/*blind*'
    ':(exclude,glob,icase)internal/classifier/**/*retired*'
    ':(exclude,glob,icase)testdata/**/*evaluation*'
    ':(exclude,glob,icase)testdata/**/*holdout*'
    ':(exclude,glob,icase)testdata/**/*consumed*'
    ':(exclude,glob,icase)testdata/**/*private*'
    ':(exclude,glob,icase)testdata/**/*blind*'
    ':(exclude,glob,icase)testdata/**/*retired*'
  )

  temporary="$(mktemp "$output_dir/.rc-source-release.XXXXXX")"
  git -C "$source_root" archive --format=tar.gz \
    --prefix="cyber-abuse-guard-v${RELEASE_ARTIFACT_VERSION}/" \
    --output="$temporary" "$RELEASE_GIT_COMMIT" -- "${archive_pathspecs[@]}"
  listing="$(tar -tzf "$temporary")"
  [[ -n "$listing" ]] || release_die "RC source archive is empty"
  if grep -Ev "^cyber-abuse-guard-v${RELEASE_ARTIFACT_VERSION}/" <<<"$listing" >/dev/null; then
    rm -f -- "$temporary"
    release_die "RC source archive contains an entry outside its fixed prefix"
  fi
  if grep -Eiq '(^|/)(\.git($|/)|dist($|/)|build($|/)|[^/]*\.(db|sqlite|sqlite3|key|pem|p12|pfx|jks|keystore|log)($|[-.])|\.env($|[./]))' <<<"$listing"; then
    rm -f -- "$temporary"
    release_die "RC source archive contains a forbidden repository, build, database, secret, or log path"
  fi
  if grep -Eiq '(^|/)[^/]*(evaluation|holdout|consumed|private|blind|retired)[^/]*($|/)' <<<"$listing"; then
    rm -f -- "$temporary"
    release_die "RC source archive contains restricted evaluation material"
  fi
  if tar -tvzf "$temporary" | grep -Eq '^l'; then
    rm -f -- "$temporary"
    release_die "RC source archive contains a symbolic link"
  fi
  chmod 0644 "$temporary"
  mv -f -- "$temporary" "$output_dir/$source_archive"
  (
    cd "$output_dir"
    sha256sum "$source_archive" >"$source_archive.sha256"
    sha256sum -c "$source_archive.sha256"
  )
}

rm -rf -- "$dist"
make -C "$root" -j1 ARTIFACT_VERSION="$RELEASE_ARTIFACT_VERSION" \
  round6-development-artifacts
normalize_rc_sbom_identity "$dist/sbom.cdx.json"
create_rc_audit_bundle "$root" "$dist"
create_rc_source_archive "$root" "$dist"
write_rc_checksums "$dist"
make -C "$root" -j1 ARTIFACT_VERSION="$RELEASE_ARTIFACT_VERSION" \
  round6-cpa-store-contract artifact-hash

for artifact in "${core_artifacts[@]}"; do
  [[ -f "$dist/$artifact" && ! -L "$dist/$artifact" ]] || \
    release_die "RC artifact must be a regular non-symlink file: $dist/$artifact"
done
expected_checksum_files="$(printf '%s\n' \
  "$so" "$so.sha256" "$store_zip" "$audit_bundle" build-metadata.json ruleset-manifest.json \
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

assert_rc_sbom_identity "$dist/sbom.cdx.json"

work="$(mktemp -d)"
clone_a="$work/source-a"
clone_b="$work/source-b"
cleanup() {
  rm -rf -- "$work"
}
trap cleanup EXIT

round6_sparse_clone() {
  local destination="$1"
  mkdir -m 0700 -- "$destination"
  git -C "$destination" init --quiet
  git -C "$destination" remote add origin "https://github.com/${GITHUB_REPOSITORY}.git"
  git -C "$destination" fetch --quiet --filter=blob:none --no-tags origin \
    "+refs/tags/$RELEASE_RC_TAG:refs/tags/$RELEASE_RC_TAG"
  [[ -d "$destination/.git" && ! -L "$destination/.git" ]] || \
    release_die "RC reproducibility clone must use an independent Git directory"
  [[ ! -e "$destination/.git/objects/info/alternates" ]] || \
    release_die "RC reproducibility clone must not share a local object database"
  [[ "$(git -C "$destination" tag --list)" == "$RELEASE_RC_TAG" ]] || \
    release_die "RC reproducibility clone must contain only the exact RC tag"
  [[ "$(git -C "$destination" cat-file -t "$RELEASE_RC_TAG")" == tag ]] || \
    release_die "RC reproducibility clone requires the annotated RC tag object"
  [[ "$(git -C "$destination" rev-parse "$RELEASE_RC_TAG^{tag}")" == \
    "$release_rc_tag_object" ]] || \
    release_die "RC reproducibility clone tag object differs from the admitted source tag"
  [[ "$(git -C "$destination" rev-parse "$RELEASE_RC_TAG^{commit}")" == \
    "$RELEASE_GIT_COMMIT" ]] || \
    release_die "RC reproducibility clone tag does not resolve to the expected commit"
  git -C "$destination" sparse-checkout set --no-cone \
    '/*' \
    '!/cmd/**/*[Ee][Vv][Aa][Ll][Uu][Aa][Tt][Ii][Oo][Nn]*' '!/cmd/**/*[Hh][Oo][Ll][Dd][Oo][Uu][Tt]*' '!/cmd/**/*[Cc][Oo][Nn][Ss][Uu][Mm][Ee][Dd]*' '!/cmd/**/*[Pp][Rr][Ii][Vv][Aa][Tt][Ee]*' '!/cmd/**/*[Bb][Ll][Ii][Nn][Dd]*' '!/cmd/**/*[Rr][Ee][Tt][Ii][Rr][Ee][Dd]*' \
    '!/docs/**/*[Ee][Vv][Aa][Ll][Uu][Aa][Tt][Ii][Oo][Nn]*' '!/docs/**/*[Hh][Oo][Ll][Dd][Oo][Uu][Tt]*' '!/docs/**/*[Hh][Oo][Ll][Dd][Oo][Uu][Tt]_[Rr][Ee][Pp][Oo][Rr][Tt].[Mm][Dd]' \
    '!/docs/**/*[Cc][Oo][Nn][Ss][Uu][Mm][Ee][Dd]*' '!/docs/**/*[Pp][Rr][Ii][Vv][Aa][Tt][Ee]*' '!/docs/**/*[Bb][Ll][Ii][Nn][Dd]*' '!/docs/**/*[Rr][Ee][Tt][Ii][Rr][Ee][Dd]*' \
    '!/internal/classifier/**/*[Ee][Vv][Aa][Ll][Uu][Aa][Tt][Ii][Oo][Nn]*' '!/internal/classifier/**/*[Hh][Oo][Ll][Dd][Oo][Uu][Tt]*' \
    '!/internal/classifier/**/*[Cc][Oo][Nn][Ss][Uu][Mm][Ee][Dd]*' '!/internal/classifier/**/*[Pp][Rr][Ii][Vv][Aa][Tt][Ee]*' '!/internal/classifier/**/*[Bb][Ll][Ii][Nn][Dd]*' '!/internal/classifier/**/*[Rr][Ee][Tt][Ii][Rr][Ee][Dd]*' \
    '!/testdata/**/*[Ee][Vv][Aa][Ll][Uu][Aa][Tt][Ii][Oo][Nn]*' '!/testdata/**/*[Hh][Oo][Ll][Dd][Oo][Uu][Tt]*' '!/testdata/**/*[Cc][Oo][Nn][Ss][Uu][Mm][Ee][Dd]*' '!/testdata/**/*[Pp][Rr][Ii][Vv][Aa][Tt][Ee]*' '!/testdata/**/*[Bb][Ll][Ii][Nn][Dd]*' '!/testdata/**/*[Rr][Ee][Tt][Ii][Rr][Ee][Dd]*'
  git -C "$destination" checkout --quiet --detach "$RELEASE_GIT_COMMIT"
  [[ "$(git -C "$destination" rev-parse HEAD)" == "$RELEASE_GIT_COMMIT" ]] || \
    release_die "RC reproducibility clone did not check out the expected commit"
  [[ "$(git -C "$destination" rev-parse 'HEAD^{tree}')" == "$RELEASE_GIT_TREE" ]] || \
    release_die "RC reproducibility clone did not check out the expected tree"
  [[ -z "$(git -C "$destination" status --porcelain)" ]] || \
    release_die "RC reproducibility clone is not clean after checkout"
}

round6_sparse_clone "$clone_a"
round6_sparse_clone "$clone_b"
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
      round6-development-artifacts
  normalize_rc_sbom_identity "$clone/dist/sbom.cdx.json"
  create_rc_audit_bundle "$clone" "$clone/dist"
  create_rc_source_archive "$clone" "$clone/dist"
  write_rc_checksums "$clone/dist"
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
      round6-cpa-store-contract artifact-hash
  [[ -z "$(git -C "$clone" status --porcelain)" ]] || \
    release_die "RC reproducibility source $name became dirty"
  assert_rc_sbom_identity "$clone/dist/sbom.cdx.json"
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

summary_input="${RC_TEST_SUMMARY_INPUT:-}"
[[ -n "$summary_input" ]] || \
  release_die "RC_TEST_SUMMARY_INPUT is required for formal-structure RC packaging"
[[ -f "$summary_input" && ! -L "$summary_input" ]] || \
  release_die "RC test summary input must be a regular non-symlink file"
summary_size="$(wc -c <"$summary_input")"
[[ "$summary_size" =~ ^[0-9]+$ ]] || release_die "RC test summary size is invalid"
((summary_size > 0 && summary_size <= 16777216)) || \
  release_die "RC test summary must be between 1 byte and 16 MiB"
for marker in \
  "commit=$RELEASE_GIT_COMMIT" \
  "tree=$RELEASE_GIT_TREE" \
  "exact_main_ci_run=$RC_CI_RUN_ID" \
  "exact_main_ci_attempt=$RC_CI_RUN_ATTEMPT" \
  "rc_gate.safe_contract=PASS" \
  "rc_gate.full_linux_quality=PASS" \
  "rc_gate.cpa_v7.2.88_source_compatibility=PASS" \
  "rc_gate.rc_integration=PASS" \
  "rc_gate.clean_tree=PASS"; do
  [[ "$(grep -Fxc "$marker" "$summary_input")" == 1 ]] || \
    release_die "RC test summary is missing exact successful gate marker: $marker"
done
release_assert_no_sensitive_env_values "$summary_input" \
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
install -m 0644 "$summary_input" "$dist/$test_summary"
(
  cd "$dist"
  sha256sum "$test_summary" >"$test_summary.sha256"
  sha256sum -c "$test_summary.sha256"
)

evidence="$dist/$rc_evidence"
evidence_temporary="$(mktemp "$dist/.rc-release-evidence.XXXXXX")"
{
  printf '# CPA Cyber Abuse Guard v%s release-candidate evidence\n\n' \
    "$RELEASE_ARTIFACT_VERSION"
  printf 'Status: RC_INTERNAL_GATES_PASS / SANDBOX_ONLY / SERVER_VALIDATION_REQUIRED / NOT_FORMAL / NOT_ROUND6_CANDIDATE\n\n'
  printf 'This record proves the internal Linux build, test, packaging, and reproducibility gates for this exact RC. '
  printf 'It does not claim real CPA Host validation, independent audit, independent evaluation, formal release approval, or production authorization.\n\n'
  printf -- '- Tag: %s\n' "$RELEASE_RC_TAG"
  printf -- '- Annotated tag object: %s\n' "$release_rc_tag_object"
  printf -- '- Commit: %s\n' "$RELEASE_GIT_COMMIT"
  printf -- '- Tree: %s\n' "$RELEASE_GIT_TREE"
  printf -- '- Exact-main CI run: https://github.com/%s/actions/runs/%s\n' \
    "$GITHUB_REPOSITORY" "$RC_CI_RUN_ID"
  printf -- '- Exact-main CI run attempt: %s\n' "$RC_CI_RUN_ATTEMPT"
  printf -- '- Release workflow run: https://github.com/%s/actions/runs/%s\n' \
    "$GITHUB_REPOSITORY" "$GITHUB_RUN_ID"
  printf -- '- Platform: linux/amd64, CGO enabled\n'
  printf -- '- CPA source/compile compatibility: PASS, v7.2.88 at 93d74a890a44802f656d7f39a573916b2611896e\n'
  printf -- '- Real CPA Host validation: NOT_RUN / SERVER_SANDBOX_REQUIRED\n'
  printf -- '- Independent audit: NOT_PROVIDED\n'
  printf -- '- Independent evaluation: NOT_PROVIDED\n\n'
  printf '## Artifact hashes\n\n'
  for name in \
    "$so" "$so.sha256" "$store_zip" "$audit_bundle" build-metadata.json \
    checksums.txt ruleset-manifest.json ruleset.sha256 sbom.cdx.json \
    "$test_summary" "$test_summary.sha256" "$source_archive" \
    "$source_archive.sha256"; do
    printf -- '- %s: %s\n' "$name" "$(hash_file "$dist/$name")"
  done
} >"$evidence_temporary"
release_assert_no_sensitive_env_values "$evidence_temporary" \
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
chmod 0644 "$evidence_temporary"
mv -f -- "$evidence_temporary" "$evidence"
(
  cd "$dist"
  sha256sum "$rc_evidence" >"$rc_evidence.sha256"
  sha256sum -c "$rc_evidence.sha256"
)

manifest="$dist/rc-release-manifest.json"
temporary="$(mktemp "$dist/.rc-release-manifest.XXXXXX")"
jq -n \
  --arg source_version "$RELEASE_SOURCE_VERSION" \
  --arg artifact_version "$RELEASE_ARTIFACT_VERSION" \
  --arg tag "$RELEASE_RC_TAG" \
  --arg tag_object "$release_rc_tag_object" \
  --arg commit "$RELEASE_GIT_COMMIT" \
  --arg tree "$RELEASE_GIT_TREE" \
  --argjson source_date_epoch "$RELEASE_SOURCE_DATE_EPOCH" \
  --argjson ci_run_id "$RC_CI_RUN_ID" \
  --argjson ci_run_attempt "$RC_CI_RUN_ATTEMPT" \
  --arg repository "$GITHUB_REPOSITORY" \
  --arg workflow_ref "$GITHUB_WORKFLOW_REF" \
  --arg workflow_sha "$RELEASE_RC_WORKFLOW_SHA" \
  --arg ref "$GITHUB_REF" \
  --argjson run_id "$GITHUB_RUN_ID" \
  --argjson run_attempt "$GITHUB_RUN_ATTEMPT" \
  --arg so "$so" \
  --arg so_sha256 "$(hash_file "$dist/$so")" \
  --arg so_sidecar_sha256 "$(hash_file "$dist/$so.sha256")" \
  --arg store_zip "$store_zip" \
  --arg store_zip_sha256 "$(hash_file "$dist/$store_zip")" \
  --arg audit_bundle "$audit_bundle" \
  --arg audit_bundle_sha256 "$(hash_file "$dist/$audit_bundle")" \
  --arg build_metadata_sha256 "$(hash_file "$dist/build-metadata.json")" \
  --arg checksums_sha256 "$(hash_file "$dist/checksums.txt")" \
  --arg ruleset_manifest_sha256 "$(hash_file "$dist/ruleset-manifest.json")" \
  --arg ruleset_sha256 "$(hash_file "$dist/ruleset.sha256")" \
  --arg sbom_sha256 "$(hash_file "$dist/sbom.cdx.json")" \
  --arg test_summary "$test_summary" \
  --arg test_summary_sha256 "$(hash_file "$dist/$test_summary")" \
  --arg test_summary_sidecar_sha256 "$(hash_file "$dist/$test_summary.sha256")" \
  --arg rc_evidence "$rc_evidence" \
  --arg rc_evidence_sha256 "$(hash_file "$dist/$rc_evidence")" \
  --arg rc_evidence_sidecar_sha256 "$(hash_file "$dist/$rc_evidence.sha256")" \
  --arg source_archive "$source_archive" \
  --arg source_archive_sha256 "$(hash_file "$dist/$source_archive")" \
  --arg source_archive_sidecar_sha256 "$(hash_file "$dist/$source_archive.sha256")" \
  '{
    schema_version: 2,
    status: "RC_INTERNAL_GATES_PASS / SANDBOX_ONLY / SERVER_VALIDATION_REQUIRED / NOT_FORMAL / NOT_ROUND6_CANDIDATE",
    packaging_profile: "FORMAL_STRUCTURE / RC EVIDENCE ONLY / NO FORMAL ATTESTATION",
    source_version: $source_version,
    artifact_version: $artifact_version,
    tag: $tag,
    tag_object: $tag_object,
    commit: $commit,
    tree: $tree,
    source_date_epoch: $source_date_epoch,
    ci_run_id: $ci_run_id,
    ci_run_attempt: $ci_run_attempt,
    cpa: {
      version: "v7.2.88",
      commit: "93d74a890a44802f656d7f39a573916b2611896e",
      source_compatibility: "PASS",
      real_host_validation: "NOT_RUN / SERVER_SANDBOX_REQUIRED"
    },
    independent_audit: "NOT_PROVIDED",
    independent_evaluation: "NOT_PROVIDED",
    workflow: {
      repository: $repository,
      ref: $workflow_ref,
      sha: $workflow_sha,
      dispatch_ref: $ref,
      run_id: $run_id,
      run_attempt: $run_attempt
    },
    artifacts: {
      so: {
        name: $so,
        sha256: $so_sha256,
        sidecar_sha256: $so_sidecar_sha256
      },
      store_zip: {name: $store_zip, sha256: $store_zip_sha256},
      audit_bundle: {name: $audit_bundle, sha256: $audit_bundle_sha256},
      build_metadata_sha256: $build_metadata_sha256,
      checksums_sha256: $checksums_sha256,
      ruleset_manifest_sha256: $ruleset_manifest_sha256,
      ruleset_sha256: $ruleset_sha256,
      sbom_sha256: $sbom_sha256,
      test_summary: {
        name: $test_summary,
        sha256: $test_summary_sha256,
        sidecar_sha256: $test_summary_sidecar_sha256
      },
      rc_evidence: {
        name: $rc_evidence,
        sha256: $rc_evidence_sha256,
        sidecar_sha256: $rc_evidence_sidecar_sha256
      },
      source_archive: {
        name: $source_archive,
        sha256: $source_archive_sha256,
        sidecar_sha256: $source_archive_sidecar_sha256
      }
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

expected_dist_files="$(printf '%s\n' \
  "$so" \
  "$so.sha256" \
  "$store_zip" \
  "$audit_bundle" \
  build-metadata.json \
  checksums.txt \
  ruleset-manifest.json \
  ruleset.sha256 \
  sbom.cdx.json \
  "$test_summary" \
  "$test_summary.sha256" \
  "$rc_evidence" \
  "$rc_evidence.sha256" \
  "$source_archive" \
  "$source_archive.sha256" \
  rc-release-manifest.json \
  rc-release-manifest.json.sha256 | LC_ALL=C sort)"
actual_dist_files="$(find "$dist" -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C sort)"
[[ "$actual_dist_files" == "$expected_dist_files" ]] || \
  release_die "RC dist directory does not contain exactly the 17 reviewed assets"
while IFS= read -r name; do
  [[ -f "$dist/$name" && ! -L "$dist/$name" ]] || \
    release_die "RC published asset must be a regular non-symlink file: $name"
done <<<"$expected_dist_files"
(
  cd "$dist"
  sha256sum -c checksums.txt
  sha256sum -c "$so.sha256"
  sha256sum -c ruleset.sha256
  sha256sum -c "$test_summary.sha256"
  sha256sum -c "$rc_evidence.sha256"
  sha256sum -c "$source_archive.sha256"
  sha256sum -c rc-release-manifest.json.sha256
)
for forbidden in round6-prerelease-attestation.json formal-release-attestation.json \
  release-evidence-final.md FORMAL_GATES_PASS; do
  [[ ! -e "$dist/$forbidden" ]] || \
    release_die "RC release must not emit formal evidence asset: $forbidden"
done

release_assert_source_unchanged
printf 'RC release assets and reproducibility verified: %s\n' "$dist"
