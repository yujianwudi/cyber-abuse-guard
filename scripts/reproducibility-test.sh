#!/usr/bin/env bash
set -euo pipefail

root="$(cd "${BASH_SOURCE[0]%/*}/.." && pwd -P)"
# shellcheck source=release-common.sh
source "$root/scripts/release-common.sh"
go_bin="${GO:-go}"
cyclonedx="${CYCLONEDX_GOMOD:-cyclonedx-gomod}"
release_require_commands "$go_bin" "$cyclonedx" git mktemp rm cmp sha256sum sed awk sort \
  mkdir

if [[ "${ALLOW_DIRTY_BUILD:-0}" != 0 ]]; then
  release_die "reproducibility-test accepts only a clean committed source tree"
fi
release_init

reproducibility_mode="${REPRODUCIBILITY_MODE:-formal}"
case "$reproducibility_mode" in
  formal)
    release_assert_tag
    artifact_version="$RELEASE_SOURCE_VERSION"
    clone_dirty_build=0
    ;;
  development)
    artifact_version="${RELEASE_SOURCE_VERSION}-dirty"
    clone_dirty_build=1
    printf '%s\n' \
      'development reproducibility mode: commit-bound dirty artifacts remain in temporary clones only' >&2
    ;;
  *)
    release_die "REPRODUCIBILITY_MODE must be formal or development"
    ;;
esac

work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT
clone_a="$work/source-a"
clone_b="$work/source-b"
git clone --quiet --no-hardlinks "$root" "$clone_a"
git clone --quiet --no-hardlinks "$root" "$clone_b"

for clone in "$clone_a" "$clone_b"; do
  [[ "$(git -C "$clone" rev-parse HEAD)" == "$RELEASE_GIT_COMMIT" ]]
  [[ -z "$(git -C "$clone" status --porcelain)" ]]
  if [[ "$reproducibility_mode" == formal ]]; then
    tag="v$RELEASE_SOURCE_VERSION"
    [[ "$(git -C "$clone" cat-file -t "refs/tags/$tag" 2>/dev/null || true)" == tag ]] || \
      release_die "clean clone is missing the real annotated release tag $tag"
    [[ "$(git -C "$clone" rev-list -n 1 "$tag")" == "$RELEASE_GIT_COMMIT" ]] || \
      release_die "clean clone tag $tag does not point to release commit"
    [[ "$(git -C "$clone" rev-parse "refs/tags/$tag^{tag}")" == \
      "$(git -C "$root" rev-parse "refs/tags/$tag^{tag}")" ]] || \
      release_die "clean clone tag object does not match the real release tag"
  fi
done

go_path="$(command -v "$go_bin")"
cyclonedx_path="$(command -v "$cyclonedx")"
for name in a b; do
  clone="$work/source-$name"
  env \
    GO="$go_path" \
    VERSION="$RELEASE_SOURCE_VERSION" \
    SOURCE_DATE_EPOCH="$RELEASE_SOURCE_DATE_EPOCH" \
    ALLOW_DIRTY_BUILD="$clone_dirty_build" \
    CYCLONEDX_GOMOD="$cyclonedx_path" \
    CYCLONEDX_GOMOD_VERSION="${CYCLONEDX_GOMOD_VERSION:-v1.9.0}" \
    GOCACHE="$work/go-build-cache-$name" \
    "$clone/scripts/build-linux-amd64.sh"
  env \
    GO="$go_path" \
    VERSION="$RELEASE_SOURCE_VERSION" \
    SOURCE_DATE_EPOCH="$RELEASE_SOURCE_DATE_EPOCH" \
    ALLOW_DIRTY_BUILD="$clone_dirty_build" \
    CYCLONEDX_GOMOD="$cyclonedx_path" \
    CYCLONEDX_GOMOD_VERSION="${CYCLONEDX_GOMOD_VERSION:-v1.9.0}" \
    "$clone/scripts/release-sbom.sh"
  env \
    GO="$go_path" \
    VERSION="$RELEASE_SOURCE_VERSION" \
    SOURCE_DATE_EPOCH="$RELEASE_SOURCE_DATE_EPOCH" \
    ALLOW_DIRTY_BUILD="$clone_dirty_build" \
    CYCLONEDX_GOMOD="$cyclonedx_path" \
    "$clone/scripts/package-release.sh"
done

so="cyber-abuse-guard-v${artifact_version}.so"
zip_name="cyber-abuse-guard_${artifact_version}_linux_amd64.zip"
sbom="sbom.cdx.json"

compare_artifact() {
  local description="$1"
  local left="$2"
  local right="$3"
  if ! cmp -s "$left" "$right"; then
    printf 'reproducibility failure: %s differ\n' "$description" >&2
    sha256sum "$left" "$right" >&2
    exit 1
  fi
}

compare_artifact "clean-clone shared objects" "$clone_a/dist/$so" "$clone_b/dist/$so"
compare_artifact "clean-clone release ZIP files" \
  "$clone_a/dist/$zip_name" "$clone_b/dist/$zip_name"
compare_artifact "clean-clone SBOM files" "$clone_a/dist/$sbom" "$clone_b/dist/$sbom"

if [[ "$reproducibility_mode" == formal ]]; then
  root_dist="${DIST_DIR:-$root/dist}"
  [[ -d "$root_dist" && ! -L "$root_dist" ]] || \
    release_die "formal reproducibility requires an existing real root artifact directory: $root_dist"
  root_artifacts=("$root_dist/$so" "$root_dist/$zip_name" "$root_dist/$sbom")
  for artifact in "${root_artifacts[@]}"; do
    [[ -f "$artifact" && ! -L "$artifact" ]] || \
      release_die "formal reproducibility requires the published artifact: $artifact"
  done

  compare_artifact "published and clean-clone shared objects" \
    "$root_dist/$so" "$clone_a/dist/$so"
  compare_artifact "published and clean-clone release ZIP files" \
    "$root_dist/$zip_name" "$clone_a/dist/$zip_name"
  compare_artifact "published and clean-clone SBOM files" \
    "$root_dist/$sbom" "$clone_a/dist/$sbom"
fi

printf 'reproducible .so: '
sha256sum "$clone_a/dist/$so" | awk '{print $1}'
printf 'reproducible ZIP: '
sha256sum "$clone_a/dist/$zip_name" | awk '{print $1}'
printf 'reproducible SBOM: '
sha256sum "$clone_a/dist/$sbom" | awk '{print $1}'
release_assert_source_unchanged
if [[ "$reproducibility_mode" == formal ]]; then
  echo "formal reproducibility passed in two real-tag clean clones and matches root/dist"
else
  echo "development reproducibility passed in two clean clones without publishing root artifacts"
fi
