#!/usr/bin/env bash
# Shared, side-effect-free release metadata helpers. Callers are responsible
# for enabling `set -euo pipefail` before sourcing this file.

RELEASE_ROOT="$(cd "${BASH_SOURCE[0]%/*}/.." && pwd -P)"
export LC_ALL=C
export TZ=UTC

release_error() {
  printf 'release error: %s\n' "$*" >&2
}

release_die() {
  release_error "$*"
  exit 1
}

release_require_commands() {
  local command_name
  for command_name in "$@"; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
      printf 'required release command not found: %s\n' "$command_name" >&2
      exit 127
    fi
  done
}

release_ruleset_files() {
  local file
  shopt -s nullglob
  local files=("$RELEASE_ROOT"/rules/*.yaml)
  shopt -u nullglob
  ((${#files[@]} > 0)) || release_die "no embedded rule YAML files found"
  for file in "${files[@]}"; do
    printf '%s\n' "$file"
  done | LC_ALL=C sort
}

release_ruleset_hash() {
  local file relative hash
  while IFS= read -r file; do
    relative="${file#"$RELEASE_ROOT"/}"
    hash="$(sha256sum "$file" | awk '{print $1}')"
    printf '%s  %s\n' "$hash" "$relative"
  done < <(release_ruleset_files) | sha256sum | awk '{print $1}'
}

release_init() {
	release_require_commands git sed awk sha256sum sort head
	local buildinfo_ruleset_version unsafe_index_entries

  RELEASE_SOURCE_VERSION="$(sed -nE 's/^[[:space:]]*Version[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' \
    "$RELEASE_ROOT/internal/buildinfo/buildinfo.go" | head -n 1)"
  [[ "$RELEASE_SOURCE_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || \
    release_die "cannot read a semantic source version from internal/buildinfo/buildinfo.go"

  RELEASE_RULESET_VERSION="$(sed -nE 's/^[[:space:]]*version:[[:space:]]*"([^"]+)".*/\1/p' \
    "$RELEASE_ROOT/rules/manifest.yaml" | head -n 1)"
	[[ "$RELEASE_RULESET_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || \
		release_die "cannot read a semantic ruleset version from rules/manifest.yaml"
	buildinfo_ruleset_version="$(sed -nE 's/^[[:space:]]*RulesetVersion[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' \
		"$RELEASE_ROOT/internal/buildinfo/buildinfo.go" | head -n 1)"
	[[ "$buildinfo_ruleset_version" == "$RELEASE_RULESET_VERSION" ]] || \
		release_die "buildinfo ruleset version $buildinfo_ruleset_version does not match manifest $RELEASE_RULESET_VERSION"

  RELEASE_VERSION="${VERSION:-$RELEASE_SOURCE_VERSION}"
  [[ "$RELEASE_VERSION" == "$RELEASE_SOURCE_VERSION" ]] || \
    release_die "VERSION=$RELEASE_VERSION does not match source version $RELEASE_SOURCE_VERSION"

  RELEASE_GIT_COMMIT="$(git -C "$RELEASE_ROOT" rev-parse --verify HEAD)"
  [[ "$RELEASE_GIT_COMMIT" =~ ^[0-9a-f]{40}$ ]] || \
    release_die "Git HEAD is not a full commit SHA"

  RELEASE_DIRTY_STATUS="$(git -C "$RELEASE_ROOT" status --porcelain --untracked-files=normal)"
  case "${ALLOW_DIRTY_BUILD:-0}" in
    0)
      if [[ -n "$RELEASE_DIRTY_STATUS" ]]; then
        release_error "formal builds require a clean Git worktree"
        printf '%s\n' "$RELEASE_DIRTY_STATUS" >&2
        release_error "set ALLOW_DIRTY_BUILD=1 only for a non-release development build"
        exit 1
      fi
      unsafe_index_entries="$(git -C "$RELEASE_ROOT" ls-files -v | \
        awk 'substr($0, 1, 1) == "S" || substr($0, 1, 1) ~ /[a-z]/')"
      if [[ -n "$unsafe_index_entries" ]]; then
        release_error "formal builds reject skip-worktree and assume-unchanged index flags"
        printf '%s\n' "$unsafe_index_entries" >&2
        release_error "clear the flags and verify the tracked worktree before releasing"
        exit 1
      fi
      RELEASE_DIRTY=false
      RELEASE_ARTIFACT_VERSION="$RELEASE_VERSION"
      ;;
    1)
      RELEASE_DIRTY=true
      RELEASE_ARTIFACT_VERSION="${RELEASE_VERSION}-dirty"
      printf 'warning: ALLOW_DIRTY_BUILD=1 creates development-only artifacts marked %s\n' \
        "$RELEASE_ARTIFACT_VERSION" >&2
      ;;
    *)
      release_die "ALLOW_DIRTY_BUILD must be 0 or 1"
      ;;
  esac

  RELEASE_RULESET_SHA256="$(release_ruleset_hash)"
  [[ "$RELEASE_RULESET_SHA256" =~ ^[0-9a-f]{64}$ ]] || \
    release_die "failed to calculate the embedded ruleset SHA256"

  RELEASE_SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$RELEASE_ROOT" show -s --format=%ct HEAD)}"
  [[ "$RELEASE_SOURCE_DATE_EPOCH" =~ ^[0-9]+$ ]] || \
    release_die "SOURCE_DATE_EPOCH must be an integer"
  ((RELEASE_SOURCE_DATE_EPOCH >= 315532800)) || \
    release_die "SOURCE_DATE_EPOCH must be at or after 1980-01-01"

  export RELEASE_ROOT RELEASE_SOURCE_VERSION RELEASE_RULESET_VERSION
  export RELEASE_VERSION RELEASE_GIT_COMMIT RELEASE_DIRTY RELEASE_ARTIFACT_VERSION
  export RELEASE_RULESET_SHA256 RELEASE_SOURCE_DATE_EPOCH
}

release_assert_tag() {
  if [[ "$RELEASE_DIRTY" == true ]]; then
    printf 'development build: annotated release tag check skipped\n' >&2
    return 0
  fi
	local tag="v$RELEASE_SOURCE_VERSION"
	if [[ "${GITHUB_ACTIONS:-false}" == true ]]; then
		[[ "${GITHUB_REF_TYPE:-}" == tag ]] || \
			release_die "formal GitHub release must be triggered by a tag ref"
		[[ "${GITHUB_REF_NAME:-}" == "$tag" ]] || \
			release_die "GitHub trigger tag ${GITHUB_REF_NAME:-<unset>} does not match source tag $tag"
	fi
	[[ "$(git -C "$RELEASE_ROOT" cat-file -t "refs/tags/$tag" 2>/dev/null || true)" == tag ]] || \
    release_die "formal release requires annotated tag $tag at HEAD"
  [[ "$(git -C "$RELEASE_ROOT" rev-list -n 1 "$tag")" == "$RELEASE_GIT_COMMIT" ]] || \
    release_die "tag $tag does not point to HEAD $RELEASE_GIT_COMMIT"
}

release_assert_source_unchanged() {
  [[ "$RELEASE_DIRTY" == true ]] && return 0
  [[ "$(git -C "$RELEASE_ROOT" rev-parse --verify HEAD)" == "$RELEASE_GIT_COMMIT" ]] || \
    release_die "Git HEAD changed during the release operation"
  local current_status
  current_status="$(git -C "$RELEASE_ROOT" status --porcelain --untracked-files=normal)"
  if [[ -n "$current_status" ]]; then
    release_error "Git worktree changed during the release operation"
    printf '%s\n' "$current_status" >&2
    exit 1
  fi
}
