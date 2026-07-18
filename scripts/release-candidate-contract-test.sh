#!/usr/bin/env bash
set -euo pipefail

root="$(cd "${BASH_SOURCE[0]%/*}/.." && pwd -P)"
# shellcheck source=release-common.sh
source "$root/scripts/release-common.sh"
release_require_commands git mktemp rm mkdir sed

work="$(mktemp -d)"
fixture="$work/repository"
cleanup() {
  rm -rf -- "$work"
}
trap cleanup EXIT

mkdir -p "$fixture/internal/buildinfo" "$fixture/internal/classifier" "$fixture/rules"
printf '%s\n' \
  'package buildinfo' \
  'const StreamingScannerIdentity = "streaming-scanner-v1"' \
  'var (' \
  '  Version = "0.15"' \
  '  RulesetVersion = "1.0.7"' \
  ')' \
  >"$fixture/internal/buildinfo/buildinfo.go"
printf '%s\n' \
  'package classifier' \
  'const ClassifierPolicyVersion = "classifier-policy-v3"' \
  'const ClassifierPolicySHA256 = "7471f3170ac832f8dc839a7da005c5d4d487c1c60f1a01eb7385e93fff49da5f"' \
  >"$fixture/internal/classifier/policy_identity.go"
printf '%s\n' 'version: "1.0.7"' 'rule_files: [rules.yaml]' >"$fixture/rules/manifest.yaml"
printf '%s\n' 'version: "1.0.7"' 'rules: []' >"$fixture/rules/rules.yaml"

git -C "$fixture" init -q
git -C "$fixture" config user.name 'Round6 Candidate Contract'
git -C "$fixture" config user.email 'candidate-contract@example.invalid'
git -C "$fixture" add .
GIT_AUTHOR_DATE='2026-07-17T00:00:00Z' GIT_COMMITTER_DATE='2026-07-17T00:00:00Z' \
  git -C "$fixture" commit -q -m baseline

commit="$(git -C "$fixture" rev-parse HEAD)"
tree="$(git -C "$fixture" rev-parse 'HEAD^{tree}')"

candidate_case() {
  RELEASE_ROOT="$fixture"
  RELEASE_CANDIDATE_BUILD="${RELEASE_CANDIDATE_BUILD:-1}"
  RELEASE_CANDIDATE_EXPECTED_COMMIT="${RELEASE_CANDIDATE_EXPECTED_COMMIT:-$commit}"
  RELEASE_CANDIDATE_EXPECTED_TREE="${RELEASE_CANDIDATE_EXPECTED_TREE:-$tree}"
  ALLOW_DIRTY_BUILD="${ALLOW_DIRTY_BUILD:-0}"
  export RELEASE_ROOT RELEASE_CANDIDATE_BUILD RELEASE_CANDIDATE_EXPECTED_COMMIT
  export RELEASE_CANDIDATE_EXPECTED_TREE ALLOW_DIRTY_BUILD
  release_init
}

run_must_pass() {
  local name="$1"
  shift
  if ("$@"); then
    printf 'candidate release contract passed: %s\n' "$name"
  else
    printf 'candidate release contract unexpectedly failed: %s\n' "$name" >&2
    exit 1
  fi
}

run_must_fail() {
  local name="$1"
  shift
  if ("$@" >/dev/null 2>&1); then
    printf 'candidate release contract unexpectedly passed: %s\n' "$name" >&2
    exit 1
  fi
  printf 'candidate release contract rejected as expected: %s\n' "$name"
}

run_must_fail_with() {
  local name="$1"
  local expected="$2"
  local output
  shift 2
  if output="$("$@" 2>&1)"; then
    printf 'candidate release contract unexpectedly passed: %s\n' "$name" >&2
    exit 1
  fi
  if [[ "$output" != *"$expected"* ]]; then
    printf 'candidate release contract failed for the wrong reason: %s\n' "$name" >&2
    printf 'expected diagnostic substring: %s\n' "$expected" >&2
    printf 'actual output:\n%s\n' "$output" >&2
    exit 1
  fi
  printf 'candidate release contract rejected with the expected diagnostic: %s\n' "$name"
}

candidate_success() {
  unset SOURCE_DATE_EPOCH
  candidate_case
  release_assert_tag
  release_assert_candidate_build
  [[ "$RELEASE_BUILD_KIND" == candidate ]]
  [[ "$RELEASE_ARTIFACT_VERSION" == 0.15 ]]
  [[ "$RELEASE_DIRTY" == false ]]
}

candidate_wrong_commit() {
  RELEASE_CANDIDATE_EXPECTED_COMMIT=0000000000000000000000000000000000000000 candidate_case
}

candidate_wrong_tree() {
  RELEASE_CANDIDATE_EXPECTED_TREE=0000000000000000000000000000000000000000 candidate_case
}

candidate_dirty_conflict() {
  ALLOW_DIRTY_BUILD=1 candidate_case
}

candidate_wrong_epoch() {
  SOURCE_DATE_EPOCH=315532800
  export SOURCE_DATE_EPOCH
  candidate_case
}

candidate_cannot_run_formal_operation() {
  candidate_case
  release_assert_formal_build
}

formal_without_tag() {
  RELEASE_ROOT="$fixture"
  ALLOW_DIRTY_BUILD=0
  RELEASE_CANDIDATE_BUILD=0
  unset SOURCE_DATE_EPOCH
  export RELEASE_ROOT ALLOW_DIRTY_BUILD RELEASE_CANDIDATE_BUILD
  release_init
  release_assert_tag
}

formal_with_annotated_tag() {
  RELEASE_ROOT="$fixture"
  ALLOW_DIRTY_BUILD=0
  RELEASE_CANDIDATE_BUILD=0
  if [[ "${GITHUB_ACTIONS:-false}" == true ]]; then
    GITHUB_REF_TYPE=tag
    GITHUB_REF_NAME=v0.15
    export GITHUB_REF_TYPE GITHUB_REF_NAME
  fi
  unset SOURCE_DATE_EPOCH
  export RELEASE_ROOT ALLOW_DIRTY_BUILD RELEASE_CANDIDATE_BUILD
  release_init
  release_assert_tag
  release_assert_formal_build
}

run_must_pass clean-exact-candidate candidate_success
run_must_fail mismatched-candidate-commit candidate_wrong_commit
run_must_fail mismatched-candidate-tree candidate_wrong_tree
run_must_fail dirty-candidate-conflict candidate_dirty_conflict
run_must_fail candidate-source-date-override candidate_wrong_epoch
run_must_fail candidate-cannot-run-formal-operation candidate_cannot_run_formal_operation
run_must_fail formal-build-without-tag formal_without_tag

git -C "$fixture" tag v0.15
run_must_fail formal-build-with-lightweight-tag formal_without_tag
run_must_fail candidate-after-lightweight-formal-tag candidate_success
git -C "$fixture" tag -d v0.15 >/dev/null

git -C "$fixture" tag -a v0.15 -m 'formal v0.15'
run_must_pass formal-build-with-annotated-tag formal_with_annotated_tag
run_must_fail candidate-after-formal-tag candidate_success
git -C "$fixture" tag -d v0.15 >/dev/null

sed -i 's/Version = "0\.15"/Version = "0.15.0"/' "$fixture/internal/buildinfo/buildinfo.go"
run_must_fail_with three-component-project-alias \
  'cannot read the exact two-component source version from internal/buildinfo/buildinfo.go' \
  candidate_success
git -C "$fixture" checkout -q -- internal/buildinfo/buildinfo.go

printf 'all candidate release contracts passed\n'
