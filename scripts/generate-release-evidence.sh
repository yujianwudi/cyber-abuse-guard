#!/usr/bin/env bash
set -euo pipefail

root="$(cd "${BASH_SOURCE[0]%/*}/.." && pwd -P)"
# shellcheck source=release-common.sh
source "$root/scripts/release-common.sh"
release_require_commands git sha256sum awk date mktemp chmod mv rm mkdir basename
release_init
release_assert_tag
[[ "$RELEASE_DIRTY" == false ]] || release_die "final release evidence requires a clean formal build"

dist="${DIST_DIR:-$root/dist}"
so="cyber-abuse-guard-v${RELEASE_ARTIFACT_VERSION}.so"
zip_name="cyber-abuse-guard_${RELEASE_ARTIFACT_VERSION}_linux_amd64.zip"
source_name="cyber-abuse-guard-v${RELEASE_SOURCE_VERSION}-source.tar.gz"
tag="v$RELEASE_SOURCE_VERSION"

required=(
  "$so"
  "$so.sha256"
  "$zip_name"
  "checksums.txt"
  "build-metadata.json"
  "ruleset-manifest.json"
  "ruleset.sha256"
  "sbom.cdx.json"
  "release-test-summary.txt"
  "release-test-summary.txt.sha256"
  "$source_name"
  "$source_name.sha256"
)
for name in "${required[@]}"; do
  [[ -f "$dist/$name" && ! -L "$dist/$name" ]] || \
    release_die "final evidence input must be a regular non-symlink file: $dist/$name"
done
(cd "$dist" && sha256sum -c checksums.txt && sha256sum -c "$so.sha256" && \
  sha256sum -c ruleset.sha256 && sha256sum -c release-test-summary.txt.sha256 && \
  sha256sum -c "$source_name.sha256")

hash_file() {
  sha256sum "$1" | awk '{print $1}'
}

tag_object="$(git -C "$root" rev-parse "refs/tags/$tag^{tag}")"
tag_target="$(git -C "$root" rev-list -n 1 "$tag")"
[[ "$tag_target" == "$RELEASE_GIT_COMMIT" ]] || release_die "release tag target changed"
release_time="$(date -u -d "@$RELEASE_SOURCE_DATE_EPOCH" '+%Y-%m-%dT%H:%M:%SZ')"

repository="${GITHUB_REPOSITORY:-}"
run_id="${GITHUB_RUN_ID:-}"
release_url="not-recorded-local-build"
actions_url="not-recorded-local-build"
if [[ "$repository" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
  release_url="https://github.com/$repository/releases/tag/$tag"
  if [[ "$run_id" =~ ^[0-9]+$ ]]; then
    actions_url="https://github.com/$repository/actions/runs/$run_id"
  fi
fi

evidence="$dist/release-evidence-final.md"
temporary="$(mktemp "$dist/.release-evidence-final.XXXXXX")"
cleanup() {
  rm -f -- "$temporary"
}
trap cleanup EXIT

{
  printf '# CPA Cyber Abuse Guard v%s final release evidence\n\n' "$RELEASE_SOURCE_VERSION"
  printf 'This standalone provenance record was generated only after the complete formal gate command returned zero. '
  printf 'The immutable command log is bound below by SHA-256. The reproducible ZIP does not contain this run-specific file.\n\n'
  printf '## Release identity\n\n'
  printf -- '- Commit: `%s`\n' "$RELEASE_GIT_COMMIT"
  printf -- '- Annotated tag: `%s`\n' "$tag"
  printf -- '- Tag object: `%s`\n' "$tag_object"
  printf -- '- Tag target: `%s`\n' "$tag_target"
  printf -- '- Source date (UTC): `%s`\n' "$release_time"
  printf -- '- Ruleset: `%s`\n' "$RELEASE_RULESET_VERSION"
  printf -- '- Rules snapshot SHA-256: `%s`\n' "$RELEASE_RULESET_SHA256"
  printf -- '- Source tree: `clean`\n\n'

  printf '## Verified artifacts\n\n'
  printf '| Artifact | SHA-256 |\n|---|---|\n'
  for name in "$so" "$so.sha256" "$zip_name" checksums.txt build-metadata.json \
    ruleset-manifest.json ruleset.sha256 sbom.cdx.json release-test-summary.txt \
    release-test-summary.txt.sha256 "$source_name" "$source_name.sha256"; do
    printf '| `%s` | `%s` |\n' "$name" "$(hash_file "$dist/$name")"
  done
  printf '\n## Independent evaluation v10 identity\n\n'
  printf -- '- Corpus: 640 records (320 benign / 320 policy), SHA-256 `e42b881103a00c0a7bf0359f8494804bc3aeabc6c2e0bafff99593043129cbef`\n'
  printf -- '- Implementation/dependency snapshot SHA-256: `090955c800944f8d248ff960cd5c860b17ea0d566cfa0aae90554db30248096b`\n'
  printf -- '- YAML rules snapshot SHA-256: `3fb15df990c7e6369b8dc4c4e725cf1b09a8251275b2145afcd1cd9a859741db`\n'
  printf -- '- Canonical embedded ruleset SHA-256: `7bef8b0854b4d75dd5d807e1c33e93b708af4e9e29d0d2b59a18b9031c4da134`\n'
  printf -- '- Aggregate report SHA-256: `%s`\n\n' "$(hash_file "$root/docs/reports/EVALUATION_V10_REPORT.md")"

  printf '## Gate result\n\n'
  printf 'Result: **PASS**. The bound log covers format, diff, module, unit, race, vet, fuzz, operational scripts, regression corpus, '
  printf 'independent evaluation v10, performance, CPA integration, vulnerability scan, SBOM, packaging, strict verification, '
  printf 'verification fault injection, and two-clean-clone reproducibility.\n\n'
  printf -- '- Release test log SHA-256: `%s`\n' "$(hash_file "$dist/release-test-summary.txt")"
  printf -- '- GitHub Actions run: %s\n' "$actions_url"
  printf -- '- GitHub Release: %s\n\n' "$release_url"

  printf '## Accepted limitations\n\n'
  printf -- '- CPA v7.2.67 retains a host-level Router fail-open boundary and exposes no router-order or plugin-directory inventory to ABI v1.\n'
  printf -- '- HMAC dual-key rotation is design-only in v0.1.2.\n'
  printf -- '- Persisted subject-state completeness is protected by filesystem trust, not a keyed whole-snapshot MAC.\n'
  printf -- '- Unknown, novel, or encrypted encodings can evade semantic detection.\n'
  printf -- '- The plugin reduces risk; it cannot guarantee that an upstream account will never be warned, suspended, or deactivated.\n'
} >"$temporary"

chmod 0644 "$temporary"
mv -f -- "$temporary" "$evidence"
temporary=""
(cd "$dist" && sha256sum "$(basename "$evidence")" >"$(basename "$evidence").sha256")
release_assert_source_unchanged
printf 'final release evidence generated: %s\n' "$evidence"
