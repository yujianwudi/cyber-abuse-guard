# CPA v7.2.88 Integration Report

```text
current_classifier_policy_version: classifier-policy-v5
current_classifier_policy_sha256: 07e972eac4faba57ca5244e9a49d5db21d5c0e414778bf617b5378fa621b4f76
```

## Active compatibility target

Cyber Abuse Guard pins active validation and the supported release/Host target to
`github.com/router-for-me/CLIProxyAPI/v7` `v7.2.88` at commit
`93d74a890a44802f656d7f39a573916b2611896e`.

The root module and both isolated integration modules use that exact version:

- `go.mod`;
- `integration/pluginstorecontract/go.mod`;
- `integration/cpalatestcontract/go.mod`.

The active module identity is:

```text
module_sum: h1:YfLBYPvkasjqFLzdht+UrEgRLsU3HcM0WDMurNEjIDo=
go_mod_sum: h1:ytvZNWbCv7PrAyR80+RKsDJPODsdL6qxyFaXDBNZdqs=
```

Legacy CPA-version-specific profiles and Make aliases have been removed. Old
version observations remain in Git history, the changelog, and explicitly
marked historical sections, but they are not executable tests, supported
profiles, or current evidence.

## Active validation commands

Only the following CPA validation paths are supported:

```bash
make cpa-host-fixture-contract
CPA_COMPAT_VERIFY_REMOTE=1 make cpa-latest-compat
make cpa-host-blackbox
make cpa-router-fixture-blackbox
make round6-cpa-store-contract
```

The compatibility contract verifies the fixed v7.2.88 Git tag-to-commit
identity directly against the official Git origin, then binds the Go module
Origin and both checksums. It does not depend on GitHub REST Release metadata
or a repository token. Later upstream CPA versions do not automatically change
the supported source or Host target.
`ALLOW_DIRTY_BUILD=1` is a development-only override and is not release
evidence.

## Coverage

The current v7.2.88 matrix covers:

- Guard compilation, registration, and routing contracts;
- official Host Router ordering, fallback, panic/fuse, target-readiness, and
  metadata-sanitization contracts;
- checksum-pinned fail-open overlays applied only to an ephemeral CPA source
  copy;
- Interactions route, handler, translator, auth-selection, and direct-executor
  format contracts;
- CPA Store archive naming, root layout, checksum, installation, repeat-install,
  overwrite, and published-artifact identity;
- an available native Linux integration target for plugin load and pre-upstream
  blocking; this target was not executed by the cited main/tag CI runs;
- an available second pure-C Router/executor fixture for priority, tie-break,
  fallback, and target-readiness scenarios; it is not claimed as executed by
  the cited main/tag CI runs.

The shared test fixtures under `integration/pluginstorecontract/testfixtures/`
are current v7.2.88 inputs and must not be treated as legacy-version fixtures.

## Last fully verified pre-cleanup baseline

The merged Round 6 source is:

```text
main_commit: 6782dfaffd4da3f09604113c7d38675f331dc759
source_tree: a8edbe2e6d19fa725fb962cdd6aaad5b416d4b85
public_source_only_prerelease_tag: v0.15-rc.1
attached_release_assets: none
private_untagged_clean_candidate: not created
formal_tag_v0.15: absent / blocked
historical_classifier_policy_version: classifier-policy-v3
historical_classifier_policy_sha256: 1294c6fd587522829d07220d5a6f4214092eba6ce1837636da5b3e3d461ba2a3
```

GitHub Actions validation for that exact commit passed:

- main push CI `29630844605`;
- tag push CI `29630926354`.

Both runs passed the quality/artifact job, long fuzz job, and clean-clone
reproducibility job. The matrix included v7.2.86 latest-source compatibility,
Host source/fail-open contracts, Round 4/5/6 regressions, unit and race tests,
vet, fuzz, benchmarks, vulnerability checks, Linux build, artifact hashing,
Store validation, integration compilation, and clean-tree verification. It did
not run the native Host black-box or pure-C Router fixture targets.

## Evidence boundary

Source contracts, fixture contracts, and CI build/artifact plus
integration-compile PASS do not replace the owner-operated isolated server
sandbox. No local validation in this report is a claim that a production CPA
process, real Provider, account pool, or production traffic was used.

The remaining server evidence must load the exact Linux artifact in CPA
v7.2.88 with a Mock upstream and prove zero deltas for locally blocked requests
at Auth Selector, Provider execution, usage accounting, and Mock-upstream
request layers.

The resulting Host record is carried by prerelease attestation schema v2 using
the generic `cpa_version`, `cpa_commit`, and `cpa_host_sha256` fields.

The supported platform for this release line is Linux amd64. Windows, macOS,
and musl/Alpine validation are outside scope.
