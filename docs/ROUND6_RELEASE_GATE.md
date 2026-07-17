# Round 6 CI and blocked-prerelease gate

Status: **BLOCKED / PENDING HOST AND INDEPENDENT AUDIT**. This is
development-only. No release is authorized by this document or by a green
ordinary CI run.

All Round 6 build, race, fuzz, benchmark, artifact, and reproducibility evidence
is Linux amd64-only. Windows and macOS are outside scope and are not required
release lanes. See
[ROUND6_DEVELOPMENT_HANDOFF.md](ROUND6_DEVELOPMENT_HANDOFF.md).

## Ordinary CI

The public CI runs `make round6-regression`. The target first lists and verifies every required Round 6 test by exact name, then runs the allowlisted suites for:

- full-envelope and streaming extraction, including long JSON, chunk, Unicode,
  media, raw multipart, CPA-transformed multipart JSON, role, and budget cases;
- classifier overlap, boundary reconstruction, negation, role isolation, coverage, and bounded composition;
- Router/disposition and the Linux long-text ladder at 64 KiB, 255 KiB,
  256 KiB, 256 KiB + 1, 270 KiB, 512 KiB, 1 MiB, 4 MiB, and near the
  effective RPC limit;
- management test/status behavior and legacy `max_scan_bytes` migration.

The CI safety checker inspects the reachable Make/script graph. Round 6 entrypoints fail closed if they reach the historical formal-release, package/verification, reproducibility, holdout, consumed-evaluation, or dynamically dispatched Make/shell paths.

The same contract requires every Round 6 job to use the exact
`ubuntu-24.04` runner label and rejects workflow/job shell defaults, custom
step shells, containers, services, YAML anchors/aliases/quoted mapping keys,
and dangerous inherited execution variables such as `BASH_ENV`, `PATH`, or
`LD_PRELOAD`. Top-level environment is limited to the pinned tool/version
values. The Linux build script is locked to its reviewed fail-closed command
sequence, including complete
`readelf --version-info` GLIBC tag validation before artifact checksum and
source-identity confirmation.

Consumed evaluation/Holdout gate tests are isolated behind the
`consumed_evaluation` build tag and excluded from the ordinary sparse checkout.
Broad `./...` Go commands are not accepted as substitutes for the allowlist.

Round 6 CI builds only these low-sensitivity development artifacts:

```text
cyber-abuse-guard-v0.1.2-dirty.so
cyber-abuse-guard-v0.1.2-dirty.so.sha256
cyber-abuse-guard_0.1.2-dirty_linux_amd64.zip
build-metadata.json
checksums.txt
ruleset-manifest.json
ruleset.sha256
sbom.cdx.json
```

It does not create or copy an audit bundle. In particular, the Round 6 artifact path does not open or package holdout/evaluation reports, private payloads, production requests, audit databases, credentials, or provider data.

`make round6-reproducibility-test` compares two clean sparse-worktree builds of
only the SO, Store ZIP, metadata, ruleset identity, and SBOM. It deliberately
does not call the historical `reproducibility-test`, because that target reaches
the old release bundle path.

## Manual prerelease workflow

`.github/workflows/round6-blocked-prerelease.yml` is manual-only
(`workflow_dispatch`). Its defaults are blocked and authorization defaults to
false. It has exactly three ordered jobs:

1. `admission` validates every input and uses a read-only `GH_TOKEN` only to
   query the cited Actions run. The run must be a completed successful `push`
   run of `.github/workflows/ci.yml` whose `head_sha` is the exact candidate
   commit.
2. `verify` depends on `admission`, has only `contents: read`, checks out the
   existing annotated tag with `persist-credentials: false`, immediately runs
   the restricted-data checker, rebuilds the Linux amd64 artifacts, rechecks
   commit/tree/tag/SO identity, and uploads one commit-named artifact. Checkout
   necessarily uses the job's read-only GitHub token while fetching; the token
   is not explicitly mapped into later commands and is not persisted in Git
   configuration. The final identity step and artifact upload use an exact
   reviewed clean execution environment: shell startup hooks, loader/language
   injection variables, Git configuration and askpass paths, CLI config homes,
   and proxy variables are cleared or pinned, while `PATH` is restricted to
   `/usr/bin:/bin`. Exact step text and environment mappings also prevent
   disabling remote CPA compatibility, disabling required artifacts, replacing
   the regression gate with a no-op, or persisting `BASH_ENV` through
   `$GITHUB_ENV`.
3. `publish` depends on `verify`, performs no checkout and runs no repository
   scripts. It downloads the exact commit-named artifact, rechecks
   commit/tree/SO identity without explicitly mapping `GH_TOKEN`, and only then
   enters the final GH-token-bearing publish step. Transfer verification
   requires the exact eight-file allowlist, the canonical `checksums.txt` file
   list and hashes, canonical one-line standalone SO/ruleset checksum files,
   matching commit/tree metadata, a JSON ruleset, and a CycloneDX SBOM. It also
   rejects unsafe ZIP paths, requires exactly one `.so`, verifies the extracted
   ZIP-contained SO against `expected_so_sha256`, and byte-compares the
   ZIP-contained SO checksum, build metadata, ruleset files, and SBOM with the
   separately transferred files.

The `publish` job receives `contents: write` only when all five expressions are
true:

```text
CPA v7.2.83 isolated Host + Mock result == PASS
CPA v7.2.82 isolated Host + Mock result == PASS
CPA v7.2.81 isolated Host + Mock result == PASS
independent audit result == PASS
explicit blocked-prerelease authorization == true
```

The `publish` job is also bound to the GitHub Environment
`round6-independent-audit`. Repository settings must create that Environment
and configure required independent reviewers before the workflow is used.
Merely naming the Environment in YAML does not create independent approval. If
the protection or reviewers are absent, bypassed, or controlled only by the
implementer, the workflow result cannot be treated as an independent audit
gate.

The dispatcher must also provide the exact existing annotated development tag,
its 40-character commit and tree, the exact successful push-CI run ID, the exact
candidate Linux amd64 SO SHA-256, and SHA-256 identities for all three Host
evidence records and the independent audit report. All three Host records and the independent
audit must cite that same candidate SO SHA-256. The `verify` job recomputes the
rebuilt SO hash before transfer, and the `publish` job recomputes it again after
download. The publish-side canonical checksum and ZIP-contained identity checks
also bind every released metadata/ruleset/SBOM file to the verified transfer;
runner, build, archive, or artifact-transfer drift therefore fails closed. The
workflow verifies the local and remote tag-to-commit binding before upload. It
does not create or move a tag.

The Host PASS values and evidence SHA-256 inputs are externally reviewed
declarations, not evidence files verified by this workflow. The protected
`round6-independent-audit` Environment reviewer must obtain each underlying
Host record independently, recompute its SHA-256, confirm that all three records
cite the same candidate SO, and have self-review disabled. The workflow checks
the declaration format and binds the citations into the draft prerelease; a
dispatcher-supplied `PASS` or 64-character string is not proof by itself.

Repository settings must also enforce a release-tag ruleset for the Round 6
development tag pattern. That ruleset must prohibit both tag modification and
tag deletion, and no actor participating in the release workflow may bypass
those protections. The `verify` job's `ls-remote` peeled-tag check and the final
publish step's GitHub API annotated-tag peel narrow the race window but are not
a substitute for immutable repository-side tags.

The final and only explicitly write-token-bearing publish step first queries the
GitHub Git References API, requires the ref object to be an annotated `tag`,
loads that tag object, requires it to peel directly to a `commit`, and compares
that commit with `expected_commit`. Only after those checks may the pinned
command sequence run `gh release create` with:

```text
--draft
--prerelease
--latest=false
--verify-tag
title contains BLOCKED / PENDING HOST AND INDEPENDENT AUDIT
explicit notes file records source, CI, Host, audit, and candidate SO identities
```

That GH CLI command must remain the end of the final job step. The step's exact
environment and literal command graph are statically locked; an earlier
release/tag mutation, a later step, a changed flag, or a missing identity line
fails the contract.

The release remains a
`BLOCKED / PENDING HOST AND INDEPENDENT AUDIT` development handoff even after
those external gates pass. It is not permission to deploy, touch Los Angeles
production, connect a real provider/account pool, or change production from
`observe` to `balanced`.

## Commands

These checks are safe to run without any restricted corpus:

```bash
python3 -B scripts/round6_safe_gate_contract_test.py
python3 -B scripts/round6_safe_gate_contract.py --root .
make round6-regression
```

The artifact and reproducibility targets require Linux amd64, Go 1.26.4, CGO, native build tools, and the pinned CycloneDX tool:

```bash
ALLOW_DIRTY_BUILD=1 make round6-development-artifacts
make round6-reproducibility-test
```

Do not run `make formal-release`, `make release`, `make holdout-test`, `make consumed-boundary-test`, the historical release workflow, or the historical release/reproducibility packaging scripts for this candidate.

CPA v7.2.83, v7.2.82, and v7.2.81 source/compile compatibility belongs to Linux CI.
Their official real Host + Mock-upstream matrices remain **NOT RUN / PENDING**
and are mandatory before any blocked prerelease step.
