# v0.1.2 Development Evidence and Release Closure

Last updated: 2026-07-14 (Asia/Shanghai)

## Decision

**RELEASE DECISION: FAIL / RELEASE BLOCKED.**

**DEVELOPMENT HANDOFF STATUS: BLOCKED FOR HANDOFF.**

The methodologically valid evaluation v10 was executed once and failed. Its
aggregate result is immutable; it was not read or rerun during this work. The
post-v10 implementation may be prepared for independent Leo verification only
after its final commit, clean tree, GitHub CI, real CPA v7.2.72 Host matrix,
proxy check, and artifact identities are recorded. Those engineering fields are
now recorded for implementation freeze `61536f9`; this is still not a release
approval or independent quality PASS.

No tag, GitHub Release, formal artifact publication, or production deployment is
authorized. Even a future-passing engineering matrix cannot guarantee that an
upstream account will never be warned, rate-limited, suspended, or deactivated.

Methodology incident: three incorrectly scoped WSL source-search commands
unexpectedly emitted several rows from the retired `testdata/holdout-v3`
corpus. All three were stopped immediately; the rows were not analyzed or used
for tuning or conclusions. Evaluation v10 content was not accessed. The retired
holdout-v3 corpus is no longer eligible as independent evidence, and the
incident independently blocks handoff.

The emitted rows appeared only in interactive command output captured by the
task transcript. None of the three commands redirected that output to a
repository or workspace file, and no separate emitted-output copy was retained
locally. There was therefore no local output file to remove before handoff; the
task transcript remains retained as the audit record and is permanently
excluded from evaluation evidence.

Independent Host audit also found a separate handoff blocker. Guard
`executor.http_request` returns an RPC error carrying status 405 and the official
adapter returns `(nil, error)`. CPA v7.2.72's provider-specific public
`POST /v1/alpha/search` consumer normally selects `codex` and maps every
`HttpRequest` error to HTTP 502. The project `httptest.Server` manually maps the
status error and is not official Host evidence. No current official route maps
Guard's error to final client 405, so that result is `NOT AVAILABLE / NOT RUN`
and current CI cannot close it.

## Development identity

```text
repository: https://github.com/yujianwudi/cyber-abuse-guard
starting_baseline: a121a444cb0d82cba4e27754914a1f88258e1d7b
branch: agent/complete-classifier-cpa-v7272-handoff
reliability_checkpoint_commit: 573def2649d164161e2dfdfeb3f59b1e1b38ebbc
implementation_freeze_commit: 61536f9f02c47a4d79031a47dc8a284f040e41c1
evidence_document_commit: SELF (resolve with git log -1 -- this file)
worktree: CLEAN AT FINAL HANDOFF
root_cpa_version: v7.2.72
cpa_upstream_tag_commit: 6279bb8a4c2835ff6ed99c6b85083b2afbefa681
cpa_module_sum: h1:ppce0MLsz2xJi2yi3/A60zu03cM7bMWBAEJ6eC29E5Y=
cpa_go_mod_sum: h1:f4pcyAej8RoeRhIxJfm+OUMkCKaApiA8WzxR2XVlBh8=
cpa_abi: C ABI/RPC schema v1
target: linux/amd64, glibc 2.34+
go_toolchain_for_recorded_wsl_checks: go1.26.4 linux/amd64
ruleset_version: 1.0.7
ruleset_sha256: 7bef8b0854b4d75dd5d807e1c33e93b708af4e9e29d0d2b59a18b9031c4da134
classifier_policy_version: classifier-policy-v2
classifier_policy_sha256: dc9a174099cb2f621e5333a508d4645604f96f470a6d9ae12a1acfb363d29cf2
```

The final resolution-only follow-up commit changes only the `SELF` evidence
identity fields to this substantive evidence snapshot's immutable parent
commit. The commit plus repository path independently identifies each exact
evidence document without a self-referential file hash.

The classifier-policy digest is source-bound and exposed through classifier
results/authenticated status. Current build metadata and artifact verification
do not yet bind it, so the full final Git commit remains part of the behavior
identity.

Three WSL commands were mistakenly executed outside the authorized evidence
path: `make cpa-router-fixture-blackbox`,
`make cpa-v7272-host-blackbox`, and
`scripts/management-proxy-413-test.sh`. They used loopback/Mock components only,
contacted no production service or real provider, and cleanup left no fixture
process running. Their status is:

```text
LOCAL MIS-EXECUTION RECORDED / EXCLUDED; NOT AUTHORITATIVE
```

They are not delivery PASS evidence.

## Current implementation closure matrix

| Area | Source state | Executed evidence at this revision |
|---|---|---|
| Wrapper/amplifier separation | Wrapper-only cannot synthesize a Cyber Abuse taxonomy; wrapper can amplify only an independent base behavior | Targeted classifier DEVELOPMENT SELF-CHECK **PASS** |
| Behavior graph | Privacy-safe evidence relations for behavior, intent, target, execution, evasion, impact, scale, authorization, role, carrier, and reasons | Targeted DEVELOPMENT SELF-CHECK **PASS** |
| Role/multi-turn/tool/placeholder/carrier | Bounded provider-aware extraction and composition | Targeted classifier/plugin DEVELOPMENT SELF-CHECK **PASS** |
| Classifier identity | `classifier-policy-v2` source digest test and authenticated status | DEVELOPMENT SELF-CHECK **PASS**; artifact binding incomplete |
| Development corpus | 35 visible cases; validator, fixed taxonomy, coverage, extraction, duplicate/near-duplicate checks | DEVELOPMENT SELF-CHECK **PASS**; never blind evidence |
| Subject idempotency | One risk hit per subject/request digest across retries, methods, races, reconfigure, persistence | Windows and WSL targeted DEVELOPMENT SELF-CHECK **PASS** |
| Pending cache | Ordered O(1) refresh/eviction | Targeted tests/benchmarks **PASS** |
| HMAC/SQLite/lifecycle | owner/mode/type, migration rollback/collision, audit close, lifecycle races | WSL race/vet DEVELOPMENT SELF-CHECK **PASS** |
| Privacy canary | DB/backup/snapshot/API/log/panic/CSV/watchdog/release-evidence scans | Recorded WSL/script DEVELOPMENT SELF-CHECK **PASS** |
| CPA root dependency | root `go.mod` on v7.2.72 | module inspection/verify **PASS** |
| Official Host source contract | 16 exact upstream test names plus fail-open overlays | Windows SOURCE OVERLAY **PASS** |
| Real Guard first install through `InstallManifest` and Host load | harness exists | **GITHUB CI PASS**; local mis-execution remains excluded |
| Same-Dist repeat-skip/tamper-repair through `TestPublishedStoreArchive` | real artifact contract exists | **GITHUB CI PASS** with required Dist artifacts; synthetic fallback disabled |
| Four-protocol 403/pre-SSE/token-count | harness exists | **GITHUB CI PASS — 32 Host subtests** |
| `http_request` 405 at ProviderExecutor adapter/status-error layer | source/adapter test | **SOURCE / ADAPTER CHECK — response=nil** |
| Final official CPA handler/client HTTP 405 | current public consumer maps executor errors to 502 | **NOT AVAILABLE / NOT RUN — BLOCKED FOR HANDOFF** |
| Auth/Provider/Usage/Mock Upstream zero side effects | counting seams exist | **GITHUB CI PASS** |
| Router priority/not-ready/invalid-target/fallback | second native fixture exists | **GITHUB CI PASS — 15 isolated scenarios** |
| Fuse/pre-result panic | official source overlay only | **SOURCE OVERLAY ONLY** |
| Management proxy 413 before CPA `io.ReadAll` | script/fixture exists | **GITHUB CI PASS** — counted CPA-handler stub remained zero |
| GitHub CI | workflow changes exist | **PASS** — push `29312969925`, PR `29312971717`; push long fuzz PASS; both reproducibility jobs PASS |
| Development-candidate artifact verification | store/audit split and verifier source exist | **GITHUB CI PASS / HASHES RECORDED**; not a formal release |

No row may be upgraded based on design intent, compilation, an older branch, or
another evidence class.

## Performance and privacy interpretation

Same-machine classifier development medians improved on all five measured
latency cases from `a121a44` to `a1be19f`. Allocations increased on the ordinary,
candidate-rich, and role-aware paths. Pending-cache and duplicate-request
microbenchmarks show the intended constant-time behavior. These results are
`DEVELOPMENT SELF-CHECK / NOT FINAL EVIDENCE`; Leo must rerun the final commit.

Privacy canary/race/vet checks passed for the named safe WSL/script commands.
The v1→v2 migration additionally fails closed before backup publication or
migration when legacy request/subject/model/source-format values violate the
digest/fixed-provider privacy contract; it preserves the original DB for
operator repair and does not auto-sanitize legacy plaintext. Exact-commit
GitHub CI passed the real Host, proxy-413, artifact, SBOM, and privacy gates;
Leo independent review remains not run.

## Frozen evaluation evidence

Evaluation generations v1-v8 remain retired or consumed historical failures;
v9 remains `CONSUMED / METHODOLOGY INVALID / FAIL`. The methodologically valid
v10 first-and-only run remains the authoritative `CONSUMED / FAIL`:

| Aggregate | Frozen result | Gate |
|---|---:|---|
| Benign false positives | 28 / 320 (8.75%) | FAIL; required `<5%` |
| Policy blocked | 49 / 320 (15.31%) | FAIL; required `>90%` |
| Policy exact taxonomy | 33 / 320 (10.31%) | FAIL; required `>90%` |

All four critical taxonomy floors also failed. The v10 report, hashes, byte/row
counts, and taxonomy aggregates remain frozen in
`EVALUATION_V10_REPORT.md`. No row-level result or sample may be used for tuning.

The visible 35-case development corpus is permanently ineligible for a future
v11. A future quality decision requires a newly authored, isolated, unseen set
outside the implementation process.

## Final engineering redlines

| Redline | Status |
|---|---|
| Clean final handoff commit and tree | **PASS AT FINAL HANDOFF** |
| Safe local Go test/race/boundary scripts | **DEVELOPMENT SELF-CHECK PASS** |
| GitHub CI on exact implementation commit | **PASS — push and PR runs** |
| Real v7.2.72 store install and native `.so` load | **GITHUB CI PASS** |
| Same-Dist repeat-skip/tamper-repair with required real artifacts | **GITHUB CI PASS** |
| Four protocols: allow/block, non-stream/stream, pre-SSE, token-count | **GITHUB CI PASS** |
| `http_request` adapter/status-error 405 | **SOURCE / ADAPTER CHECK — response=nil** |
| Final official CPA client HTTP 405 | **NOT AVAILABLE / NOT RUN — current public consumer maps the error to 502; BLOCKER** |
| Blocked Auth Selector/Provider/Usage/Mock Upstream all zero | **GITHUB CI PASS** |
| Multi-Router priority/fallback fixture | **GITHUB CI PASS — 15 scenarios** |
| Management proxy 413 before CPA read | **GITHUB CI PASS** |
| Development-candidate privacy/artifact canary scan | **GITHUB CI PASS** |
| Implementation-freeze performance rerun | **GITHUB CI PASS**; Leo rerun not run |
| Leo independent verification | **NOT RUN** |
| New independent blind evaluation | **NOT CREATED**; development corpus forbidden |
| Tag/GitHub Release/production deployment | **NOT CREATED / PROHIBITED** |

## Required development artifacts

These would be development candidates only, not approved release assets:

| Artifact | SHA-256 | Status |
|---|---|---|
| `cyber-abuse-guard-v0.1.2-dirty.so` | `61ca7324b647efe1fc264878b712827982c636518896f7e9b4d6797e52e4edda` | **GITHUB CI VERIFIED** |
| `cyber-abuse-guard-v0.1.2-dirty.so.sha256` | `214c3c393416c10880e1cf9320b3d7de5e540452b224dcd7f2d384dc9eaf88ea` | **GITHUB CI VERIFIED** |
| `cyber-abuse-guard_0.1.2-dirty_linux_amd64.zip` (one root `.so`) | `16c5e089b7d7e0cf07f837b70ec745a2dcae73acfd60e3e18ab0118303b6959e` | **GITHUB CI VERIFIED / REAL HOST INSTALLED** |
| `cyber-abuse-guard-v0.1.2-dirty-audit-bundle.zip` | `7592938325fd0e879139ba96f11c33c400ad3d8019e2c7ffb1b53742d6188a21` | **GITHUB CI VERIFIED** |
| `build-metadata.json` | `10fe6f16663667dbfda18001e131ea1383a2b687777ae68091da478edd2f7d16` | **GITHUB CI VERIFIED** |
| `checksums.txt` | `b79fb5e9a608d0d8bc2c949c4dac159f23a3a36e529a74761d912b52e7663618` | **DOWNLOADED CI ARTIFACT / LOCALLY REHASHED** |
| `ruleset-manifest.json` | `486a4dfad49b4e96a600f908cbea47376baab5c8875324999ae50b6251f1af7e` | **GITHUB CI VERIFIED** |
| `ruleset.sha256` | `a8ff687340617dc18832047f841979a0bd06ff8c50a4bc3c15dd7da37b6fbee2` | **GITHUB CI VERIFIED** |
| `sbom.cdx.json` | `da6e6caec7dce7e0daa33be67e488a47318b8404509a03f79d7ad052264c7169` | **GITHUB CI VERIFIED** |
| `release-test-summary.txt` | NOT CREATED | **FORMAL-RELEASE-ONLY; RELEASE BLOCKED** |

Push artifact `cyber-abuse-guard-linux-amd64-dirty` is Actions artifact ID
`8303051476`, uploaded size `10276537`, container digest
`sha256:1d134b2c211665faab3478bd3c9cc2badc2f7ace7c76780f2d662c0b72d171d8`.
The PR-run artifact is ID `8302950575`, size `10276698`, container digest
`sha256:e90cd200df9b20201da5506a3c6440dcdb2232b12028acd9dad818aeaea40318`.
Container digests are not substitutes for the internal-file hashes above.

Store ZIP and audit bundle must remain separate. The store ZIP must contain
exactly one root regular executable `.so`, with no absolute path, `..`,
backslash escape, symlink, or duplicate entry. Formal release scripts remain
blocked because v10 failed; development artifacts must be clearly dirty/non-
release and must not be uploaded as a GitHub Release.

## Known unresolved limitations

- CPA ABI-v1 Host fail-open, Router enumeration, and duplicate plugin-directory
  visibility;
- no HMAC dual-key rotation and no keyed whole-snapshot MAC;
- bounded text decoders cannot interpret arbitrary encoding, encryption,
  archive/document content, or opaque media semantics;
- cross-request classifier semantics remain stateless;
- classifier-policy identity is not yet embedded in artifact metadata;
- a local SQLite writer remains trusted for snapshot completeness;
- no guarantee against upstream account action.

## Final approval block

```text
implementation_freeze_commit: 61536f9f02c47a4d79031a47dc8a284f040e41c1
evidence_document_commit: SELF (resolve with git log -1 -- this file)
annotated_tag: NOT CREATED — RELEASE BLOCKED
github_release_url: NOT CREATED — RELEASE BLOCKED
github_actions_ci_run: PASS — push 29312969925; pull_request 29312971717
real_host_matrix: GITHUB CI PASS — 32 Host subtests; 15 Router scenarios
management_proxy_413: GITHUB CI PASS
http_request_adapter_405: SOURCE / ADAPTER STATUS-ERROR CHECK (response=nil)
official_cpa_final_client_http_405: NOT AVAILABLE / NOT RUN — BLOCKED FOR HANDOFF
development_candidate_artifact_hashes: RECORDED / VERIFIED; not formal release assets
leo_verification: NOT RUN
new_independent_blind_evaluation: NOT CREATED
all_handoff_redlines_pass: NO
release_owner: NOT APPROVED
independent_reviewer: NOT APPROVED
decision: BLOCKED FOR HANDOFF / RELEASE FAIL
```
