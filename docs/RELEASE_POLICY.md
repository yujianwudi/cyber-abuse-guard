# v0.16 release admission policy

```text
current_classifier_policy_version: classifier-policy-v7
current_classifier_policy_sha256: ea8c4dcfacacc6478f86fd2ca5de96d667ae98f2fc6ff0c83d8e6092e9f6a82d
```

This source file defines the release process; it does not claim that external
Host, audit, or publication gates have passed. A source commit becomes an
official stable release only when the GitHub Release is non-draft and carries
the attestations named below. A non-draft RC prerelease is still not a stable
release or deployment authorization. Pull requests and source snapshots are
never deployment authorization by themselves.

```text
release_version: 0.16
formal_tag: v0.16
version_alias_policy: reject-v0.16.0
platform: linux-amd64
local_rc_artifact_version: 0.16-rc.2
local_rc_artifact_scope: two-stage-linux-amd64-private-candidate-or-prerelease
local_rc_evidence_policy: phase1-no-host-evidence-phase2-strict-counted-mock-evidence
v016_candidate_workflow_status: NOT_MIGRATED/NOT_AVAILABLE
v016_rc_workflow_status: ACTIVE/PRERELEASE_ONLY/NO_PRODUCTION_APPROVAL
v016_formal_workflow_status: NOT_MIGRATED/NOT_AVAILABLE
v016_promotion_workflow_status: NOT_MIGRATED/NOT_AVAILABLE
candidate_workflow: .github/workflows/candidate.yml
candidate_attestation: candidate-manifest.json
attested_prerelease_workflow: .github/workflows/attested-prerelease.yml
rc_workflow: .github/workflows/release-rc.yml
rc_workflow_archive: docs/archive/workflows/release-rc-v0.15-rc.2.yml
rc_artifact_version: 0.16-rc.2
rc_artifact_history: active-v0.16-rc2-prerelease-only
rc_status: two-stage-private-candidate-or-counted-mock-verified-prerelease-independent-audit-required-production-not-approved
rc_manifest_schema: 4
rc_build_metadata_schema: 4
rc_builder_reference: docker.io/library/golang:1.26.4-bookworm@sha256:b305420a68d0f229d91eb3b3ed9e519fcf2cf5461da4bef997bf927e8c0bfd2b
rc_runner_label: ubuntu-24.04
rc_runner_os_arch_environment: Linux/X64/github-hosted
rc_runner_image_identity: UNOBSERVABLE_FROM_PINNED_JOB_CONTAINER
rc_candidate_asset_count: 17
rc_publish_asset_count: 19
rc_publish_host_evidence: round8-host-evidence.json
rc_publish_host_evidence_sidecar: round8-host-evidence.json.sha256
host_audit_attestation: round6-prerelease-attestation.json
formal_gate_attestation: formal-release-attestation.json
promotion_workflow: .github/workflows/release-promote.yml
historical_v015_stable_release: PUBLISHED_MANUALLY/2026-07-20/TEN_ASSETS
historical_v015_independent_attestation: NOT_ATTACHED
host_matrix: v7.2.95
host_matrix_commit: f71ec0eb6776854457892452cf28c47f0d658251
candidate_manifest_schema: 3
host_attestation_schema: 2
host_evidence_fields: schema_version,validation_scope,candidate,cpa,mock,safety
upstream_version_policy: no-automatic-follow
independent_audit_status: required-not-provided
production_approval_status: not-granted
stable_v0.16_status: not-released
external_admission: required
minimum_independent_evaluation: evaluation-v11
independent_evaluation_required_status: CONSUMED/PASS
historical_evaluation_v10_policy: immutable-consumed-fail-not-formal-input
formal_bundle_content_policy: exclude-evaluation-holdout-consumed-private-blind-retired
```

The `release_version`, `formal_tag`, and `local_rc_*` keys define the current
v0.16 source and `v0.16-rc.2` prerelease target. The active RC workflow is
Linux amd64 only and requires an annotated exact-main tag, successful exact-main
CI, complete internal gates, reproducible assets, and the fixed CPA v7.2.95
source contract. It has two explicit stages. The build job records its
`runner.os`, `runner.arch`, and `runner.environment` context and requires the
declared `ubuntu-24.04` label. Ephemeral `runner.name` and release-workflow
run/attempt identifiers are intentionally represented by stable
`UNRECORDED_EPHEMERAL_*` sentinels so independently repeated builds can produce
the same bytes without pretending that those ephemeral values were observed in
the artifact identity. A pinned job container cannot
reliably observe the host runner image's `ImageOS` or `ImageVersion`, so both
metadata fields intentionally contain
`UNOBSERVABLE_FROM_PINNED_JOB_CONTAINER`; the immutable builder reference above,
not a fabricated host-image version, is the compiler-environment identity.

With `publish_rc_release=false`, all four top-level protected-Host inputs must be
empty. `host_run` binds the positive Host run ID and attempt as
`RUN_ID:RUN_ATTEMPT`; the remaining Host inputs bind the artifact ID, artifact
digest, and one-time challenge. The workflow
reproduces exactly 17 final assets, uploads them as a private Actions artifact
for Host testing, and cannot create or modify a GitHub Release. The manifest
records Host and counted-Mock validation as `NOT_RUN / HOST_TEST_REQUIRED`.

The only publication-admissible Host evidence is schema v2 produced by
`round8-host-validation.yml` on the protected self-hosted Linux x64
`cag-round8-sandbox` runner. That workflow downloads the exact Phase 1 artifact
by run/attempt and artifact ID/digest, verifies every Phase 1 GitHub attestation,
checks the protected daemon ID, sandbox/production labels, immutable probe image,
and bind-mount nonce locality challenge, then signs exactly the canonical Host
JSON and sidecar with GitHub artifact attestation.

With `publish_rc_release=true`, the release workflow requires the exact
successful Host run ID/attempt, Host artifact ID/digest, and the same one-time
64-hex challenge. It fetches the two-file Host artifact directly from GitHub and
rejects it before download unless GitHub reports a positive integral
`size_in_bytes` no larger than 1 MiB. After download, the compressed byte count
must equal that API value and remain within the same cap. A bounded Python ZIP
reader then requires exactly two unique, top-level expected regular files,
rejects directories, links, path traversal, encryption, unreviewed compression,
and per-entry or aggregate expansion beyond the reviewed limits, and writes the
files without overwrite semantics. No generic `unzip` extraction is permitted.
The workflow then verifies the signer workflow, signer commit, source ref/commit,
Host run identity, Phase 1 artifact binding, protected runner identity, and exact
nested execution schema. The evidence must bind the exact tag, commit, tree, Linux amd64 SO
SHA-256, the CPA v7.2.95 primary identity, and counted-Mock `PASS` for that
single target. It must also contain the fixed safety
assertions that no real Provider was contacted, production was not accessed,
unexpected restart count is zero, OOM is false, and panic/fatal/plugin error
counts are all zero. The primary CPA result must additionally provide the closed
numeric/boolean matrix:
Chat and Responses benign/malicious upstream deltas `1/0`, 42 benign cases all
passed, 42 paired malicious cases all blocked, stream/nonstream plus
audit/balanced/strict coverage, SQLite quick-check/WAL success, and a restart
cycle with zero unexpected restarts. It also locks Balanced-incomplete allow,
Strict-incomplete block, usage-queue allow/blocked deltas, and Raw Capture
only-blocked, TTL dedup, schema-v3 redaction metadata, and purge/WAL results.
A bare `counted_mock_validation=PASS` is not sufficient. JSON scalar types are
exact: count fields are integers and cannot be replaced by booleans or
floating-point lookalikes. Extra fields in `execution`, `workflow`, `phase1`,
`runner`, or `sandbox` fail closed. The evidence and sidecar are included in both clean-clone builds,
`checksums.txt`, the audit bundle, manifest, transfer artifact, and the exact
19-asset Release allowlist. Only this stage may publish, and the result must be
`prerelease=true` and non-latest; the stable latest release must remain exactly
`v0.15`.

This workflow design does not itself create its trust root. Repository
administrators must configure protected `round8-host-validation` and
`round8-rc-publication` environments, required reviewers, disabled self-review
and admin bypass, exact deployment policies, the dedicated runner, and the three
protected sandbox identity variables. Until those external controls are present,
the RC publication path is not authorized. GitHub-attested counted-Mock evidence
is still not real-Provider validation, production validation, an independent
audit, or stable-release approval.

If the exact `v0.16-rc.2` Release becomes public (`draft=false`) before the
publishing job records its terminal verification, **Re-run failed jobs** on that
same workflow run can reuse the exact 19-file transfer artifact and enter the
existing fail-only, no-mutation verification branch. A new dispatch or
**Re-run all jobs** reruns admission instead. Admission emits
`already_public=true`; the write-capable build and publish jobs are skipped
before their setup, cache, provenance generation, or artifact upload, and the
separate `verify_published` job runs with only `actions: read`,
`attestations: read`, and `contents: read`. That verifier uses the same pinned
builder container, restricted checkout, and complete Linux gate sequence, but
sets `setup-go` to `cache:false` and has no artifact- or attestation-write step.

Both read-only paths verify the Release/tag/annotated-tag target/exact commit,
canonical title and body, `draft=false`, `immutable=true`, `prerelease=true`,
and non-latest state, and reconfirm that latest remains exactly `v0.15`. The
dedicated public verifier downloads exactly the 19 existing Release assets,
checks every GitHub SHA-256 digest, checksum sidecar, manifest-bound hash,
canonical timing-free test summary, and signed build attestation. In both the
publication transfer and read-only public verifier, each of the 17 ordinary
assets must be attested by the exact `release-rc.yml` signer workflow at the
exact tag and commit; the two Host evidence assets must separately verify the
exact protected `round8-host-validation.yml` signer at that same tag and commit.
Repository-only attestation verification is not sufficient. The verifier then rebuilds
the exact 19-asset publish candidate from the annotated tag and byte-compares
every local artifact with the downloaded public artifact. It does not upload
replacement bytes or mutate remote state. Any mismatch is fail-only and
requires manual investigation rather than repair.

```text
immutable_published_rc_identity_verification: release-object,tag=v0.16-rc.2,annotated-tag-target=exact-commit,target-commitish=exact-commit,title=exact,body=exact,prerelease=true,latest=false,draft=false,immutable=true
immutable_published_rc_asset_verification: exact-count=19,download-count=19,byte-compare-each=rebuilt-candidate,release-digest-and-attestation-check=each
immutable_published_rc_recovery: same-run-re-run-failed-or-admission-read-only-verifier
immutable_published_rc_new_dispatch_or_rerun_all: admission-already-public-skip-write-capable-build-and-publish
immutable_published_rc_recovery_access_policy: read-only-no-state-mutation
immutable_published_rc_forbidden_mutations: release-create,release-edit,release-upload,release-delete,artifact-upload,attestation-write,cache-write
immutable_published_rc_latest_release: v0.15
immutable_published_rc_mismatch_policy: fail-only-no-automatic-repair
```

Counted-Mock Host evidence is not real Provider or production validation.
Manifest schema 4 keeps both independent audit and independent evaluation at
`NOT_PROVIDED` with requirement `required`; production authorization and a
stable `v0.16` release remain absent.

The earlier local `v0.16-rc.1` package and its failed exact-main CI are
historical incident evidence only. They cannot satisfy any `v0.16-rc.2` gate,
and no old artifact may be overwritten or silently relabeled.

The candidate, attested-prerelease, formal, and promotion workflows still
describe the historical v0.15 chain. Only `release-rc.yml` has been migrated to
the v0.16-rc.2 prerelease lane. No stable-v0.16 workflow is admitted by this
policy.

## Historical v0.15 workflow record

The candidate workflow creates a private, untagged, clean `0.15` SO and CPA
Store ZIP bound to an exact commit and tree. The Host and independent-audit
workflow may later attach an external attestation to an annotated development
tag at the same commit. The formal `v0.15` workflow rebuilds and byte-compares
the Host-tested SO and Store ZIP, creates a draft, and the separate promotion
workflow publishes that unchanged draft only after another protected approval.

The historical `v0.15-rc.4` workflow is a Linux-only side lane. It requires an
annotated tag at the exact `main` tip, a successful exact-main push CI, the
complete internal Linux gate set, its then-pinned CPA source contract, RC-versioned
integration, two independent clean-clone rebuilds, and byte verification of a
17-asset formal-structure package. Its evidence and manifest explicitly state
`RC_INTERNAL_GATES_PASS / SANDBOX_ONLY / SERVER_VALIDATION_REQUIRED /
NOT_FORMAL / NOT_ROUND6_CANDIDATE`; real CPA Host validation, independent audit,
and independent evaluation remain absent.

The later `v0.15` stable Release was published manually on 2026-07-20 with ten
assets. Its Release Notes disclose the GitHub Billing limitation, manual build,
and owner-reported production sandbox result. That publication did not complete
the protected draft/promotion chain and does not supply independent Host,
audit, or evaluation attestation.

The archived `v0.15-rc.2` workflow remains immutable historical evidence. Its
recorded attempts failed; the public RC2 assets were published separately
through the disclosed direct owner override. The protected `v0.15-rc.3` tag
records failed workflow run 29728286559: admission passed, build failed before
packaging, publish was skipped, and no Actions artifact or GitHub Release was
created. RC2, RC3, and RC4 assets are never
accepted as the private Round 6 candidate, external Host/audit/evaluation
evidence, or formal `v0.15` input.

The consumed v10 evaluation remains historical FAIL evidence. It is never
rerun, upgraded, or treated as a formal-build input. A release candidate needs
a separately authored, previously unseen v11-or-later evaluation whose
low-sensitivity report is bound by SHA-256 in the Host/audit prerelease
attestation. Raw evaluation, holdout, consumed, private, blind, and retired
materials are not copied into formal source or audit bundles.

`0.16` is the current source version and `v0.16-rc.2` is the only admitted
publication target in this round. A stable `v0.16` has not been approved or
released. If a future independent process admits it, the project version remains
two-component and must not publish a `v0.16.0` alias. The historical v0.15
workflow record above retains its original identity and does not become a
v0.16 release path.
