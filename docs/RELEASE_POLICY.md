# v0.16 release admission policy

```text
current_classifier_policy_version: classifier-policy-v6
current_classifier_policy_sha256: ece497210db938528cb166a34f2ce3013324b792a7eedf276a96fa5d256001d4
```

This source file defines the release process; it does not claim that external
Host, audit, or publication gates have passed. A source commit becomes an
official release only when the GitHub Release is non-draft and carries the
attestations named below. Pull requests and source snapshots are never
deployment authorization by themselves.

```text
release_version: 0.16
formal_tag: v0.16
version_alias_policy: reject-v0.16.0
platform: linux-amd64
local_rc_artifact_version: 0.16-rc.1
local_rc_artifact_scope: local-linux-amd64-core-package
local_rc_evidence_policy: not-github-release-actions-or-host-evidence
v016_candidate_workflow_status: NOT_MIGRATED/NOT_AVAILABLE
v016_rc_workflow_status: NOT_MIGRATED/NOT_AVAILABLE
v016_formal_workflow_status: NOT_MIGRATED/NOT_AVAILABLE
v016_promotion_workflow_status: NOT_MIGRATED/NOT_AVAILABLE
candidate_workflow: .github/workflows/candidate.yml
candidate_attestation: candidate-manifest.json
attested_prerelease_workflow: .github/workflows/attested-prerelease.yml
rc_workflow: .github/workflows/release-rc.yml
rc_workflow_archive: docs/archive/workflows/release-rc-v0.15-rc.2.yml
rc_artifact_version: 0.15-rc.4
rc_artifact_history: historical-v0.15-rc4-only
rc_status: internal-gates-required-sandbox-only-not-formal-not-round6-candidate
host_audit_attestation: round6-prerelease-attestation.json
formal_gate_attestation: formal-release-attestation.json
promotion_workflow: .github/workflows/release-promote.yml
historical_v015_stable_release: PUBLISHED_MANUALLY/2026-07-20/TEN_ASSETS
historical_v015_independent_attestation: NOT_ATTACHED
host_matrix: v7.2.88
host_matrix_commit: 93d74a890a44802f656d7f39a573916b2611896e
host_attestation_schema: 2
host_evidence_fields: cpa_version,cpa_commit,cpa_host_sha256
upstream_version_policy: no-automatic-follow
external_admission: required
minimum_independent_evaluation: evaluation-v11
independent_evaluation_required_status: CONSUMED/PASS
historical_evaluation_v10_policy: immutable-consumed-fail-not-formal-input
formal_bundle_content_policy: exclude-evaluation-holdout-consumed-private-blind-retired
```

The `release_version`, `formal_tag`, and `local_rc_*` keys define the current
v0.16 source and local package target. The local `v0.16-rc.1` package may be
built for Linux amd64 handoff, but it does not create or imply a GitHub
Release, GitHub Actions result, formal attestation, production authorization,
or fresh CPA Host validation.

The workflow fields, `rc_artifact_version`, and `rc_status` intentionally
preserve the previously reviewed v0.15 release machinery as historical
records. Those workflows have not been migrated to v0.16 and must not be used
to claim v0.16 release evidence.

## Historical v0.15 workflow record

The candidate workflow creates a private, untagged, clean `0.15` SO and CPA
Store ZIP bound to an exact commit and tree. The Host and independent-audit
workflow may later attach an external attestation to an annotated development
tag at the same commit. The formal `v0.15` workflow rebuilds and byte-compares
the Host-tested SO and Store ZIP, creates a draft, and the separate promotion
workflow publishes that unchanged draft only after another protected approval.

The historical `v0.15-rc.4` workflow is a Linux-only side lane. It requires an
annotated tag at the exact `main` tip, a successful exact-main push CI, the
complete internal Linux gate set, CPA v7.2.88 source compatibility, RC-versioned
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

`v0.16` is the current CPA plugin/artifact tag target. It is intentionally a
two-component project version and is not a canonical Go module
semantic-version tag. The project must not publish a `v0.16.0` alias. The
historical v0.15 workflow record above retains its original two-component
identity and does not become a v0.16 release path.
