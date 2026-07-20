# v0.15 release admission policy

```text
current_classifier_policy_version: classifier-policy-v5
current_classifier_policy_sha256: 0e114d98862282d2492fb62e4300297b4746eeaf8165339603d02c48d11bd60b
```

This source file defines the release process; it does not claim that external
Host, audit, or publication gates have passed. A source commit becomes an
official release only when the GitHub Release is non-draft and carries the
attestations named below. Pull requests and source snapshots are never
deployment authorization by themselves.

```text
release_version: 0.15
formal_tag: v0.15
version_alias_policy: reject-v0.15.0
platform: linux-amd64
candidate_workflow: .github/workflows/candidate.yml
candidate_attestation: candidate-manifest.json
attested_prerelease_workflow: .github/workflows/attested-prerelease.yml
rc_workflow: .github/workflows/release-rc.yml
rc_workflow_archive: docs/archive/workflows/release-rc-v0.15-rc.2.yml
rc_artifact_version: 0.15-rc.3
rc_status: internal-gates-pass-sandbox-only-not-formal-not-round6-candidate
host_audit_attestation: round6-prerelease-attestation.json
formal_gate_attestation: formal-release-attestation.json
promotion_workflow: .github/workflows/release-promote.yml
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

The candidate workflow creates a private, untagged, clean `0.15` SO and CPA
Store ZIP bound to an exact commit and tree. The Host and independent-audit
workflow may later attach an external attestation to an annotated development
tag at the same commit. The formal `v0.15` workflow rebuilds and byte-compares
the Host-tested SO and Store ZIP, creates a draft, and the separate promotion
workflow publishes that unchanged draft only after another protected approval.

The active `v0.15-rc.3` workflow is a Linux-only side lane. It requires an
annotated tag at the exact `main` tip, a successful exact-main push CI, the
complete internal Linux gate set, CPA v7.2.88 source compatibility, RC-versioned
integration, two independent clean-clone rebuilds, and byte verification of a
17-asset formal-structure package. Its evidence and manifest explicitly state
`RC_INTERNAL_GATES_PASS / SANDBOX_ONLY / SERVER_VALIDATION_REQUIRED /
NOT_FORMAL / NOT_ROUND6_CANDIDATE`; real CPA Host validation, independent audit,
and independent evaluation remain absent.

The archived `v0.15-rc.2` workflow remains immutable historical evidence. Its
recorded attempts failed; the public RC2 assets were published separately
through the disclosed direct owner override. RC2 and RC3 assets are never
accepted as the private Round 6 candidate, external Host/audit/evaluation
evidence, or formal `v0.15` input.

The consumed v10 evaluation remains historical FAIL evidence. It is never
rerun, upgraded, or treated as a formal-build input. A release candidate needs
a separately authored, previously unseen v11-or-later evaluation whose
low-sensitivity report is bound by SHA-256 in the Host/audit prerelease
attestation. Raw evaluation, holdout, consumed, private, blind, and retired
materials are not copied into formal source or audit bundles.

`v0.15` is a CPA plugin/artifact tag. It is intentionally a two-component
project version and is not a canonical Go module semantic-version tag. The
project must not publish a `v0.15.0` alias.
