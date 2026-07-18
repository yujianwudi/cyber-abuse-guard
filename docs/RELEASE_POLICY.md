# v0.15 release admission policy

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
rc_workflow_archive: docs/archive/workflows/release-rc-v0.15-rc.2.yml
rc_artifact_version: 0.15-rc.2
rc_status: sandbox-only-not-formal-not-round6-candidate
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

The archived `v0.15-rc.2` workflow definition records a retired attempted
publication path. Its recorded runs failed and did not produce the public RC.
The public Linux amd64 sandbox assets were instead published through the
separately disclosed direct owner override. Their artifact identity is exactly
`0.15-rc.2`, and the release manifest explicitly states `SANDBOX_ONLY /
SERVER_VALIDATION_REQUIRED / NOT_FORMAL / NOT_ROUND6_CANDIDATE`. RC assets are
never accepted as the private Round 6 candidate, external
Host/audit/evaluation evidence, or formal `v0.15` input. The retired attempted
workflow is retained only as non-executable historical evidence and is not an
active publication entry point.

The consumed v10 evaluation remains historical FAIL evidence. It is never
rerun, upgraded, or treated as a formal-build input. A release candidate needs
a separately authored, previously unseen v11-or-later evaluation whose
low-sensitivity report is bound by SHA-256 in the Host/audit prerelease
attestation. Raw evaluation, holdout, consumed, private, blind, and retired
materials are not copied into formal source or audit bundles.

`v0.15` is a CPA plugin/artifact tag. It is intentionally a two-component
project version and is not a canonical Go module semantic-version tag. The
project must not publish a `v0.15.0` alias.
