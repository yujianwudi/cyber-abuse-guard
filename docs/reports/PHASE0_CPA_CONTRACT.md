# CPA v7.2.88 Packaging and Contract Baseline

```text
current_classifier_policy_version: classifier-policy-v5
current_classifier_policy_sha256: 07e972eac4faba57ca5244e9a49d5db21d5c0e414778bf617b5378fa621b4f76
```

This path is retained by the audit-bundle contract, but its contents describe
only the current CPA target. Historical Phase 0 version matrices are available
in Git history and are not shipped here as active validation guidance.

The root module and both isolated integration modules pin CPA v7.2.88 at commit
`93d74a890a44802f656d7f39a573916b2611896e`. Current validation paths are:

- the official Host source and fail-open fixture contract;
- pinned-source compile, Interactions, and Store contracts;
- the Linux native Host and Router fixture targets;
- the CPA Store archive naming, root-layout, checksum, install, and overwrite
  contract.

See [CPA_INTEGRATION.md](CPA_INTEGRATION.md) for the active commands, exact
module checksums, last fully verified source baseline, and evidence boundary.
The owner-operated isolated CPA v7.2.88 Host + Mock-upstream record remains a
separate release requirement; source or CI compile checks do not authorize
production deployment.

This release line does not automatically follow later upstream CPA versions.
Host evidence uses prerelease attestation schema v2 fields `cpa_version`,
`cpa_commit`, and `cpa_host_sha256`.
