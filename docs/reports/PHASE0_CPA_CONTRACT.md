# CPA v7.2.86 Packaging and Contract Baseline

This path is retained by the audit-bundle contract, but its contents describe
only the current CPA target. Historical Phase 0 version matrices are available
in Git history and are not shipped here as active validation guidance.

The root module and both isolated integration modules pin CPA v7.2.86 at commit
`81d70f5d9f3fdb39a6290ed9c917ff0c6f27ca30`. Current validation paths are:

- the official Host source and fail-open fixture contract;
- latest-source compile, Interactions, and Store contracts;
- the Linux native Host and Router fixture targets;
- the CPA Store archive naming, root-layout, checksum, install, and overwrite
  contract.

See [CPA_INTEGRATION.md](CPA_INTEGRATION.md) for the active commands, exact
module checksums, last fully verified source baseline, and evidence boundary.
The owner-operated isolated CPA v7.2.86 Host + Mock-upstream record remains a
separate release requirement; source or CI compile checks do not authorize
production deployment.
