# CPA v7.2.72 source contracts

This isolated Go module exists because the repository's main module cannot
legally import CPA's `internal/pluginstore` package. Its module path is under
the CPA v7 import prefix and its dependency is pinned exactly to `v7.2.72`.

It contains two source-level contract suites:

- `archive_contract_test.go` exercises the official
  `pluginstore.InstallArchive` naming, ZIP-root layout, checksum, install,
  overwrite, and repeat-install behavior with opaque plugin bytes.
- `host_source_contract_test.go` runs CPA's official Host Router
  ordering/fallback tests with the upstream in-memory fakes. The exact audited
  behaviors and limitations are recorded in
  [CPA_HOST_SOURCE_CONTRACT.md](CPA_HOST_SOURCE_CONTRACT.md).

The suites never load or execute this project's `.so`. Pinning CPA v7.2.72
here does not change the root module's CPA v7.2.67 runtime baseline and is not
evidence of native-host compatibility with CPA v7.2.72.

Run the source-level contract tests:

```bash
go test ./... -count=1
```

After release packaging has populated a distribution directory, verify the
real store ZIP, `checksums.txt`, standalone library, official install path, and
repeat-install behavior:

```bash
DIST_DIR=/absolute/path/to/dist go test ./... -run '^TestPublishedStoreArchive$' -count=1 -v
```
