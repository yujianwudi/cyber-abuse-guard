# CPA v7.2.72 plugin-store contract test

This isolated Go module exists because the repository's main module cannot
legally import CPA's `internal/pluginstore` package. Its module path is under
the CPA v7 import prefix and its dependency is pinned exactly to `v7.2.72`.

The tests treat the plugin library as opaque bytes. They never load or execute
the `.so` file.

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
