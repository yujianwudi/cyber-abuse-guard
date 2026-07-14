# Phase 0 CPA contract and packaging report

Last updated: 2026-07-14 (Asia/Shanghai)

> Historical Phase 0 snapshot. At that time the root module used CPA v7.2.67
> while `integration/pluginstorecontract` used v7.2.72. Those statements are
> superseded by implementation freeze `61536f9`, whose root dependency is CPA
> v7.2.72. See `CPA_INTEGRATION.md` and
> `LEO_VERIFICATION_HANDOFF.md` for current evidence. The historical findings
> below are intentionally retained rather than rewritten.

## Decision

**RELEASE BLOCKED.** This Phase 0 work repairs source-level CPA contracts and
the release-chain design without changing classifier semantics. It does not
override the consumed v10 failure, authorize a tag or GitHub Release, or claim
production readiness.

The root module remains pinned to CPA `v7.2.67`. The isolated contract module
under `integration/pluginstorecontract` pins CPA `v7.2.72` only so the project
can test the official `pluginstore.InstallArchive` and host-routing source
contracts. This is not a claim that the native plugin is compatible with CPA
v7.2.72; that claim requires owner-operated server integration.

## Artifact contract

The release chain now distinguishes two archives:

```text
cyber-abuse-guard_<version>_linux_amd64.zip
└── cyber-abuse-guard-v<version>.so

cyber-abuse-guard-v<version>-audit-bundle.zip
├── plugins/linux/amd64/cyber-abuse-guard-v<version>.so
├── README.md
├── docs/
├── build-metadata.json
├── ruleset-manifest.json
└── sbom.cdx.json
```

The CPA store ZIP must contain exactly one regular mode-0755 `.so` at the ZIP
root. The audit bundle retains the strict documentation, metadata, history,
mode, source-binding, secret-path, and symlink checks. `checksums.txt` covers
both archives.

The isolated contract tests call the real CPA v7.2.72
`pluginstore.InstallArchive`. They verify the official archive name, checksum,
installed path, installed bytes, repeat-install skip behavior, repair after an
installed file is modified, and rejection of the legacy nested layout. The
tests treat `.so` content as opaque bytes and never load it.

## Executor contract

`executor.execute`, `executor.execute_stream`, and `executor.count_tokens` now
return the same local policy 403 envelope. Oversized calls on all three paths
also return a policy 403 with category `scan_limit`. `executor.http_request`
remains explicitly unsupported with HTTP 405.

Source-level tests prove that these executor paths do not invoke plugin host
callbacks. Real CPA HTTP evidence for OpenAI Chat, OpenAI Responses, Claude,
Gemini, streaming headers/chunks, token counting, Auth Selector, Usage, and
Mock Upstream remains a required server-sandbox matrix.

## Host fail-open boundary

The pinned CPA v7.2.72 official source tests confirm priority descending order
and plugin-ID ascending order at equal priority. They also confirm that Router
errors, Router panic/fuse, invalid or unavailable targets, and executor
readiness failures continue to later Routers or native routing.

The plugin's `enforcement_ready` status is internal only. It does not prove
that the host loaded and registered the library, that the plugin is not fused,
that Router priority is effective, or that the host accepted the executor
identifier, scope, and formats.

## Management boundary

Plugin-level limits remain 1 MiB for the management request body and 2 MiB for
the serialized RPC envelope. CPA v7.2.72 currently calls `io.ReadAll` on the
HTTP body before invoking the plugin, so these limits do not bound host-side
HTTP memory use. A reverse proxy or gateway must reject oversized management
requests before CPA; the server sandbox must prove that boundary with HTTP 413.

## Verification completed in this workspace

No native library was loaded, no CPA service was deployed, no formal release
archive was produced, and no v10 row or rerun was accessed.

Completed source-level checks:

```text
bash -n changed release scripts                                  PASS
scripts/create-store-archive-test.sh                             PASS
go test -tags=sqlite_omit_load_extension plugin/cmd packages     PASS
targeted go vet and race for plugin/cmd packages                 PASS
go -C integration/pluginstorecontract test ./...                PASS
synthetic DIST_DIR TestPublishedStoreArchive                    PASS
CPA v7.2.72 TestHostRouteModel*                                  PASS
CPA v7.2.72 TestSortRecordsPriorityDescendingAndIDTieBreak       PASS
```

`TestPublishedStoreArchive` passed against a synthetic distribution directory
created by `scripts/create-store-archive-test.sh`. The same test is wired into
`scripts/package-release.sh` and `make cpa-store-contract`. It was not run
against a real built `.so` in this workspace because formal/local packaging is
prohibited for the blocked candidate; that final artifact check must run on the
server-built output.

## Required server-sandbox evidence

- the real store ZIP installs to
  `<plugins>/linux/amd64/cyber-abuse-guard-v<version>.so`;
- OpenAI Chat, OpenAI Responses, Claude, and Gemini non-stream blocks return
  HTTP 403 with Auth Selector, Usage, Provider, and Upstream counts all zero;
- streaming blocks return synchronous HTTP 403 before a success SSE content
  type or chunk;
- token counting returns the same policy 403 with all upstream-side counts
  zero;
- higher-priority Router takeover, guard-first priority, equal-priority ID
  ordering, unloaded/register-failed/not-ready/fused cases match the documented
  host fail-open behavior;
- the deployment proxy returns 413 before CPA reads an oversized management
  body.

Until those checks and later classifier phases pass, the release decision is
`BLOCKED`.
