# CPA v7.2.72 host routing source contract

This isolated module pins `github.com/router-for-me/CLIProxyAPI/v7` to
`v7.2.72`. `host_source_contract_test.go` verifies the resolved module version
and then runs the routing tests shipped in CPA's official
`internal/pluginhost` package.

Run only this contract:

```bash
go test -run TestOfficialCPAHostRoutingSourceContract -count=1 -v .
```

Run every contract in this isolated module:

```bash
go test -count=1 -v ./...
```

The upstream selection is intentionally broad enough to cover:

- descending Router priority and first handled match;
- same-priority ordering by ascending plugin ID;
- continuation after an unhandled response or Router error;
- panic recovery, plugin fuse, and fallback to the next Router;
- invalid, missing, or unavailable executor targets;
- executor readiness failures caused by a missing identifier, unsupported
  formats, or an OAuth-only scope.

This is source-level evidence only. It does not build, load, or execute a
Cyber Abuse Guard shared object, and it does not replace server-sandbox tests
of the compiled plugin, HTTP responses, Auth Selector, Usage, or upstream
isolation.
