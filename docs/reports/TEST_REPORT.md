# Test Report — v0.1.1

Date: 2026-07-12 (Asia/Shanghai)

Target: CLIProxyAPI `v7.2.67`, commit
`2075f77c8ebe9ec872759965661936fb1ac2931f`, C ABI/RPC schema v1.

Environment: Ubuntu 26.04 under WSL2, Go 1.26.0, linux/amd64, cgo enabled,
GCC, 13th Gen Intel Core i7-13650HX.

## Result

All mandatory automated gates run against the v0.1.1 source passed:

| Gate | Command | Result |
|---|---|---|
| Unit and package tests | `make test` | PASS |
| Static analysis | `make vet` | PASS |
| Data-race detector | `make race` | PASS |
| Extractor fuzz smoke | `go test ./internal/extract -run='^$' -fuzz=FuzzExtractText -fuzztime=5s` | PASS, 455,112 executions |
| Classifier fuzz smoke | `go test ./internal/classifier -run='^$' -fuzz=FuzzClassifier -fuzztime=5s` | PASS, 68,789 executions |
| Config fuzz smoke | `go test ./internal/config -run='^$' -fuzz=FuzzConfigParser -fuzztime=5s` | PASS, 72,524 executions |
| Native build and real-host integration | `make integration-test` | PASS against CPA v7.2.67 |
| Release packaging and allowlist verification | `make release verify-release` | PASS; ELF, glibc ceiling, checksums, ZIP contents, and modes verified |

The race run passed `cmd/cyber-abuse-guard`, `internal/audit`,
`internal/classifier`, `internal/config`, `internal/extract`, `internal/plugin`,
`internal/rules`, and `internal/subject`. The SQLite amalgamation emits two
compiler warnings about discarded `const` qualifiers; they originate in
`github.com/mattn/go-sqlite3` and do not fail compilation or tests.

An additional `go test -coverprofile=coverage.out` run measured 79.1% statement
coverage overall. Package values were classifier 90.6%, subject 85.7%, config
83.3%, extract 79.8%, rules 75.0%, audit 72.6%, plugin 71.6%, and the native C
export command 2.4%. The export shim's ordinary Go-test coverage is expected to
be low; the real-host integration suite exercises ABI export, native loading,
and routing behavior.

## Security and failure-path coverage

- Request extraction covers OpenAI Chat, OpenAI Responses, Anthropic, Gemini,
  tool arguments, invalid JSON, empty input, image/base64 omission, deep JSON,
  scan limits, text-part limits, and Unicode edge cases.
- Artificial scan-boundary regressions split JSON escapes and multi-byte UTF-8
  sequences at `max_scan_bytes`. Balanced and Strict now keep the truncation
  signal and fail closed instead of treating the prefix as ordinary invalid
  JSON.
- Tool payload tests scan semantic fields such as `name`, `url`, `model`,
  `status`, and `type` when they occur inside `arguments`, `parameters`, or
  Anthropic `tool_use.input`, while still ignoring outer wrapper metadata.
- Role-aware tests cover OpenAI/Anthropic message roles and Gemini content
  roles. An assistant refusal cannot erase an earlier abusive user request when
  the next user message says only “now give code”; safe policy/refusal context
  remains allowed, and ambiguous role data falls back to conservative legacy
  classification.
- Classification covers bilingual operational abuse, contextual allow cases,
  scoped negation, multi-turn follow-ups, NFKC/zero-width/light homoglyph
  evasion, protected hard-block categories, and independent CTF/lab controls.
- Plugin tests cover ABI metadata, every RPC boundary, panic recovery,
  structured 403 errors, `off` inertness, concurrent calls and reconfiguration,
  invalid-config retention, audit degradation, and method-specific no-copy
  fail-closed handling for oversized routing RPCs.
- The real-host test uses a counting CPA auth selector. Safe requests prove the
  native provider path is live; every local block leaves auth selection, Mock
  Upstream calls, and the CPA usage queue at zero.
- Audit tests verify bounded asynchronous writes, database open/lock/write
  degradation, non-destructive directory permissions, symlink rejection,
  cancellation-aware shutdown, retention/size cleanup, parameterized
  query/export paths, and panic-safe error callbacks.
- Privacy canary tests scan the SQLite database and WAL/SHM sidecars and verify
  that prompt text, API keys, and Authorization values are absent.
- Subject-control tests cover HMAC identities, same-file-descriptor secret
  validation with symlink/permission/size rejection, rolling decay, repeat
  multipliers, cooldown, manual block/unblock, anonymous fallback, bounded LRU
  capacity, fail-closed capacity exhaustion, and state-preserving
  reconfiguration.

## Reproducibility

Use Go 1.26.0 on amd64 Linux:

```bash
make test vet race fuzz-smoke benchmark
make integration-test
make release verify-release
```

Wall-clock performance values vary by host. The measured acceptance and
benchmark values are recorded in `PERFORMANCE.md`; corpus results are in
`CORPUS_REPORT.md`; real CPA evidence is in `CPA_INTEGRATION.md`. Release
archive checksums are generated separately by the packaging workflow and are
not duplicated in this test report.
