# Test Report — v0.1.0

Date: 2026-07-12 (Asia/Shanghai)

Target: CLIProxyAPI `v7.2.67`, commit
`2075f77c8ebe9ec872759965661936fb1ac2931f`, C ABI/RPC schema v1.

Environment: Ubuntu 26.04 under WSL2, Go 1.26.0, linux/amd64, cgo enabled,
GCC, 13th Gen Intel Core i7-13650HX.

## Result

All mandatory automated gates passed on the final source:

| Gate | Command | Result |
|---|---|---|
| Unit and package tests | `make test` | PASS |
| Static analysis | `make vet` | PASS |
| Data-race detector | `make race` | PASS |
| Extractor fuzz smoke | `go test ./internal/extract -run='^$' -fuzz=FuzzExtractText -fuzztime=5s` | PASS, 363,110 executions after the `data`-field bypass fix |
| Classifier fuzz smoke | `go test ./internal/classifier -run='^$' -fuzz=FuzzClassifier -fuzztime=5s` | PASS, 63,434 executions |
| Config fuzz smoke | `go test ./internal/config -run='^$' -fuzz=FuzzConfigParser -fuzztime=5s` | PASS, 91,869 executions |
| Native build | `make build-linux-amd64` | PASS, ELF x86-64 shared object |
| Real-host integration | `make integration-test` | PASS against CPA v7.2.67 |
| Release packaging | `make release verify-release` | PASS, checksums and ZIP allowlist verified |

The race run passed `cmd/cyber-abuse-guard`, `internal/audit`,
`internal/classifier`, `internal/config`, `internal/extract`, `internal/plugin`,
`internal/rules`, and `internal/subject`. The SQLite amalgamation emits two
compiler warnings about discarded `const` qualifiers; they originate in
`github.com/mattn/go-sqlite3` and do not fail compilation or tests.

An additional `go test -coverprofile=coverage.out` run measured 78.8% statement
coverage overall. Core-package values were classifier 90.2%, extract 87.8%,
subject 86.7%, config 83.2%, rules 75.0%, audit 70.5%, and plugin 69.7%. The C
export shim's coverage appears low under ordinary Go package tests; its ABI
exports and loader behavior are exercised by the native real-host suite.

## Security and failure-path coverage

- Request extraction covers OpenAI Chat, OpenAI Responses, Anthropic, Gemini,
  tool arguments, invalid JSON, empty input, image/base64 omission, deep JSON,
  scan limits, text-part limits, and Unicode edge cases.
- Regression cases prove that unknown/top-level/tool-argument fields named
  `data` remain scanned, while recognized media is omitted with a fail-closed
  truncation marker; unknown base64-like text is never silently discarded.
- Classification covers bilingual operational abuse, contextual allow cases,
  negation, multi-turn follow-ups, NFKC/zero-width/light homoglyph evasion,
  protected hard-block categories, and independent CTF/lab controls.
- Plugin tests cover ABI metadata, registration, every RPC boundary, panic
  recovery, structured 403 errors, `off` inertness, concurrent calls and
  reconfigure, invalid-config retention, and invalid-to-valid recovery.
- The real-host test injects a counting CPA auth selector: a safe request proves
  the probe is live, while all local blocks leave both auth-selection count and
  upstream usage count at zero. It also verifies the safe model/role/content
  arrives at the Mock Upstream unchanged.
- Audit tests verify WAL/busy-timeout behavior, bounded asynchronous writes,
  database-lock and open-failure degradation, retention/size cleanup,
  parameterized query/export paths, and idempotent shutdown.
- Privacy canary tests scan the SQLite database and WAL/SHM sidecars and verify
  that prompt text, API keys, and Authorization values are absent.
- Subject tests cover HMAC identities, secret-file permissions, rolling decay,
  repeat multipliers, cooldown, manual block/unblock, anonymous fallback, and
  concurrent access. Safe low-risk requests remain allowed during cooldown or
  manual block.

## Reproducibility

Use Go 1.26.0 on amd64 Linux:

```bash
make test vet race fuzz-smoke benchmark
make integration-test
make release verify-release
```

Wall-clock performance values vary by host. The enforced acceptance limits are
recorded in `PERFORMANCE.md`; corpus results are in `CORPUS_REPORT.md`; the
real CPA evidence is in `CPA_INTEGRATION.md`.
