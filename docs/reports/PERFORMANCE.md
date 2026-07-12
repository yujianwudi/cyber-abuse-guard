# Performance Report — v0.1.1

Measured 2026-07-12 on Ubuntu 26.04/WSL2, Go 1.26.0, linux/amd64, cgo enabled,
13th Gen Intel Core i7-13650HX. Remote classification was disabled.

## Acceptance run

`TestClassifierPerformanceAcceptance` measured 10,000 sequential decisions
after warm-up:

| Metric | Result | Target | Status |
|---|---:|---:|---|
| P50 | 28.332 microseconds | < 0.5 ms | PASS |
| P95 | 53.809 microseconds | < 2 ms | PASS |
| P99 | 142.819 microseconds | < 5 ms | PASS |
| Total allocation | 32,482,232 bytes / 10,000 | bounded | PASS |

The measured allocation is about 3.25 kB per ordinary decision. The test also
forces garbage collection before and after the run and rejects more than 16
MiB of retained-heap growth.

## Concurrency and resource stability

`TestClassifierRepeatedConcurrencyAndResourceSanity` ran 100 workers and
10,000 total classifications. It reported:

- zero incorrect decisions;
- goroutines `2 -> 2`;
- retained heap delta `-2,541,768` bytes after GC;
- no race findings in the full `make race` run.

SQLite audit writes use a bounded queue and never wait on the request path.
Database open/lock/write failures degrade audit status while rule enforcement
continues. On its deadline, shutdown cancels in-flight SQLite work and returns;
a background finalizer owns any driver cleanup that has not yet completed.
Callbacks run outside store locks, and runtime shutdown clears the handler so
no new host callback starts. An already-running host logger is a documented
trusted/nonblocking host assumption. These paths are covered by unit and race
tests.

## Go benchmarks

`go test ./internal/classifier -run='^$' -bench=. -benchmem -count=3` produced:

| Case | Time/op range | Bytes/op | Allocs/op |
|---|---:|---:|---:|
| Typical operational prompt | 21.843–23.626 microseconds | 3,272 | 27 |
| Four-role follow-up (`system/user/assistant/user`) | 33.189–39.317 microseconds | 11,600 | 68 |
| Large benign input (~280 KiB) | 17.171–18.156 ms | 1,050,144–1,050,149 | 7 |
| Maximum punctuation-heavy normalization | 17.038–23.336 ms | 1,050,144–1,050,145 | 7 |
| Candidate-rich adversarial input | 74.634–81.537 ms | 12,624 | 118 |

Ordinary and role-aware conversational requests remain far below every latency
target. v0.1.1 performs directive analysis once per classification and reuses
matcher scratch storage, which keeps the candidate-rich case to about 12.6
kB/op even though its intentionally dense candidate set costs substantially
more CPU than a normal prompt.

Deliberately large near-budget inputs remain bounded but allocate about
1,050,144–1,050,149 bytes/op, slightly above the task book's aspirational
“under 1 MB” goal. This
is disclosed rather than hidden: `max_scan_bytes`, normalized-rune, JSON-depth,
role-segment, and text-part limits bound the work, and a future streaming or
byte-oriented normalized matcher could reduce peak allocation further.
