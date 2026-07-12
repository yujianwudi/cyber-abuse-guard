# Performance Report — v0.1.0

Measured 2026-07-12 on Ubuntu 26.04/WSL2, Go 1.26.0, linux/amd64, cgo enabled,
13th Gen Intel Core i7-13650HX. Remote classification was disabled.

## Acceptance run

`TestClassifierPerformanceAcceptance` measured 10,000 sequential decisions
after warm-up:

| Metric | Result | Target | Status |
|---|---:|---:|---|
| P50 | 34.221 microseconds | < 0.5 ms | PASS |
| P95 | 66.810 microseconds | < 2 ms | PASS |
| P99 | 125.515 microseconds | < 5 ms | PASS |
| Total allocation | 34,402,248 bytes / 10,000 | bounded | PASS |

The measured allocation is about 3.44 KiB per ordinary decision. The test also
forces garbage collection before and after the run and rejects more than 16 MiB
of retained-heap growth.

## Concurrency and resource stability

`TestClassifierRepeatedConcurrencyAndResourceSanity` ran 100 workers and
10,000 total classifications. It reported:

- zero incorrect decisions;
- goroutines `32 -> 32`;
- retained heap delta `-2,527,824` bytes after GC;
- no race findings in the full `make race` run.

SQLite audit writes use a bounded queue and never wait on the request path.
Database open/lock/write failures degrade audit status while rule enforcement
continues. These paths are covered by unit and race tests.

## Go benchmarks

`make benchmark` (`-benchmem -count=3`) produced:

| Case | Time/op range | Bytes/op | Allocs/op |
|---|---:|---:|---:|
| Typical operational prompt | 35.485–37.444 microseconds | 3,464 | 29 |
| Large benign input (~280 KiB) | 25.561–27.898 ms | 1,320,448 | 7 |
| Maximum punctuation-heavy normalization | 28.366–31.022 ms | 1,590,784 | 8 |

The ordinary request path is far below every latency target. Deliberately large
near-budget inputs are bounded but allocate about 1.3–1.6 MiB in the classifier,
so the task book's aspirational “under 1 MiB” goal is not met for these worst
cases. This is disclosed rather than hidden; `max_scan_bytes`, normalized-rune,
JSON-depth, and text-part limits bound the work, and a future version should use
a streaming/byte-oriented normalized matcher to reduce peak allocation.
