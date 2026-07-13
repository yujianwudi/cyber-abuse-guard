# Performance Report — v0.1.2 candidate

## Status

**PRE-PROMPT-INJECTION-CHANGE BASELINE — CURRENT DIFF NOT BENCHMARKED.** The
recorded v0.1.2 engineering performance preflight passed on the recorded WSL2
host before the current classifier/extractor changes. The values below are
historical regression context, not current-diff performance evidence. This does
not approve release: methodologically valid evaluation v10 is `CONSUMED / FAIL`,
so no clean release tag or production artifact may be created.

The release acceptance targets are:

| Metric/case | Release target | Pre-change baseline result |
|---|---:|---|
| Ordinary decision P95 | `< 2 ms` | **PASS — 124.682 us** |
| Ordinary decision P99 | `< 5 ms` | **PASS — 216.869 us** |
| Resource sanity after acceptance run | bounded; no leak trend | **PASS — goroutines stable** |
| Candidate-rich adversarial input | `<= 100 ms/op` on recorded host | **PASS — 78.335194 ms/op** |
| Near-budget large input | `<= 25 ms/op` on recorded host | **PASS — 14.970291 ms/op** |
| Near-budget allocation | `< 1,000,000 bytes/op` | **PASS — 293,906 B/op** |
| Race detector | no findings | **PASS** |

The candidate-rich and near-budget CPU limits are host-specific regression
ceilings. The final report must record CPU model, OS/kernel, Go version,
`GOMAXPROCS`, power/virtualization context, run count, and variance. A materially
different release runner needs a recorded baseline rather than an unexplained
waiver.

## Historical v0.1.1 baseline (not v0.1.2 evidence)

The last accepted v0.1.1 run on Ubuntu/WSL2 with a 13th Gen Intel Core
i7-13650HX recorded:

| Case | Historical result |
|---|---:|
| Ordinary P50 | 28.332 microseconds |
| Ordinary P95 | 53.809 microseconds |
| Ordinary P99 | 142.819 microseconds |
| Typical operational prompt | 21.843–23.626 microseconds; 3,272 B/op |
| Four-role follow-up | 33.189–39.317 microseconds; 11,600 B/op |
| Near-budget large input | 17.171–18.156 ms; ~1,050,144 B/op |
| Candidate-rich adversarial input | 74.634–81.537 ms; 12,624 B/op |

The historical near-budget allocation exceeded the v0.1.2 aspirational
`< 1,000,000 bytes/op` goal. That is a known baseline gap, not a PASS. Bounded
URL/HTML/Base64 decoding also adds work and therefore requires a fresh
measurement.

## Pre-change v0.1.2 candidate measurements

Recorded on Go 1.26.4, Linux amd64 under WSL2, 20 logical CPUs, 13th Gen
Intel(R) Core(TM) i7-13650HX:

| Case | Candidate result |
|---|---:|
| Ordinary P50 / P95 / P99 | 76.296 / 124.682 / 216.869 microseconds |
| Typical raw classifier benchmark | 79.695–83.886 microseconds; 20,350 B/op; 42 allocs/op |
| Candidate-rich max-parts acceptance | 78.335194 ms/op |
| Candidate-rich raw benchmark | 76.693716–80.439013 ms/op; 78,360 B/op; 174 allocs/op |
| Near-budget acceptance | 14.970291 ms/op; 293,906 B/op |
| Concurrency/resource sanity | 100 workers; 10,000 classifications; goroutines 2→2 |

## Reproduction

Run the release acceptance and raw benchmarks on the final commit:

```bash
go test -tags=sqlite_omit_load_extension ./internal/classifier \
  -run 'TestClassifierPerformanceAcceptance|TestClassifierRepeatedConcurrencyAndResourceSanity' \
  -count=1 -v

go test -tags=sqlite_omit_load_extension ./internal/classifier \
  -run='^$' -bench=. -benchmem -count=5
```

Capture machine and Go information:

```bash
go version
go env GOOS GOARCH CGO_ENABLED GOMAXPROCS GOAMD64
uname -a
lscpu
```

The release CI runs at least the light acceptance and benchmark suite. If the
allocation target or any hard latency/CPU gate fails, report the failure and do
not weaken scan coverage, byte/depth/part limits, decoding, role handling, or
rules merely to improve a benchmark.

## CPU profile procedure

Generate a classifier-only profile with fixed inputs and no network activity:

```bash
mkdir -p build/profiles
go test -tags=sqlite_omit_load_extension ./internal/classifier \
  -run='^$' -bench='BenchmarkClassifier|BenchmarkClassifierCandidateRich' \
  -benchtime=10s -cpuprofile=build/profiles/classifier-cpu.pprof \
  -memprofile=build/profiles/classifier-mem.pprof

go tool pprof -top build/profiles/classifier-cpu.pprof \
  > build/profiles/classifier-cpu-top.txt
go tool pprof -top build/profiles/classifier-mem.pprof \
  > build/profiles/classifier-mem-top.txt
```

Profiles may contain function/file names but must not use production requests.
Use repository fixtures only, do not ship `.pprof` files in either release ZIP,
and record only aggregate findings in this report.

## Final result block

```text
release_commit_and_tag: NOT CREATED — RELEASE BLOCKED
ruleset_version: 1.0.7
ruleset_sha256: 7bef8b0854b4d75dd5d807e1c33e93b708af4e9e29d0d2b59a18b9031c4da134
host: WSL2 Linux 6.18.33.1; 13th Gen Intel Core i7-13650HX; 20 logical CPUs
go_version: go1.26.4 linux/amd64
ordinary_p50: 76.296 us
ordinary_p95: 124.682 us
ordinary_p99: 216.869 us
raw_classifier_benchmark: 79.695-83.886 us/op; 20350 B/op; 42 allocs/op
candidate_rich_acceptance: 78.335194 ms/op
candidate_rich_benchmark: 76.693716-80.439013 ms/op; 78360 B/op; 174 allocs/op
near_budget_acceptance: 14.970291 ms/op
near_budget_bytes_op: 293906
race_result: PASS
overall_performance_gate: PASS PRE-CHANGE BASELINE; CURRENT DIFF NOT RUN; RELEASE GATE remains FAIL
```
