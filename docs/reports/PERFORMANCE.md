# Performance Report — historical evidence and v0.16 development acceptance

```text
current_classifier_policy_version: classifier-policy-v6
current_classifier_policy_sha256: ece497210db938528cb166a34f2ce3013324b792a7eedf276a96fa5d256001d4
```

Last updated: 2026-07-21 (Asia/Shanghai)

## Status

**DEVELOPMENT SELF-CHECK / NOT RELEASE EVIDENCE.** The current section records
the complete local Linux P1-P2 gate and benchmark run on branch
`fix/p1-p2-hardening-v016`, based on
`7b2422ed30c11d405d05bcb6b46a2527eed6471b`. It is not bound to a package,
GitHub Actions artifact, GitHub Release, or real CPA Host attestation.

The later sections retain older classifier and reliability measurements as
historical regression context. They are not current v0.16 evidence, a formal
release benchmark, or a blind quality result. Methodologically valid evaluation
v10 remains the frozen, first-and-only authoritative `FAIL`; that blind set is
consumed and was not rerun.

The WSL command `make cpa-router-fixture-blackbox`, the now-removed legacy
target `cpa-v7272-host-blackbox`, and
`scripts/management-proxy-413-test.sh` were mistakenly executed outside the
authorized evidence path. They used loopback/Mock components only and cleanup
left no fixture process. Their results are excluded from this report:

```text
LOCAL MIS-EXECUTION RECORDED / EXCLUDED; NOT AUTHORITATIVE
```

## Current v0.16 P1-P2 performance self-check

Environment and scope:

- Date: 2026-07-21 (Asia/Shanghai).
- Platform: WSL Ubuntu-26.04, Linux amd64.
- Toolchain: Go 1.26.4 with `GOTOOLCHAIN=local`.
- Source: P1-P2 development branch based on `7b2422e`; not artifact-bound.
- Evidence class: **DEVELOPMENT SELF-CHECK / NOT RELEASE EVIDENCE**.

The acceptance checks below were produced by the complete
`make round6-benchmark` target with the existing Linux toolchain. The same
frozen code also passed `make test`, `make round6-vet`,
`make round6-format-check`, `make round6-module-verify`,
`make round6-script-test`, deterministic 13-target `make fuzz-smoke`, audit and
raw-capture race tests, and the pinned CPA v7.2.88 raw-capture Host source
overlay.

- `go test ./internal/extract -count=1 -v -run='^TestRound6LongTextScaleAcceptance$'`
- `go test ./internal/audit -count=1 -v -run='^TestRawCapturePerformanceAcceptance$'`
- `go test -tags=sqlite_omit_load_extension ./internal/plugin -count=1 -v -run='^TestRawCaptureManagementResponsePerformanceAcceptance$'`

### P2 long-JSON scaling

The Near-8 MiB body size is `8 MiB - 4 KiB`. Every fixture also enforces a
CPU-slope gate: its Near-8 MiB `ns/byte` must be no more than 2.5 times its
1 MiB `ns/byte`.

| Fixture | 1 MiB threshold and observation | Near-8 MiB threshold and observation | Self-check |
|---|---|---|---|
| Text | <= 150 ms, <= 512 KiB/op, <= 64 allocs/op; observed 20.0 ms, 342,036 B/op, 45 allocs/op | <= 1.2 s, <= 512 KiB/op, <= 64 allocs/op; observed 155.7 ms, 341,997 B/op, 45 allocs/op | **PASS**, including slope |
| KeyRich | <= 150 ms, <= 768 KiB/op, <= 25,000 allocs/op; observed 4.89 ms, 372,029 B/op, 17,205 allocs/op | <= 1.2 s, <= 3 MiB/op, <= 160,000 allocs/op; observed 41.8 ms, 2,409,686 B/op, 137,464 allocs/op | **PASS**, including slope |
| SemanticRich | <= 150 ms, <= 512 KiB/op, <= 10,000 allocs/op; observed 4.33 ms, 160,400 B/op, 5,473 allocs/op | <= 1.2 s, <= 1 MiB/op, <= 60,000 allocs/op; observed 32.9 ms, 717,366 B/op, 43,553 allocs/op | **PASS**, including slope |

### P1 raw-capture and management response

| Acceptance case | Frozen threshold | Observed result | Self-check |
|---|---|---|---|
| Near-8 MiB prepare (`8 MiB - 64 KiB` request) | latency <= 1.2 s; <= 4 MiB/op; <= 160 allocs/op | 457,790,105 ns/op; 3,355,125 B/op; 43 allocs/op | **PASS** |
| Near-8 MiB composite event + capture admission | latency <= 1.5 s; <= 5 MiB/op; <= 200 allocs/op | 454,296,686 ns/op; 3,360,418 B/op; 68 allocs/op | **PASS** |
| Queue-full rejection before body preparation | latency <= 50 us; exactly 0 B/op and 0 allocs/op | 46 ns/op; 0 B/op; 0 allocs/op | **PASS** |
| Management response, eight 1 MiB worst-case HTML fixtures, bounded to complete 8 MiB CPA Host body | latency <= 500 ms; <= 16 MiB/op; <= 1,600 allocs/op | 54,596,462 ns/op; 8,529,000 B/op; 1,329 allocs/op | **PASS** |

These `testing.Benchmark` acceptance samples report aggregate `ns/op`,
`B/op`, and `allocs/op`. They do **not** collect or prove p50, p95, p99, peak
RSS, end-to-end CPA Host latency, request throughput, or concurrent-load
behavior; those values are **UNAVAILABLE / NOT MEASURED** and must not be
inferred from `ns/op`. A release candidate still needs an exact-commit run with
the pinned CPA v7.2.88 Host and a separately instrumented tail-latency/RSS test
if those metrics are made release gates.

Exact-main GitHub CI run
[`29799561002`](https://github.com/yujianwudi/cyber-abuse-guard/actions/runs/29799561002)
predates this P1-P2 working tree and failed in both attempts before benchmark
and artifact stages completed. It supplies no current v0.16 performance
evidence or Actions artifact.

The remaining release-level comparisons are **NOT RUN**: ordinary allowed
requests with capture disabled/enabled, final blocked requests through the real
Host, 1 MiB and Host-limit end-to-end routes, `limit=20` versus `limit=100`
management pages, and concurrent load. Sensitive request text must not appear
in benchmark logs or public Actions artifacts.

## Historical classifier before/after reference

Environment:

```text
OS/arch: Windows amd64
CPU: 13th Gen Intel Core i7-13650HX
Go: 1.26.4
Command: go test ./internal/classifier -run '^$' \
  -bench '^BenchmarkClassifier' -benchmem -count=3
Statistic: median of three runs
```

| Benchmark | `a121a44` median | `a1be19f` median | Latency change |
|---|---:|---:|---:|
| `Classifier` | 165,552 ns/op; 24,446 B/op; 43 allocs/op | 103,190 ns/op; 25,487 B/op; 46 allocs/op | -37.7% |
| `LargeBenign` | 18,461,010 ns/op; 301,778 B/op; 9 allocs/op | 17,682,477 ns/op; 300,966 B/op; 9 allocs/op | -4.2% |
| `LargePunctuation` | 17,705,454 ns/op; 301,778 B/op; 9 allocs/op | 16,397,845 ns/op; 299,551 B/op; 9 allocs/op | -7.4% |
| `CandidateRichMaxParts` | 119,484,917 ns/op; 82,548 B/op; 175 allocs/op | 97,126,983 ns/op; 83,588 B/op; 178 allocs/op | -18.7% |
| `RoleAwareConversation` | 383,775 ns/op; 130,412 B/op; 198 allocs/op | 356,226 ns/op; 135,614 B/op; 213 allocs/op | -7.2% |

Interpretation:

- all five measured median latency cases improved on the same machine;
- large benign/punctuation allocations decreased slightly;
- the ordinary, candidate-rich, and role-aware paths allocate more after adding
  the behavior graph and richer evidence ownership;
- the role-aware path increased from 198 to 213 allocations/op, so memory work
  remains open even though latency improved;
- no scan, decode, part, history, carrier, or taxonomy coverage was reduced to
  obtain these measurements.

## Historical implementation-freeze development rerun

The full local WSL/Linux amd64 rerun used review-closure commit `8814dbf` with Go
1.26.4 and classifier-policy SHA-256
`dc9a174099cb2f621e5333a508d4645604f96f470a6d9ae12a1acfb363d29cf2`.
The final implementation freeze `9c8114e` changes only the integration-test
Provider probe lifecycle; its exact-commit GitHub CI benchmark is recorded
separately below. Neither result is Leo or release evidence.

Median of three `-bench=. -benchmem` runs:

| Benchmark | Local `8814dbf` median |
|---|---:|
| `Classifier` | 92,070 ns/op; 25,488 B/op; 46 allocs/op |
| `LargeBenign` | 15,612,625 ns/op; 297,664 B/op; 9 allocs/op |
| `LargePunctuation` | 15,395,706 ns/op; 298,037 B/op; 9 allocs/op |
| `CandidateRichMaxParts` | 88,235,463 ns/op; 83,559 B/op; 178 allocs/op |
| `RoleAwareConversation` | 333,250 ns/op; 135,616 B/op; 213 allocs/op |

The acceptance test recorded p50 80.412 us, p95 123.307 us, p99 215.204 us;
candidate-rich 90.261 ms/op; near-budget 15.731 ms/op and 299,131 B/op. Both
acceptance cases and the full benchmark target passed.

Exact-freeze GitHub CI run `29292693070` also passed benchmark acceptance. Its
three-run medians were:

| Benchmark | CI `9c8114e` median |
|---|---:|
| `Classifier` | 94,050 ns/op; 25,480 B/op; 46 allocs/op |
| `LargeBenign` | 14,301,144 ns/op; 297,742 B/op; 9 allocs/op |
| `LargePunctuation` | 13,073,068 ns/op; 296,386 B/op; 9 allocs/op |
| `CandidateRichMaxParts` | 81,008,678 ns/op; 83,322 B/op; 178 allocs/op |
| `RoleAwareConversation` | 354,428 ns/op; 135,577 B/op; 213 allocs/op |

The CI acceptance sample recorded p50 84.275 us, p95 150.672 us, p99 182.349
us; candidate-rich 81.051285 ms/op; near-budget 14.665888 ms/op and 297,256
B/op.

## Historical subject and pending-cache reference

The shared reliability work replaces linear pending-cache eviction with ordered
O(1) refresh/eviction and makes subject scoring idempotent per domain-separated
request digest.

Windows development ranges on the same i7-13650HX / Go 1.26.4 machine:

| Benchmark | Result |
|---|---:|
| Pending cache parallel hit | 119.6–124.1 ns/op; 0 B/op; 0 allocs/op |
| Pending cache full insert | 266.4–318.5 ns/op; 64 B/op; 2 allocs/op |
| Previous linear full-cache reference | 105.2–112.3 us/op |
| Parallel duplicate subject request | 374.9–405.5 ns/op; 0 B/op; 0 allocs/op |

WSL/ext4 development ranges with Go 1.26.4 independently showed:

| Benchmark | Result |
|---|---:|
| Pending cache full insert | 302.9–409.8 ns/op; 64 B/op; 2 allocs/op |
| Previous linear full-cache reference | 121.6–136.1 us/op |
| Duplicate subject request | 438.4–479.0 ns/op; 0 B/op; 0 allocs/op |

These microbenchmarks isolate data-structure operations. They do not predict
end-to-end CPA throughput or tail latency.

## Historical pre-v0.16 rerun instruction

Leo should rerun on the proposed frozen commit and record raw output, runner
identity, variance, and artifact/commit identity:

```bash
go version
go env GOOS GOARCH CGO_ENABLED GOMAXPROCS GOAMD64
uname -a
lscpu

go test ./internal/classifier -run '^$' \
  -bench '^BenchmarkClassifier' -benchmem -count=5

make benchmark
```

If the final tree changes classifier, extractor, rules, pending-cache, subject,
audit-event, or build dependencies, these development numbers must be treated as
stale and rerun. Do not weaken coverage or resource boundaries to improve them.

## Historical evidence block

```text
starting_baseline: a121a444cb0d82cba4e27754914a1f88258e1d7b
classifier_reference_commit: a1be19f2f5a5317cf979d608f89289ac7cfa2a71
reliability_checkpoint_commit: 573def2649d164161e2dfdfeb3f59b1e1b38ebbc
implementation_freeze_commit: 9c8114e22841f9a19b15b1f4b3c48531aa2453a0
evidence_document_commit: SELF (resolve with git log -1 -- this file)
ruleset_version: 1.0.7
ruleset_sha256: 7bef8b0854b4d75dd5d807e1c33e93b708af4e9e29d0d2b59a18b9031c4da134
historical_classifier_policy_version: classifier-policy-v2
historical_classifier_policy_sha256: dc9a174099cb2f621e5333a508d4645604f96f470a6d9ae12a1acfb363d29cf2
development_benchmark_result: PASS FOR RECORDED SELF-CHECKS
github_ci_benchmark: PASS — push run 29292693070
leo_independent_benchmark: NOT RUN
formal_performance_gate: BLOCKED
```
