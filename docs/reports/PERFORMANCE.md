# Performance Report — post-v10 development handoff

Last updated: 2026-07-14 (Asia/Shanghai)

## Status

**DEVELOPMENT SELF-CHECK / NOT FINAL EVIDENCE.** The measurements below compare
the actual starting baseline `a121a444cb0d82cba4e27754914a1f88258e1d7b`
(`a121a44`) with committed classifier redesign state
`a1be19f2f5a5317cf979d608f89289ac7cfa2a71` (`a1be19f`) on the same Windows
machine and command. Reliability microbenchmarks were also run on the shared
worktree, but that worktree was not yet a frozen clean commit.

These numbers are useful regression evidence only. They are not GitHub CI
evidence, not a real CPA Host result, not a formal release benchmark, and not a
blind quality result. Methodologically valid evaluation v10 remains
the frozen, first-and-only authoritative `FAIL`; that blind set is consumed and
was not rerun.

The WSL commands `make cpa-router-fixture-blackbox`,
`make cpa-v7272-host-blackbox`, and
`scripts/management-proxy-413-test.sh` were mistakenly executed outside the
authorized evidence path. They used loopback/Mock components only and cleanup
left no fixture process. Their results are excluded from this report:

```text
LOCAL MIS-EXECUTION RECORDED / EXCLUDED; NOT AUTHORITATIVE
```

## Classifier before/after reference

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

## Implementation-freeze development rerun

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

## Subject and pending-cache reference

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

## Required final rerun

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

## Evidence block

```text
starting_baseline: a121a444cb0d82cba4e27754914a1f88258e1d7b
classifier_reference_commit: a1be19f2f5a5317cf979d608f89289ac7cfa2a71
reliability_checkpoint_commit: 573def2649d164161e2dfdfeb3f59b1e1b38ebbc
implementation_freeze_commit: 9c8114e22841f9a19b15b1f4b3c48531aa2453a0
evidence_document_commit: SELF (resolve with git log -1 -- this file)
ruleset_version: 1.0.7
ruleset_sha256: 7bef8b0854b4d75dd5d807e1c33e93b708af4e9e29d0d2b59a18b9031c4da134
classifier_policy_version: classifier-policy-v2
classifier_policy_sha256: dc9a174099cb2f621e5333a508d4645604f96f470a6d9ae12a1acfb363d29cf2
development_benchmark_result: PASS FOR RECORDED SELF-CHECKS
github_ci_benchmark: PASS — push run 29292693070
leo_independent_benchmark: NOT RUN
formal_performance_gate: BLOCKED
```
