# CPA latest source/compile compatibility contract

This isolated module is the source-contract half of the Round6 CPA latest-version
gate. The fixed profile is:

| Profile | CPA | Commit | Module sum |
|---|---|---|---|
| `primary` | `v7.2.86` | `81d70f5d9f3fdb39a6290ed9c917ff0c6f27ca30` | `h1:hngt58VNLMXtQ048U59kXOugcMt2Sw60M4gpmwnj1jA=` |

The profile pins go.mod sum
`h1:ytvZNWbCv7PrAyR80+RKsDJPODsdL6qxyFaXDBNZdqs=`. Unknown profile names fail
closed. The checked-in root and isolated modules both use the current latest
CPA release.

The tests run 18 official Host routing/status and metadata-sanitization contracts and
11 official Interactions route/handler contracts, then apply three
checksum-pinned overlays only to ephemeral copies of the selected official CPA
module. `scripts/cpa-latest-compat.sh` compiles the Guard and integration
packages and runs the real Guard registration/route tests against the latest
profile through temporary modfiles. With `CPA_COMPAT_VERIFY_REMOTE=1`, the script
requires `v7.2.86` to remain GitHub's current `releases/latest` and verifies its
Tag-to-Commit identity. `CPA_LATEST_VERIFY_REMOTE=1` remains a compatibility
alias for the same remote check.

`CPA_COMPAT_PROFILE=primary` is the only supported profile and is the default.

No CPA process is started, no Guard `.so` is loaded, and no Provider or account
is contacted. A PASS proves source and compile compatibility only; native Host,
Store installation, request reconstruction, logging, and upstream-isolation
evidence remain server-sandbox work. No profile is real Host evidence.
