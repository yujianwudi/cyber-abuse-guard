# CPA v7.2.88 pinned source/compile compatibility contract

This isolated module is the source-contract half of the Round6 CPA compatibility
gate. Its only profile is the reviewed CPA release pin:

| Profile | CPA | Commit | Module sum |
|---|---|---|---|
| `primary` | `v7.2.88` | `93d74a890a44802f656d7f39a573916b2611896e` | `h1:YfLBYPvkasjqFLzdht+UrEgRLsU3HcM0WDMurNEjIDo=` |

The profile pins go.mod sum
`h1:ytvZNWbCv7PrAyR80+RKsDJPODsdL6qxyFaXDBNZdqs=`. The checked-in isolated
module uses this reviewed CPA release. Unknown profile names fail closed.

The tests run 18 official Host routing/status and metadata-sanitization contracts and
11 official Interactions route/handler contracts, then apply three
checksum-pinned overlays only to ephemeral copies of the selected official CPA
module. `scripts/cpa-latest-compat.sh` compiles the Guard and integration
packages against the checked-in v7.2.88 modules and runs the real Guard
registration/route tests. Only the official upstream test graph and overlays
use ephemeral modfiles. With `CPA_COMPAT_VERIFY_REMOTE=1`, it verifies the exact
`v7.2.88` Tag-to-Commit identity through the official Git origin, the
official Go module `Origin`, and both Go sums. It deliberately does not query
GitHub REST Release metadata or `releases/latest`, and it needs no repository
token; a PASS applies only to the reviewed pinned source and never claims
moving-latest compatibility.

`CPA_COMPAT_PROFILE=primary` is the only supported profile and is the default.

No CPA process is started, no Guard `.so` is loaded, and no Provider or account
is contacted. A PASS proves source and compile compatibility only; native Host,
Store installation, request reconstruction, logging, and upstream-isolation
evidence remain server-sandbox work. No profile is real Host evidence.
