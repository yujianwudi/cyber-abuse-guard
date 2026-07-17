# CPA source/compile compatibility matrix

This isolated module is the source-contract half of the Round6 CPA compatibility
matrix. The fixed profiles are:

| Profile | CPA | Commit | Module sum |
|---|---|---|---|
| `primary` | `v7.2.83` | `9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66` | `h1:fCGraERLPW08Kl8aP3F/A5XQC34ZPD0mEfxpTvevF7Y=` |
| `previous` | `v7.2.82` | `f583414fd9914f9ccfd280fc3a23aebaea30e9eb` | `h1:5Yl3qmdDiQ4w8WEJ0N8i4YHNB0hF959lMpoOAb4ib8c=` |
| `backward` | `v7.2.81` | `106270bea6f18ba2f2cc8b0b5887987f2874eed8` | `h1:TNhOAGi8zDfnUE8KKyhi6NEvCI/Lu2VBj953WT9GKCs=` |

All three profiles pin go.mod sum
`h1:ytvZNWbCv7PrAyR80+RKsDJPODsdL6qxyFaXDBNZdqs=`. Unknown profile names fail
closed. The checked-in module remains on the primary profile; the compatibility
script creates temporary mod/sum pairs for all profiles without rewriting the
repository.

It is intentionally separate from the repository's CPA `v7.2.75` runtime and
artifact baseline. The tests run 17 official Host routing/status contracts and
11 official Interactions route/handler contracts, then apply three
checksum-pinned overlays only to ephemeral copies of the selected official CPA
module. `scripts/cpa-latest-compat.sh` compiles the Guard and integration
packages and runs the real Guard registration/route tests against all profiles
through temporary modfiles. With `CPA_COMPAT_VERIFY_REMOTE=1`, the script
requires `v7.2.83` to remain GitHub's current `releases/latest` and verifies all
three Tag-to-Commit identities. `CPA_LATEST_VERIFY_REMOTE=1` remains a compatibility
alias for the same remote check.

Set `CPA_COMPAT_PROFILE=primary`, `previous`, or `backward` to run one fixed
profile. The default is `all`, which runs all three and is the ordinary-CI
contract.

No CPA process is started, no Guard `.so` is loaded, and no Provider or account
is contacted. A PASS proves source and compile compatibility only; native Host,
Store installation, request reconstruction, logging, and upstream-isolation
evidence remain server-sandbox work. No profile is real Host evidence.
