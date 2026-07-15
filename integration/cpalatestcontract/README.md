# Latest CPA source/compile compatibility contract

This isolated module pins the newest CPA version audited for the round5.2
development prerelease: `v7.2.79` at commit
`b6ce0beecd31dff389d3190f7db6d7a1d4ce0e7e`.

It is intentionally separate from the repository's CPA `v7.2.75` runtime and
artifact baseline. The tests list and run the same 16 official Router contract
tests and add the checksum-verified fail-open overlay only to an ephemeral copy
of the official `v7.2.79` module. `scripts/cpa-latest-compat.sh` also compiles
the Guard plugin and integration packages against `v7.2.79` through a temporary
modfile.

No CPA process is started, no Guard `.so` is loaded, and no Provider or account
is contacted. A PASS proves source and compile compatibility only; native Host,
Store installation, request reconstruction, logging, and upstream-isolation
evidence remain server-sandbox work.
