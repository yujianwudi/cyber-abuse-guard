# Latest CPA source/compile compatibility contract

This isolated module pins the newest CPA version audited for the round5.2
development prerelease: `v7.2.80` at commit
`09da52ad509e2c18e7b9540db3b98c2214c280aa`.

It is intentionally separate from the repository's CPA `v7.2.75` runtime and
artifact baseline. The tests list and run the same 16 official Router contract
tests and add the checksum-verified fail-open overlay only to an ephemeral copy
of the official `v7.2.80` module. The default `scripts/cpa-latest-compat.sh`
contract compiles the Guard plugin and integration packages against `v7.2.80`
through a temporary modfile. With `CPA_LATEST_VERIFY_REMOTE=1`, the script also
verifies GitHub's current `releases/latest` tag and its Tag-to-Commit identity.

No CPA process is started, no Guard `.so` is loaded, and no Provider or account
is contacted. A PASS proves source and compile compatibility only; native Host,
Store installation, request reconstruction, logging, and upstream-isolation
evidence remain server-sandbox work.
