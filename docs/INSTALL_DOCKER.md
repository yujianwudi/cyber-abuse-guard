# Docker Installation, Upgrade, and Rollback

## Preconditions

- CPA must be `v7.2.67` and built with `CGO_ENABLED=1`. Assets labeled
  `_no-plugin` cannot load native plugins.
- The container architecture must be Linux amd64 with glibc 2.34 or newer. The
  published binary is compatible with the official Debian Bookworm CPA image;
  musl/Alpine containers are not supported.
- The deployment host needs `curl`, `unzip`, `sha256sum`, and `openssl`.
- Back up the active CPA configuration before changing it.

The release verifier rejects an artifact that imports a glibc symbol version
newer than `GLIBC_2.34`, and `make release` runs the pinned real-CPA integration
suite before creating an archive.

## Install

```bash
set -eu
VERSION=0.1.1
ARCHIVE="cyber-abuse-guard_${VERSION}_linux_amd64.zip"
# Override this for a fork or an internal release mirror.
RELEASE_BASE="${CYBER_ABUSE_GUARD_RELEASE_BASE:-https://github.com/yujianwudi/cyber-abuse-guard/releases/download/v${VERSION}}"

curl -fLO "${RELEASE_BASE}/${ARCHIVE}"
curl -fLO "${RELEASE_BASE}/checksums.txt"
grep -F "  ${ARCHIVE}" checksums.txt | sha256sum -c -

release_dir="cyber-abuse-guard-${VERSION}"
mkdir -p "$release_dir"
unzip -q "$ARCHIVE" -d "$release_dir"
(cd "$release_dir/plugins/linux/amd64" && \
  sha256sum -c "cyber-abuse-guard-v${VERSION}.so.sha256")

cp config.yaml "config.yaml.backup.$(date +%Y%m%d%H%M%S)"
mkdir -p plugins/linux/amd64 plugin-data/cyber-abuse-guard
install -m 0755 "$release_dir/plugins/linux/amd64/cyber-abuse-guard-v${VERSION}.so" \
  "plugins/linux/amd64/cyber-abuse-guard-v${VERSION}.so"
chmod 0700 plugin-data/cyber-abuse-guard
```

Use a dedicated audit data directory. The plugin creates missing directories
with mode 0700 but deliberately does not change permissions on an existing
operator-owned directory. An existing directory must not be group/world
writable; the final directory and DB/WAL/SHM paths must not be symlinks. Keep
the entire ancestor chain outside attacker-controlled or same-user-mutated
locations.

The default URL matches the plugin metadata. If the artifact is delivered from
an internal mirror, set `CYBER_ABUSE_GUARD_RELEASE_BASE` to the directory URL
that contains the ZIP and `checksums.txt`; do not disable checksum validation.

Generate a stable HMAC secret without printing it to logs:

```bash
secret_dir="${XDG_CONFIG_HOME:-$HOME/.config}/cyber-abuse-guard"
install -d -m 0700 "$secret_dir"
umask 077
openssl rand -base64 48 > "$secret_dir/hmac"
chmod 0600 "$secret_dir/hmac"
export CYBER_ABUSE_GUARD_SECRET_FILE="$secret_dir/hmac"
```

Reference it from the Compose environment or secret manager. Do not place the
secret in this repository, Docker build context, or a release ZIP. The target
must be a regular mode-0600 file, not a symlink. On Linux the plugin opens it
with `O_NOFOLLOW`, then validates and reads through the same file descriptor.

Mount:

```yaml
services:
  cli-proxy-api:
    volumes:
      - ./plugins:/CLIProxyAPI/plugins:ro
      - ./plugin-data:/root/.cli-proxy-api/plugins
      # Bind a regular mode-0600 file. Compose secrets are commonly mounted
      # 0444, which this plugin intentionally rejects.
      - "${CYBER_ABUSE_GUARD_SECRET_FILE:?set CYBER_ABUSE_GUARD_SECRET_FILE}:/run/secrets/cyber_abuse_guard_hmac:ro"
    environment:
      CYBER_ABUSE_GUARD_HMAC_KEY_FILE: /run/secrets/cyber_abuse_guard_hmac
```

Merge `config.example.yaml` into the real `plugins` section. For the first
deployment, explicitly keep audit-first mode and the bounded subject default:

```yaml
plugins:
  configs:
    cyber-abuse-guard:
      mode: audit
      subject_control:
        enabled: true
        max_subjects: 10000
      audit:
        enabled: true
```

Then restart and inspect status:

```bash
docker compose restart cli-proxy-api
docker compose logs --since=2m cli-proxy-api | grep -E 'plugin (loaded|registered)'
curl -fsS -H "Authorization: Bearer $CPA_MANAGEMENT_KEY" \
  http://127.0.0.1:8317/v0/management/plugins/cyber-abuse-guard/status
```

Confirm that status reports the expected `configured_at` and
`subject_control.max_subjects`. On later compatible hot reloads, `started_at`
must remain unchanged while `configured_at` advances; the `subject_control`
snapshot also reports current entries, manual blocks, evictions, and capacity
rejections.

Keep `mode: audit` while running the local management test route and reviewing
events without prompt text. Switch to `balanced` only after the observed
decisions match the deployment's expected traffic.

## Functional verification

Use only harmless test descriptions. Confirm a normal programming prompt
reaches a test provider, a clearly malicious descriptive test returns 403, and
the upstream mock/provider access counter does not increment for the blocked
request. Confirm a defensive remediation request is allowed.

## Upgrade

```bash
set -eu
: "${NEXT_VERSION:?export NEXT_VERSION, for example 0.2.0}"
: "${CPA_MANAGEMENT_KEY:?export CPA_MANAGEMENT_KEY}"
NEXT_ARCHIVE="cyber-abuse-guard_${NEXT_VERSION}_linux_amd64.zip"
NEXT_RELEASE_BASE="${CYBER_ABUSE_GUARD_RELEASE_BASE:-https://github.com/yujianwudi/cyber-abuse-guard/releases/download/v${NEXT_VERSION}}"
upgrade_dir="$(mktemp -d)"
trap 'rm -rf "$upgrade_dir"' EXIT

curl -fL "${NEXT_RELEASE_BASE}/${NEXT_ARCHIVE}" -o "$upgrade_dir/$NEXT_ARCHIVE"
curl -fL "${NEXT_RELEASE_BASE}/checksums.txt" -o "$upgrade_dir/checksums.txt"
(cd "$upgrade_dir" && \
  grep -F "  ${NEXT_ARCHIVE}" checksums.txt | sha256sum -c - && \
  unzip -q "$NEXT_ARCHIVE" -d release && \
  cd release/plugins/linux/amd64 && \
  sha256sum -c "cyber-abuse-guard-v${NEXT_VERSION}.so.sha256")

CONFIG_BACKUP="config.yaml.backup.$(date +%Y%m%d%H%M%S)"
cp -p config.yaml "$CONFIG_BACKUP"
install -m 0755 \
  "$upgrade_dir/release/plugins/linux/amd64/cyber-abuse-guard-v${NEXT_VERSION}.so" \
  "plugins/linux/amd64/cyber-abuse-guard-v${NEXT_VERSION}.so"
docker compose restart cli-proxy-api
docker compose logs --since=2m cli-proxy-api | grep -E 'plugin (loaded|registered)'
curl -fsS -H "Authorization: Bearer $CPA_MANAGEMENT_KEY" \
  http://127.0.0.1:8317/v0/management/plugins/cyber-abuse-guard/status \
  | grep -F "\"version\":\"${NEXT_VERSION}\""
```

CPA selects the highest versioned matching plugin file. Verify the reported
version and integration behavior before removing the prior `.so`. Back up the
SQLite database before a schema-changing release.

## Rollback

The following performs a full disable/remove rollback. Set the exact installed
version and the backup path created during install/upgrade:

```bash
set -eu
: "${CURRENT_VERSION:?export CURRENT_VERSION, for example 0.1.1}"
: "${CONFIG_BACKUP:?export CONFIG_BACKUP with the config backup path}"
: "${CPA_MANAGEMENT_KEY:?export CPA_MANAGEMENT_KEY}"
CPA_BASE_URL="${CPA_BASE_URL:-http://127.0.0.1:8317}"

curl -fsS -X PATCH \
  -H "Authorization: Bearer $CPA_MANAGEMENT_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"enabled":false}' \
  "$CPA_BASE_URL/v0/management/plugins/cyber-abuse-guard/enabled"
docker compose restart cli-proxy-api
curl -fsS -H "Authorization: Bearer $CPA_MANAGEMENT_KEY" \
  "$CPA_BASE_URL/v0/management/plugins" \
  | grep -F '"effective_enabled":false'

rm -f -- \
  "plugins/linux/amd64/cyber-abuse-guard-v${CURRENT_VERSION}.so" \
  "plugins/linux/amd64/cyber-abuse-guard-v${CURRENT_VERSION}.so.sha256"

# Data deletion is deliberately opt-in. Leave DELETE_PLUGIN_DATA unset to keep it.
if [ "${DELETE_PLUGIN_DATA:-no}" = yes ]; then
  docker compose stop cli-proxy-api
  rm -f -- plugin-data/cyber-abuse-guard/events.db \
    plugin-data/cyber-abuse-guard/events.db-wal \
    plugin-data/cyber-abuse-guard/events.db-shm
fi

cp -p -- "$CONFIG_BACKUP" config.yaml
docker compose restart cli-proxy-api
if curl -fsS -H "Authorization: Bearer $CPA_MANAGEMENT_KEY" \
  "$CPA_BASE_URL/v0/management/plugins" \
  | grep -F '"id":"cyber-abuse-guard"'; then
  echo 'rollback verification failed: plugin is still discovered' >&2
  exit 1
fi
```

To roll back an upgrade to an older plugin rather than remove the plugin,
leave the prior versioned `.so` in `plugins/linux/amd64`, remove only the new
version, restore the matching config backup, restart, and verify the old
`version` through the authenticated status endpoint.

CPA does not need to be reinstalled.
