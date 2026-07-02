# ADR-0001: Envelope encryption for stored secrets

## Status

Accepted

## Context

CP stores three classes of secrets (spec §6): CP-level credentials (bot
tokens, SMTP password, OIDC client secret), server credentials (SSH keys),
and module secrets pushed to target servers (DB passwords, S3 credentials,
JWS license tokens). All of them end up in the same SQLite database. A
leaked database file must not be enough to read any of them.

## Decision

Use envelope encryption: a single `master.key` (256-bit), generated on
first run, encrypts every secret value with AES-256-GCM before it is
written to SQLite (`secrets` table, see `migrations/0001_init.sql`).
`master.key` is stored on a separate volume from the database and is never
written to the same table, backup archive, or filesystem path as the data
it protects.

```
docker run \
  -v ./data:/data     # SQLite — encrypted secrets live here
  -v ./keys:/keys:ro  # master.key — lives here, nowhere else
  ghcr.io/aplicon-ru/control
```

## Consequences

- A copied `data/` volume without `keys/` is unreadable — this is
  intentional and shapes the backup design (spec §7): backup archives and
  `master.key` are always exported separately.
- Losing `master.key` means losing every secret irrecoverably. There is no
  recovery path by design — rotating it requires re-entering SSH
  credentials and re-issuing licenses.
- Passphrase-protecting `master.key` at startup is optional and off by
  default: it turns every CP restart into a manual step. Organizations
  with stricter requirements can enable it.

## Alternatives considered

- **Per-secret keys via an external KMS** (Vault, cloud KMS): more
  robust, but adds a dependency that contradicts the "one binary, `docker
  run`" installation story (spec §11).
- **OS keyring:** not viable — CP runs headless on a server, and keyring
  availability varies too much across the Linux distributions target
  servers use.
