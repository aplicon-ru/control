// Package secrets implements envelope encryption (AES-256-GCM under a
// master.key held outside the database) for the three secret classes:
// CP credentials (A), server credentials (B), and module secrets
// pushed to target servers (C). See spec §6 and
// docs/adr/0001-secrets-encryption.md.
package secrets
