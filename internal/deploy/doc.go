// Package deploy implements the SSH-based deployment engine for a single
// server at a time: resolving a module version, pushing its .env, running
// `docker compose pull && up -d`, verifying a healthcheck, and recording
// the attempt in module_installations/deployments. See spec §5.3.
//
// module_catalog/module_versions themselves — creation, editing,
// dependency graphs — belong to internal/modules (§5.2, project structure
// §12); this package only reads a version by ID to act on it.
//
// Deferred, each its own follow-up:
//   - Full pre-flight matrix (disk/RAM/CPU/ports/DNS/registry
//     reachability/license/cert checks, §5.3 table) — needs new Executor
//     command patterns, internal/license, and internal/ssl, none of which
//     exist yet. Docker-running is the one check with an already-supported
//     primitive (`docker version`) and ships as a plain method, not a
//     preview of a Check abstraction guessed at from a single case.
//   - Maintenance page (nginx push, branded template) — no branding/
//     templating system exists yet.
//   - SSE log streaming — needs an HTTP layer that doesn't exist yet
//     (same boundary as internal/servers.Executor existing before this
//     package had a caller). deployments.log is still populated, as a
//     plain string written once at the end of an attempt.
//   - Scheduling (deployments.scheduled_at, a ticker/cron mechanism) —
//     its own atomic feature; no scheduler infrastructure exists.
//   - Group operations (deploy to N servers) — a thin loop over Deploy
//     for a caller (HTTP/CLI) that doesn't exist yet.
//   - Config-apply flow / drift detection (config vs config_pending) —
//     internal/modules' territory (§5.2), no consumer yet.
//   - Automatic rollback-on-deploy-failure — Rollback exists as a
//     manually invoked operation; auto-triggering it from a failed
//     Deploy needs maintenance-page removal and alerting
//     (internal/notify), neither built yet, and is ambiguous for a
//     first-ever install with no prior version.
package deploy
