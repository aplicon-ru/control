// Package backup implements whole-application snapshotting for CP and
// managed servers: scheduling, retention templates, checksum
// validation, and restore. A backup is always the application as a
// whole (image + volumes + config), never a partial slice — see
// spec §7.
package backup
