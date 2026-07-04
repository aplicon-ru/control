// Package servers implements the server registry (add/list/update/delete
// against the servers table) and a connect/exec primitive — real SSH and a
// deterministic mock — for managed hosts (docker_only / full / mock). See
// spec §5.1. Diagnostics (§5.8) and the deploy engine (§5.3) build on top
// of the Executor this package provides but are out of scope here.
package servers
