package deploy

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/aplicon-ru/control/internal/servers"
)

// Deployer runs the deploy flow for a single server at a time: connect →
// preflight → push .env → docker compose pull/up → healthcheck → record.
type Deployer struct {
	registry      *servers.Registry
	catalog       *CatalogReader
	installations *Installations
	deployments   *Deployments
	httpClient    *http.Client

	// connect and getServer default to registry.Connect/registry.Get.
	// They exist as unexported fields — not part of the public API — so
	// this package's own tests can script executor behavior (e.g. a step
	// failing) that servers.Registry's real mock executor can't produce,
	// without adding a second exported constructor or an interface over
	// *servers.Registry that nothing else needs.
	connect   func(ctx context.Context, orgID, serverID int64) (servers.Executor, error)
	getServer func(ctx context.Context, orgID, serverID int64) (servers.Server, error)
}

// NewDeployer returns a Deployer composing registry, catalog,
// installations, deployments, and httpClient.
func NewDeployer(registry *servers.Registry, catalog *CatalogReader, installations *Installations, deployments *Deployments, httpClient *http.Client) *Deployer {
	return &Deployer{
		registry:      registry,
		catalog:       catalog,
		installations: installations,
		deployments:   deployments,
		httpClient:    httpClient,
		connect:       registry.Connect,
		getServer:     registry.Get,
	}
}

// DeployInput is everything a caller must supply to run a deploy. EnvVars
// is plaintext the caller assembles — Deployer does not read Class C
// secrets itself; which secrets belong to which module is
// internal/modules' config-schema territory (§5.2), not built yet.
type DeployInput struct {
	OrgID             int64
	ServerID          int64
	ModuleCatalogID   int64
	ToVersionID       int64
	Kind              Kind // KindInstall or KindUpdate — caller decides based on whether an installation already exists
	EnvVars           map[string]string
	EnvPath           string // absolute path on the target host, e.g. "/opt/ukon/testikon/.env"
	InitiatedByUserID *int64
}

// Deploy runs the full flow for one server: connect → docker compose pull
// → push .env → docker compose up -d → healthcheck → record
// success/failure, updating module_installations on success. It writes a
// deployments row throughout (pending → running → success/failed) so a
// crash mid-flow still leaves an accurate row, not silence.
func (d *Deployer) Deploy(ctx context.Context, in DeployInput) (Deployment, error) {
	dep := Deployment{
		ServerID:          in.ServerID,
		Kind:              in.Kind,
		ToVersionID:       &in.ToVersionID,
		Status:            StatusPending,
		InitiatedByUserID: in.InitiatedByUserID,
	}

	if existing, err := d.installations.GetByServerAndModule(ctx, in.ServerID, in.ModuleCatalogID); err == nil {
		dep.ModuleInstallationID = &existing.ID
		from := existing.InstalledVersionID
		dep.FromVersionID = &from
	} else if !errors.Is(err, ErrInstallationNotFound) {
		return Deployment{}, fmt.Errorf("deploy: %w", err)
	}

	deploymentID, err := d.deployments.Create(ctx, dep)
	if err != nil {
		return Deployment{}, err
	}

	var log strings.Builder
	finish := func(status Status) (Deployment, error) {
		if err := d.deployments.MarkFinished(ctx, deploymentID, status, time.Now(), log.String()); err != nil {
			return Deployment{}, err
		}
		return d.deployments.Get(ctx, deploymentID)
	}

	if err := d.deployments.MarkRunning(ctx, deploymentID, time.Now()); err != nil {
		return Deployment{}, err
	}

	srv, err := d.getServer(ctx, in.OrgID, in.ServerID)
	if err != nil {
		fmt.Fprintf(&log, "$ resolve server\n%v\n", err)
		return finish(StatusFailed)
	}

	exec, err := d.connect(ctx, in.OrgID, in.ServerID)
	if err != nil {
		fmt.Fprintf(&log, "$ connect\n%v\n", err)
		return finish(StatusFailed)
	}
	defer exec.Close()

	ver, err := d.catalog.GetVersion(ctx, in.ToVersionID)
	if err != nil {
		fmt.Fprintf(&log, "$ resolve version\n%v\n", err)
		return finish(StatusFailed)
	}

	fmt.Fprintf(&log, "$ docker version\n")
	if err := checkDockerRunning(ctx, exec); err != nil {
		fmt.Fprintf(&log, "%v\n", err)
		return finish(StatusFailed)
	}

	if len(in.EnvVars) > 0 {
		rendered, err := RenderEnv(in.EnvVars)
		if err != nil {
			fmt.Fprintf(&log, "$ render env\n%v\n", err)
			return finish(StatusFailed)
		}
		fmt.Fprintf(&log, "$ push .env (%d vars)\n", len(in.EnvVars))
		if err := PushEnv(ctx, exec, in.EnvPath, rendered); err != nil {
			fmt.Fprintf(&log, "%v\n", err)
			return finish(StatusFailed)
		}
	}

	if err := runStep(ctx, exec, &log, "docker compose -f "+ver.ComposeRef+" pull"); err != nil {
		return finish(StatusFailed)
	}
	if err := runStep(ctx, exec, &log, "docker compose -f "+ver.ComposeRef+" up -d"); err != nil {
		return finish(StatusFailed)
	}

	if ver.HealthcheckURL != "" {
		resolved, err := resolveHealthcheckURL(ver.HealthcheckURL, srv.Host)
		if err != nil {
			fmt.Fprintf(&log, "$ healthcheck\n%v\n", err)
			return finish(StatusFailed)
		}
		fmt.Fprintf(&log, "$ healthcheck %s\n", resolved)
		if err := Healthcheck(ctx, d.httpClient, resolved); err != nil {
			fmt.Fprintf(&log, "%v\n", err)
			return finish(StatusFailed)
		}
		log.WriteString("ok\n")
	}

	installationID, err := d.installations.Upsert(ctx, Installation{
		ServerID:           in.ServerID,
		ModuleCatalogID:    in.ModuleCatalogID,
		InstalledVersionID: in.ToVersionID,
		Status:             InstallationRunning,
		DeployedAt:         time.Now(),
		DeployedByUserID:   in.InitiatedByUserID,
	})
	if err != nil {
		fmt.Fprintf(&log, "$ record installation\n%v\n", err)
		return finish(StatusFailed)
	}

	// The very first install has no module_installation_id yet — the
	// installation didn't exist when the deployment row was created above.
	// Back-fill it now so Rollback can find this deployment later.
	if dep.ModuleInstallationID == nil {
		if err := d.deployments.SetModuleInstallationID(ctx, deploymentID, installationID); err != nil {
			fmt.Fprintf(&log, "$ link installation\n%v\n", err)
			return finish(StatusFailed)
		}
	}

	return finish(StatusSuccess)
}

// Rollback re-runs Deploy targeting the ToVersionID of the most recent
// successful deployment for installationID that is not the currently
// installed version — i.e. the version immediately before the current
// one, not FromVersionID of the latest deployment (which would skip a
// version if more than one update has happened since).
func (d *Deployer) Rollback(ctx context.Context, orgID, installationID int64, initiatedBy *int64) (Deployment, error) {
	inst, err := d.installations.Get(ctx, installationID)
	if err != nil {
		return Deployment{}, err
	}

	history, err := d.deployments.ListByServer(ctx, inst.ServerID)
	if err != nil {
		return Deployment{}, err
	}

	var targetVersionID int64
	found := false
	for _, h := range history {
		if h.ModuleInstallationID == nil || *h.ModuleInstallationID != installationID {
			continue
		}
		if h.Status != StatusSuccess || h.ToVersionID == nil {
			continue
		}
		if *h.ToVersionID == inst.InstalledVersionID {
			continue // this is the current version, not a rollback target
		}
		targetVersionID = *h.ToVersionID
		found = true
		break
	}
	if !found {
		return Deployment{}, ErrNoRollbackTarget
	}

	return d.Deploy(ctx, DeployInput{
		OrgID:             orgID,
		ServerID:          inst.ServerID,
		ModuleCatalogID:   inst.ModuleCatalogID,
		ToVersionID:       targetVersionID,
		Kind:              KindRollback,
		InitiatedByUserID: initiatedBy,
	})
}

// PreflightDockerRunning checks that Docker is installed and its daemon
// is reachable on the target server, via `docker version`. This is the
// one pre-flight check in scope for this slice — see doc.go for why the
// rest of spec §5.3's matrix is deferred.
func (d *Deployer) PreflightDockerRunning(ctx context.Context, orgID, serverID int64) error {
	exec, err := d.connect(ctx, orgID, serverID)
	if err != nil {
		return fmt.Errorf("deploy: preflight docker running: %w", err)
	}
	defer exec.Close()
	return checkDockerRunning(ctx, exec)
}

func checkDockerRunning(ctx context.Context, exec servers.Executor) error {
	result, err := exec.Run(ctx, "docker version")
	if err != nil {
		return fmt.Errorf("deploy: preflight docker running: %w", err)
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("deploy: preflight docker running: exit code %d: %s", result.ExitCode, result.Stderr)
	}
	return nil
}

func runStep(ctx context.Context, exec servers.Executor, log *strings.Builder, cmd string) error {
	fmt.Fprintf(log, "$ %s\n", cmd)
	result, err := exec.Run(ctx, cmd)
	if err != nil {
		fmt.Fprintf(log, "%v\n", err)
		return err
	}
	log.Write(result.Stdout)
	log.Write(result.Stderr)
	log.WriteByte('\n')
	if result.ExitCode != 0 {
		err := fmt.Errorf("deploy: %q exited %d", cmd, result.ExitCode)
		fmt.Fprintf(log, "%v\n", err)
		return err
	}
	return nil
}
