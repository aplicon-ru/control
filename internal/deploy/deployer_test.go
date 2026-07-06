package deploy

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/aplicon-ru/control/internal/secrets"
	"github.com/aplicon-ru/control/internal/servers"
)

func newTestDeployer(catalog *CatalogReader, installations *Installations, deployments *Deployments, srv servers.Server, exec servers.Executor, connectErr error) *Deployer {
	return &Deployer{
		catalog:       catalog,
		installations: installations,
		deployments:   deployments,
		httpClient:    http.DefaultClient,
		getServer: func(context.Context, int64, int64) (servers.Server, error) {
			return srv, nil
		},
		connect: func(context.Context, int64, int64) (servers.Executor, error) {
			if connectErr != nil {
				return nil, connectErr
			}
			return exec, nil
		},
	}
}

func TestDeploy_Success(t *testing.T) {
	db := newTestDB(t)
	f := newTestFixtures(t, db)
	versionID := newTestVersion(t, db, f.ModuleCatalogID, "1.0.0", "")

	exec := newTestFakeExecutor()
	srv := servers.Server{ID: f.ServerID, OrgID: f.OrgID, Host: "10.0.0.5"}
	d := newTestDeployer(NewCatalogReader(db), NewInstallations(db), NewDeployments(db), srv, exec, nil)

	result, err := d.Deploy(context.Background(), DeployInput{
		OrgID: f.OrgID, ServerID: f.ServerID, ModuleCatalogID: f.ModuleCatalogID,
		ToVersionID: versionID, Kind: KindInstall,
		EnvVars: map[string]string{"DB_PASSWORD": "hunter2"},
		EnvPath: "/opt/ukon/.env",
	})
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	if result.Status != StatusSuccess {
		t.Fatalf("Deploy: got status %q, want %q\nlog:\n%s", result.Status, StatusSuccess, result.Log)
	}
	if !exec.closed {
		t.Error("Deploy: want executor closed")
	}
	if strings.Contains(result.Log, "hunter2") {
		t.Error("Deploy: log leaked a secret value")
	}

	joined := strings.Join(exec.commands, "\n")
	for _, want := range []string{"docker version", "cat >", "docker compose"} {
		if !strings.Contains(joined, want) {
			t.Errorf("Deploy: commands missing %q, got %v", want, exec.commands)
		}
	}

	inst, err := NewInstallations(db).GetByServerAndModule(context.Background(), f.ServerID, f.ModuleCatalogID)
	if err != nil {
		t.Fatalf("GetByServerAndModule: %v", err)
	}
	if inst.InstalledVersionID != versionID || inst.Status != InstallationRunning {
		t.Fatalf("GetByServerAndModule: got %+v", inst)
	}
}

func TestDeploy_ConnectFails(t *testing.T) {
	db := newTestDB(t)
	f := newTestFixtures(t, db)
	versionID := newTestVersion(t, db, f.ModuleCatalogID, "1.0.0", "")

	d := newTestDeployer(NewCatalogReader(db), NewInstallations(db), NewDeployments(db),
		servers.Server{ID: f.ServerID}, nil, errFakeConnectionLost)

	result, err := d.Deploy(context.Background(), DeployInput{
		OrgID: f.OrgID, ServerID: f.ServerID, ModuleCatalogID: f.ModuleCatalogID, ToVersionID: versionID, Kind: KindInstall,
	})
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	if result.Status != StatusFailed {
		t.Fatalf("Deploy: got status %q, want %q", result.Status, StatusFailed)
	}
}

func TestDeploy_VersionNotFound(t *testing.T) {
	db := newTestDB(t)
	f := newTestFixtures(t, db)

	exec := newTestFakeExecutor()
	d := newTestDeployer(NewCatalogReader(db), NewInstallations(db), NewDeployments(db),
		servers.Server{ID: f.ServerID}, exec, nil)

	result, err := d.Deploy(context.Background(), DeployInput{
		OrgID: f.OrgID, ServerID: f.ServerID, ModuleCatalogID: f.ModuleCatalogID, ToVersionID: 999999, Kind: KindInstall,
	})
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	if result.Status != StatusFailed {
		t.Fatalf("Deploy: got status %q, want %q", result.Status, StatusFailed)
	}
}

func TestDeploy_DockerNotRunning(t *testing.T) {
	db := newTestDB(t)
	f := newTestFixtures(t, db)
	versionID := newTestVersion(t, db, f.ModuleCatalogID, "1.0.0", "")

	exec := newTestFakeExecutor()
	exec.script["docker version"] = fakeStep{result: servers.Result{ExitCode: 1, Stderr: []byte("docker: not found")}}
	d := newTestDeployer(NewCatalogReader(db), NewInstallations(db), NewDeployments(db),
		servers.Server{ID: f.ServerID}, exec, nil)

	result, err := d.Deploy(context.Background(), DeployInput{
		OrgID: f.OrgID, ServerID: f.ServerID, ModuleCatalogID: f.ModuleCatalogID, ToVersionID: versionID, Kind: KindInstall,
	})
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	if result.Status != StatusFailed {
		t.Fatalf("Deploy: got status %q, want %q", result.Status, StatusFailed)
	}
	assertNoInstallation(t, db, f)
}

func TestDeploy_EnvPushFails(t *testing.T) {
	db := newTestDB(t)
	f := newTestFixtures(t, db)
	versionID := newTestVersion(t, db, f.ModuleCatalogID, "1.0.0", "")

	exec := newTestFakeExecutor()
	exec.script["cat >"] = fakeStep{result: servers.Result{ExitCode: 1}}
	d := newTestDeployer(NewCatalogReader(db), NewInstallations(db), NewDeployments(db),
		servers.Server{ID: f.ServerID}, exec, nil)

	result, err := d.Deploy(context.Background(), DeployInput{
		OrgID: f.OrgID, ServerID: f.ServerID, ModuleCatalogID: f.ModuleCatalogID, ToVersionID: versionID, Kind: KindInstall,
		EnvVars: map[string]string{"K": "v"}, EnvPath: "/opt/ukon/.env",
	})
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	if result.Status != StatusFailed {
		t.Fatalf("Deploy: got status %q, want %q", result.Status, StatusFailed)
	}
	assertNoInstallation(t, db, f)
}

func TestDeploy_ComposePullFails(t *testing.T) {
	db := newTestDB(t)
	f := newTestFixtures(t, db)
	versionID := newTestVersion(t, db, f.ModuleCatalogID, "1.0.0", "")

	exec := newTestFakeExecutor()
	exec.script["pull"] = fakeStep{result: servers.Result{ExitCode: 1, Stderr: []byte("no such image")}}
	d := newTestDeployer(NewCatalogReader(db), NewInstallations(db), NewDeployments(db),
		servers.Server{ID: f.ServerID}, exec, nil)

	result, err := d.Deploy(context.Background(), DeployInput{
		OrgID: f.OrgID, ServerID: f.ServerID, ModuleCatalogID: f.ModuleCatalogID, ToVersionID: versionID, Kind: KindInstall,
	})
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	if result.Status != StatusFailed {
		t.Fatalf("Deploy: got status %q, want %q", result.Status, StatusFailed)
	}
	assertNoInstallation(t, db, f)
}

func TestDeploy_ComposeUpFails(t *testing.T) {
	db := newTestDB(t)
	f := newTestFixtures(t, db)
	versionID := newTestVersion(t, db, f.ModuleCatalogID, "1.0.0", "")

	exec := newTestFakeExecutor()
	exec.script["up -d"] = fakeStep{result: servers.Result{ExitCode: 1, Stderr: []byte("port already in use")}}
	d := newTestDeployer(NewCatalogReader(db), NewInstallations(db), NewDeployments(db),
		servers.Server{ID: f.ServerID}, exec, nil)

	result, err := d.Deploy(context.Background(), DeployInput{
		OrgID: f.OrgID, ServerID: f.ServerID, ModuleCatalogID: f.ModuleCatalogID, ToVersionID: versionID, Kind: KindInstall,
	})
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	if result.Status != StatusFailed {
		t.Fatalf("Deploy: got status %q, want %q", result.Status, StatusFailed)
	}
	assertNoInstallation(t, db, f)
}

func TestDeploy_HealthcheckFails(t *testing.T) {
	db := newTestDB(t)
	f := newTestFixtures(t, db)
	versionID := newTestVersion(t, db, f.ModuleCatalogID, "1.0.0", "http://127.0.0.1:1/health")

	exec := newTestFakeExecutor()
	srv := servers.Server{ID: f.ServerID, Host: "127.0.0.1"}
	d := newTestDeployer(NewCatalogReader(db), NewInstallations(db), NewDeployments(db), srv, exec, nil)

	result, err := d.Deploy(context.Background(), DeployInput{
		OrgID: f.OrgID, ServerID: f.ServerID, ModuleCatalogID: f.ModuleCatalogID, ToVersionID: versionID, Kind: KindInstall,
	})
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	if result.Status != StatusFailed {
		t.Fatalf("Deploy: got status %q, want %q\nlog:\n%s", result.Status, StatusFailed, result.Log)
	}
	assertNoInstallation(t, db, f)
}

func TestDeploy_UpdateRecordsFromVersion(t *testing.T) {
	db := newTestDB(t)
	f := newTestFixtures(t, db)
	v1 := newTestVersion(t, db, f.ModuleCatalogID, "1.0.0", "")
	v2 := newTestVersion(t, db, f.ModuleCatalogID, "2.0.0", "")

	exec := newTestFakeExecutor()
	srv := servers.Server{ID: f.ServerID, Host: "10.0.0.5"}
	d := newTestDeployer(NewCatalogReader(db), NewInstallations(db), NewDeployments(db), srv, exec, nil)
	ctx := context.Background()

	if _, err := d.Deploy(ctx, DeployInput{OrgID: f.OrgID, ServerID: f.ServerID, ModuleCatalogID: f.ModuleCatalogID, ToVersionID: v1, Kind: KindInstall}); err != nil {
		t.Fatalf("Deploy (install): %v", err)
	}

	result, err := d.Deploy(ctx, DeployInput{OrgID: f.OrgID, ServerID: f.ServerID, ModuleCatalogID: f.ModuleCatalogID, ToVersionID: v2, Kind: KindUpdate})
	if err != nil {
		t.Fatalf("Deploy (update): %v", err)
	}
	if result.Status != StatusSuccess {
		t.Fatalf("Deploy (update): got status %q\nlog:\n%s", result.Status, result.Log)
	}
	if result.FromVersionID == nil || *result.FromVersionID != v1 {
		t.Fatalf("Deploy (update): got FromVersionID %v, want %d", result.FromVersionID, v1)
	}
	if result.ModuleInstallationID == nil {
		t.Fatal("Deploy (update): want non-nil ModuleInstallationID")
	}
}

func TestRollback_Success(t *testing.T) {
	db := newTestDB(t)
	f := newTestFixtures(t, db)
	v1 := newTestVersion(t, db, f.ModuleCatalogID, "1.0.0", "")
	v2 := newTestVersion(t, db, f.ModuleCatalogID, "2.0.0", "")

	exec := newTestFakeExecutor()
	srv := servers.Server{ID: f.ServerID, Host: "10.0.0.5"}
	d := newTestDeployer(NewCatalogReader(db), NewInstallations(db), NewDeployments(db), srv, exec, nil)
	ctx := context.Background()

	if _, err := d.Deploy(ctx, DeployInput{OrgID: f.OrgID, ServerID: f.ServerID, ModuleCatalogID: f.ModuleCatalogID, ToVersionID: v1, Kind: KindInstall}); err != nil {
		t.Fatalf("Deploy v1: %v", err)
	}
	if _, err := d.Deploy(ctx, DeployInput{OrgID: f.OrgID, ServerID: f.ServerID, ModuleCatalogID: f.ModuleCatalogID, ToVersionID: v2, Kind: KindUpdate}); err != nil {
		t.Fatalf("Deploy v2: %v", err)
	}

	inst, err := d.installations.GetByServerAndModule(ctx, f.ServerID, f.ModuleCatalogID)
	if err != nil {
		t.Fatalf("GetByServerAndModule: %v", err)
	}
	if inst.InstalledVersionID != v2 {
		t.Fatalf("want installed v2 (%d), got %d", v2, inst.InstalledVersionID)
	}

	rollback, err := d.Rollback(ctx, f.OrgID, inst.ID, nil)
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if rollback.Status != StatusSuccess {
		t.Fatalf("Rollback: got status %q\nlog:\n%s", rollback.Status, rollback.Log)
	}
	if rollback.Kind != KindRollback {
		t.Fatalf("Rollback: got kind %q, want %q", rollback.Kind, KindRollback)
	}
	if rollback.ToVersionID == nil || *rollback.ToVersionID != v1 {
		t.Fatalf("Rollback: got ToVersionID %v, want %d", rollback.ToVersionID, v1)
	}

	inst2, err := d.installations.GetByServerAndModule(ctx, f.ServerID, f.ModuleCatalogID)
	if err != nil {
		t.Fatalf("GetByServerAndModule (after rollback): %v", err)
	}
	if inst2.InstalledVersionID != v1 {
		t.Fatalf("after rollback: want installed v1 (%d), got %d", v1, inst2.InstalledVersionID)
	}
}

func TestRollback_NoTarget(t *testing.T) {
	db := newTestDB(t)
	f := newTestFixtures(t, db)
	v1 := newTestVersion(t, db, f.ModuleCatalogID, "1.0.0", "")

	exec := newTestFakeExecutor()
	srv := servers.Server{ID: f.ServerID, Host: "10.0.0.5"}
	d := newTestDeployer(NewCatalogReader(db), NewInstallations(db), NewDeployments(db), srv, exec, nil)
	ctx := context.Background()

	if _, err := d.Deploy(ctx, DeployInput{OrgID: f.OrgID, ServerID: f.ServerID, ModuleCatalogID: f.ModuleCatalogID, ToVersionID: v1, Kind: KindInstall}); err != nil {
		t.Fatalf("Deploy: %v", err)
	}

	inst, err := d.installations.GetByServerAndModule(ctx, f.ServerID, f.ModuleCatalogID)
	if err != nil {
		t.Fatalf("GetByServerAndModule: %v", err)
	}

	if _, err := d.Rollback(ctx, f.OrgID, inst.ID, nil); !errors.Is(err, ErrNoRollbackTarget) {
		t.Fatalf("Rollback: got err %v, want ErrNoRollbackTarget", err)
	}
}

func TestRollback_InstallationNotFound(t *testing.T) {
	db := newTestDB(t)
	d := newTestDeployer(NewCatalogReader(db), NewInstallations(db), NewDeployments(db), servers.Server{}, nil, nil)

	_, err := d.Rollback(context.Background(), 1, 999, nil)
	if !errors.Is(err, ErrInstallationNotFound) {
		t.Fatalf("Rollback: got err %v, want ErrInstallationNotFound", err)
	}
}

func TestPreflightDockerRunning_Success(t *testing.T) {
	exec := newTestFakeExecutor()
	d := &Deployer{connect: func(context.Context, int64, int64) (servers.Executor, error) { return exec, nil }}

	if err := d.PreflightDockerRunning(context.Background(), 1, 1); err != nil {
		t.Fatalf("PreflightDockerRunning: %v", err)
	}
}

func TestPreflightDockerRunning_DockerNotRunning(t *testing.T) {
	exec := newTestFakeExecutor()
	exec.script["docker version"] = fakeStep{result: servers.Result{ExitCode: 1}}
	d := &Deployer{connect: func(context.Context, int64, int64) (servers.Executor, error) { return exec, nil }}

	if err := d.PreflightDockerRunning(context.Background(), 1, 1); err == nil {
		t.Fatal("PreflightDockerRunning: want error, got nil")
	}
}

func TestPreflightDockerRunning_ConnectFails(t *testing.T) {
	d := &Deployer{connect: func(context.Context, int64, int64) (servers.Executor, error) { return nil, errFakeConnectionLost }}

	if err := d.PreflightDockerRunning(context.Background(), 1, 1); err == nil {
		t.Fatal("PreflightDockerRunning: want error, got nil")
	}
}

// TestDeploy_RealRegistryMockServer wires a real servers.Registry +
// secrets.Store + a Type: TypeMock server through NewDeployer (the actual
// public constructor, not the test-only field-injection helper) to prove
// the seams between internal/deploy and internal/servers/internal/secrets
// fit together end to end.
func TestDeploy_RealRegistryMockServer(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	res, err := db.ExecContext(ctx, `INSERT INTO organizations (slug, name) VALUES ('acme', 'Acme')`)
	if err != nil {
		t.Fatalf("insert organization: %v", err)
	}
	orgID, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("LastInsertId: %v", err)
	}

	masterKey, err := secrets.GenerateMasterKey()
	if err != nil {
		t.Fatalf("GenerateMasterKey: %v", err)
	}
	secretsStore := secrets.NewStore(db, masterKey)
	registry := servers.NewRegistry(db, secretsStore)

	serverID, err := registry.Create(ctx, servers.Server{
		OrgID: orgID, Name: "mock-01", Host: "127.0.0.1", Port: 22, SSHUser: "deploy",
		AuthType: servers.AuthKey, Type: servers.TypeMock, Environment: servers.EnvDev,
	}, servers.Credential{Type: servers.AuthKey, PrivateKey: []byte("unused-for-mock")})
	if err != nil {
		t.Fatalf("registry.Create: %v", err)
	}

	res, err = db.ExecContext(ctx, `INSERT INTO module_catalog (key, name) VALUES ('testikon', 'Тестикон')`)
	if err != nil {
		t.Fatalf("insert module_catalog: %v", err)
	}
	moduleCatalogID, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("LastInsertId: %v", err)
	}
	versionID := newTestVersion(t, db, moduleCatalogID, "1.0.0", "")

	deployer := NewDeployer(registry, NewCatalogReader(db), NewInstallations(db), NewDeployments(db), http.DefaultClient)

	result, err := deployer.Deploy(ctx, DeployInput{
		OrgID: orgID, ServerID: serverID, ModuleCatalogID: moduleCatalogID, ToVersionID: versionID, Kind: KindInstall,
	})
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	if result.Status != StatusSuccess {
		t.Fatalf("Deploy: got status %q, want %q\nlog:\n%s", result.Status, StatusSuccess, result.Log)
	}
}

func assertNoInstallation(t *testing.T, db *sql.DB, f testFixtures) {
	t.Helper()
	_, err := NewInstallations(db).GetByServerAndModule(context.Background(), f.ServerID, f.ModuleCatalogID)
	if !errors.Is(err, ErrInstallationNotFound) {
		t.Fatalf("GetByServerAndModule: got err %v, want ErrInstallationNotFound (installation should not exist after a failed deploy)", err)
	}
}
