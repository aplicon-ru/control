package deploy

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func newTestDB(t *testing.T) *sql.DB {
	t.Helper()

	db, err := sql.Open("sqlite", "file::memory:")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	schema, err := os.ReadFile("../../migrations/0001_init.sql")
	if err != nil {
		t.Fatalf("read migrations/0001_init.sql: %v", err)
	}
	if _, err := db.ExecContext(context.Background(), string(schema)); err != nil {
		t.Fatalf("apply migrations/0001_init.sql: %v", err)
	}

	return db
}

// testFixtures seeds an organization, a mock server, and a module catalog
// entry, returning their IDs for use by tests across this package.
type testFixtures struct {
	OrgID           int64
	ServerID        int64
	ModuleCatalogID int64
}

func newTestFixtures(t *testing.T, db *sql.DB) testFixtures {
	t.Helper()
	ctx := context.Background()

	var f testFixtures

	res, err := db.ExecContext(ctx, `INSERT INTO organizations (slug, name) VALUES ('acme', 'Acme')`)
	if err != nil {
		t.Fatalf("insert organization: %v", err)
	}
	f.OrgID, err = res.LastInsertId()
	if err != nil {
		t.Fatalf("LastInsertId: %v", err)
	}

	res, err = db.ExecContext(ctx, `
		INSERT INTO servers (org_id, name, host, port, ssh_user, auth_type, type, environment)
		VALUES (?, 'mock-01', '127.0.0.1', 22, 'deploy', 'key', 'mock', 'dev')
	`, f.OrgID)
	if err != nil {
		t.Fatalf("insert server: %v", err)
	}
	f.ServerID, err = res.LastInsertId()
	if err != nil {
		t.Fatalf("LastInsertId: %v", err)
	}

	res, err = db.ExecContext(ctx, `INSERT INTO module_catalog (key, name) VALUES ('testikon', 'Тестикон')`)
	if err != nil {
		t.Fatalf("insert module_catalog: %v", err)
	}
	f.ModuleCatalogID, err = res.LastInsertId()
	if err != nil {
		t.Fatalf("LastInsertId: %v", err)
	}

	return f
}

func newTestVersion(t *testing.T, db *sql.DB, moduleCatalogID int64, version, healthcheckURL string) int64 {
	t.Helper()
	res, err := db.ExecContext(context.Background(), `
		INSERT INTO module_versions (module_catalog_id, version, image, compose_ref, vars_schema, healthcheck_url, released_at)
		VALUES (?, ?, 'ghcr.io/aplicon-ru/testikon:'||?, './compose.yml', '{}', ?, ?)
	`, moduleCatalogID, version, version, nullIfEmpty(healthcheckURL), formatSQLiteTime(time.Now()))
	if err != nil {
		t.Fatalf("insert module_versions: %v", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("LastInsertId: %v", err)
	}
	return id
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func TestCatalogReader_GetVersion(t *testing.T) {
	db := newTestDB(t)
	f := newTestFixtures(t, db)
	versionID := newTestVersion(t, db, f.ModuleCatalogID, "1.0.0", "http://localhost:8001/health")

	reader := NewCatalogReader(db)
	v, err := reader.GetVersion(context.Background(), versionID)
	if err != nil {
		t.Fatalf("GetVersion: %v", err)
	}

	if v.ModuleKey != "testikon" || v.Version != "1.0.0" || v.ComposeRef != "./compose.yml" {
		t.Fatalf("GetVersion: got %+v", v)
	}
	if v.HealthcheckURL != "http://localhost:8001/health" {
		t.Fatalf("GetVersion: got HealthcheckURL %q", v.HealthcheckURL)
	}
	if v.DemoMode != "" {
		t.Fatalf("GetVersion: got DemoMode %q, want empty", v.DemoMode)
	}
}

func TestCatalogReader_GetVersion_NotFound(t *testing.T) {
	db := newTestDB(t)
	reader := NewCatalogReader(db)

	_, err := reader.GetVersion(context.Background(), 999)
	if !errors.Is(err, ErrVersionNotFound) {
		t.Fatalf("GetVersion: got err %v, want ErrVersionNotFound", err)
	}
}

func TestCatalogReader_GetVersion_NoHealthcheck(t *testing.T) {
	db := newTestDB(t)
	f := newTestFixtures(t, db)
	versionID := newTestVersion(t, db, f.ModuleCatalogID, "1.0.0", "")

	reader := NewCatalogReader(db)
	v, err := reader.GetVersion(context.Background(), versionID)
	if err != nil {
		t.Fatalf("GetVersion: %v", err)
	}
	if v.HealthcheckURL != "" {
		t.Fatalf("GetVersion: got HealthcheckURL %q, want empty", v.HealthcheckURL)
	}
}
