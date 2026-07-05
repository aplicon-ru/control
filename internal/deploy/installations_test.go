package deploy

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestInstallations_UpsertGet_Roundtrip(t *testing.T) {
	db := newTestDB(t)
	f := newTestFixtures(t, db)
	versionID := newTestVersion(t, db, f.ModuleCatalogID, "1.0.0", "")

	store := NewInstallations(db)
	ctx := context.Background()

	id, err := store.Upsert(ctx, Installation{
		ServerID:           f.ServerID,
		ModuleCatalogID:    f.ModuleCatalogID,
		InstalledVersionID: versionID,
		Status:             InstallationRunning,
		DeployedAt:         time.Now(),
	})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	got, err := store.Get(ctx, id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ServerID != f.ServerID || got.ModuleCatalogID != f.ModuleCatalogID || got.InstalledVersionID != versionID {
		t.Fatalf("Get: got %+v", got)
	}
	if got.Status != InstallationRunning {
		t.Fatalf("Get: got status %q, want %q", got.Status, InstallationRunning)
	}
	if got.Config != "{}" {
		t.Fatalf("Get: got config %q, want default {}", got.Config)
	}
}

func TestInstallations_UpsertOverwrites(t *testing.T) {
	db := newTestDB(t)
	f := newTestFixtures(t, db)
	v1 := newTestVersion(t, db, f.ModuleCatalogID, "1.0.0", "")
	v2 := newTestVersion(t, db, f.ModuleCatalogID, "2.0.0", "")

	store := NewInstallations(db)
	ctx := context.Background()

	id1, err := store.Upsert(ctx, Installation{
		ServerID: f.ServerID, ModuleCatalogID: f.ModuleCatalogID, InstalledVersionID: v1,
		Status: InstallationRunning, DeployedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("Upsert (v1): %v", err)
	}

	id2, err := store.Upsert(ctx, Installation{
		ServerID: f.ServerID, ModuleCatalogID: f.ModuleCatalogID, InstalledVersionID: v2,
		Status: InstallationRunning, DeployedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("Upsert (v2): %v", err)
	}
	if id1 != id2 {
		t.Fatalf("Upsert: got different IDs %d, %d — want the same row upserted", id1, id2)
	}

	got, err := store.Get(ctx, id2)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.InstalledVersionID != v2 {
		t.Fatalf("Get: got InstalledVersionID %d, want %d (upsert should overwrite)", got.InstalledVersionID, v2)
	}

	var count int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM module_installations WHERE server_id = ? AND module_catalog_id = ?`, f.ServerID, f.ModuleCatalogID).Scan(&count); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if count != 1 {
		t.Fatalf("upsert produced %d rows, want 1", count)
	}
}

func TestInstallations_GetByServerAndModule(t *testing.T) {
	db := newTestDB(t)
	f := newTestFixtures(t, db)
	versionID := newTestVersion(t, db, f.ModuleCatalogID, "1.0.0", "")

	store := NewInstallations(db)
	ctx := context.Background()

	id, err := store.Upsert(ctx, Installation{
		ServerID: f.ServerID, ModuleCatalogID: f.ModuleCatalogID, InstalledVersionID: versionID,
		Status: InstallationRunning, DeployedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	got, err := store.GetByServerAndModule(ctx, f.ServerID, f.ModuleCatalogID)
	if err != nil {
		t.Fatalf("GetByServerAndModule: %v", err)
	}
	if got.ID != id {
		t.Fatalf("GetByServerAndModule: got ID %d, want %d", got.ID, id)
	}
}

func TestInstallations_GetByServerAndModule_NotFound(t *testing.T) {
	db := newTestDB(t)
	store := NewInstallations(db)

	_, err := store.GetByServerAndModule(context.Background(), 999, 999)
	if !errors.Is(err, ErrInstallationNotFound) {
		t.Fatalf("GetByServerAndModule: got err %v, want ErrInstallationNotFound", err)
	}
}

func TestInstallations_Get_NotFound(t *testing.T) {
	db := newTestDB(t)
	store := NewInstallations(db)

	_, err := store.Get(context.Background(), 999)
	if !errors.Is(err, ErrInstallationNotFound) {
		t.Fatalf("Get: got err %v, want ErrInstallationNotFound", err)
	}
}

func TestInstallations_UpdateStatus(t *testing.T) {
	db := newTestDB(t)
	f := newTestFixtures(t, db)
	versionID := newTestVersion(t, db, f.ModuleCatalogID, "1.0.0", "")

	store := NewInstallations(db)
	ctx := context.Background()

	id, err := store.Upsert(ctx, Installation{
		ServerID: f.ServerID, ModuleCatalogID: f.ModuleCatalogID, InstalledVersionID: versionID,
		Status: InstallationDeploying, DeployedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	if err := store.UpdateStatus(ctx, id, InstallationError); err != nil {
		t.Fatalf("UpdateStatus: %v", err)
	}

	got, err := store.Get(ctx, id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != InstallationError {
		t.Fatalf("Get: got status %q, want %q", got.Status, InstallationError)
	}
}

func TestInstallations_UpdateStatus_NotFound(t *testing.T) {
	db := newTestDB(t)
	store := NewInstallations(db)

	err := store.UpdateStatus(context.Background(), 999, InstallationError)
	if !errors.Is(err, ErrInstallationNotFound) {
		t.Fatalf("UpdateStatus: got err %v, want ErrInstallationNotFound", err)
	}
}

func TestInstallations_ClosedDB(t *testing.T) {
	db := newTestDB(t)
	store := NewInstallations(db)
	db.Close()

	if _, err := store.Upsert(context.Background(), Installation{DeployedAt: time.Now()}); err == nil {
		t.Fatal("Upsert: want error on closed DB, got nil")
	}
	if err := store.UpdateStatus(context.Background(), 1, InstallationError); err == nil {
		t.Fatal("UpdateStatus: want error on closed DB, got nil")
	}
}
