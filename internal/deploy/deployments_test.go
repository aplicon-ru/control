package deploy

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestDeployments_CreateGet_Roundtrip(t *testing.T) {
	db := newTestDB(t)
	f := newTestFixtures(t, db)
	versionID := newTestVersion(t, db, f.ModuleCatalogID, "1.0.0", "")

	store := NewDeployments(db)
	ctx := context.Background()

	id, err := store.Create(ctx, Deployment{
		ServerID:    f.ServerID,
		Kind:        KindInstall,
		ToVersionID: &versionID,
		Status:      StatusPending,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := store.Get(ctx, id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ServerID != f.ServerID || got.Kind != KindInstall || got.Status != StatusPending {
		t.Fatalf("Get: got %+v", got)
	}
	if got.ToVersionID == nil || *got.ToVersionID != versionID {
		t.Fatalf("Get: got ToVersionID %v, want %d", got.ToVersionID, versionID)
	}
	if got.StartedAt != nil || got.FinishedAt != nil {
		t.Fatalf("Get: want nil StartedAt/FinishedAt on a fresh row, got %+v", got)
	}
}

func TestDeployments_Get_NotFound(t *testing.T) {
	db := newTestDB(t)
	store := NewDeployments(db)

	_, err := store.Get(context.Background(), 999)
	if !errors.Is(err, ErrDeploymentNotFound) {
		t.Fatalf("Get: got err %v, want ErrDeploymentNotFound", err)
	}
}

func TestDeployments_MarkRunning_MarkFinished(t *testing.T) {
	db := newTestDB(t)
	f := newTestFixtures(t, db)
	versionID := newTestVersion(t, db, f.ModuleCatalogID, "1.0.0", "")

	store := NewDeployments(db)
	ctx := context.Background()

	id, err := store.Create(ctx, Deployment{ServerID: f.ServerID, Kind: KindInstall, ToVersionID: &versionID, Status: StatusPending})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	startedAt := time.Now()
	if err := store.MarkRunning(ctx, id, startedAt); err != nil {
		t.Fatalf("MarkRunning: %v", err)
	}

	got, err := store.Get(ctx, id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != StatusRunning {
		t.Fatalf("Get: got status %q, want %q", got.Status, StatusRunning)
	}
	if got.StartedAt == nil {
		t.Fatal("Get: want non-nil StartedAt after MarkRunning")
	}

	finishedAt := startedAt.Add(time.Minute)
	if err := store.MarkFinished(ctx, id, StatusSuccess, finishedAt, "deploy log"); err != nil {
		t.Fatalf("MarkFinished: %v", err)
	}

	got, err = store.Get(ctx, id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != StatusSuccess {
		t.Fatalf("Get: got status %q, want %q", got.Status, StatusSuccess)
	}
	if got.FinishedAt == nil {
		t.Fatal("Get: want non-nil FinishedAt after MarkFinished")
	}
	if got.Log != "deploy log" {
		t.Fatalf("Get: got log %q, want %q", got.Log, "deploy log")
	}
}

func TestDeployments_MarkRunning_NotFound(t *testing.T) {
	db := newTestDB(t)
	store := NewDeployments(db)

	err := store.MarkRunning(context.Background(), 999, time.Now())
	if !errors.Is(err, ErrDeploymentNotFound) {
		t.Fatalf("MarkRunning: got err %v, want ErrDeploymentNotFound", err)
	}
}

func TestDeployments_MarkFinished_NotFound(t *testing.T) {
	db := newTestDB(t)
	store := NewDeployments(db)

	err := store.MarkFinished(context.Background(), 999, StatusFailed, time.Now(), "")
	if !errors.Is(err, ErrDeploymentNotFound) {
		t.Fatalf("MarkFinished: got err %v, want ErrDeploymentNotFound", err)
	}
}

func TestDeployments_ListByServer_NewestFirst(t *testing.T) {
	db := newTestDB(t)
	f := newTestFixtures(t, db)
	versionID := newTestVersion(t, db, f.ModuleCatalogID, "1.0.0", "")

	store := NewDeployments(db)
	ctx := context.Background()

	id1, err := store.Create(ctx, Deployment{ServerID: f.ServerID, Kind: KindInstall, ToVersionID: &versionID, Status: StatusSuccess})
	if err != nil {
		t.Fatalf("Create (1): %v", err)
	}
	id2, err := store.Create(ctx, Deployment{ServerID: f.ServerID, Kind: KindUpdate, ToVersionID: &versionID, Status: StatusSuccess})
	if err != nil {
		t.Fatalf("Create (2): %v", err)
	}

	list, err := store.ListByServer(ctx, f.ServerID)
	if err != nil {
		t.Fatalf("ListByServer: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("ListByServer: got %d rows, want 2", len(list))
	}
	if list[0].ID != id2 || list[1].ID != id1 {
		t.Fatalf("ListByServer: got order [%d, %d], want [%d, %d] (newest first)", list[0].ID, list[1].ID, id2, id1)
	}
}

func TestDeployments_ListByServer_Empty(t *testing.T) {
	db := newTestDB(t)
	store := NewDeployments(db)

	list, err := store.ListByServer(context.Background(), 999)
	if err != nil {
		t.Fatalf("ListByServer: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("ListByServer: got %d rows, want 0", len(list))
	}
}

func TestDeployments_ClosedDB(t *testing.T) {
	db := newTestDB(t)
	store := NewDeployments(db)
	db.Close()

	if _, err := store.Create(context.Background(), Deployment{}); err == nil {
		t.Fatal("Create: want error on closed DB, got nil")
	}
	if _, err := store.ListByServer(context.Background(), 1); err == nil {
		t.Fatal("ListByServer: want error on closed DB, got nil")
	}
}

func TestParseSQLiteTime_Invalid(t *testing.T) {
	if _, err := parseSQLiteTime("garbage"); err == nil {
		t.Fatal("parseSQLiteTime: want error for unparseable input, got nil")
	}
}
