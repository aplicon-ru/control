package auth

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"

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

func newTestOrg(t *testing.T, db *sql.DB) int64 {
	t.Helper()
	res, err := db.ExecContext(context.Background(), `INSERT INTO organizations (slug, name) VALUES ('acme', 'Acme')`)
	if err != nil {
		t.Fatalf("insert organization: %v", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("LastInsertId: %v", err)
	}
	return id
}

func TestCreateLocal_GetByEmail_Roundtrip(t *testing.T) {
	db := newTestDB(t)
	orgID := newTestOrg(t, db)
	store := NewUserStore(db)
	ctx := context.Background()

	hash, err := HashPassword("hunter2")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	id, err := store.CreateLocal(ctx, &orgID, "admin@example.com", hash, RoleOrgAdmin)
	if err != nil {
		t.Fatalf("CreateLocal: %v", err)
	}

	u, err := store.GetByEmail(ctx, "admin@example.com")
	if err != nil {
		t.Fatalf("GetByEmail: %v", err)
	}
	if u.ID != id || u.Email != "admin@example.com" || u.Role != RoleOrgAdmin {
		t.Fatalf("GetByEmail: got %+v", u)
	}
	if u.OrgID == nil || *u.OrgID != orgID {
		t.Fatalf("GetByEmail: got OrgID %v, want %d", u.OrgID, orgID)
	}
	if u.PasswordHash != hash {
		t.Fatalf("GetByEmail: password hash mismatch")
	}
	if u.TOTPEnabled {
		t.Fatal("GetByEmail: want TOTPEnabled false by default")
	}
}

func TestCreateLocal_SuperAdminHasNilOrg(t *testing.T) {
	db := newTestDB(t)
	store := NewUserStore(db)
	ctx := context.Background()

	hash, err := HashPassword("hunter2")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	id, err := store.CreateLocal(ctx, nil, "root@example.com", hash, RoleSuperAdmin)
	if err != nil {
		t.Fatalf("CreateLocal: %v", err)
	}

	u, err := store.GetByID(ctx, id)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if u.OrgID != nil {
		t.Fatalf("GetByID: want nil OrgID for super_admin, got %v", u.OrgID)
	}
}

func TestCreateLocal_RejectsOrgAdminWithNilOrg(t *testing.T) {
	db := newTestDB(t)
	store := NewUserStore(db)

	_, err := store.CreateLocal(context.Background(), nil, "a@example.com", "hash", RoleOrgAdmin)
	if !errors.Is(err, ErrInvalidField) {
		t.Fatalf("CreateLocal: got err %v, want ErrInvalidField", err)
	}
}

func TestCreateLocal_RejectsSuperAdminWithOrg(t *testing.T) {
	db := newTestDB(t)
	orgID := newTestOrg(t, db)
	store := NewUserStore(db)

	_, err := store.CreateLocal(context.Background(), &orgID, "a@example.com", "hash", RoleSuperAdmin)
	if !errors.Is(err, ErrInvalidField) {
		t.Fatalf("CreateLocal: got err %v, want ErrInvalidField", err)
	}
}

func TestCreateLocal_RejectsInvalidRole(t *testing.T) {
	db := newTestDB(t)
	orgID := newTestOrg(t, db)
	store := NewUserStore(db)

	_, err := store.CreateLocal(context.Background(), &orgID, "a@example.com", "hash", Role("root"))
	if !errors.Is(err, ErrInvalidField) {
		t.Fatalf("CreateLocal: got err %v, want ErrInvalidField", err)
	}
}

func TestCreateLocal_DuplicateEmail(t *testing.T) {
	db := newTestDB(t)
	orgID := newTestOrg(t, db)
	store := NewUserStore(db)
	ctx := context.Background()

	if _, err := store.CreateLocal(ctx, &orgID, "dup@example.com", "hash", RoleViewer); err != nil {
		t.Fatalf("CreateLocal (first): %v", err)
	}
	_, err := store.CreateLocal(ctx, &orgID, "dup@example.com", "hash", RoleViewer)
	if !errors.Is(err, ErrEmailTaken) {
		t.Fatalf("CreateLocal (duplicate): got err %v, want ErrEmailTaken", err)
	}
}

func TestGetByEmail_NotFound(t *testing.T) {
	db := newTestDB(t)
	store := NewUserStore(db)

	_, err := store.GetByEmail(context.Background(), "nobody@example.com")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetByEmail: got err %v, want ErrNotFound", err)
	}
}

func TestGetByID_NotFound(t *testing.T) {
	db := newTestDB(t)
	store := NewUserStore(db)

	_, err := store.GetByID(context.Background(), 999)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetByID: got err %v, want ErrNotFound", err)
	}
}

func TestCreateLocal_ClosedDB(t *testing.T) {
	db := newTestDB(t)
	store := NewUserStore(db)
	db.Close()

	orgID := int64(1)
	if _, err := store.CreateLocal(context.Background(), &orgID, "a@example.com", "hash", RoleViewer); err == nil {
		t.Fatal("CreateLocal: want error on closed DB, got nil")
	}
}

func TestGetByEmail_ClosedDB(t *testing.T) {
	db := newTestDB(t)
	store := NewUserStore(db)
	db.Close()

	if _, err := store.GetByEmail(context.Background(), "a@example.com"); err == nil {
		t.Fatal("GetByEmail: want error on closed DB, got nil")
	}
}

func TestParseSQLiteTime_Invalid(t *testing.T) {
	if _, err := parseSQLiteTime("not a timestamp"); err == nil {
		t.Fatal("parseSQLiteTime: want error for unparseable input, got nil")
	}
}
