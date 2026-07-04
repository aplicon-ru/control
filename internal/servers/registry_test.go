package servers

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/aplicon-ru/control/internal/secrets"
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

func newTestRegistry(t *testing.T) (*Registry, int64) {
	t.Helper()

	db := newTestDB(t)
	ctx := context.Background()

	key, err := secrets.GenerateMasterKey()
	if err != nil {
		t.Fatalf("GenerateMasterKey: %v", err)
	}
	store := secrets.NewStore(db, key)

	res, err := db.ExecContext(ctx, `INSERT INTO organizations (slug, name) VALUES ('acme', 'Acme')`)
	if err != nil {
		t.Fatalf("insert organization: %v", err)
	}
	orgID, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("LastInsertId: %v", err)
	}

	return NewRegistry(db, store), orgID
}

func testServer(orgID int64) Server {
	return Server{
		OrgID:       orgID,
		Name:        "prod-01",
		Host:        "10.0.0.1",
		Port:        22,
		SSHUser:     "deploy",
		AuthType:    AuthKey,
		Type:        TypeDockerOnly,
		Environment: EnvProd,
	}
}

func TestCreateGet_Roundtrip(t *testing.T) {
	r, orgID := newTestRegistry(t)
	ctx := context.Background()

	id, err := r.Create(ctx, testServer(orgID), Credential{Type: AuthKey, PrivateKey: []byte("fake-key")})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := r.Get(ctx, orgID, id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Name != "prod-01" || got.Host != "10.0.0.1" || got.Type != TypeDockerOnly {
		t.Fatalf("Get: got %+v, want matching fields from testServer", got)
	}
	if got.Status != StatusUnknown {
		t.Fatalf("Get: got status %q, want default %q", got.Status, StatusUnknown)
	}

	secretBytes, class, err := r.secrets.Get(ctx, "server", id, "ssh_private_key")
	if err != nil {
		t.Fatalf("secrets.Get: %v", err)
	}
	if string(secretBytes) != "fake-key" {
		t.Fatalf("secrets.Get: got %q, want %q", secretBytes, "fake-key")
	}
	if class != secrets.ClassServer {
		t.Fatalf("secrets.Get: got class %q, want %q", class, secrets.ClassServer)
	}
}

func TestCreate_PasswordCredential(t *testing.T) {
	r, orgID := newTestRegistry(t)
	ctx := context.Background()

	s := testServer(orgID)
	s.AuthType = AuthPassword

	id, err := r.Create(ctx, s, Credential{Type: AuthPassword, Password: "hunter2"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	pw, class, err := r.secrets.Get(ctx, "server", id, "ssh_password")
	if err != nil {
		t.Fatalf("secrets.Get: %v", err)
	}
	if string(pw) != "hunter2" {
		t.Fatalf("secrets.Get: got %q, want %q", pw, "hunter2")
	}
	if class != secrets.ClassServer {
		t.Fatalf("secrets.Get: got class %q, want %q", class, secrets.ClassServer)
	}
}

func TestParseSQLiteTime_Invalid(t *testing.T) {
	if _, err := parseSQLiteTime("not a timestamp"); err == nil {
		t.Fatal("parseSQLiteTime: want error for unparseable input, got nil")
	}
}

func TestUpdate_InvalidField(t *testing.T) {
	r, orgID := newTestRegistry(t)
	ctx := context.Background()

	id, err := r.Create(ctx, testServer(orgID), Credential{Type: AuthKey, PrivateKey: []byte("k")})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	s := testServer(orgID)
	s.ID = id
	s.Environment = Environment("qa")

	if err := r.Update(ctx, s); !errors.Is(err, ErrInvalidField) {
		t.Fatalf("Update: got err %v, want ErrInvalidField", err)
	}
}

func TestCreate_InvalidFieldRejectedPreDB(t *testing.T) {
	r, orgID := newTestRegistry(t)
	s := testServer(orgID)
	s.Type = ServerType("vm")

	if _, err := r.Create(context.Background(), s, Credential{Type: AuthKey, PrivateKey: []byte("k")}); !errors.Is(err, ErrInvalidField) {
		t.Fatalf("Create: got err %v, want ErrInvalidField", err)
	}
}

func TestCreate_CredentialTypeMustMatchAuthType(t *testing.T) {
	r, orgID := newTestRegistry(t)
	s := testServer(orgID) // AuthType: AuthKey

	_, err := r.Create(context.Background(), s, Credential{Type: AuthPassword, Password: "hunter2"})
	if !errors.Is(err, ErrInvalidField) {
		t.Fatalf("Create: got err %v, want ErrInvalidField", err)
	}
}

func TestCreate_DuplicateNameInOrgFails(t *testing.T) {
	r, orgID := newTestRegistry(t)
	ctx := context.Background()

	if _, err := r.Create(ctx, testServer(orgID), Credential{Type: AuthKey, PrivateKey: []byte("k")}); err != nil {
		t.Fatalf("Create (first): %v", err)
	}
	if _, err := r.Create(ctx, testServer(orgID), Credential{Type: AuthKey, PrivateKey: []byte("k")}); err == nil {
		t.Fatal("Create (duplicate name): want error, got nil")
	}
}

func TestGet_NotFound(t *testing.T) {
	r, orgID := newTestRegistry(t)
	if _, err := r.Get(context.Background(), orgID, 999); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get: got err %v, want ErrNotFound", err)
	}
}

func TestGet_WrongOrgIsNotFound(t *testing.T) {
	r, orgID := newTestRegistry(t)
	ctx := context.Background()

	id, err := r.Create(ctx, testServer(orgID), Credential{Type: AuthKey, PrivateKey: []byte("k")})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if _, err := r.Get(ctx, orgID+1, id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get with wrong org: got err %v, want ErrNotFound", err)
	}
}

func TestList_ScopedByOrg(t *testing.T) {
	r, orgID := newTestRegistry(t)
	ctx := context.Background()

	otherOrgID := orgID + 1
	if _, err := r.db.ExecContext(ctx, `INSERT INTO organizations (id, slug, name) VALUES (?, 'other', 'Other')`, otherOrgID); err != nil {
		t.Fatalf("insert other org: %v", err)
	}

	if _, err := r.Create(ctx, testServer(orgID), Credential{Type: AuthKey, PrivateKey: []byte("k")}); err != nil {
		t.Fatalf("Create (org): %v", err)
	}
	other := testServer(otherOrgID)
	other.Name = "other-01"
	if _, err := r.Create(ctx, other, Credential{Type: AuthKey, PrivateKey: []byte("k")}); err != nil {
		t.Fatalf("Create (other org): %v", err)
	}

	list, err := r.List(ctx, orgID)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 || list[0].Name != "prod-01" {
		t.Fatalf("List: got %+v, want exactly [prod-01]", list)
	}
}

func TestUpdate_OverwritesFields(t *testing.T) {
	r, orgID := newTestRegistry(t)
	ctx := context.Background()

	id, err := r.Create(ctx, testServer(orgID), Credential{Type: AuthKey, PrivateKey: []byte("k")})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	updated := testServer(orgID)
	updated.ID = id
	updated.Host = "10.0.0.2"

	if err := r.Update(ctx, updated); err != nil {
		t.Fatalf("Update: %v", err)
	}

	got, err := r.Get(ctx, orgID, id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Host != "10.0.0.2" {
		t.Fatalf("Get after Update: got host %q, want %q", got.Host, "10.0.0.2")
	}
}

func TestUpdate_NotFound(t *testing.T) {
	r, orgID := newTestRegistry(t)
	s := testServer(orgID)
	s.ID = 999

	if err := r.Update(context.Background(), s); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Update: got err %v, want ErrNotFound", err)
	}
}

func TestUpdateStatus(t *testing.T) {
	r, orgID := newTestRegistry(t)
	ctx := context.Background()

	id, err := r.Create(ctx, testServer(orgID), Credential{Type: AuthKey, PrivateKey: []byte("k")})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	checkedAt := time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)
	if err := r.UpdateStatus(ctx, id, StatusOnline, checkedAt); err != nil {
		t.Fatalf("UpdateStatus: %v", err)
	}

	got, err := r.Get(ctx, orgID, id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != StatusOnline {
		t.Fatalf("Get: got status %q, want %q", got.Status, StatusOnline)
	}
	if got.LastCheckedAt == nil || !got.LastCheckedAt.Equal(checkedAt) {
		t.Fatalf("Get: got LastCheckedAt %v, want %v", got.LastCheckedAt, checkedAt)
	}
}

func TestUpdateStatus_InvalidStatus(t *testing.T) {
	r, orgID := newTestRegistry(t)
	ctx := context.Background()

	id, err := r.Create(ctx, testServer(orgID), Credential{Type: AuthKey, PrivateKey: []byte("k")})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := r.UpdateStatus(ctx, id, Status("degraded"), time.Now()); !errors.Is(err, ErrInvalidField) {
		t.Fatalf("UpdateStatus: got err %v, want ErrInvalidField", err)
	}
}

func TestDelete_RemovesServerAndSecrets(t *testing.T) {
	r, orgID := newTestRegistry(t)
	ctx := context.Background()

	id, err := r.Create(ctx, testServer(orgID), Credential{Type: AuthKey, PrivateKey: []byte("k")})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := r.Delete(ctx, orgID, id); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	if _, err := r.Get(ctx, orgID, id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get after Delete: got err %v, want ErrNotFound", err)
	}
	if _, _, err := r.secrets.Get(ctx, "server", id, "ssh_private_key"); !errors.Is(err, secrets.ErrNotFound) {
		t.Fatalf("secrets.Get after Delete: got err %v, want secrets.ErrNotFound", err)
	}
}

func TestDelete_RefusesIsSelf(t *testing.T) {
	r, orgID := newTestRegistry(t)
	ctx := context.Background()

	s := testServer(orgID)
	s.IsSelf = true
	id, err := r.Create(ctx, s, Credential{Type: AuthKey, PrivateKey: []byte("k")})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := r.Delete(ctx, orgID, id); !errors.Is(err, ErrIsSelfProtected) {
		t.Fatalf("Delete: got err %v, want ErrIsSelfProtected", err)
	}

	if _, err := r.Get(ctx, orgID, id); err != nil {
		t.Fatalf("Get after refused Delete: want the server to still exist, got err %v", err)
	}
}

func TestDelete_NotFound(t *testing.T) {
	r, orgID := newTestRegistry(t)
	if err := r.Delete(context.Background(), orgID, 999); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Delete: got err %v, want ErrNotFound", err)
	}
}

func TestConnect_Mock(t *testing.T) {
	r, orgID := newTestRegistry(t)
	ctx := context.Background()

	s := testServer(orgID)
	s.Type = TypeMock
	id, err := r.Create(ctx, s, Credential{Type: AuthKey, PrivateKey: []byte("k")})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	exec, err := r.Connect(ctx, orgID, id)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer exec.Close()

	result, err := exec.Run(ctx, "docker version")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("Run: exit code %d, want 0", result.ExitCode)
	}
}

func TestConnect_NotFound(t *testing.T) {
	r, orgID := newTestRegistry(t)
	if _, err := r.Connect(context.Background(), orgID, 999); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Connect: got err %v, want ErrNotFound", err)
	}
}
