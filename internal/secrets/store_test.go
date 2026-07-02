package secrets

import (
	"bytes"
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

func TestPutGet_Roundtrip(t *testing.T) {
	db := newTestDB(t)
	store := NewStore(db, testKey(t))
	ctx := context.Background()

	if err := store.Put(ctx, ClassServer, "server", 1, "ssh_private_key", []byte("-----BEGIN KEY-----")); err != nil {
		t.Fatalf("Put: %v", err)
	}

	plaintext, class, err := store.Get(ctx, "server", 1, "ssh_private_key")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(plaintext, []byte("-----BEGIN KEY-----")) {
		t.Fatalf("Get: got %q, want %q", plaintext, "-----BEGIN KEY-----")
	}
	if class != ClassServer {
		t.Fatalf("Get: got class %q, want %q", class, ClassServer)
	}
}

func TestGet_NotFound(t *testing.T) {
	db := newTestDB(t)
	store := NewStore(db, testKey(t))

	_, _, err := store.Get(context.Background(), "server", 999, "ssh_private_key")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get: got err %v, want ErrNotFound", err)
	}
}

func TestPut_UpsertOverwrites(t *testing.T) {
	db := newTestDB(t)
	store := NewStore(db, testKey(t))
	ctx := context.Background()

	if err := store.Put(ctx, ClassServer, "server", 1, "ssh_private_key", []byte("first")); err != nil {
		t.Fatalf("Put (first): %v", err)
	}
	if err := store.Put(ctx, ClassServer, "server", 1, "ssh_private_key", []byte("second")); err != nil {
		t.Fatalf("Put (second): %v", err)
	}

	plaintext, _, err := store.Get(ctx, "server", 1, "ssh_private_key")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(plaintext, []byte("second")) {
		t.Fatalf("Get: got %q, want %q (upsert should overwrite)", plaintext, "second")
	}

	var count int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM secrets WHERE owner_type = 'server' AND owner_id = 1 AND key_name = 'ssh_private_key'`).Scan(&count); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if count != 1 {
		t.Fatalf("upsert produced %d rows, want 1", count)
	}
}

func TestPut_UpsertUpdatesClass(t *testing.T) {
	db := newTestDB(t)
	store := NewStore(db, testKey(t))
	ctx := context.Background()

	if err := store.Put(ctx, ClassServer, "server", 1, "k", []byte("v")); err != nil {
		t.Fatalf("Put (first): %v", err)
	}
	if err := store.Put(ctx, ClassModule, "server", 1, "k", []byte("v")); err != nil {
		t.Fatalf("Put (second): %v", err)
	}

	_, class, err := store.Get(ctx, "server", 1, "k")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if class != ClassModule {
		t.Fatalf("Get: got class %q after upsert, want %q", class, ClassModule)
	}
}

func TestPut_InvalidClass(t *testing.T) {
	db := newTestDB(t)
	store := NewStore(db, testKey(t))

	err := store.Put(context.Background(), Class("Z"), "server", 1, "k", []byte("v"))
	if !errors.Is(err, ErrInvalidClass) {
		t.Fatalf("Put: got err %v, want ErrInvalidClass", err)
	}
}

func TestDelete_RemovesRow(t *testing.T) {
	db := newTestDB(t)
	store := NewStore(db, testKey(t))
	ctx := context.Background()

	if err := store.Put(ctx, ClassServer, "server", 1, "k", []byte("v")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := store.Delete(ctx, "server", 1, "k"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	_, _, err := store.Get(ctx, "server", 1, "k")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get after Delete: got err %v, want ErrNotFound", err)
	}
}

func TestDelete_MissingRowIsNoop(t *testing.T) {
	db := newTestDB(t)
	store := NewStore(db, testKey(t))

	if err := store.Delete(context.Background(), "server", 999, "k"); err != nil {
		t.Fatalf("Delete on missing row: got err %v, want nil", err)
	}
}

func TestGet_CorruptedRowFailsClosed(t *testing.T) {
	db := newTestDB(t)
	store := NewStore(db, testKey(t))
	ctx := context.Background()

	if err := store.Put(ctx, ClassServer, "server", 1, "k", []byte("v")); err != nil {
		t.Fatalf("Put: %v", err)
	}

	if _, err := db.ExecContext(ctx, `UPDATE secrets SET ciphertext = X'DEADBEEF' WHERE owner_type = 'server' AND owner_id = 1 AND key_name = 'k'`); err != nil {
		t.Fatalf("corrupt row: %v", err)
	}

	if _, _, err := store.Get(ctx, "server", 1, "k"); err == nil {
		t.Fatal("Get: want error for tampered row, got nil")
	}
}

func TestPut_ClosedDB(t *testing.T) {
	db := newTestDB(t)
	store := NewStore(db, testKey(t))
	db.Close()

	if err := store.Put(context.Background(), ClassServer, "server", 1, "k", []byte("v")); err == nil {
		t.Fatal("Put: want error on closed DB, got nil")
	}
}

func TestGet_ClosedDB(t *testing.T) {
	db := newTestDB(t)
	store := NewStore(db, testKey(t))
	db.Close()

	if _, _, err := store.Get(context.Background(), "server", 1, "k"); err == nil {
		t.Fatal("Get: want error on closed DB, got nil")
	}
}

func TestDelete_ClosedDB(t *testing.T) {
	db := newTestDB(t)
	store := NewStore(db, testKey(t))
	db.Close()

	if err := store.Delete(context.Background(), "server", 1, "k"); err == nil {
		t.Fatal("Delete: want error on closed DB, got nil")
	}
}

func TestGet_WrongKeyCannotDecryptOldData(t *testing.T) {
	db := newTestDB(t)
	storeA := NewStore(db, testKey(t))
	storeB := NewStore(db, testKey(t))
	ctx := context.Background()

	if err := storeA.Put(ctx, ClassServer, "server", 1, "k", []byte("v")); err != nil {
		t.Fatalf("Put: %v", err)
	}

	if _, _, err := storeB.Get(ctx, "server", 1, "k"); err == nil {
		t.Fatal("Get: want error when reading with a different master key, got nil")
	}
}
