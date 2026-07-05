package auth

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestSessionCreate_ClosedDB(t *testing.T) {
	db := newTestDB(t)
	sessions := NewSessionStore(db)
	db.Close()

	if _, err := sessions.Create(context.Background(), 1, "127.0.0.1", "ua", time.Hour); err == nil {
		t.Fatal("Create: want error on closed DB, got nil")
	}
}

func TestSessionVerify_ClosedDB(t *testing.T) {
	db := newTestDB(t)
	sessions := NewSessionStore(db)
	db.Close()

	if _, _, err := sessions.Verify(context.Background(), "anything"); err == nil {
		t.Fatal("Verify: want error on closed DB, got nil")
	}
}

func TestSessionRevoke_ClosedDB(t *testing.T) {
	db := newTestDB(t)
	sessions := NewSessionStore(db)
	db.Close()

	if err := sessions.Revoke(context.Background(), "anything"); err == nil {
		t.Fatal("Revoke: want error on closed DB, got nil")
	}
}

func TestSessionRevokeAllForUser_ClosedDB(t *testing.T) {
	db := newTestDB(t)
	sessions := NewSessionStore(db)
	db.Close()

	if err := sessions.RevokeAllForUser(context.Background(), 1); err == nil {
		t.Fatal("RevokeAllForUser: want error on closed DB, got nil")
	}
}

func TestSessionCreateVerify_Roundtrip(t *testing.T) {
	db := newTestDB(t)
	orgID := newTestOrg(t, db)
	users := NewUserStore(db)
	userID, err := users.CreateLocal(context.Background(), &orgID, "u@example.com", "hash", RoleViewer)
	if err != nil {
		t.Fatalf("CreateLocal: %v", err)
	}

	sessions := NewSessionStore(db)
	ctx := context.Background()

	raw, err := sessions.Create(ctx, userID, "127.0.0.1", "test-agent", time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if raw == "" {
		t.Fatal("Create: got empty raw token")
	}

	gotUserID, sessionID, err := sessions.Verify(ctx, raw)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if gotUserID != userID {
		t.Fatalf("Verify: got userID %d, want %d", gotUserID, userID)
	}
	if sessionID == 0 {
		t.Fatal("Verify: got sessionID 0")
	}
}

func TestSessionVerify_GarbageToken(t *testing.T) {
	db := newTestDB(t)
	sessions := NewSessionStore(db)

	_, _, err := sessions.Verify(context.Background(), "not-a-real-token")
	if !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("Verify: got err %v, want ErrSessionExpired", err)
	}
}

func TestSessionVerify_Expired(t *testing.T) {
	db := newTestDB(t)
	orgID := newTestOrg(t, db)
	users := NewUserStore(db)
	userID, err := users.CreateLocal(context.Background(), &orgID, "u@example.com", "hash", RoleViewer)
	if err != nil {
		t.Fatalf("CreateLocal: %v", err)
	}

	sessions := NewSessionStore(db)
	ctx := context.Background()

	raw, err := sessions.Create(ctx, userID, "127.0.0.1", "test-agent", -time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if _, _, err := sessions.Verify(ctx, raw); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("Verify: got err %v, want ErrSessionExpired", err)
	}

	// Verify should have cleaned up the expired row.
	if _, _, err := sessions.Verify(ctx, raw); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("Verify (second call): got err %v, want ErrSessionExpired", err)
	}
}

func TestSessionRotate_InvalidatesOldToken(t *testing.T) {
	db := newTestDB(t)
	orgID := newTestOrg(t, db)
	users := NewUserStore(db)
	userID, err := users.CreateLocal(context.Background(), &orgID, "u@example.com", "hash", RoleViewer)
	if err != nil {
		t.Fatalf("CreateLocal: %v", err)
	}

	sessions := NewSessionStore(db)
	ctx := context.Background()

	oldRaw, err := sessions.Create(ctx, userID, "127.0.0.1", "test-agent", time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	newRaw, gotUserID, err := sessions.Rotate(ctx, oldRaw, "127.0.0.1", "test-agent", time.Hour)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if gotUserID != userID {
		t.Fatalf("Rotate: got userID %d, want %d", gotUserID, userID)
	}
	if newRaw == oldRaw {
		t.Fatal("Rotate: new token equals old token")
	}

	if _, _, err := sessions.Verify(ctx, oldRaw); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("Verify(old): got err %v, want ErrSessionExpired", err)
	}
	if _, _, err := sessions.Verify(ctx, newRaw); err != nil {
		t.Fatalf("Verify(new): %v", err)
	}
}

func TestSessionRotate_InvalidToken(t *testing.T) {
	db := newTestDB(t)
	sessions := NewSessionStore(db)

	_, _, err := sessions.Rotate(context.Background(), "garbage", "127.0.0.1", "ua", time.Hour)
	if !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("Rotate: got err %v, want ErrSessionExpired", err)
	}
}

func TestSessionRevoke_Idempotent(t *testing.T) {
	db := newTestDB(t)
	orgID := newTestOrg(t, db)
	users := NewUserStore(db)
	userID, err := users.CreateLocal(context.Background(), &orgID, "u@example.com", "hash", RoleViewer)
	if err != nil {
		t.Fatalf("CreateLocal: %v", err)
	}

	sessions := NewSessionStore(db)
	ctx := context.Background()

	raw, err := sessions.Create(ctx, userID, "127.0.0.1", "test-agent", time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := sessions.Revoke(ctx, raw); err != nil {
		t.Fatalf("Revoke (first): %v", err)
	}
	if err := sessions.Revoke(ctx, raw); err != nil {
		t.Fatalf("Revoke (second, idempotent): %v", err)
	}

	if _, _, err := sessions.Verify(ctx, raw); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("Verify after Revoke: got err %v, want ErrSessionExpired", err)
	}
}

func TestSessionRevokeAllForUser(t *testing.T) {
	db := newTestDB(t)
	orgID := newTestOrg(t, db)
	users := NewUserStore(db)
	userID, err := users.CreateLocal(context.Background(), &orgID, "u@example.com", "hash", RoleViewer)
	if err != nil {
		t.Fatalf("CreateLocal: %v", err)
	}

	sessions := NewSessionStore(db)
	ctx := context.Background()

	raw1, err := sessions.Create(ctx, userID, "127.0.0.1", "ua1", time.Hour)
	if err != nil {
		t.Fatalf("Create (1): %v", err)
	}
	raw2, err := sessions.Create(ctx, userID, "127.0.0.1", "ua2", time.Hour)
	if err != nil {
		t.Fatalf("Create (2): %v", err)
	}

	if err := sessions.RevokeAllForUser(ctx, userID); err != nil {
		t.Fatalf("RevokeAllForUser: %v", err)
	}

	if _, _, err := sessions.Verify(ctx, raw1); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("Verify(raw1): got err %v, want ErrSessionExpired", err)
	}
	if _, _, err := sessions.Verify(ctx, raw2); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("Verify(raw2): got err %v, want ErrSessionExpired", err)
	}
}
