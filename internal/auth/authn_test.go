package auth

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"
)

func newTestAuthSetup(t *testing.T) (*Authenticator, *sql.DB, int64) {
	t.Helper()
	db := newTestDB(t)
	orgID := newTestOrg(t, db)

	users := NewUserStore(db)
	sessions := NewSessionStore(db)
	ipAllowlist := NewIPAllowlist(db)
	a := NewAuthenticator(users, sessions, ipAllowlist, []byte("test-signing-key"), time.Minute*15, time.Hour*24)
	return a, db, orgID
}

func createTestUser(t *testing.T, a *Authenticator, orgID int64, email, password string, role Role) int64 {
	t.Helper()
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	id, err := a.users.CreateLocal(context.Background(), &orgID, email, hash, role)
	if err != nil {
		t.Fatalf("CreateLocal: %v", err)
	}
	return id
}

func TestLogin_Success(t *testing.T) {
	a, _, orgID := newTestAuthSetup(t)
	createTestUser(t, a, orgID, "admin@example.com", "hunter2", RoleOrgAdmin)

	result, err := a.Login(context.Background(), "admin@example.com", "hunter2", "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if result.AccessToken == "" || result.RefreshToken == "" {
		t.Fatal("Login: got empty token(s)")
	}
	if result.User.Email != "admin@example.com" {
		t.Fatalf("Login: got user %+v", result.User)
	}

	claims, err := ParseAccessToken([]byte("test-signing-key"), result.AccessToken)
	if err != nil {
		t.Fatalf("ParseAccessToken: %v", err)
	}
	if claims.UserID != result.User.ID {
		t.Fatalf("ParseAccessToken: got UserID %d, want %d", claims.UserID, result.User.ID)
	}
}

func TestLogin_WrongPassword(t *testing.T) {
	a, _, orgID := newTestAuthSetup(t)
	createTestUser(t, a, orgID, "admin@example.com", "hunter2", RoleOrgAdmin)

	_, err := a.Login(context.Background(), "admin@example.com", "wrong", "127.0.0.1", "test-agent")
	if !errors.Is(err, ErrInvalidCreds) {
		t.Fatalf("Login: got err %v, want ErrInvalidCreds", err)
	}
}

func TestLogin_NonexistentUser(t *testing.T) {
	a, _, _ := newTestAuthSetup(t)

	_, err := a.Login(context.Background(), "nobody@example.com", "anything", "127.0.0.1", "test-agent")
	if !errors.Is(err, ErrInvalidCreds) {
		t.Fatalf("Login: got err %v, want ErrInvalidCreds", err)
	}
}

func TestLogin_BlockedByIPAllowlist(t *testing.T) {
	a, db, orgID := newTestAuthSetup(t)
	createTestUser(t, a, orgID, "admin@example.com", "hunter2", RoleOrgAdmin)

	if _, err := db.ExecContext(context.Background(), `INSERT INTO ip_allowlist (org_id, cidr) VALUES (?, ?)`, orgID, "10.0.0.0/24"); err != nil {
		t.Fatalf("insert ip_allowlist row: %v", err)
	}

	_, err := a.Login(context.Background(), "admin@example.com", "hunter2", "192.168.1.1", "test-agent")
	if !errors.Is(err, ErrIPNotAllowed) {
		t.Fatalf("Login: got err %v, want ErrIPNotAllowed", err)
	}
}

func TestRefresh_IssuesNewPairAndRotates(t *testing.T) {
	a, _, orgID := newTestAuthSetup(t)
	createTestUser(t, a, orgID, "admin@example.com", "hunter2", RoleOrgAdmin)
	ctx := context.Background()

	login, err := a.Login(ctx, "admin@example.com", "hunter2", "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	refreshed, err := a.Refresh(ctx, login.RefreshToken, "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if refreshed.RefreshToken == login.RefreshToken {
		t.Fatal("Refresh: refresh token was not rotated")
	}
	if refreshed.User.Email != login.User.Email {
		t.Fatalf("Refresh: got user %+v", refreshed.User)
	}

	// The original refresh token must no longer work.
	if _, err := a.Refresh(ctx, login.RefreshToken, "127.0.0.1", "test-agent"); err == nil {
		t.Fatal("Refresh: want error reusing a rotated-out token, got nil")
	}
}

func TestLogin_IPAllowlistError(t *testing.T) {
	a, db, orgID := newTestAuthSetup(t)
	createTestUser(t, a, orgID, "admin@example.com", "hunter2", RoleOrgAdmin)
	ctx := context.Background()

	if _, err := db.ExecContext(ctx, `INSERT INTO ip_allowlist (org_id, cidr) VALUES (?, ?)`, orgID, "not-a-cidr"); err != nil {
		t.Fatalf("insert malformed ip_allowlist row: %v", err)
	}

	_, err := a.Login(ctx, "admin@example.com", "hunter2", "127.0.0.1", "test-agent")
	if err == nil {
		t.Fatal("Login: want error from malformed ip_allowlist entry, got nil")
	}
}

func TestRefresh_UserDeletedAfterSessionIssued(t *testing.T) {
	a, db, orgID := newTestAuthSetup(t)
	userID := createTestUser(t, a, orgID, "admin@example.com", "hunter2", RoleOrgAdmin)
	ctx := context.Background()

	login, err := a.Login(ctx, "admin@example.com", "hunter2", "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	// The test DB doesn't enable PRAGMA foreign_keys, so this deletes the
	// user row without cascading to its session — simulating a user
	// removed out-of-band while a still-valid refresh token exists.
	if _, err := db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, userID); err != nil {
		t.Fatalf("delete user: %v", err)
	}

	if _, err := a.Refresh(ctx, login.RefreshToken, "127.0.0.1", "test-agent"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Refresh: got err %v, want ErrNotFound", err)
	}
}

func TestRefresh_InvalidToken(t *testing.T) {
	a, _, _ := newTestAuthSetup(t)

	_, err := a.Refresh(context.Background(), "garbage", "127.0.0.1", "test-agent")
	if !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("Refresh: got err %v, want ErrSessionExpired", err)
	}
}

func TestLogout_ThenRefreshFails(t *testing.T) {
	a, _, orgID := newTestAuthSetup(t)
	createTestUser(t, a, orgID, "admin@example.com", "hunter2", RoleOrgAdmin)
	ctx := context.Background()

	login, err := a.Login(ctx, "admin@example.com", "hunter2", "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	if err := a.Logout(ctx, login.RefreshToken); err != nil {
		t.Fatalf("Logout: %v", err)
	}

	if _, err := a.Refresh(ctx, login.RefreshToken, "127.0.0.1", "test-agent"); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("Refresh after Logout: got err %v, want ErrSessionExpired", err)
	}
}

func TestMustHashPassword_PanicsOnError(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("mustHashPassword: want panic for a >72 byte password, got none")
		}
	}()
	long := make([]byte, 100)
	for i := range long {
		long[i] = 'a'
	}
	mustHashPassword(string(long))
}

func TestLogout_Idempotent(t *testing.T) {
	a, _, _ := newTestAuthSetup(t)
	if err := a.Logout(context.Background(), "never-existed"); err != nil {
		t.Fatalf("Logout: %v", err)
	}
}
