package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// rawTokenSize is the byte length of a refresh token before hex encoding
// — high enough entropy that the stored hash needs no slow-hash defense
// (see hashToken).
const rawTokenSize = 32

// SessionStore manages opaque refresh-token sessions in the sessions
// table. The raw token is returned to the caller once and never stored;
// only its SHA-256 hash lives in token_hash (matches the column's own
// comment: "hashed — never store raw").
type SessionStore struct {
	db *sql.DB
}

// NewSessionStore returns a SessionStore backed by db.
func NewSessionStore(db *sql.DB) *SessionStore {
	return &SessionStore{db: db}
}

// Create issues a new refresh token for userID, valid for ttl.
func (s *SessionStore) Create(ctx context.Context, userID int64, ip, userAgent string, ttl time.Duration) (string, error) {
	raw, err := generateRawToken()
	if err != nil {
		return "", err
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO sessions (user_id, token_hash, ip, user_agent, expires_at)
		VALUES (?, ?, ?, ?, ?)
	`, userID, hashToken(raw), ip, userAgent, formatSQLiteTime(time.Now().Add(ttl)))
	if err != nil {
		return "", fmt.Errorf("auth: create session: %w", err)
	}
	return raw, nil
}

// Verify checks rawToken against the stored hash and expiry, returning
// the owning userID and the session's row ID. A token that never existed
// and one that existed but expired are both reported as ErrSessionExpired
// — the caller's remedy is the same either way (log in again), and
// distinguishing them would leak whether a given token was ever valid.
func (s *SessionStore) Verify(ctx context.Context, rawToken string) (userID int64, sessionID int64, err error) {
	var expiresAt string
	err = s.db.QueryRowContext(ctx, `
		SELECT id, user_id, expires_at FROM sessions WHERE token_hash = ?
	`, hashToken(rawToken)).Scan(&sessionID, &userID, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, 0, ErrSessionExpired
	}
	if err != nil {
		return 0, 0, fmt.Errorf("auth: verify session: %w", err)
	}

	expiry, err := parseSQLiteTime(expiresAt)
	if err != nil {
		return 0, 0, fmt.Errorf("auth: verify session: %w", err)
	}
	if time.Now().After(expiry) {
		_, _ = s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id = ?`, sessionID)
		return 0, 0, ErrSessionExpired
	}

	return userID, sessionID, nil
}

// Rotate verifies oldRawToken, deletes it, and issues a fresh one — this
// bounds the replay window of any given refresh token to a single use.
func (s *SessionStore) Rotate(ctx context.Context, oldRawToken, ip, userAgent string, ttl time.Duration) (newRawToken string, userID int64, err error) {
	userID, _, err = s.Verify(ctx, oldRawToken)
	if err != nil {
		return "", 0, err
	}
	if err := s.Revoke(ctx, oldRawToken); err != nil {
		return "", 0, err
	}

	newRawToken, err = s.Create(ctx, userID, ip, userAgent, ttl)
	if err != nil {
		return "", 0, err
	}
	return newRawToken, userID, nil
}

// Revoke deletes the session identified by rawToken. It is idempotent:
// revoking an already-absent session is a no-op success.
func (s *SessionStore) Revoke(ctx context.Context, rawToken string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ?`, hashToken(rawToken)); err != nil {
		return fmt.Errorf("auth: revoke session: %w", err)
	}
	return nil
}

// RevokeAllForUser deletes every session belonging to userID.
func (s *SessionStore) RevokeAllForUser(ctx context.Context, userID int64) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, userID); err != nil {
		return fmt.Errorf("auth: revoke all sessions: %w", err)
	}
	return nil
}

func generateRawToken() (string, error) {
	buf := make([]byte, rawTokenSize)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("auth: generate session token: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// hashToken is a plain SHA-256, not a slow hash like bcrypt: rawToken
// already has rawTokenSize*8 bits of min-entropy from crypto/rand, so
// there's no low-entropy secret for a slow hash to protect against
// offline brute force — unlike a human password (see password.go).
func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
