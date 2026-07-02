package secrets

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// Class is one of the three secret classes from spec §6.
type Class string

const (
	ClassCP     Class = "A" // CP-level credentials (bot tokens, SMTP, OIDC client secret, Лицензикон API key)
	ClassServer Class = "B" // server credentials (SSH private keys, sudo passwords)
	ClassModule Class = "C" // module secrets pushed to target servers (DB passwords, S3 creds, JWS tokens)
)

var (
	// ErrNotFound is returned by Get when no row matches the given owner/key.
	ErrNotFound = errors.New("secrets: not found")
	// ErrInvalidClass is returned by Put when class is not one of ClassCP, ClassServer, ClassModule.
	ErrInvalidClass = errors.New("secrets: invalid class")
)

// Store reads and writes envelope-encrypted secrets in the `secrets`
// table. It never opens its own database connection — callers hand it an
// already-open *sql.DB.
type Store struct {
	db  *sql.DB
	key []byte
}

// NewStore returns a Store that encrypts/decrypts with masterKey.
func NewStore(db *sql.DB, masterKey []byte) *Store {
	return &Store{db: db, key: masterKey}
}

func validClass(c Class) bool {
	switch c {
	case ClassCP, ClassServer, ClassModule:
		return true
	default:
		return false
	}
}

// Put encrypts plaintext and upserts it under (ownerType, ownerID, keyName).
// A second Put for the same owner/key overwrites the previous class,
// ciphertext, and nonce.
func (s *Store) Put(ctx context.Context, class Class, ownerType string, ownerID int64, keyName string, plaintext []byte) error {
	if !validClass(class) {
		return ErrInvalidClass
	}

	ciphertext, nonce, err := Seal(s.key, plaintext)
	if err != nil {
		return fmt.Errorf("secrets: put: %w", err)
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO secrets (class, owner_type, owner_id, key_name, ciphertext, nonce, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT (owner_type, owner_id, key_name)
		DO UPDATE SET class = excluded.class, ciphertext = excluded.ciphertext,
			nonce = excluded.nonce, updated_at = CURRENT_TIMESTAMP
	`, string(class), ownerType, ownerID, keyName, ciphertext, nonce)
	if err != nil {
		return fmt.Errorf("secrets: put: %w", err)
	}
	return nil
}

// Get decrypts and returns the secret stored under (ownerType, ownerID,
// keyName), along with its class. It returns ErrNotFound if no such row
// exists.
func (s *Store) Get(ctx context.Context, ownerType string, ownerID int64, keyName string) ([]byte, Class, error) {
	var class string
	var ciphertext, nonce []byte

	row := s.db.QueryRowContext(ctx, `
		SELECT class, ciphertext, nonce FROM secrets
		WHERE owner_type = ? AND owner_id = ? AND key_name = ?
	`, ownerType, ownerID, keyName)

	if err := row.Scan(&class, &ciphertext, &nonce); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, "", ErrNotFound
		}
		return nil, "", fmt.Errorf("secrets: get: %w", err)
	}

	plaintext, err := Open(s.key, ciphertext, nonce)
	if err != nil {
		return nil, "", fmt.Errorf("secrets: get: %w", err)
	}
	return plaintext, Class(class), nil
}

// Delete removes the secret stored under (ownerType, ownerID, keyName). It
// is idempotent: deleting an already-absent secret is a no-op success,
// matching the more common caller intent ("ensure this doesn't exist").
func (s *Store) Delete(ctx context.Context, ownerType string, ownerID int64, keyName string) error {
	_, err := s.db.ExecContext(ctx, `
		DELETE FROM secrets WHERE owner_type = ? AND owner_id = ? AND key_name = ?
	`, ownerType, ownerID, keyName)
	if err != nil {
		return fmt.Errorf("secrets: delete: %w", err)
	}
	return nil
}
