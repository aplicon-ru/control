package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// UserStore manages the users table.
type UserStore struct {
	db *sql.DB
}

// NewUserStore returns a UserStore backed by db.
func NewUserStore(db *sql.DB) *UserStore {
	return &UserStore{db: db}
}

// CreateLocal inserts a local (password-authenticated) user. It enforces
// the users table's own invariant — orgID is nil if and only if role is
// RoleSuperAdmin — in Go before the insert, the same way servers.Create
// validates its enums before hitting a DB CHECK constraint.
func (s *UserStore) CreateLocal(ctx context.Context, orgID *int64, email, passwordHash string, role Role) (int64, error) {
	if !validRole(role) {
		return 0, fmt.Errorf("%w: role %q", ErrInvalidField, role)
	}
	if (role == RoleSuperAdmin) != (orgID == nil) {
		return 0, fmt.Errorf("%w: org_id must be nil iff role is %q", ErrInvalidField, RoleSuperAdmin)
	}

	res, err := s.db.ExecContext(ctx, `
		INSERT INTO users (org_id, email, password_hash, role)
		VALUES (?, ?, ?, ?)
	`, orgID, email, passwordHash, string(role))
	if err != nil {
		if isUniqueConstraintErr(err) {
			return 0, ErrEmailTaken
		}
		return 0, fmt.Errorf("auth: create user: %w", err)
	}

	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("auth: create user: %w", err)
	}
	return id, nil
}

// GetByEmail returns the user with the given email, or ErrNotFound.
func (s *UserStore) GetByEmail(ctx context.Context, email string) (User, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, org_id, email, password_hash, role, totp_enabled, created_at
		FROM users WHERE email = ?
	`, email)
	return scanUser(row)
}

// GetByID returns the user with the given ID, or ErrNotFound.
func (s *UserStore) GetByID(ctx context.Context, id int64) (User, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, org_id, email, password_hash, role, totp_enabled, created_at
		FROM users WHERE id = ?
	`, id)
	return scanUser(row)
}

func scanUser(row *sql.Row) (User, error) {
	var u User
	var orgID sql.NullInt64
	var passwordHash sql.NullString
	var role string
	var totpEnabled int
	var createdAt string

	if err := row.Scan(&u.ID, &orgID, &u.Email, &passwordHash, &role, &totpEnabled, &createdAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, ErrNotFound
		}
		return User{}, fmt.Errorf("auth: get user: %w", err)
	}

	if orgID.Valid {
		u.OrgID = &orgID.Int64
	}
	u.PasswordHash = passwordHash.String
	u.Role = Role(role)
	u.TOTPEnabled = totpEnabled != 0

	created, err := parseSQLiteTime(createdAt)
	if err != nil {
		return User{}, fmt.Errorf("auth: get user: %w", err)
	}
	u.CreatedAt = created

	return u, nil
}
