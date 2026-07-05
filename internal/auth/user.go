package auth

import (
	"errors"
	"time"
)

type Role string

const (
	RoleSuperAdmin Role = "super_admin"
	RoleOrgAdmin   Role = "org_admin"
	RoleOperator   Role = "operator"
	RoleViewer     Role = "viewer"
)

func validRole(r Role) bool {
	switch r {
	case RoleSuperAdmin, RoleOrgAdmin, RoleOperator, RoleViewer:
		return true
	default:
		return false
	}
}

// User mirrors a row in the users table (migrations/0001_init.sql).
// OrgID is nil if and only if Role is RoleSuperAdmin — enforced by the
// table's own CHECK constraint, validated in Go before insert too (see
// UserStore.CreateLocal).
type User struct {
	ID           int64
	OrgID        *int64
	Email        string
	PasswordHash string
	Role         Role
	TOTPEnabled  bool
	CreatedAt    time.Time
}

var (
	// ErrNotFound is returned when no user matches the given lookup.
	ErrNotFound = errors.New("auth: not found")
	// ErrInvalidField is returned when a field holds a value outside its
	// allowed set, checked in Go before it reaches a DB CHECK constraint.
	ErrInvalidField = errors.New("auth: invalid field value")
	// ErrEmailTaken is returned by CreateLocal when the email is already
	// registered.
	ErrEmailTaken = errors.New("auth: email already registered")
	// ErrInvalidCreds is returned by Login for both a nonexistent email
	// and a wrong password — the two are indistinguishable by design.
	ErrInvalidCreds = errors.New("auth: invalid email or password")
	// ErrSessionExpired is returned by SessionStore.Verify for an expired
	// or otherwise invalid session.
	ErrSessionExpired = errors.New("auth: session expired")
	// ErrIPNotAllowed is returned by Login when the caller's IP is
	// rejected by the IP allowlist.
	ErrIPNotAllowed = errors.New("auth: ip not allowed")
)
