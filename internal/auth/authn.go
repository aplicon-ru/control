package auth

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// dummyPasswordHash is compared against on a nonexistent-user login so
// that "no such user" and "wrong password" take comparable time — without
// it, the bcrypt compare would simply be skipped for a nonexistent email,
// giving an attacker a timing oracle to enumerate registered addresses.
var dummyPasswordHash = mustHashPassword("dummy-password-for-timing-safety")

func mustHashPassword(plaintext string) string {
	hash, err := HashPassword(plaintext)
	if err != nil {
		panic(fmt.Sprintf("auth: precompute dummy password hash: %v", err))
	}
	return hash
}

// Authenticator wires UserStore, SessionStore, and IPAllowlist together
// into the login/refresh/logout flows.
type Authenticator struct {
	users       *UserStore
	sessions    *SessionStore
	ipAllowlist *IPAllowlist
	signKey     []byte
	accessTTL   time.Duration
	refreshTTL  time.Duration
}

// NewAuthenticator returns an Authenticator. signKey signs access tokens;
// keep it separate from (and never derived from) any secrets.Store master
// key — a leaked signing key only forges sessions, not the whole secrets
// database.
func NewAuthenticator(users *UserStore, sessions *SessionStore, ipAllowlist *IPAllowlist, signKey []byte, accessTTL, refreshTTL time.Duration) *Authenticator {
	return &Authenticator{
		users:       users,
		sessions:    sessions,
		ipAllowlist: ipAllowlist,
		signKey:     signKey,
		accessTTL:   accessTTL,
		refreshTTL:  refreshTTL,
	}
}

// LoginResult is returned by Login and Refresh.
type LoginResult struct {
	AccessToken  string
	RefreshToken string
	User         User
}

// Login authenticates email/password, checking the IP allowlist for the
// user's org before comparing the password so a blocked IP fails fast.
// A nonexistent email and a correct-email-wrong-password both return
// ErrInvalidCreds, indistinguishable by error value or timing.
func (a *Authenticator) Login(ctx context.Context, email, password, ip, userAgent string) (LoginResult, error) {
	user, err := a.users.GetByEmail(ctx, email)
	if errors.Is(err, ErrNotFound) {
		_ = VerifyPassword(dummyPasswordHash, password)
		return LoginResult{}, ErrInvalidCreds
	}
	if err != nil {
		return LoginResult{}, fmt.Errorf("auth: login: %w", err)
	}

	allowed, err := a.ipAllowlist.Check(ctx, ip, user.OrgID)
	if err != nil {
		return LoginResult{}, fmt.Errorf("auth: login: %w", err)
	}
	if !allowed {
		return LoginResult{}, ErrIPNotAllowed
	}

	if err := VerifyPassword(user.PasswordHash, password); err != nil {
		return LoginResult{}, ErrInvalidCreds
	}

	return a.issueSession(ctx, user, ip, userAgent)
}

// Refresh rotates refreshToken for a new access/refresh pair. See
// SessionStore.Rotate for the single-use guarantee.
func (a *Authenticator) Refresh(ctx context.Context, refreshToken, ip, userAgent string) (LoginResult, error) {
	newRaw, userID, err := a.sessions.Rotate(ctx, refreshToken, ip, userAgent, a.refreshTTL)
	if err != nil {
		return LoginResult{}, err
	}

	user, err := a.users.GetByID(ctx, userID)
	if err != nil {
		return LoginResult{}, fmt.Errorf("auth: refresh: %w", err)
	}

	access, err := IssueAccessToken(a.signKey, user, a.accessTTL)
	if err != nil {
		return LoginResult{}, fmt.Errorf("auth: refresh: %w", err)
	}

	return LoginResult{AccessToken: access, RefreshToken: newRaw, User: user}, nil
}

// Logout revokes refreshToken. It is idempotent (see SessionStore.Revoke).
func (a *Authenticator) Logout(ctx context.Context, refreshToken string) error {
	return a.sessions.Revoke(ctx, refreshToken)
}

func (a *Authenticator) issueSession(ctx context.Context, user User, ip, userAgent string) (LoginResult, error) {
	access, err := IssueAccessToken(a.signKey, user, a.accessTTL)
	if err != nil {
		return LoginResult{}, fmt.Errorf("auth: login: %w", err)
	}

	refresh, err := a.sessions.Create(ctx, user.ID, ip, userAgent, a.refreshTTL)
	if err != nil {
		return LoginResult{}, fmt.Errorf("auth: login: %w", err)
	}

	return LoginResult{AccessToken: access, RefreshToken: refresh, User: user}, nil
}
