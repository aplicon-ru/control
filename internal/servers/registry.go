package servers

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/aplicon-ru/control/internal/secrets"
)

// sqliteTimeLayout matches SQLite's CURRENT_TIMESTAMP default format. Times
// are formatted/parsed explicitly rather than relying on driver-specific
// time.Time marshaling, so the on-disk representation stays predictable
// regardless of whether a row's timestamp came from CURRENT_TIMESTAMP or
// from Go.
const sqliteTimeLayout = "2006-01-02 15:04:05"

func formatSQLiteTime(t time.Time) string {
	return t.UTC().Format(sqliteTimeLayout)
}

func parseSQLiteTime(s string) (time.Time, error) {
	if t, err := time.Parse(sqliteTimeLayout, s); err == nil {
		return t.UTC(), nil
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t.UTC(), nil
	}
	return time.Time{}, fmt.Errorf("servers: parse timestamp %q", s)
}

// Registry manages the servers table and the SSH credentials attached to
// each row via secretsStore.
type Registry struct {
	db      *sql.DB
	secrets *secrets.Store
}

// NewRegistry returns a Registry backed by db and secretsStore.
func NewRegistry(db *sql.DB, secretsStore *secrets.Store) *Registry {
	return &Registry{db: db, secrets: secretsStore}
}

func validateServer(s Server) error {
	if !validAuthType(s.AuthType) {
		return fmt.Errorf("%w: auth_type %q", ErrInvalidField, s.AuthType)
	}
	if !validServerType(s.Type) {
		return fmt.Errorf("%w: type %q", ErrInvalidField, s.Type)
	}
	if !validEnvironment(s.Environment) {
		return fmt.Errorf("%w: environment %q", ErrInvalidField, s.Environment)
	}
	return nil
}

// Create inserts s and stores cred under its new ID. If storing the
// credential fails, the just-inserted server row is deleted — a crash
// between the two steps leaves at worst an orphaned credential-less
// server row, never a secret pointing at a nonexistent server.
func (r *Registry) Create(ctx context.Context, s Server, cred Credential) (int64, error) {
	if err := validateServer(s); err != nil {
		return 0, err
	}
	if cred.Type != s.AuthType {
		return 0, fmt.Errorf("%w: credential type %q does not match server auth_type %q", ErrInvalidField, cred.Type, s.AuthType)
	}

	isSelf := 0
	if s.IsSelf {
		isSelf = 1
	}

	res, err := r.db.ExecContext(ctx, `
		INSERT INTO servers (org_id, name, host, port, ssh_user, auth_type, type, environment, is_self)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, s.OrgID, s.Name, s.Host, s.Port, s.SSHUser, string(s.AuthType), string(s.Type), string(s.Environment), isSelf)
	if err != nil {
		return 0, fmt.Errorf("servers: create: %w", err)
	}

	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("servers: create: %w", err)
	}

	if err := r.putCredential(ctx, id, cred); err != nil {
		_, _ = r.db.ExecContext(ctx, `DELETE FROM servers WHERE id = ?`, id)
		return 0, err
	}

	return id, nil
}

func (r *Registry) putCredential(ctx context.Context, serverID int64, cred Credential) error {
	switch cred.Type {
	case AuthKey:
		if err := r.secrets.Put(ctx, secrets.ClassServer, "server", serverID, "ssh_private_key", cred.PrivateKey); err != nil {
			return fmt.Errorf("servers: store credential: %w", err)
		}
	case AuthPassword:
		if err := r.secrets.Put(ctx, secrets.ClassServer, "server", serverID, "ssh_password", []byte(cred.Password)); err != nil {
			return fmt.Errorf("servers: store credential: %w", err)
		}
	default:
		return fmt.Errorf("%w: credential type %q", ErrInvalidField, cred.Type)
	}
	return nil
}

// Get returns the server identified by (orgID, id). It returns ErrNotFound
// if no such server exists in that org — a caller cannot fetch another
// org's server by guessing an ID.
func (r *Registry) Get(ctx context.Context, orgID, id int64) (Server, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT id, org_id, name, host, port, ssh_user, auth_type, type, environment, is_self, status, last_checked_at, created_at
		FROM servers WHERE org_id = ? AND id = ?
	`, orgID, id)

	s, err := scanServer(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Server{}, ErrNotFound
	}
	if err != nil {
		return Server{}, fmt.Errorf("servers: get: %w", err)
	}
	return s, nil
}

// List returns every server belonging to orgID, ordered by name.
func (r *Registry) List(ctx context.Context, orgID int64) ([]Server, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, org_id, name, host, port, ssh_user, auth_type, type, environment, is_self, status, last_checked_at, created_at
		FROM servers WHERE org_id = ? ORDER BY name
	`, orgID)
	if err != nil {
		return nil, fmt.Errorf("servers: list: %w", err)
	}
	defer rows.Close()

	var out []Server
	for rows.Next() {
		s, err := scanServer(rows)
		if err != nil {
			return nil, fmt.Errorf("servers: list: %w", err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("servers: list: %w", err)
	}
	return out, nil
}

// Update overwrites the mutable fields of the server identified by
// (s.OrgID, s.ID). It does not touch Status or credentials — see
// UpdateStatus and Create.
func (r *Registry) Update(ctx context.Context, s Server) error {
	if err := validateServer(s); err != nil {
		return err
	}

	res, err := r.db.ExecContext(ctx, `
		UPDATE servers SET name = ?, host = ?, port = ?, ssh_user = ?, auth_type = ?, type = ?, environment = ?
		WHERE org_id = ? AND id = ?
	`, s.Name, s.Host, s.Port, s.SSHUser, string(s.AuthType), string(s.Type), string(s.Environment), s.OrgID, s.ID)
	if err != nil {
		return fmt.Errorf("servers: update: %w", err)
	}
	return checkRowsAffected(res, "update")
}

// UpdateStatus records the outcome of a connectivity check.
func (r *Registry) UpdateStatus(ctx context.Context, id int64, status Status, checkedAt time.Time) error {
	if !validStatus(status) {
		return fmt.Errorf("%w: status %q", ErrInvalidField, status)
	}

	res, err := r.db.ExecContext(ctx, `
		UPDATE servers SET status = ?, last_checked_at = ? WHERE id = ?
	`, string(status), formatSQLiteTime(checkedAt), id)
	if err != nil {
		return fmt.Errorf("servers: update status: %w", err)
	}
	return checkRowsAffected(res, "update status")
}

// Delete removes the server identified by (orgID, id) and its stored
// credentials. It refuses to delete the server hosting CP itself (spec §2
// [THIS] marker).
func (r *Registry) Delete(ctx context.Context, orgID, id int64) error {
	s, err := r.Get(ctx, orgID, id)
	if err != nil {
		return err
	}
	if s.IsSelf {
		return ErrIsSelfProtected
	}

	for _, keyName := range []string{"ssh_private_key", "ssh_password", "ssh_host_key"} {
		if err := r.secrets.Delete(ctx, "server", id, keyName); err != nil {
			return fmt.Errorf("servers: delete: %w", err)
		}
	}

	res, err := r.db.ExecContext(ctx, `DELETE FROM servers WHERE org_id = ? AND id = ?`, orgID, id)
	if err != nil {
		return fmt.Errorf("servers: delete: %w", err)
	}
	return checkRowsAffected(res, "delete")
}

// Connect loads the server identified by (orgID, id) and returns an
// Executor for it — a mock for type=mock, otherwise a real SSH connection
// authenticated with its stored credential.
func (r *Registry) Connect(ctx context.Context, orgID, id int64) (Executor, error) {
	s, err := r.Get(ctx, orgID, id)
	if err != nil {
		return nil, err
	}

	if s.Type == TypeMock {
		return newMockExecutor(s), nil
	}

	cred, err := r.loadCredential(ctx, s)
	if err != nil {
		return nil, err
	}
	return newSSHExecutor(ctx, s, cred, r.secrets)
}

func (r *Registry) loadCredential(ctx context.Context, s Server) (Credential, error) {
	switch s.AuthType {
	case AuthKey:
		key, _, err := r.secrets.Get(ctx, "server", s.ID, "ssh_private_key")
		if err != nil {
			return Credential{}, fmt.Errorf("servers: load credential: %w", err)
		}
		return Credential{Type: AuthKey, PrivateKey: key}, nil
	case AuthPassword:
		pw, _, err := r.secrets.Get(ctx, "server", s.ID, "ssh_password")
		if err != nil {
			return Credential{}, fmt.Errorf("servers: load credential: %w", err)
		}
		return Credential{Type: AuthPassword, Password: string(pw)}, nil
	default:
		return Credential{}, fmt.Errorf("%w: auth_type %q", ErrInvalidField, s.AuthType)
	}
}

func checkRowsAffected(res sql.Result, op string) error {
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("servers: %s: %w", op, err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanServer(row rowScanner) (Server, error) {
	var s Server
	var authType, serverType, environment, status, createdAt string
	var lastCheckedAt sql.NullString
	var isSelf int

	if err := row.Scan(&s.ID, &s.OrgID, &s.Name, &s.Host, &s.Port, &s.SSHUser,
		&authType, &serverType, &environment, &isSelf, &status, &lastCheckedAt, &createdAt); err != nil {
		return Server{}, err
	}

	s.AuthType = AuthType(authType)
	s.Type = ServerType(serverType)
	s.Environment = Environment(environment)
	s.Status = Status(status)
	s.IsSelf = isSelf != 0

	created, err := parseSQLiteTime(createdAt)
	if err != nil {
		return Server{}, err
	}
	s.CreatedAt = created

	if lastCheckedAt.Valid {
		t, err := parseSQLiteTime(lastCheckedAt.String)
		if err != nil {
			return Server{}, err
		}
		s.LastCheckedAt = &t
	}

	return s, nil
}
