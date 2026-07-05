package deploy

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

type Kind string

const (
	KindInstall     Kind = "install"
	KindUpdate      Kind = "update"
	KindRollback    Kind = "rollback"
	KindConfigApply Kind = "config_apply"
)

type Status string

const (
	StatusPending Status = "pending"
	StatusRunning Status = "running"
	StatusSuccess Status = "success"
	StatusFailed  Status = "failed"
)

// Deployment mirrors a row in the deployments table.
type Deployment struct {
	ID                   int64
	ServerID             int64
	ModuleInstallationID *int64
	Kind                 Kind
	FromVersionID        *int64
	ToVersionID          *int64
	Status               Status
	ScheduledAt          *time.Time // always nil in this slice — scheduling is deferred
	StartedAt            *time.Time
	FinishedAt           *time.Time
	Log                  string
	InitiatedByUserID    *int64
	CreatedAt            time.Time
}

// Deployments manages the deployments table.
type Deployments struct {
	db *sql.DB
}

// NewDeployments returns a Deployments store backed by db.
func NewDeployments(db *sql.DB) *Deployments {
	return &Deployments{db: db}
}

// Create inserts a deployment row (typically with Status: StatusPending)
// and returns its ID. Deployer calls this before doing any work, so a
// crash mid-deploy still leaves a pending/running row in history rather
// than no record at all.
func (d *Deployments) Create(ctx context.Context, dep Deployment) (int64, error) {
	res, err := d.db.ExecContext(ctx, `
		INSERT INTO deployments (server_id, module_installation_id, kind, from_version_id, to_version_id, status, initiated_by_user_id)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, dep.ServerID, dep.ModuleInstallationID, string(dep.Kind), dep.FromVersionID, dep.ToVersionID, string(dep.Status), dep.InitiatedByUserID)
	if err != nil {
		return 0, fmt.Errorf("deploy: create deployment: %w", err)
	}

	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("deploy: create deployment: %w", err)
	}
	return id, nil
}

// Get returns the deployment identified by id, or ErrDeploymentNotFound.
func (d *Deployments) Get(ctx context.Context, id int64) (Deployment, error) {
	row := d.db.QueryRowContext(ctx, `
		SELECT id, server_id, module_installation_id, kind, from_version_id, to_version_id, status, started_at, finished_at, log, initiated_by_user_id, created_at
		FROM deployments WHERE id = ?
	`, id)
	return scanDeployment(row)
}

// ListByServer returns deployments for serverID, newest first — the
// minimum needed for Rollback to find the most recent successful
// deployment, and for a future history view.
func (d *Deployments) ListByServer(ctx context.Context, serverID int64) ([]Deployment, error) {
	rows, err := d.db.QueryContext(ctx, `
		SELECT id, server_id, module_installation_id, kind, from_version_id, to_version_id, status, started_at, finished_at, log, initiated_by_user_id, created_at
		FROM deployments WHERE server_id = ? ORDER BY created_at DESC, id DESC
	`, serverID)
	if err != nil {
		return nil, fmt.Errorf("deploy: list deployments: %w", err)
	}
	defer rows.Close()

	var out []Deployment
	for rows.Next() {
		dep, err := scanDeployment(rows)
		if err != nil {
			return nil, fmt.Errorf("deploy: list deployments: %w", err)
		}
		out = append(out, dep)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("deploy: list deployments: %w", err)
	}
	return out, nil
}

// MarkRunning transitions the deployment to StatusRunning and stamps
// started_at.
func (d *Deployments) MarkRunning(ctx context.Context, id int64, startedAt time.Time) error {
	res, err := d.db.ExecContext(ctx, `
		UPDATE deployments SET status = ?, started_at = ? WHERE id = ?
	`, string(StatusRunning), formatSQLiteTime(startedAt), id)
	if err != nil {
		return fmt.Errorf("deploy: mark deployment running: %w", err)
	}
	return checkRowsAffected(res, "mark deployment running")
}

// SetModuleInstallationID links deployment id to installationID. Used by
// Deployer to backfill the very first install's deployment row once its
// module_installations row exists — it doesn't exist yet at the moment
// the deployment row is first created, since Upsert only succeeds after
// the deploy itself does.
func (d *Deployments) SetModuleInstallationID(ctx context.Context, id, installationID int64) error {
	res, err := d.db.ExecContext(ctx, `UPDATE deployments SET module_installation_id = ? WHERE id = ?`, installationID, id)
	if err != nil {
		return fmt.Errorf("deploy: set module installation id: %w", err)
	}
	return checkRowsAffected(res, "set module installation id")
}

// MarkFinished transitions the deployment to status (StatusSuccess or
// StatusFailed), stamps finished_at, and records log — a single plain-text
// blob written once at the end of the attempt (not streamed; see doc.go).
func (d *Deployments) MarkFinished(ctx context.Context, id int64, status Status, finishedAt time.Time, log string) error {
	res, err := d.db.ExecContext(ctx, `
		UPDATE deployments SET status = ?, finished_at = ?, log = ? WHERE id = ?
	`, string(status), formatSQLiteTime(finishedAt), log, id)
	if err != nil {
		return fmt.Errorf("deploy: mark deployment finished: %w", err)
	}
	return checkRowsAffected(res, "mark deployment finished")
}

func checkRowsAffected(res sql.Result, op string) error {
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("deploy: %s: %w", op, err)
	}
	if n == 0 {
		return ErrDeploymentNotFound
	}
	return nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanDeployment(row rowScanner) (Deployment, error) {
	var dep Deployment
	var moduleInstallationID, fromVersionID, toVersionID, initiatedByUserID sql.NullInt64
	var kind, status string
	var startedAt, finishedAt sql.NullString
	var log sql.NullString
	var createdAt string

	err := row.Scan(&dep.ID, &dep.ServerID, &moduleInstallationID, &kind, &fromVersionID, &toVersionID,
		&status, &startedAt, &finishedAt, &log, &initiatedByUserID, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Deployment{}, ErrDeploymentNotFound
	}
	if err != nil {
		return Deployment{}, fmt.Errorf("deploy: get deployment: %w", err)
	}

	dep.Kind = Kind(kind)
	dep.Status = Status(status)
	dep.Log = log.String

	if moduleInstallationID.Valid {
		dep.ModuleInstallationID = &moduleInstallationID.Int64
	}
	if fromVersionID.Valid {
		dep.FromVersionID = &fromVersionID.Int64
	}
	if toVersionID.Valid {
		dep.ToVersionID = &toVersionID.Int64
	}
	if initiatedByUserID.Valid {
		dep.InitiatedByUserID = &initiatedByUserID.Int64
	}

	if startedAt.Valid {
		t, err := parseSQLiteTime(startedAt.String)
		if err != nil {
			return Deployment{}, fmt.Errorf("deploy: get deployment: %w", err)
		}
		dep.StartedAt = &t
	}
	if finishedAt.Valid {
		t, err := parseSQLiteTime(finishedAt.String)
		if err != nil {
			return Deployment{}, fmt.Errorf("deploy: get deployment: %w", err)
		}
		dep.FinishedAt = &t
	}

	created, err := parseSQLiteTime(createdAt)
	if err != nil {
		return Deployment{}, fmt.Errorf("deploy: get deployment: %w", err)
	}
	dep.CreatedAt = created

	return dep, nil
}
