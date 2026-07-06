package deploy

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

type InstallationStatus string

const (
	InstallationDeploying InstallationStatus = "deploying"
	InstallationRunning   InstallationStatus = "running"
	InstallationStopped   InstallationStatus = "stopped"
	InstallationError     InstallationStatus = "error"
)

// Installation mirrors a row in module_installations.
type Installation struct {
	ID                 int64
	ServerID           int64
	ModuleCatalogID    int64
	InstalledVersionID int64
	Status             InstallationStatus
	DemoMode           bool
	Config             string // JSON, currently-applied config — opaque here
	ConfigPending      *string
	S3PoolID           *int64
	DeployedAt         time.Time
	DeployedByUserID   *int64
}

// Installations manages the module_installations table.
type Installations struct {
	db *sql.DB
}

// NewInstallations returns an Installations store backed by db.
func NewInstallations(db *sql.DB) *Installations {
	return &Installations{db: db}
}

// Upsert creates or updates the (ServerID, ModuleCatalogID) installation
// row, matching the table's own UNIQUE constraint — this is how a second
// deploy to the same server+module becomes an update rather than a
// constraint error.
func (s *Installations) Upsert(ctx context.Context, in Installation) (int64, error) {
	demoMode := 0
	if in.DemoMode {
		demoMode = 1
	}
	config := in.Config
	if config == "" {
		config = "{}"
	}

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO module_installations
			(server_id, module_catalog_id, installed_version_id, status, demo_mode, config, config_pending, s3_pool_id, deployed_at, deployed_by_user_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (server_id, module_catalog_id) DO UPDATE SET
			installed_version_id = excluded.installed_version_id,
			status = excluded.status,
			demo_mode = excluded.demo_mode,
			config = excluded.config,
			config_pending = excluded.config_pending,
			s3_pool_id = excluded.s3_pool_id,
			deployed_at = excluded.deployed_at,
			deployed_by_user_id = excluded.deployed_by_user_id
	`, in.ServerID, in.ModuleCatalogID, in.InstalledVersionID, string(in.Status), demoMode,
		config, in.ConfigPending, in.S3PoolID, formatSQLiteTime(in.DeployedAt), in.DeployedByUserID)
	if err != nil {
		return 0, fmt.Errorf("deploy: upsert installation: %w", err)
	}

	var id int64
	err = s.db.QueryRowContext(ctx, `
		SELECT id FROM module_installations WHERE server_id = ? AND module_catalog_id = ?
	`, in.ServerID, in.ModuleCatalogID).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("deploy: upsert installation: %w", err)
	}
	return id, nil
}

// Get returns the installation identified by id, or ErrInstallationNotFound.
func (s *Installations) Get(ctx context.Context, id int64) (Installation, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, server_id, module_catalog_id, installed_version_id, status, demo_mode, config, config_pending, s3_pool_id, deployed_at, deployed_by_user_id
		FROM module_installations WHERE id = ?
	`, id)
	return scanInstallation(row)
}

// GetByServerAndModule returns the installation for (serverID,
// moduleCatalogID), or ErrInstallationNotFound if none exists.
func (s *Installations) GetByServerAndModule(ctx context.Context, serverID, moduleCatalogID int64) (Installation, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, server_id, module_catalog_id, installed_version_id, status, demo_mode, config, config_pending, s3_pool_id, deployed_at, deployed_by_user_id
		FROM module_installations WHERE server_id = ? AND module_catalog_id = ?
	`, serverID, moduleCatalogID)
	return scanInstallation(row)
}

// UpdateStatus sets the status of the installation identified by id.
func (s *Installations) UpdateStatus(ctx context.Context, id int64, status InstallationStatus) error {
	res, err := s.db.ExecContext(ctx, `UPDATE module_installations SET status = ? WHERE id = ?`, string(status), id)
	if err != nil {
		return fmt.Errorf("deploy: update installation status: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("deploy: update installation status: %w", err)
	}
	if n == 0 {
		return ErrInstallationNotFound
	}
	return nil
}

func scanInstallation(row *sql.Row) (Installation, error) {
	var in Installation
	var status string
	var demoMode int
	var configPending sql.NullString
	var s3PoolID sql.NullInt64
	var deployedAt string
	var deployedByUserID sql.NullInt64

	err := row.Scan(&in.ID, &in.ServerID, &in.ModuleCatalogID, &in.InstalledVersionID, &status, &demoMode,
		&in.Config, &configPending, &s3PoolID, &deployedAt, &deployedByUserID)
	if errors.Is(err, sql.ErrNoRows) {
		return Installation{}, ErrInstallationNotFound
	}
	if err != nil {
		return Installation{}, fmt.Errorf("deploy: get installation: %w", err)
	}

	in.Status = InstallationStatus(status)
	in.DemoMode = demoMode != 0
	if configPending.Valid {
		in.ConfigPending = &configPending.String
	}
	if s3PoolID.Valid {
		in.S3PoolID = &s3PoolID.Int64
	}
	if deployedByUserID.Valid {
		in.DeployedByUserID = &deployedByUserID.Int64
	}

	deployed, err := parseSQLiteTime(deployedAt)
	if err != nil {
		return Installation{}, fmt.Errorf("deploy: get installation: %w", err)
	}
	in.DeployedAt = deployed

	return in, nil
}
