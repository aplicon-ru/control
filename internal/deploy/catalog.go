package deploy

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// ModuleVersion is the subset of module_versions a deploy needs to act on.
type ModuleVersion struct {
	ID              int64
	ModuleCatalogID int64
	ModuleKey       string // joined from module_catalog.key, for log/display use
	Version         string
	Image           string
	ComposeRef      string
	VarsSchema      string
	HealthcheckURL  string // "" if NULL
	DemoMode        string // "" if NULL — raw JSON, not parsed here (internal/license's job)
	ReleasedAt      time.Time
}

// CatalogReader is a read-only view onto module_catalog/module_versions.
// Creating or editing modules and versions belongs to internal/modules
// (spec §5.2, §12) — this type exists only so a deploy can resolve "what
// is version N" for the version it's about to act on.
type CatalogReader struct {
	db *sql.DB
}

// NewCatalogReader returns a CatalogReader backed by db.
func NewCatalogReader(db *sql.DB) *CatalogReader {
	return &CatalogReader{db: db}
}

// GetVersion returns the module_versions row identified by id, joined
// with its module_catalog.key. Returns ErrVersionNotFound if absent.
func (c *CatalogReader) GetVersion(ctx context.Context, id int64) (ModuleVersion, error) {
	row := c.db.QueryRowContext(ctx, `
		SELECT mv.id, mv.module_catalog_id, mc.key, mv.version, mv.image,
		       mv.compose_ref, mv.vars_schema, mv.healthcheck_url, mv.demo_mode, mv.released_at
		FROM module_versions mv
		JOIN module_catalog mc ON mc.id = mv.module_catalog_id
		WHERE mv.id = ?
	`, id)

	var v ModuleVersion
	var healthcheckURL, demoMode sql.NullString
	var releasedAt string

	err := row.Scan(&v.ID, &v.ModuleCatalogID, &v.ModuleKey, &v.Version, &v.Image,
		&v.ComposeRef, &v.VarsSchema, &healthcheckURL, &demoMode, &releasedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return ModuleVersion{}, ErrVersionNotFound
	}
	if err != nil {
		return ModuleVersion{}, fmt.Errorf("deploy: get module version: %w", err)
	}

	v.HealthcheckURL = healthcheckURL.String
	v.DemoMode = demoMode.String

	released, err := parseSQLiteTime(releasedAt)
	if err != nil {
		return ModuleVersion{}, fmt.Errorf("deploy: get module version: %w", err)
	}
	v.ReleasedAt = released

	return v, nil
}
