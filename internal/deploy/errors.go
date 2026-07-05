package deploy

import "errors"

var (
	// ErrVersionNotFound is returned by CatalogReader.GetVersion when no
	// module_versions row matches the given ID.
	ErrVersionNotFound = errors.New("deploy: module version not found")
	// ErrInstallationNotFound is returned by Installations.Get and
	// GetByServerAndModule when no matching row exists.
	ErrInstallationNotFound = errors.New("deploy: installation not found")
	// ErrDeploymentNotFound is returned by Deployments.Get when no
	// matching row exists.
	ErrDeploymentNotFound = errors.New("deploy: deployment not found")
	// ErrNoRollbackTarget is returned by Deployer.Rollback when the
	// installation has no prior successful deployment to roll back to.
	ErrNoRollbackTarget = errors.New("deploy: no prior successful deployment to roll back to")
)
