package auth

// CanAccessOrg reports whether a user with the given role and userOrgID
// may access resources scoped to targetOrgID. RoleSuperAdmin always can
// (global scope, userOrgID is nil for that role by the schema's own
// invariant); every other role may only access its own org. This is the
// one scoping primitive the current schema supports — there is no
// per-server assignment table yet for finer-grained Operator scoping.
func CanAccessOrg(role Role, userOrgID *int64, targetOrgID int64) bool {
	if role == RoleSuperAdmin {
		return true
	}
	return userOrgID != nil && *userOrgID == targetOrgID
}
