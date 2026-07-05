package auth

import "testing"

func TestCanAccessOrg(t *testing.T) {
	org1 := int64(1)
	org2 := int64(2)

	tests := []struct {
		name      string
		role      Role
		userOrgID *int64
		targetOrg int64
		want      bool
	}{
		{"super_admin any org", RoleSuperAdmin, nil, org2, true},
		{"org_admin own org", RoleOrgAdmin, &org1, org1, true},
		{"org_admin other org", RoleOrgAdmin, &org1, org2, false},
		{"operator own org", RoleOperator, &org1, org1, true},
		{"operator other org", RoleOperator, &org1, org2, false},
		{"viewer own org", RoleViewer, &org1, org1, true},
		{"viewer other org", RoleViewer, &org1, org2, false},
		{"non-super-admin with nil org", RoleOrgAdmin, nil, org1, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CanAccessOrg(tt.role, tt.userOrgID, tt.targetOrg); got != tt.want {
				t.Errorf("CanAccessOrg(%q, %v, %d) = %v, want %v", tt.role, tt.userOrgID, tt.targetOrg, got, tt.want)
			}
		})
	}
}
