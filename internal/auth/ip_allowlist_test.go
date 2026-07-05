package auth

import (
	"context"
	"testing"
)

func TestIPAllowlist_EmptyScopeIsUnrestricted(t *testing.T) {
	db := newTestDB(t)
	a := NewIPAllowlist(db)

	allowed, err := a.Check(context.Background(), "10.0.0.5", nil)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !allowed {
		t.Fatal("Check: want allowed for empty allowlist, got denied")
	}
}

func TestIPAllowlist_MatchingCIDR(t *testing.T) {
	db := newTestDB(t)
	orgID := newTestOrg(t, db)
	ctx := context.Background()

	if _, err := db.ExecContext(ctx, `INSERT INTO ip_allowlist (org_id, cidr) VALUES (?, ?)`, orgID, "10.0.0.0/24"); err != nil {
		t.Fatalf("insert ip_allowlist row: %v", err)
	}

	a := NewIPAllowlist(db)
	allowed, err := a.Check(ctx, "10.0.0.5", &orgID)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !allowed {
		t.Fatal("Check: want allowed for matching CIDR, got denied")
	}
}

func TestIPAllowlist_NonMatchingCIDR(t *testing.T) {
	db := newTestDB(t)
	orgID := newTestOrg(t, db)
	ctx := context.Background()

	if _, err := db.ExecContext(ctx, `INSERT INTO ip_allowlist (org_id, cidr) VALUES (?, ?)`, orgID, "10.0.0.0/24"); err != nil {
		t.Fatalf("insert ip_allowlist row: %v", err)
	}

	a := NewIPAllowlist(db)
	allowed, err := a.Check(ctx, "192.168.1.1", &orgID)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if allowed {
		t.Fatal("Check: want denied for non-matching CIDR, got allowed")
	}
}

func TestIPAllowlist_GlobalRowAppliesToAnyOrg(t *testing.T) {
	db := newTestDB(t)
	orgID := newTestOrg(t, db)
	ctx := context.Background()

	if _, err := db.ExecContext(ctx, `INSERT INTO ip_allowlist (org_id, cidr) VALUES (NULL, ?)`, "172.16.0.0/16"); err != nil {
		t.Fatalf("insert global ip_allowlist row: %v", err)
	}

	a := NewIPAllowlist(db)
	allowed, err := a.Check(ctx, "172.16.5.5", &orgID)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !allowed {
		t.Fatal("Check: want allowed via global row, got denied")
	}
}

func TestIPAllowlist_OrgScopeDoesNotLeakAcrossOrgs(t *testing.T) {
	db := newTestDB(t)
	orgA := newTestOrg(t, db)
	ctx := context.Background()

	res, err := db.ExecContext(ctx, `INSERT INTO organizations (slug, name) VALUES ('other', 'Other')`)
	if err != nil {
		t.Fatalf("insert other org: %v", err)
	}
	orgB, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("LastInsertId: %v", err)
	}

	if _, err := db.ExecContext(ctx, `INSERT INTO ip_allowlist (org_id, cidr) VALUES (?, ?)`, orgA, "10.0.0.0/24"); err != nil {
		t.Fatalf("insert ip_allowlist row: %v", err)
	}

	a := NewIPAllowlist(db)
	// orgB has no rows of its own and no global rows exist — its scope is
	// empty, so it's unrestricted, unaffected by orgA's restriction.
	allowed, err := a.Check(ctx, "192.168.1.1", &orgB)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !allowed {
		t.Fatal("Check: orgB's empty scope should be unrestricted regardless of orgA's allowlist")
	}
}

func TestIPAllowlist_MalformedCIDRFailsClosed(t *testing.T) {
	db := newTestDB(t)
	orgID := newTestOrg(t, db)
	ctx := context.Background()

	if _, err := db.ExecContext(ctx, `INSERT INTO ip_allowlist (org_id, cidr) VALUES (?, ?)`, orgID, "not-a-cidr"); err != nil {
		t.Fatalf("insert ip_allowlist row: %v", err)
	}

	a := NewIPAllowlist(db)
	if _, err := a.Check(ctx, "10.0.0.5", &orgID); err == nil {
		t.Fatal("Check: want error for malformed stored CIDR, got nil")
	}
}

func TestIPAllowlist_InvalidIP(t *testing.T) {
	db := newTestDB(t)
	a := NewIPAllowlist(db)

	if _, err := a.Check(context.Background(), "not-an-ip", nil); err == nil {
		t.Fatal("Check: want error for invalid ip argument, got nil")
	}
}

func TestIPAllowlist_ClosedDB(t *testing.T) {
	db := newTestDB(t)
	a := NewIPAllowlist(db)
	db.Close()

	orgID := int64(1)
	if _, err := a.Check(context.Background(), "10.0.0.1", &orgID); err == nil {
		t.Fatal("Check: want error on closed DB, got nil")
	}
	if _, err := a.Check(context.Background(), "10.0.0.1", nil); err == nil {
		t.Fatal("Check: want error on closed DB (global scope), got nil")
	}
}
