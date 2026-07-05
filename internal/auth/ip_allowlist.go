package auth

import (
	"context"
	"database/sql"
	"fmt"
	"net/netip"
)

// IPAllowlist checks addresses against the ip_allowlist table.
type IPAllowlist struct {
	db *sql.DB
}

// NewIPAllowlist returns an IPAllowlist backed by db.
func NewIPAllowlist(db *sql.DB) *IPAllowlist {
	return &IPAllowlist{db: db}
}

// Check reports whether ip is permitted under the allowlist scoped to
// orgID, plus any global entries (org_id IS NULL). No rows configured for
// that scope means unrestricted — matches spec's framing of the IP
// allowlist as optional. A malformed CIDR already stored in the table
// fails the check closed rather than being silently skipped.
func (a *IPAllowlist) Check(ctx context.Context, ip string, orgID *int64) (bool, error) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false, fmt.Errorf("auth: check ip allowlist: parse ip %q: %w", ip, err)
	}

	var rows *sql.Rows
	if orgID != nil {
		rows, err = a.db.QueryContext(ctx, `SELECT cidr FROM ip_allowlist WHERE org_id = ? OR org_id IS NULL`, *orgID)
	} else {
		rows, err = a.db.QueryContext(ctx, `SELECT cidr FROM ip_allowlist WHERE org_id IS NULL`)
	}
	if err != nil {
		return false, fmt.Errorf("auth: check ip allowlist: %w", err)
	}
	defer rows.Close()

	found := false
	for rows.Next() {
		found = true
		var cidr string
		if err := rows.Scan(&cidr); err != nil {
			return false, fmt.Errorf("auth: check ip allowlist: %w", err)
		}

		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return false, fmt.Errorf("auth: check ip allowlist: malformed cidr %q: %w", cidr, err)
		}
		if prefix.Contains(addr) {
			return true, nil
		}
	}
	if err := rows.Err(); err != nil {
		return false, fmt.Errorf("auth: check ip allowlist: %w", err)
	}

	if !found {
		return true, nil
	}
	return false, nil
}
