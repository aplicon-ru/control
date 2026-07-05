package auth

import (
	"fmt"
	"strings"
	"time"
)

// sqliteTimeLayout matches SQLite's CURRENT_TIMESTAMP default format. Times
// are formatted/parsed explicitly rather than relying on driver-specific
// time.Time marshaling — same approach as internal/servers.
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
	return time.Time{}, fmt.Errorf("auth: parse timestamp %q", s)
}

// sqliteErrorContains reports whether err's message contains substr. This
// avoids depending on the sqlite driver's concrete error type — its
// Error() text follows the standard SQLite message format regardless.
func sqliteErrorContains(err error, substr string) bool {
	return err != nil && strings.Contains(err.Error(), substr)
}

// isUniqueConstraintErr reports whether err came from violating a SQLite
// UNIQUE constraint.
func isUniqueConstraintErr(err error) bool {
	return sqliteErrorContains(err, "UNIQUE constraint failed")
}
