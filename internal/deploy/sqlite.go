package deploy

import (
	"fmt"
	"time"
)

// sqliteTimeLayout matches SQLite's CURRENT_TIMESTAMP default format. Times
// are formatted/parsed explicitly rather than relying on driver-specific
// time.Time marshaling — same approach as internal/servers and internal/auth.
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
	return time.Time{}, fmt.Errorf("deploy: parse timestamp %q", s)
}
