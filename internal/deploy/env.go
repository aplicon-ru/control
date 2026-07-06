package deploy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/aplicon-ru/control/internal/servers"
)

var envKeyPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// RenderEnv formats vars as sorted KEY=VALUE lines suitable for a .env
// file. Keys must match [A-Za-z_][A-Za-z0-9_]* and values must not contain
// a newline (which would break the heredoc PushEnv uses to write them) —
// this is deliberately not a general .env parser/escaper, just enough to
// push a module's own secret values safely.
func RenderEnv(vars map[string]string) (string, error) {
	keys := make([]string, 0, len(vars))
	for k := range vars {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	for _, k := range keys {
		if !envKeyPattern.MatchString(k) {
			return "", fmt.Errorf("deploy: render env: invalid key %q", k)
		}
		v := vars[k]
		if strings.ContainsAny(v, "\n\r") {
			return "", fmt.Errorf("deploy: render env: value for %q contains a newline", k)
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(v)
		b.WriteByte('\n')
	}
	return b.String(), nil
}

// PushEnv writes contents to path on the remote host via a heredoc over
// exec, then chmod 600s it. There's no SFTP method on Executor — a .env
// file's few dozen bytes fit comfortably in a heredoc'd shell command,
// which the existing Run(cmd) interface already supports.
func PushEnv(ctx context.Context, exec servers.Executor, path, contents string) error {
	delim, err := randomDelimiter()
	if err != nil {
		return fmt.Errorf("deploy: push env: %w", err)
	}

	cmd := fmt.Sprintf("cat > '%s' <<'%s'\n%s%s\nchmod 600 '%s'", path, delim, contents, delim, path)

	result, err := exec.Run(ctx, cmd)
	if err != nil {
		return fmt.Errorf("deploy: push env: %w", err)
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("deploy: push env: exit code %d: %s", result.ExitCode, result.Stderr)
	}
	return nil
}

func randomDelimiter() (string, error) {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate delimiter: %w", err)
	}
	return "UKON_EOF_" + hex.EncodeToString(buf), nil
}
