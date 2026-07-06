package deploy

import (
	"context"
	"strings"
	"testing"

	"github.com/aplicon-ru/control/internal/servers"
)

func TestRenderEnv_SortedDeterministicOutput(t *testing.T) {
	got, err := RenderEnv(map[string]string{"B_VAR": "2", "A_VAR": "1"})
	if err != nil {
		t.Fatalf("RenderEnv: %v", err)
	}
	if got != "A_VAR=1\nB_VAR=2\n" {
		t.Fatalf("RenderEnv: got %q", got)
	}
}

func TestRenderEnv_Empty(t *testing.T) {
	got, err := RenderEnv(map[string]string{})
	if err != nil {
		t.Fatalf("RenderEnv: %v", err)
	}
	if got != "" {
		t.Fatalf("RenderEnv: got %q, want empty", got)
	}
}

func TestRenderEnv_InvalidKey(t *testing.T) {
	tests := []string{"1LEADING_DIGIT", "has-dash", "has space", ""}
	for _, k := range tests {
		if _, err := RenderEnv(map[string]string{k: "v"}); err == nil {
			t.Errorf("RenderEnv(%q): want error, got nil", k)
		}
	}
}

func TestRenderEnv_ValueWithNewlineRejected(t *testing.T) {
	if _, err := RenderEnv(map[string]string{"KEY": "line1\nline2"}); err == nil {
		t.Fatal("RenderEnv: want error for value containing newline, got nil")
	}
}

func TestPushEnv_Success(t *testing.T) {
	exec := newTestFakeExecutor()
	if err := PushEnv(context.Background(), exec, "/opt/ukon/.env", "KEY=VALUE\n"); err != nil {
		t.Fatalf("PushEnv: %v", err)
	}
	if len(exec.commands) != 1 {
		t.Fatalf("PushEnv: want 1 command run, got %d", len(exec.commands))
	}
	if !strings.Contains(exec.commands[0], "cat > '/opt/ukon/.env'") {
		t.Fatalf("PushEnv: command %q missing expected heredoc prefix", exec.commands[0])
	}
	if !strings.Contains(exec.commands[0], "chmod 600 '/opt/ukon/.env'") {
		t.Fatalf("PushEnv: command %q missing expected chmod", exec.commands[0])
	}
}

func TestPushEnv_NonZeroExit(t *testing.T) {
	exec := newTestFakeExecutor()
	exec.script["cat >"] = fakeStep{result: servers.Result{ExitCode: 1, Stderr: []byte("permission denied")}}

	if err := PushEnv(context.Background(), exec, "/opt/ukon/.env", "KEY=VALUE\n"); err == nil {
		t.Fatal("PushEnv: want error for non-zero exit, got nil")
	}
}

func TestPushEnv_RunError(t *testing.T) {
	exec := newTestFakeExecutor()
	exec.script["cat >"] = fakeStep{err: errFakeConnectionLost}

	if err := PushEnv(context.Background(), exec, "/opt/ukon/.env", "KEY=VALUE\n"); err == nil {
		t.Fatal("PushEnv: want error when Run itself fails, got nil")
	}
}
