package servers

import (
	"context"
	"testing"
)

func TestMockExecutor_Run(t *testing.T) {
	tests := []struct {
		name string
		cmd  string
		want string
	}{
		{"docker version", "docker version --format json", "Docker version 27.0.0, build mock"},
		{"docker compose", "docker compose -f compose.yml up -d", "mock: compose ok"},
		{"unknown command", "echo hello", ""},
	}

	e := newMockExecutor(Server{Type: TypeMock})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := e.Run(context.Background(), tt.cmd)
			if err != nil {
				t.Fatalf("Run(%q): %v", tt.cmd, err)
			}
			if result.ExitCode != 0 {
				t.Fatalf("Run(%q): exit code %d, want 0", tt.cmd, result.ExitCode)
			}
			if string(result.Stdout) != tt.want {
				t.Fatalf("Run(%q): stdout %q, want %q", tt.cmd, result.Stdout, tt.want)
			}
		})
	}
}

func TestMockExecutor_CloseIsIdempotent(t *testing.T) {
	e := newMockExecutor(Server{Type: TypeMock})
	if err := e.Close(); err != nil {
		t.Fatalf("Close (first): %v", err)
	}
	if err := e.Close(); err != nil {
		t.Fatalf("Close (second): %v", err)
	}
}
