package servers

import (
	"context"
	"strings"
)

var _ Executor = (*mockExecutor)(nil)

// mockExecutor simulates command execution for type=mock servers — no SSH,
// no Docker (spec: "SSH не используется, операции симулируются"). It
// recognizes the handful of command patterns the current e2e story needs
// (spec §17.4: add server → deploy module → check status) and otherwise
// succeeds with empty output, so it never blocks whatever internal/deploy
// throws at it next — broader simulation is added on demand, not
// speculatively now.
type mockExecutor struct{}

func newMockExecutor(Server) *mockExecutor {
	return &mockExecutor{}
}

func (e *mockExecutor) Run(_ context.Context, cmd string) (Result, error) {
	switch {
	case strings.Contains(cmd, "docker version"):
		return Result{Stdout: []byte("Docker version 27.0.0, build mock"), ExitCode: 0}, nil
	case strings.Contains(cmd, "docker compose"):
		return Result{Stdout: []byte("mock: compose ok"), ExitCode: 0}, nil
	default:
		return Result{ExitCode: 0}, nil
	}
}

func (e *mockExecutor) Close() error {
	return nil
}
