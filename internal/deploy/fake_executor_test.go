package deploy

import (
	"context"
	"errors"
	"strings"

	"github.com/aplicon-ru/control/internal/servers"
)

// fakeExecutor is a lightweight, test-local implementation of
// servers.Executor. It's deliberately not servers.mockExecutor: that type
// backs a product requirement (spec §17.4's e2e fixture) with a scope
// owned by the mock-server story, not by this package's unit tests —
// coupling it to deploy's exact command phrasing would mean any future
// change here silently requires touching internal/servers too.
type fakeExecutor struct {
	commands []string
	// script maps a substring of a command to a scripted step. The first
	// matching substring wins; if none match, the default is a
	// successful, empty Result.
	script map[string]fakeStep
	closed bool
}

type fakeStep struct {
	result servers.Result
	err    error
}

var errFakeConnectionLost = errors.New("fake: connection lost")

func newTestFakeExecutor() *fakeExecutor {
	return &fakeExecutor{script: map[string]fakeStep{}}
}

func (e *fakeExecutor) Run(_ context.Context, cmd string) (servers.Result, error) {
	e.commands = append(e.commands, cmd)
	for substr, step := range e.script {
		if strings.Contains(cmd, substr) {
			return step.result, step.err
		}
	}
	return servers.Result{ExitCode: 0}, nil
}

func (e *fakeExecutor) Close() error {
	e.closed = true
	return nil
}

var _ servers.Executor = (*fakeExecutor)(nil)
