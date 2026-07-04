package servers

import "context"

// Result is the outcome of running one command through an Executor.
type Result struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
}

// Executor runs commands on a server — real over SSH, or simulated for
// type=mock. Both implementations sit behind this interface because
// internal/deploy calls Run/Close identically regardless of server type;
// the mock is a product requirement (spec §17.4 Playwright e2e fixture),
// not a testing convenience.
type Executor interface {
	Run(ctx context.Context, cmd string) (Result, error)
	Close() error
}
