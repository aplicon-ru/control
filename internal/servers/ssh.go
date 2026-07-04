package servers

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"

	"golang.org/x/crypto/ssh"

	"github.com/aplicon-ru/control/internal/secrets"
)

var _ Executor = (*sshExecutor)(nil)

type sshExecutor struct {
	client *ssh.Client
}

// newSSHExecutor dials s over SSH using cred, verifying the host key via
// trust-on-first-use against store (see tofuHostKeyCallback) rather than
// ssh.InsecureIgnoreHostKey.
func newSSHExecutor(ctx context.Context, s Server, cred Credential, store *secrets.Store) (*sshExecutor, error) {
	authMethod, err := authMethodFor(cred)
	if err != nil {
		return nil, err
	}

	config := &ssh.ClientConfig{
		User:            s.SSHUser,
		Auth:            []ssh.AuthMethod{authMethod},
		HostKeyCallback: tofuHostKeyCallback(ctx, s.ID, store),
	}

	addr := fmt.Sprintf("%s:%d", s.Host, s.Port)
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("servers: ssh dial: %w", err)
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("servers: ssh handshake: %w", err)
	}

	return &sshExecutor{client: ssh.NewClient(sshConn, chans, reqs)}, nil
}

func authMethodFor(cred Credential) (ssh.AuthMethod, error) {
	switch cred.Type {
	case AuthKey:
		signer, err := ssh.ParsePrivateKey(cred.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("servers: parse private key: %w", err)
		}
		return ssh.PublicKeys(signer), nil
	case AuthPassword:
		return ssh.Password(cred.Password), nil
	default:
		return nil, fmt.Errorf("%w: auth type %q", ErrInvalidField, cred.Type)
	}
}

// tofuHostKeyCallback implements trust-on-first-use: the first connection
// to serverID stores the presented host key's fingerprint as a Class B
// secret; every later connection must present the same key, or the
// connection is rejected. A changed key is either a legitimate
// re-provision or a MITM — either way it needs manual operator
// intervention, not a silent accept.
func tofuHostKeyCallback(ctx context.Context, serverID int64, store *secrets.Store) ssh.HostKeyCallback {
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		observed := []byte(ssh.FingerprintSHA256(key))

		stored, _, err := store.Get(ctx, "server", serverID, "ssh_host_key")
		if errors.Is(err, secrets.ErrNotFound) {
			if putErr := store.Put(ctx, secrets.ClassServer, "server", serverID, "ssh_host_key", observed); putErr != nil {
				return fmt.Errorf("servers: store host key on first connect: %w", putErr)
			}
			return nil
		}
		if err != nil {
			return fmt.Errorf("servers: load stored host key: %w", err)
		}

		if !fingerprintMatches(stored, observed) {
			return ErrHostKeyMismatch
		}
		return nil
	}
}

func fingerprintMatches(stored, observed []byte) bool {
	return bytes.Equal(stored, observed)
}

func (e *sshExecutor) Run(ctx context.Context, cmd string) (Result, error) {
	session, err := e.client.NewSession()
	if err != nil {
		return Result{}, fmt.Errorf("servers: new ssh session: %w", err)
	}
	defer session.Close()

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	done := make(chan error, 1)
	go func() { done <- session.Run(cmd) }()

	select {
	case <-ctx.Done():
		_ = session.Signal(ssh.SIGKILL)
		return Result{}, ctx.Err()
	case runErr := <-done:
		var exitErr *ssh.ExitError
		switch {
		case errors.As(runErr, &exitErr):
			return Result{Stdout: stdout.Bytes(), Stderr: stderr.Bytes(), ExitCode: exitErr.ExitStatus()}, nil
		case runErr != nil:
			return Result{}, fmt.Errorf("servers: run command: %w", runErr)
		default:
			return Result{Stdout: stdout.Bytes(), Stderr: stderr.Bytes(), ExitCode: 0}, nil
		}
	}
}

func (e *sshExecutor) Close() error {
	return e.client.Close()
}
