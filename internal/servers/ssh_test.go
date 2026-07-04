package servers

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/aplicon-ru/control/internal/secrets"
)

// testSSHServer is a hermetic, in-process SSH server for exercising
// sshExecutor's real handshake/auth/exec path without a system sshd.
type testSSHServer struct {
	addr       string
	clientPriv ed25519.PrivateKey
	password   string
	listener   net.Listener
}

func newTestSSHServer(t *testing.T) *testSSHServer {
	t.Helper()

	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatalf("NewSignerFromKey (host): %v", err)
	}

	clientPub, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	clientPubKey, err := ssh.NewPublicKey(clientPub)
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}

	const password = "testpass"

	config := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if string(key.Marshal()) == string(clientPubKey.Marshal()) {
				return &ssh.Permissions{}, nil
			}
			return nil, fmt.Errorf("unauthorized key")
		},
		PasswordCallback: func(_ ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if string(pass) == password {
				return &ssh.Permissions{}, nil
			}
			return nil, fmt.Errorf("unauthorized password")
		},
	}
	config.AddHostKey(hostSigner)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	t.Cleanup(func() { listener.Close() })

	srv := &testSSHServer{
		addr:       listener.Addr().String(),
		clientPriv: clientPriv,
		password:   password,
		listener:   listener,
	}
	go srv.serve(config)
	return srv
}

func (srv *testSSHServer) serve(config *ssh.ServerConfig) {
	for {
		conn, err := srv.listener.Accept()
		if err != nil {
			return // listener closed, test is over
		}
		go handleTestConn(conn, config)
	}
}

func handleTestConn(conn net.Conn, config *ssh.ServerConfig) {
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		return
	}
	defer sshConn.Close()
	go ssh.DiscardRequests(reqs)

	for newChan := range chans {
		if newChan.ChannelType() != "session" {
			_ = newChan.Reject(ssh.UnknownChannelType, "unsupported channel type")
			continue
		}
		channel, requests, err := newChan.Accept()
		if err != nil {
			continue
		}
		go handleTestSession(channel, requests)
	}
}

func handleTestSession(channel ssh.Channel, requests <-chan *ssh.Request) {
	defer channel.Close()
	for req := range requests {
		if req.Type != "exec" {
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
			continue
		}

		var payload struct{ Command string }
		_ = ssh.Unmarshal(req.Payload, &payload)
		if req.WantReply {
			_ = req.Reply(true, nil)
		}

		exitCode := uint32(0)
		if strings.Contains(payload.Command, "fail") {
			_, _ = channel.Stderr().Write([]byte("boom"))
			exitCode = 1
		} else {
			_, _ = channel.Write([]byte("ok"))
		}

		_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ ExitStatus uint32 }{exitCode}))
		return
	}
}

func marshalPrivateKey(t *testing.T, key ed25519.PrivateKey) []byte {
	t.Helper()
	block, err := ssh.MarshalPrivateKey(key, "")
	if err != nil {
		t.Fatalf("ssh.MarshalPrivateKey: %v", err)
	}
	return pem.EncodeToMemory(block)
}

func testSSHServerAndStore(t *testing.T) (*testSSHServer, string, int, *secrets.Store) {
	t.Helper()

	srv := newTestSSHServer(t)
	host, portStr, err := net.SplitHostPort(srv.addr)
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("Atoi: %v", err)
	}

	db := newTestDB(t)
	key, err := secrets.GenerateMasterKey()
	if err != nil {
		t.Fatalf("GenerateMasterKey: %v", err)
	}
	return srv, host, port, secrets.NewStore(db, key)
}

func TestSSHExecutor_KeyAuthAndExec(t *testing.T) {
	srv, host, port, store := testSSHServerAndStore(t)

	s := Server{ID: 1, Host: host, Port: port, SSHUser: "deploy", AuthType: AuthKey}
	cred := Credential{Type: AuthKey, PrivateKey: clientPrivateKeyPEM(t, srv)}

	exec, err := newSSHExecutor(context.Background(), s, cred, store)
	if err != nil {
		t.Fatalf("newSSHExecutor: %v", err)
	}
	defer exec.Close()

	result, err := exec.Run(context.Background(), "echo hi")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("Run: exit code %d, want 0", result.ExitCode)
	}
	if string(result.Stdout) != "ok" {
		t.Fatalf("Run: stdout %q, want %q", result.Stdout, "ok")
	}
}

func TestSSHExecutor_NonZeroExit(t *testing.T) {
	srv, host, port, store := testSSHServerAndStore(t)

	s := Server{ID: 1, Host: host, Port: port, SSHUser: "deploy", AuthType: AuthKey}
	cred := Credential{Type: AuthKey, PrivateKey: clientPrivateKeyPEM(t, srv)}

	exec, err := newSSHExecutor(context.Background(), s, cred, store)
	if err != nil {
		t.Fatalf("newSSHExecutor: %v", err)
	}
	defer exec.Close()

	result, err := exec.Run(context.Background(), "will-fail")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.ExitCode != 1 {
		t.Fatalf("Run: exit code %d, want 1", result.ExitCode)
	}
	if string(result.Stderr) != "boom" {
		t.Fatalf("Run: stderr %q, want %q", result.Stderr, "boom")
	}
}

func TestSSHExecutor_PasswordAuth(t *testing.T) {
	srv, host, port, store := testSSHServerAndStore(t)

	s := Server{ID: 1, Host: host, Port: port, SSHUser: "deploy", AuthType: AuthPassword}
	cred := Credential{Type: AuthPassword, Password: srv.password}

	exec, err := newSSHExecutor(context.Background(), s, cred, store)
	if err != nil {
		t.Fatalf("newSSHExecutor: %v", err)
	}
	defer exec.Close()

	if _, err := exec.Run(context.Background(), "echo hi"); err != nil {
		t.Fatalf("Run: %v", err)
	}
}

func TestSSHExecutor_WrongPasswordRejected(t *testing.T) {
	_, host, port, store := testSSHServerAndStore(t)

	s := Server{ID: 1, Host: host, Port: port, SSHUser: "deploy", AuthType: AuthPassword}
	cred := Credential{Type: AuthPassword, Password: "wrong"}

	if _, err := newSSHExecutor(context.Background(), s, cred, store); err == nil {
		t.Fatal("newSSHExecutor: want error for wrong password, got nil")
	}
}

func TestSSHExecutor_HostKeyTOFU_AcceptsThenRejectsMismatch(t *testing.T) {
	srv, host, port, store := testSSHServerAndStore(t)
	s := Server{ID: 1, Host: host, Port: port, SSHUser: "deploy", AuthType: AuthKey}
	cred := Credential{Type: AuthKey, PrivateKey: clientPrivateKeyPEM(t, srv)}
	ctx := context.Background()

	exec1, err := newSSHExecutor(ctx, s, cred, store)
	if err != nil {
		t.Fatalf("newSSHExecutor (first connect): %v", err)
	}
	exec1.Close()

	if _, _, err := store.Get(ctx, "server", s.ID, "ssh_host_key"); err != nil {
		t.Fatalf("expected host key to be stored after first connect: %v", err)
	}

	// Second connect to the SAME server with the SAME stored key succeeds.
	exec2, err := newSSHExecutor(ctx, s, cred, store)
	if err != nil {
		t.Fatalf("newSSHExecutor (second connect, same key): %v", err)
	}
	exec2.Close()

	// A different server identity presenting a different host key (a new
	// in-process server) must be rejected under the same s.ID.
	otherSrv := newTestSSHServer(t)
	otherHost, otherPortStr, err := net.SplitHostPort(otherSrv.addr)
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	otherPort, err := strconv.Atoi(otherPortStr)
	if err != nil {
		t.Fatalf("Atoi: %v", err)
	}
	otherS := s
	otherS.Host = otherHost
	otherS.Port = otherPort
	otherCred := Credential{Type: AuthKey, PrivateKey: clientPrivateKeyPEM(t, otherSrv)}

	if _, err := newSSHExecutor(ctx, otherS, otherCred, store); !errors.Is(err, ErrHostKeyMismatch) {
		t.Fatalf("newSSHExecutor (different host key, same server ID): got err %v, want ErrHostKeyMismatch", err)
	}
}

func TestRegistryConnect_RealSSH_KeyAuth(t *testing.T) {
	srv := newTestSSHServer(t)
	host, portStr, err := net.SplitHostPort(srv.addr)
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("Atoi: %v", err)
	}

	r, orgID := newTestRegistry(t)
	ctx := context.Background()

	s := testServer(orgID)
	s.Host = host
	s.Port = port
	s.AuthType = AuthKey

	id, err := r.Create(ctx, s, Credential{Type: AuthKey, PrivateKey: clientPrivateKeyPEM(t, srv)})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	exec, err := r.Connect(ctx, orgID, id)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer exec.Close()

	result, err := exec.Run(ctx, "echo hi")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("Run: exit code %d, want 0", result.ExitCode)
	}
}

func TestRegistryConnect_RealSSH_PasswordAuth(t *testing.T) {
	srv := newTestSSHServer(t)
	host, portStr, err := net.SplitHostPort(srv.addr)
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("Atoi: %v", err)
	}

	r, orgID := newTestRegistry(t)
	ctx := context.Background()

	s := testServer(orgID)
	s.Host = host
	s.Port = port
	s.AuthType = AuthPassword

	id, err := r.Create(ctx, s, Credential{Type: AuthPassword, Password: srv.password})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	exec, err := r.Connect(ctx, orgID, id)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer exec.Close()

	if _, err := exec.Run(ctx, "echo hi"); err != nil {
		t.Fatalf("Run: %v", err)
	}
}

func TestFingerprintMatches(t *testing.T) {
	if !fingerprintMatches([]byte("abc"), []byte("abc")) {
		t.Error("fingerprintMatches: want true for equal byte slices")
	}
	if fingerprintMatches([]byte("abc"), []byte("xyz")) {
		t.Error("fingerprintMatches: want false for different byte slices")
	}
}

func TestAuthMethodFor_InvalidType(t *testing.T) {
	if _, err := authMethodFor(Credential{Type: AuthType("token")}); !errors.Is(err, ErrInvalidField) {
		t.Fatalf("authMethodFor: got err %v, want ErrInvalidField", err)
	}
}

func TestAuthMethodFor_InvalidPrivateKey(t *testing.T) {
	if _, err := authMethodFor(Credential{Type: AuthKey, PrivateKey: []byte("not a key")}); err == nil {
		t.Fatal("authMethodFor: want error for malformed private key, got nil")
	}
}

// clientPrivateKeyPEM PEM-encodes srv's client key, matching what a real
// Credential.PrivateKey would hold.
func clientPrivateKeyPEM(t *testing.T, srv *testSSHServer) []byte {
	t.Helper()
	return marshalPrivateKey(t, srv.clientPriv)
}
