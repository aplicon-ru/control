package servers

import (
	"errors"
	"time"
)

type AuthType string

const (
	AuthKey      AuthType = "key"
	AuthPassword AuthType = "password"
)

type ServerType string

const (
	TypeDockerOnly ServerType = "docker_only"
	TypeFull       ServerType = "full"
	TypeMock       ServerType = "mock"
)

type Environment string

const (
	EnvProd    Environment = "prod"
	EnvStaging Environment = "staging"
	EnvDev     Environment = "dev"
)

type Status string

const (
	StatusOnline  Status = "online"
	StatusOffline Status = "offline"
	StatusUnknown Status = "unknown"
)

// Server mirrors a row in the servers table (migrations/0001_init.sql).
type Server struct {
	ID            int64
	OrgID         int64
	Name          string
	Host          string
	Port          int
	SSHUser       string
	AuthType      AuthType
	Type          ServerType
	Environment   Environment
	IsSelf        bool
	Status        Status
	LastCheckedAt *time.Time
	CreatedAt     time.Time
}

// Credential holds the SSH secret material for a server. It is never
// persisted directly — Registry.Create stores it via internal/secrets.
type Credential struct {
	Type       AuthType
	PrivateKey []byte // set when Type == AuthKey
	Password   string // set when Type == AuthPassword
}

var (
	// ErrNotFound is returned when no server matches the given org/id.
	ErrNotFound = errors.New("servers: not found")
	// ErrInvalidField is returned when a Server field holds a value outside
	// its allowed set, checked in Go before it reaches the DB CHECK constraint.
	ErrInvalidField = errors.New("servers: invalid field value")
	// ErrIsSelfProtected is returned by Delete for the server hosting CP
	// itself (spec §2 [THIS] marker) — it cannot be removed through itself.
	ErrIsSelfProtected = errors.New("servers: server is marked is_self and cannot be deleted")
	// ErrHostKeyMismatch is returned when a server's presented SSH host key
	// does not match the one recorded on first connect.
	ErrHostKeyMismatch = errors.New("servers: host key does not match the one recorded on first connect")
)

func validAuthType(t AuthType) bool {
	switch t {
	case AuthKey, AuthPassword:
		return true
	default:
		return false
	}
}

func validServerType(t ServerType) bool {
	switch t {
	case TypeDockerOnly, TypeFull, TypeMock:
		return true
	default:
		return false
	}
}

func validEnvironment(e Environment) bool {
	switch e {
	case EnvProd, EnvStaging, EnvDev:
		return true
	default:
		return false
	}
}

func validStatus(s Status) bool {
	switch s {
	case StatusOnline, StatusOffline, StatusUnknown:
		return true
	default:
		return false
	}
}
