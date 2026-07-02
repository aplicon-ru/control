package secrets

import (
	"crypto/rand"
	"fmt"
	"os"
)

// MasterKeySize is the size in bytes of an AES-256 key.
const MasterKeySize = 32

// GenerateMasterKey returns MasterKeySize cryptographically random bytes.
func GenerateMasterKey() ([]byte, error) {
	key := make([]byte, MasterKeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("secrets: generate master key: %w", err)
	}
	return key, nil
}

// SaveMasterKey writes key to path with 0600 permissions. It refuses to
// overwrite an existing file: a bug that calls this twice for the same path
// must fail loudly, not silently strand every secret already encrypted
// under the key that was there first.
func SaveMasterKey(path string, key []byte) error {
	if len(key) != MasterKeySize {
		return fmt.Errorf("secrets: save master key: want %d bytes, got %d", MasterKeySize, len(key))
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("secrets: save master key: %w", err)
	}
	defer f.Close()
	if _, err := f.Write(key); err != nil {
		return fmt.Errorf("secrets: save master key: %w", err)
	}
	return nil
}

// LoadMasterKey reads and validates a master key from path.
func LoadMasterKey(path string) ([]byte, error) {
	key, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("secrets: load master key: %w", err)
	}
	if len(key) != MasterKeySize {
		return nil, fmt.Errorf("secrets: load master key: want %d bytes, got %d", MasterKeySize, len(key))
	}
	return key, nil
}

// LoadOrGenerateMasterKey loads the key at path if it exists, otherwise
// generates, persists, and returns a new one. This is the single
// entrypoint callers (main.go, install wizard) use.
func LoadOrGenerateMasterKey(path string) ([]byte, error) {
	if _, err := os.Stat(path); err == nil {
		return LoadMasterKey(path)
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("secrets: load or generate master key: %w", err)
	}

	key, err := GenerateMasterKey()
	if err != nil {
		return nil, err
	}
	if err := SaveMasterKey(path, key); err != nil {
		return nil, err
	}
	return key, nil
}
