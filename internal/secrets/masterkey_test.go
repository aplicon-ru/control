package secrets

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestGenerateMasterKey_Size(t *testing.T) {
	key, err := GenerateMasterKey()
	if err != nil {
		t.Fatalf("GenerateMasterKey: %v", err)
	}
	if len(key) != MasterKeySize {
		t.Fatalf("GenerateMasterKey: want %d bytes, got %d", MasterKeySize, len(key))
	}

	key2, err := GenerateMasterKey()
	if err != nil {
		t.Fatalf("GenerateMasterKey: %v", err)
	}
	if bytes.Equal(key, key2) {
		t.Fatal("GenerateMasterKey: two calls produced the same key")
	}
}

func TestSaveLoadMasterKey_Roundtrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")
	key, err := GenerateMasterKey()
	if err != nil {
		t.Fatalf("GenerateMasterKey: %v", err)
	}

	if err := SaveMasterKey(path, key); err != nil {
		t.Fatalf("SaveMasterKey: %v", err)
	}

	got, err := LoadMasterKey(path)
	if err != nil {
		t.Fatalf("LoadMasterKey: %v", err)
	}
	if !bytes.Equal(got, key) {
		t.Fatal("LoadMasterKey: loaded key does not match saved key")
	}
}

func TestSaveMasterKey_Perms(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix file permissions don't apply on windows")
	}
	path := filepath.Join(t.TempDir(), "master.key")
	key, err := GenerateMasterKey()
	if err != nil {
		t.Fatalf("GenerateMasterKey: %v", err)
	}
	if err := SaveMasterKey(path, key); err != nil {
		t.Fatalf("SaveMasterKey: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("SaveMasterKey: want mode 0600, got %o", perm)
	}
}

func TestSaveMasterKey_RefusesOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")
	key, err := GenerateMasterKey()
	if err != nil {
		t.Fatalf("GenerateMasterKey: %v", err)
	}
	if err := SaveMasterKey(path, key); err != nil {
		t.Fatalf("SaveMasterKey (first): %v", err)
	}

	if err := SaveMasterKey(path, key); err == nil {
		t.Fatal("SaveMasterKey: want error on second write to same path, got nil")
	}
}

func TestSaveMasterKey_WrongKeySize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")
	if err := SaveMasterKey(path, []byte("too short")); err == nil {
		t.Fatal("SaveMasterKey: want error for wrong-size key, got nil")
	}
}

func TestLoadMasterKey_MissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist.key")
	if _, err := LoadMasterKey(path); err == nil {
		t.Fatal("LoadMasterKey: want error for missing file, got nil")
	}
}

func TestLoadMasterKey_WrongSize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")
	if err := os.WriteFile(path, []byte("too short"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := LoadMasterKey(path); err == nil {
		t.Fatal("LoadMasterKey: want error for wrong-size file, got nil")
	}
}

func TestLoadOrGenerateMasterKey_StatErrorOtherThanNotExist(t *testing.T) {
	dir := t.TempDir()
	notADir := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(notADir, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	// A path with a regular file as a non-final component fails os.Stat
	// with ENOTDIR, not ENOENT — os.IsNotExist(err) is false for that.
	path := filepath.Join(notADir, "master.key")

	if _, err := LoadOrGenerateMasterKey(path); err == nil {
		t.Fatal("LoadOrGenerateMasterKey: want error for non-directory path component, got nil")
	}
}

func TestLoadOrGenerateMasterKey_GeneratesWhenMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")

	key, err := LoadOrGenerateMasterKey(path)
	if err != nil {
		t.Fatalf("LoadOrGenerateMasterKey: %v", err)
	}
	if len(key) != MasterKeySize {
		t.Fatalf("LoadOrGenerateMasterKey: want %d bytes, got %d", MasterKeySize, len(key))
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("LoadOrGenerateMasterKey: expected file to be created: %v", err)
	}
}

func TestLoadOrGenerateMasterKey_LoadsWhenPresent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")
	existing, err := GenerateMasterKey()
	if err != nil {
		t.Fatalf("GenerateMasterKey: %v", err)
	}
	if err := SaveMasterKey(path, existing); err != nil {
		t.Fatalf("SaveMasterKey: %v", err)
	}

	got, err := LoadOrGenerateMasterKey(path)
	if err != nil {
		t.Fatalf("LoadOrGenerateMasterKey: %v", err)
	}
	if !bytes.Equal(got, existing) {
		t.Fatal("LoadOrGenerateMasterKey: returned a different key than the one on disk")
	}
}
