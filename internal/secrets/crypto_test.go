package secrets

import (
	"bytes"
	"testing"
)

func testKey(t *testing.T) []byte {
	t.Helper()
	key, err := GenerateMasterKey()
	if err != nil {
		t.Fatalf("GenerateMasterKey: %v", err)
	}
	return key
}

func TestSealOpen_Roundtrip(t *testing.T) {
	key := testKey(t)
	plaintext := []byte("hunter2")

	ciphertext, nonce, err := Seal(key, plaintext)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if len(ciphertext) == 0 {
		t.Fatal("Seal: empty ciphertext")
	}
	if len(nonce) != 12 {
		t.Fatalf("Seal: want 12-byte nonce, got %d", len(nonce))
	}

	got, err := Open(key, ciphertext, nonce)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("Open: got %q, want %q", got, plaintext)
	}
}

func TestSealOpen_EmptyPlaintext(t *testing.T) {
	key := testKey(t)

	ciphertext, nonce, err := Seal(key, []byte(""))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	got, err := Open(key, ciphertext, nonce)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("Open: want empty plaintext, got %q", got)
	}
}

func TestOpen_TamperedCiphertext(t *testing.T) {
	key := testKey(t)
	ciphertext, nonce, err := Seal(key, []byte("hunter2"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	tampered := bytes.Clone(ciphertext)
	tampered[0] ^= 0xFF

	if _, err := Open(key, tampered, nonce); err == nil {
		t.Fatal("Open: want error for tampered ciphertext, got nil")
	}
}

func TestOpen_TamperedNonce(t *testing.T) {
	key := testKey(t)
	ciphertext, nonce, err := Seal(key, []byte("hunter2"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	tampered := bytes.Clone(nonce)
	tampered[0] ^= 0xFF

	if _, err := Open(key, ciphertext, tampered); err == nil {
		t.Fatal("Open: want error for tampered nonce, got nil")
	}
}

func TestSeal_WrongKeySize(t *testing.T) {
	for _, size := range []int{0, 16, 24, 31, 33} {
		if _, _, err := Seal(make([]byte, size), []byte("x")); err == nil {
			t.Errorf("Seal: want error for %d-byte key, got nil", size)
		}
	}
}

func TestOpen_WrongKeySize(t *testing.T) {
	key := testKey(t)
	ciphertext, nonce, err := Seal(key, []byte("x"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	for _, size := range []int{0, 16, 24, 31, 33} {
		if _, err := Open(make([]byte, size), ciphertext, nonce); err == nil {
			t.Errorf("Open: want error for %d-byte key, got nil", size)
		}
	}
}

func TestOpen_WrongNonceSize(t *testing.T) {
	key := testKey(t)
	ciphertext, _, err := Seal(key, []byte("x"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	if _, err := Open(key, ciphertext, []byte("short")); err == nil {
		t.Fatal("Open: want error for wrong-size nonce, got nil")
	}
}

func TestSeal_UniqueNoncePerCall(t *testing.T) {
	key := testKey(t)
	_, nonce1, err := Seal(key, []byte("x"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	_, nonce2, err := Seal(key, []byte("x"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if bytes.Equal(nonce1, nonce2) {
		t.Fatal("Seal: two calls produced the same nonce")
	}
}
