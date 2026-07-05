package auth

import "testing"

func TestHashVerifyPassword_Roundtrip(t *testing.T) {
	hash, err := HashPassword("hunter2")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if hash == "hunter2" {
		t.Fatal("HashPassword: returned the plaintext unchanged")
	}
	if err := VerifyPassword(hash, "hunter2"); err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
}

func TestVerifyPassword_WrongPassword(t *testing.T) {
	hash, err := HashPassword("hunter2")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if err := VerifyPassword(hash, "wrong"); err == nil {
		t.Fatal("VerifyPassword: want error for wrong password, got nil")
	}
}

func TestVerifyPassword_MalformedHash(t *testing.T) {
	if err := VerifyPassword("not a bcrypt hash", "anything"); err == nil {
		t.Fatal("VerifyPassword: want error for malformed hash, got nil")
	}
}

func TestHashPassword_TooLong(t *testing.T) {
	// bcrypt rejects plaintext over 72 bytes.
	long := make([]byte, 100)
	for i := range long {
		long[i] = 'a'
	}
	if _, err := HashPassword(string(long)); err == nil {
		t.Fatal("HashPassword: want error for >72 byte password, got nil")
	}
}
