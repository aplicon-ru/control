package auth

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// passwordHashCost is bumped above bcrypt.DefaultCost (10) since this
// guards Super Admin / Org Admin accounts directly — still fast enough in
// 2026 while adding meaningful brute-force resistance.
const passwordHashCost = 12

// HashPassword returns a bcrypt hash of plaintext suitable for storing in
// users.password_hash.
func HashPassword(plaintext string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(plaintext), passwordHashCost)
	if err != nil {
		return "", fmt.Errorf("auth: hash password: %w", err)
	}
	return string(hash), nil
}

// VerifyPassword returns nil if plaintext matches hash, and a non-nil
// error otherwise (mismatch or malformed hash).
func VerifyPassword(hash, plaintext string) error {
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(plaintext)); err != nil {
		return fmt.Errorf("auth: verify password: %w", err)
	}
	return nil
}
