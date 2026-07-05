package auth

import (
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func testUser() User {
	orgID := int64(1)
	return User{ID: 42, OrgID: &orgID, Email: "admin@example.com", Role: RoleOrgAdmin}
}

func TestIssueParseAccessToken_Roundtrip(t *testing.T) {
	key := []byte("test-signing-key")
	u := testUser()

	token, err := IssueAccessToken(key, u, time.Hour)
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}

	claims, err := ParseAccessToken(key, token)
	if err != nil {
		t.Fatalf("ParseAccessToken: %v", err)
	}
	if claims.UserID != u.ID {
		t.Errorf("UserID = %d, want %d", claims.UserID, u.ID)
	}
	if claims.Role != u.Role {
		t.Errorf("Role = %q, want %q", claims.Role, u.Role)
	}
	if claims.OrgID == nil || *claims.OrgID != *u.OrgID {
		t.Errorf("OrgID = %v, want %v", claims.OrgID, u.OrgID)
	}
}

func TestParseAccessToken_TamperedSignature(t *testing.T) {
	key := []byte("test-signing-key")
	token, err := IssueAccessToken(key, testUser(), time.Hour)
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}

	tampered := token[:len(token)-1] + "x"
	if _, err := ParseAccessToken(key, tampered); err == nil {
		t.Fatal("ParseAccessToken: want error for tampered signature, got nil")
	}
}

func TestParseAccessToken_Expired(t *testing.T) {
	key := []byte("test-signing-key")
	token, err := IssueAccessToken(key, testUser(), -time.Hour)
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}

	if _, err := ParseAccessToken(key, token); err == nil {
		t.Fatal("ParseAccessToken: want error for expired token, got nil")
	}
}

func TestParseAccessToken_WrongKey(t *testing.T) {
	token, err := IssueAccessToken([]byte("key-a"), testUser(), time.Hour)
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}

	if _, err := ParseAccessToken([]byte("key-b"), token); err == nil {
		t.Fatal("ParseAccessToken: want error for wrong key, got nil")
	}
}

func TestParseAccessToken_RejectsWrongAlgorithm(t *testing.T) {
	// Forge a token signed with HS384 instead of the HS256 this package
	// issues and requires — WithValidMethods must reject it even though
	// the signature itself is otherwise valid for that algorithm.
	key := []byte("test-signing-key")
	claims := AccessClaims{
		UserID: 1,
		Role:   RoleViewer,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	forged, err := jwt.NewWithClaims(jwt.SigningMethodHS384, claims).SignedString(key)
	if err != nil {
		t.Fatalf("sign forged token: %v", err)
	}

	if _, err := ParseAccessToken(key, forged); err == nil {
		t.Fatal("ParseAccessToken: want error for wrong algorithm, got nil")
	}
}

func TestParseAccessToken_Garbage(t *testing.T) {
	if _, err := ParseAccessToken([]byte("k"), "not.a.jwt"); err == nil {
		t.Fatal("ParseAccessToken: want error for garbage input, got nil")
	}
}

func TestParseAccessToken_EmptyString(t *testing.T) {
	if _, err := ParseAccessToken([]byte("k"), ""); err == nil {
		t.Fatal("ParseAccessToken: want error for empty input, got nil")
	}
}

func TestIssueAccessToken_LooksLikeAJWT(t *testing.T) {
	token, err := IssueAccessToken([]byte("k"), testUser(), time.Hour)
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}
	if parts := strings.Split(token, "."); len(parts) != 3 {
		t.Fatalf("IssueAccessToken: want 3 dot-separated parts, got %d", len(parts))
	}
}
