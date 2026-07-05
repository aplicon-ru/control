package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// AccessClaims is the payload of a short-lived, stateless JWT access
// token — never persisted (unlike refresh tokens, see session.go).
type AccessClaims struct {
	UserID int64  `json:"user_id"`
	OrgID  *int64 `json:"org_id,omitempty"`
	Role   Role   `json:"role"`
	jwt.RegisteredClaims
}

// IssueAccessToken signs a new access token for u, valid for ttl.
func IssueAccessToken(signingKey []byte, u User, ttl time.Duration) (string, error) {
	now := time.Now()
	claims := AccessClaims{
		UserID: u.ID,
		OrgID:  u.OrgID,
		Role:   u.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   u.Email,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}

	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(signingKey)
	if err != nil {
		return "", fmt.Errorf("auth: issue access token: %w", err)
	}
	return signed, nil
}

// ParseAccessToken verifies tokenString's signature and expiry and
// returns its claims. Only HS256 is accepted — WithValidMethods closes
// algorithm-confusion attacks (e.g. a forged "alg: none" token, or one
// signed with a different algorithm the caller didn't intend to trust) by
// construction rather than relying on the caller to check afterward.
func ParseAccessToken(signingKey []byte, tokenString string) (AccessClaims, error) {
	var claims AccessClaims
	token, err := jwt.ParseWithClaims(tokenString, &claims, func(*jwt.Token) (interface{}, error) {
		return signingKey, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
	if err != nil {
		return AccessClaims{}, fmt.Errorf("auth: parse access token: %w", err)
	}
	if !token.Valid {
		return AccessClaims{}, fmt.Errorf("auth: parse access token: invalid token")
	}
	return claims, nil
}
