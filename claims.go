package jwt

import (
	"errors"
	"time"
)

var (
	// ErrExpired indicates that token is used after expiry time indicated in "exp" claim.
	ErrExpired = errors.New("token expired")
	// ErrNotValidYet indicates that token is used before time indicated in "nbf" claim.
	ErrNotValidYet = errors.New("token not valid yet")
	// ErrIssuedInTheFuture indicates that the "iat" claim is in the future.
	ErrIssuedInTheFuture = errors.New("token issued in the future")
)

// Claims holds the standard JWT claims (payload fields).
type Claims struct {
	NotBefore int64 `json:"nbf,omitempty"`
	IssuedAt  int64 `json:"iat,omitempty"`
	Expiry    int64 `json:"exp,omitempty"`

	ID       string   `json:"jti,omitempty"`
	Issuer   string   `json:"iss,omitempty"`
	Subject  string   `json:"sub,omitempty"`
	Audience []string `json:"aud,omitempty"`
}

// ClaimsValidator provides further claims validation.
type ClaimsValidator func(Claims) error

func validateClaims(t time.Time, claims Claims, validators ...ClaimsValidator) error {
	now := t.Unix()

	if claims.NotBefore > 0 {
		if now < claims.NotBefore {
			return ErrNotValidYet
		}
	}

	if claims.IssuedAt > 0 {
		if now < claims.IssuedAt {
			return ErrIssuedInTheFuture
		}
	}

	if claims.Expiry > 0 {
		if now > claims.Expiry {
			return ErrExpired
		}
	}

	for _, validator := range validators {
		if err := validator(claims); err != nil {
			return err
		}
	}

	return nil
}
