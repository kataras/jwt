package jwt

import (
	"errors"
	"time"
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

var (
	errExpired           = errors.New("token expired")
	errNotValidYet       = errors.New("token not valid yet")
	errIssuedInTheFuture = errors.New("token issued in the future")
)

// ClaimsValidator provides further claims validation.
type ClaimsValidator func(Claims) error

func validateClaims(t time.Time, claims Claims, validators ...ClaimsValidator) error {
	now := t.Unix()

	if claims.NotBefore > 0 {
		if now < claims.NotBefore {
			return errNotValidYet
		}
	}

	if claims.IssuedAt > 0 {
		if now < claims.IssuedAt {
			return errIssuedInTheFuture
		}
	}

	if claims.Expiry > 0 {
		if now > claims.Expiry {
			return errExpired
		}
	}

	for _, validator := range validators {
		if err := validator(claims); err != nil {
			return err
		}
	}

	return nil
}
