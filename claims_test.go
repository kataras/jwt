package jwt

import (
	"testing"
	"time"
)

func TestValidateClaims(t *testing.T) {
	now := Clock()
	claims := Claims{
		Expiry:    now.Add(time.Minute).Unix(),
		NotBefore: now.Unix(),
		IssuedAt:  now.Unix(),
	}
	if err := validateClaims(now, claims); err != nil {
		t.Fatal(err)
	}
}

func TestValidateClaimsNotBefore(t *testing.T) {
	now := Clock()
	claims := Claims{
		NotBefore: now.Add(time.Minute).Unix(),
	}
	if err := validateClaims(now, claims); err != errNotValidYet {
		t.Fatalf("expected token error: %v but got: %v", errNotValidYet, err)
	}
}

func TestValidateClaimsIssuedAt(t *testing.T) {
	now := Clock()
	claims := Claims{
		IssuedAt: now.Unix(),
	}

	if err := validateClaims(now.Truncate(time.Minute), claims); err != errIssuedInTheFuture {
		t.Fatalf("expected token error: %v but got: %v", errIssuedInTheFuture, err)
	}
}

func TestValidateClaimsExpiry(t *testing.T) {
	now := Clock()
	claims := Claims{
		Expiry: now.Add(20 * time.Second).Unix(),
	}

	if err := validateClaims(now.Add(21*time.Second), claims); err != errExpired {
		t.Fatalf("expected token error: %v but got: %v", errExpired, err)
	}
}
