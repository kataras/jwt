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
		NotBefore: now.Add(2 * time.Minute).Unix(),
	}
	if err := validateClaims(now, claims); err != ErrNotValidYet {
		t.Fatalf("expected token error: %v but got: %v", ErrNotValidYet, err)
	}
}

func TestValidateClaimsIssuedAt(t *testing.T) {
	now := Clock()
	claims := Claims{
		IssuedAt: now.Unix(),
	}

	if err := validateClaims(now.Truncate(2*time.Minute), claims); err != ErrIssuedInTheFuture {
		t.Fatalf("expected token error: %v but got: %v", ErrIssuedInTheFuture, err)
	}
}

func TestValidateClaimsExpiry(t *testing.T) {
	now := Clock()
	claims := Claims{
		Expiry: now.Add(20 * time.Second).Unix(),
	}

	if err := validateClaims(now.Add(21*time.Second), claims); err != ErrExpired {
		t.Fatalf("expected token error: %v but got: %v", ErrExpired, err)
	}
}
