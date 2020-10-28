package jwt

import (
	"testing"
	"time"
)

func TestLeeway(t *testing.T) {
	l := Leeway(10 * time.Second)
	err := l.ValidateToken(nil, Claims{
		Expiry: Clock().Add(8 * time.Second).Unix(),
	}, nil)
	if err != ErrExpired {
		t.Fatalf("expected ErrExpired error but got: %v", err)
	}

	// Test respect previous error
	err = l.ValidateToken(nil, Claims{}, ErrInvalidKey)
	if err != ErrInvalidKey {
		t.Fatalf("expected to respect previous error 'ErrInvalidKey' but got: %v", err)
	}
}
