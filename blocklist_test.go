package jwt

import (
	"testing"
	"time"
)

func TestBlocklist(t *testing.T) {
	b := NewBlocklist(0)
	c := Map{"username": "kataras", "age": 27}
	sc := Claims{Expiry: Clock().Add(2 * time.Minute).Unix()}
	token, err := Sign(testAlg, testSecret, Merge(c, sc))
	if err != nil {
		t.Fatal(err)
	}

	b.InvalidateToken(token, sc.Expiry)
	if !b.Has(token) {
		t.Fatalf("expected token to be in the list")
	}

	if b.Count() != 1 {
		t.Fatalf("expected list to contain a single token entry")
	}

	if err = b.ValidateToken(token, Claims{}, nil); err != ErrBlocked {
		t.Fatalf("expected error: ErrBlock but got: %v", err)
	}

	if removed := b.GC(); removed != 0 {
		t.Fatalf("expected nothing to be removed because the expiration is before current time but got: %d", removed)
	}

	b.Del(token)

	if count := b.Count(); count != 0 {
		t.Fatalf("expected count to be zero but got: %d", count)
	}

	if err = b.ValidateToken(token, Claims{}, nil); err != nil {
		t.Fatalf("expected no error as this token is now not blocked")
	}
}
