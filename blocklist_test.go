package jwt

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestBlocklist(t *testing.T) {
	b := NewBlocklist(0)
	b.GetKey = DefaultBlocklistKey

	key := "jti:1"
	c := Map{"username": "kataras", "age": 27}
	sc := Claims{Expiry: Clock().Add(2 * time.Minute).Unix(), ID: key}

	mergedClaims, err := Merge(c, sc)
	if err != nil {
		t.Fatal(err)
	}

	token, err := Sign(testAlg, testSecret, mergedClaims)
	if err != nil {
		t.Fatal(err)
	}

	if err = b.InvalidateToken(token, sc); err != nil {
		t.Fatal(err)
	}
	if has, _ := b.Has(key); !has {
		t.Fatalf("expected token to be in the list")
	}

	if count, _ := b.Count(); count != 1 {
		t.Fatalf("expected list to contain a single token entry but got: %d", count)
	}

	if err = b.ValidateToken(token, Claims{ID: key}, nil); err != ErrBlocked {
		t.Fatalf("expected error: ErrBlock but got: %v", err)
	}

	if err = b.ValidateToken(token, Claims{ID: key}, ErrExpired); err != ErrExpired {
		t.Fatalf("expected error: ErrExpired as it respects the previous one but got: %v", err)
	}

	if has, _ := b.Has(key); has {
		t.Fatalf("expected token to be removed as the validate token's error was ErrExpired")
	}

	if err = b.InvalidateToken(token, sc); err != nil {
		t.Fatal(err)
	}
	if removed := b.GC(); removed != 0 {
		t.Fatalf("expected nothing to be removed because the expiration is before current time but got: %d", removed)
	}

	if err = b.Del(key); err != nil {
		t.Fatal(err)
	}

	if count, _ := b.Count(); count != 0 {
		t.Fatalf("expected count to be zero but got: %d", count)
	}

	if err = b.ValidateToken(token, Claims{}, nil); err != nil {
		t.Fatalf("expected no error as this token is now not blocked")
	}

	// An empty token has nothing to key an entry on, so this one is expected to fail.
	if err = b.InvalidateToken([]byte{}, Claims{Expiry: 1}); !errors.Is(err, ErrMissing) {
		t.Fatalf("expected ErrMissing for an empty token but got: %v", err)
	}
	if got, _ := b.Count(); got != 0 {
		t.Fatalf("expected zero entries as the token was empty but got: %d", got)
	}

	if has, _ := b.Has(""); has {
		t.Fatalf("expected Has to always return false as the given token was empty")
	}

	// Test GC expired.
	if err = b.InvalidateToken([]byte("expired one"), Claims{Expiry: 1}); err != nil {
		t.Fatal(err)
	}
	if got, _ := b.Count(); got != 1 {
		t.Fatalf("expected upsert not append")
	}
	if removed := b.GC(); removed != 1 {
		t.Fatalf("expected one token to be removed as it's expired")
	}

	// test automatic gc
	ctx, cancel := context.WithCancel(context.Background())
	b = NewBlocklistContext(ctx, 500*time.Millisecond)
	for range 10 {
		if err = b.InvalidateToken(MustGenerateRandom(92), Claims{Expiry: Clock().Add(time.Second).Unix()}); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(2 * time.Second)
	cancel()

	if got, _ := b.Count(); got != 0 {
		t.Fatalf("expected all entries to be removed but: %d", got)
	}
}
