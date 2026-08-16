package jwt

import (
	"errors"
	"sync"
	"testing"
	"time"
)

// A revocation that reports success and then quietly stops being a revocation is worse
// than one that fails loudly, because nothing anywhere says the session is still live.
// These tests hold that line.

func TestInvalidateTokenSurvivesGCWithoutExpiry(t *testing.T) {
	b := NewBlocklist(0) // no background GC; this test drives it directly.
	t.Cleanup(func() {
		if err := b.Close(); err != nil {
			t.Error(err)
		}
	})

	// A token with no "exp" at all. InvalidateToken used to store the zero Expiry, which
	// GC read as "expired in 1970" and deleted on the next pass.
	token, err := Sign(HS256, testSecret, map[string]any{"sub": "user", "jti": "no-expiry"})
	if err != nil {
		t.Fatal(err)
	}

	verified, err := Verify(HS256, testSecret, token)
	if err != nil {
		t.Fatal(err)
	}

	if err = b.InvalidateToken(token, verified.StandardClaims); err != nil {
		t.Fatal(err)
	}

	if removed := b.GC(); removed != 0 {
		t.Fatalf("GC removed %d entries; a revocation with no expiry must not be collected", removed)
	}

	count, err := b.Count()
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected the revocation to survive, but the blocklist holds %d entries", count)
	}

	// And the token is still refused.
	if _, err = Verify(HS256, testSecret, token, b); !errors.Is(err, ErrBlocked) {
		t.Fatalf("expected ErrBlocked but got: %v", err)
	}
}

func TestGCStillCollectsExpiredEntries(t *testing.T) {
	// The counterpart: an entry that really has expired is still removed, so the fix
	// above does not turn the blocklist into a leak for ordinary tokens.
	b := NewBlocklist(0)
	t.Cleanup(func() {
		if err := b.Close(); err != nil {
			t.Error(err)
		}
	})

	token, err := Sign(HS256, testSecret, map[string]any{"sub": "user"}, MaxAge(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}

	verified, err := Verify(HS256, testSecret, token)
	if err != nil {
		t.Fatal(err)
	}

	if err = b.InvalidateToken(token, verified.StandardClaims); err != nil {
		t.Fatal(err)
	}

	// Move the blocklist's own clock past the token's expiry rather than sleeping.
	b.Clock = func() time.Time { return time.Now().Add(time.Hour) }

	if removed := b.GC(); removed != 1 {
		t.Fatalf("expected 1 expired entry to be collected, got %d", removed)
	}

	count, err := b.Count()
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("expected an empty blocklist, got %d entries", count)
	}
}

func TestInvalidateTokenDoesNotAliasTheCallerBuffer(t *testing.T) {
	// Without a "jti" the entry key is the token itself, produced by the zero-copy
	// BytesToString. Storing that string header directly would let a caller who reuses
	// the buffer rewrite the contents of a live map key.
	b := NewBlocklist(0)
	t.Cleanup(func() {
		if err := b.Close(); err != nil {
			t.Error(err)
		}
	})

	token, err := Sign(HS256, testSecret, map[string]any{"sub": "user"})
	if err != nil {
		t.Fatal(err)
	}

	// Hand the blocklist a buffer we then scribble over, the way a pooled read buffer
	// would be reused for the next request.
	buffer := make([]byte, len(token))
	copy(buffer, token)

	verified, err := Verify(HS256, testSecret, buffer)
	if err != nil {
		t.Fatal(err)
	}

	if err = b.InvalidateToken(buffer, verified.StandardClaims); err != nil {
		t.Fatal(err)
	}

	for i := range buffer {
		buffer[i] = 'x'
	}

	// The original token must still be recognised as blocked.
	if has, err := b.Has(string(token)); err != nil || !has {
		t.Fatalf("the stored key changed with the caller's buffer: has=%v err=%v", has, err)
	}
}

func TestBlocklistZeroValueIsUsable(t *testing.T) {
	// Nothing in the type says NewBlocklist is mandatory, and every method used to
	// panic on the zero value: a nil GetKey, a nil Clock and a nil map.
	var b Blocklist

	token, err := Sign(HS256, testSecret, map[string]any{"sub": "user", "jti": "zero-value"})
	if err != nil {
		t.Fatal(err)
	}

	verified, err := Verify(HS256, testSecret, token)
	if err != nil {
		t.Fatal(err)
	}

	if err = b.InvalidateToken(token, verified.StandardClaims); err != nil {
		t.Fatal(err)
	}

	if has, err := b.Has("zero-value"); err != nil || !has {
		t.Fatalf("expected the token to be blocked: has=%v err=%v", has, err)
	}

	if b.GC() != 0 {
		t.Fatal("GC removed an entry that never expires")
	}

	if err := b.ValidateToken(token, verified.StandardClaims, nil); !errors.Is(err, ErrBlocked) {
		t.Fatalf("expected ErrBlocked but got: %v", err)
	}
}

func TestGCDoesNotDropAConcurrentRevocation(t *testing.T) {
	// GC used to collect keys under a read lock, release it, then delete each one under a
	// fresh write lock. A token revoked in that window was deleted right after it was
	// added, so it stopped being blocked with nothing reporting a problem.
	b := NewBlocklist(0)
	t.Cleanup(func() {
		if err := b.Close(); err != nil {
			t.Error(err)
		}
	})

	// Fill with entries that are already expired, so a sweep has real work to do.
	expired := Claims{ID: "", Expiry: time.Now().Add(-time.Hour).Unix()}
	for i := range 500 {
		expired.ID = "expired-" + string(rune('a'+i%26)) + string(rune('a'+i/26))
		if err := b.InvalidateToken([]byte("token"), expired); err != nil {
			t.Fatal(err)
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		b.GC()
	}()

	live := Claims{ID: "live-session", Expiry: time.Now().Add(time.Hour).Unix()}
	go func() {
		defer wg.Done()
		if err := b.InvalidateToken([]byte("live-token"), live); err != nil {
			t.Error(err)
		}
	}()

	wg.Wait()

	if has, err := b.Has("live-session"); err != nil || !has {
		t.Fatalf("a revocation made during a GC sweep was lost: has=%v err=%v", has, err)
	}
}

func TestBlocklistCloseStopsTheGoroutine(t *testing.T) {
	b := NewBlocklist(time.Millisecond)

	if err := b.Close(); err != nil {
		t.Fatal(err)
	}

	// Closing twice must not panic on a closed channel.
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}

	// The blocklist stays readable after Close.
	if _, err := b.Count(); err != nil {
		t.Fatal(err)
	}
}

func TestBlocklistGCSurvivesAPanickingClock(t *testing.T) {
	// GC calls a clock the caller owns. A panic there used to travel up the GC goroutine,
	// which nothing recovers, and take the process with it.
	b := NewBlocklistContext(t.Context(), time.Millisecond)
	t.Cleanup(func() {
		if err := b.Close(); err != nil {
			t.Error(err)
		}
	})

	b.Clock = func() time.Time { panic("the clock broke") }

	// Give the ticker several chances to fire. If the panic escaped, the test binary dies
	// here rather than failing.
	time.Sleep(50 * time.Millisecond)

	b.Clock = time.Now
	if _, err := b.Count(); err != nil {
		t.Fatal(err)
	}
}

func TestInvalidateTokenRefusesAnEmptyKey(t *testing.T) {
	// A GetKey that returns the "jti" unconditionally maps every token without one to the
	// empty key. Has refuses an empty key with ErrMissing, so the stored entry matched
	// nothing: InvalidateToken returned nil, the entry sat in the map, and ValidateToken
	// let the token straight through. A revocation that reports success and does nothing
	// is worse than one that fails.
	b := NewBlocklist(0)
	t.Cleanup(func() {
		if err := b.Close(); err != nil {
			t.Error(err)
		}
	})

	b.GetKey = func(token []byte, c Claims) string { return c.ID }

	token, err := Sign(HS256, testSecret, map[string]any{"sub": "user"}) // no jti
	if err != nil {
		t.Fatal(err)
	}

	verified, err := Verify(HS256, testSecret, token)
	if err != nil {
		t.Fatal(err)
	}

	if err = b.InvalidateToken(token, verified.StandardClaims); !errors.Is(err, ErrMissing) {
		t.Fatalf("expected ErrMissing for an unusable key but got: %v", err)
	}

	count, err := b.Count()
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("a refused revocation must not leave an entry behind, found %d", count)
	}

	// With a jti, the same blocklist works.
	withID, err := Sign(HS256, testSecret, map[string]any{"sub": "user", "jti": "session-1"})
	if err != nil {
		t.Fatal(err)
	}

	verified, err = Verify(HS256, testSecret, withID)
	if err != nil {
		t.Fatal(err)
	}

	if err = b.InvalidateToken(withID, verified.StandardClaims); err != nil {
		t.Fatal(err)
	}
	if err = b.ValidateToken(withID, verified.StandardClaims, nil); !errors.Is(err, ErrBlocked) {
		t.Fatalf("expected ErrBlocked but got: %v", err)
	}
}
