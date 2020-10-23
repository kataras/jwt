package jwt

import (
	"context"
	"errors"
	"sync"
	"time"
)

// ErrBlocked indicates that the token has not yet expired
// but was blocked by the server's Blocklist.
var ErrBlocked = errors.New("token is blocked")

// Blocklist is an in-memory storage of tokens that should be
// immediately invalidated by the server-side.
// The most common way to invalidate a token, e.g. on user logout,
// is to make the client-side remove the token itself.
type Blocklist struct {
	entries map[string]int64 // key = token | value = expiration unix seconds (to remove expired).
	// ^ we could make it a map[*VerifiedToken]struct{} too
	// but let's have a more general usage here.
	mu sync.RWMutex
}

var _ TokenValidator = (*Blocklist)(nil)

// NewBlocklist returns a new up and running in-memory Token Blocklist.
// It accepts the clear every "x" duration. Indeed, this duration
// can match the usual tokens expiration one.
//
// A blocklist implements the `TokenValidator` interface.
func NewBlocklist(gcEvery time.Duration) *Blocklist {
	return NewBlocklistContext(context.Background(), gcEvery)
}

// NewBlocklistContext same as `NewBlocklist`
// but it also accepts a standard Go Context for GC cancelation.
func NewBlocklistContext(ctx context.Context, gcEvery time.Duration) *Blocklist {
	b := &Blocklist{
		entries: make(map[string]int64),
	}

	if gcEvery > 0 {
		go b.runGC(ctx, gcEvery)
	}

	return b
}

// ValidateToken completes the `TokenValidator` interface.
// Returns ErrBlocked if the "token" was blocked by this Blocklist.
func (b *Blocklist) ValidateToken(token []byte, _ Claims, err error) error {
	if err != nil {
		if err == ErrExpired {
			b.Del(token)
		}

		return err // respect the previous error.
	}

	if b.Has(token) {
		return ErrBlocked
	}

	return nil
}

// InvalidateToken invalidates a verified JWT token.
// It adds the request token, retrieved by Verify method, to this blocklist.
// Next request will be blocked, even if the token was not yet expired.
// This method can be used when the client-side does not clear the token
// on a user logout operation.
func (b *Blocklist) InvalidateToken(token []byte, expiry int64) {
	b.mu.Lock()
	b.entries[BytesToString(token)] = expiry
	b.mu.Unlock()
}

// Del removes a "token" from the blocklist.
func (b *Blocklist) Del(token []byte) {
	b.mu.Lock()
	delete(b.entries, BytesToString(token))
	b.mu.Unlock()
}

// Count returns the total amount of blocked tokens.
func (b *Blocklist) Count() int {
	b.mu.RLock()
	n := len(b.entries)
	b.mu.RUnlock()

	return n
}

// Has reports whether the given "token" is blocked by the server.
// This method is called before the token verification,
// so even if was expired it is removed from the blocklist.
func (b *Blocklist) Has(token []byte) bool {
	if len(token) == 0 {
		return false
	}

	b.mu.RLock()
	_, ok := b.entries[BytesToString(token)]
	b.mu.RUnlock()

	return ok
}

// GC iterates over all entries and removes expired tokens.
// This method is helpful to keep the list size small.
// Depending on the application, the GC method can be scheduled
// to called every half or a whole hour.
// A good value for a GC cron task is the Token's max age.
func (b *Blocklist) GC() int {
	now := Clock().Round(time.Second).Unix()
	var markedForDeletion []string

	b.mu.RLock()
	for token, expiry := range b.entries {
		if now > expiry {
			markedForDeletion = append(markedForDeletion, token)
		}
	}
	b.mu.RUnlock()

	n := len(markedForDeletion)
	if n > 0 {
		for _, token := range markedForDeletion {
			b.mu.Lock()
			delete(b.entries, token)
			b.mu.Unlock()
		}
	}

	return n
}

func (b *Blocklist) runGC(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)

	for {
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
			b.GC()
		}
	}
}
