package jwt

import (
	"context"
	"errors"
	"sync"
	"time"
)

// ErrBlocked indicates that the token has not yet expired
// but was blocked by the server's Blocklist.
var ErrBlocked = errors.New("jwt: token is blocked")

// Blocklist is an in-memory storage system for invalidated JWT tokens.
// It provides server-side token revocation capabilities, which is essential
// for scenarios like user logout, account suspension, or security breaches.
//
// The Blocklist maintains a thread-safe map of token identifiers to expiration times,
// automatically cleaning up expired entries to prevent memory leaks.
//
// While client-side token removal is the most common invalidation method,
// server-side blocklisting provides an additional security layer for cases where:
//   - Users cannot be trusted to remove tokens
//   - Tokens may have been compromised
//   - Immediate revocation is required
//
// Custom storage backends (Redis, database, etc.) can be implemented by
// satisfying the TokenValidator interface for distributed applications.
//
// Example:
//
//	// Create a blocklist with hourly cleanup
//	blocklist := jwt.NewBlocklist(1 * time.Hour)
//
//	// Use in token verification
//	verifiedToken, err := jwt.Verify(alg, key, token, blocklist)
//
//	// Invalidate a token (e.g., on logout)
//	err = blocklist.InvalidateToken(token, verifiedToken.StandardClaims)
type Blocklist struct {
	Clock func() time.Time
	// GetKey is a function which can be used how to extract
	// the unique identifier for a token, by default
	// it checks if the "jti" is not empty, if it's then the key is the token itself.
	GetKey func(token []byte, claims Claims) string

	entries map[string]int64 // key = token or its ID | value = expiration unix seconds (to remove expired).
	// ^ we could make it a map[*VerifiedToken]struct{} too
	// but let's have a more general usage here.
	mu sync.RWMutex
}

var _ TokenValidator = (*Blocklist)(nil)

// NewBlocklist creates a new in-memory token blocklist with automatic garbage collection.
//
// The gcEvery parameter controls how frequently expired tokens are removed from memory.
// A good value is typically the same as your token expiration time (e.g., 1 hour).
// Pass 0 to disable automatic garbage collection.
//
// The returned Blocklist implements the TokenValidator interface and can be passed
// directly to Verify functions.
//
// Example:
//
//	// Cleanup every hour
//	blocklist := jwt.NewBlocklist(1 * time.Hour)
//
//	// No automatic cleanup (manual GC required)
//	blocklist := jwt.NewBlocklist(0)
func NewBlocklist(gcEvery time.Duration) *Blocklist {
	return NewBlocklistContext(context.Background(), gcEvery)
}

// NewBlocklistContext creates a new in-memory token blocklist with context-aware garbage collection.
//
// This function is identical to NewBlocklist but accepts a context for controlling
// the garbage collection goroutine lifecycle. When the context is canceled,
// the GC goroutine will stop gracefully.
//
// This is useful in applications where you need to coordinate shutdown or
// want to control the blocklist lifecycle explicitly.
//
// Example:
//
//	ctx, cancel := context.WithCancel(context.Background())
//	defer cancel()
//
//	blocklist := jwt.NewBlocklistContext(ctx, 1*time.Hour)
//	// GC will stop when cancel() is called
func NewBlocklistContext(ctx context.Context, gcEvery time.Duration) *Blocklist {
	b := &Blocklist{
		entries: make(map[string]int64),
		Clock:   Clock,
		GetKey:  defaultGetKey,
	}

	if gcEvery > 0 {
		go b.runGC(ctx, gcEvery)
	}

	return b
}

// defaultGetKey extracts a unique identifier from a token for blocklist storage.
// It prefers the "jti" (JWT ID) claim if present, otherwise uses the full token.
// This function can be customized by setting the Blocklist.GetKey field.
func defaultGetKey(token []byte, c Claims) string {
	if c.ID != "" {
		return c.ID
	}

	return BytesToString(token)
}

// ValidateToken implements the TokenValidator interface.
// It checks if the token is present in the blocklist and returns ErrBlocked if found.
//
// This method also performs automatic cleanup by removing expired blocked tokens
// when they encounter an ErrExpired error during normal validation.
//
// The validation flow:
//  1. If there's a previous validation error (like expiration), handle cleanup
//  2. Check if the token key exists in the blocklist
//  3. Return ErrBlocked if found, otherwise allow the token
func (b *Blocklist) ValidateToken(token []byte, c Claims, err error) error {
	key := b.GetKey(token, c)
	if err != nil {
		if err == ErrExpired {
			b.Del(key)
		}

		return err // respect the previous error.
	}

	if has, _ := b.Has(key); has {
		return ErrBlocked
	}

	return nil
}

// InvalidateToken adds a JWT token to the blocklist, preventing its future use.
//
// This method extracts the token's unique identifier using the configured GetKey function
// and stores it with the token's expiration time for automatic cleanup.
//
// Common use cases:
//   - User logout when client-side token removal cannot be guaranteed
//   - Immediate token revocation due to security concerns
//   - Account suspension or privilege changes
//   - Compromised token scenarios
//
// The token will be blocked until its natural expiration time, after which
// it will be automatically removed during garbage collection.
//
// Example:
//
//	// After successful logout
//	err := blocklist.InvalidateToken(token, verifiedToken.StandardClaims)
//	if err != nil {
//	    log.Printf("Failed to blocklist token: %v", err)
//	}
func (b *Blocklist) InvalidateToken(token []byte, c Claims) error {
	if len(token) == 0 {
		return ErrMissing
	}

	key := b.GetKey(token, c)

	b.mu.Lock()
	b.entries[key] = c.Expiry
	b.mu.Unlock()

	return nil
}

// Del removes a token from the blocklist by its key.
// This method can be used to manually unblock a token or for cleanup operations.
//
// The key should be the same identifier used by the GetKey function
// (typically the "jti" claim or the full token).
func (b *Blocklist) Del(key string) error {
	b.mu.Lock()
	delete(b.entries, key)
	b.mu.Unlock()

	return nil
}

// Count returns the total number of currently blocked tokens in memory.
// This can be useful for monitoring and debugging purposes.
func (b *Blocklist) Count() (int64, error) {
	b.mu.RLock()
	n := len(b.entries)
	b.mu.RUnlock()

	return int64(n), nil
}

// Has checks whether a token key is currently blocked.
//
// This method performs a read-only check without modifying the blocklist.
// It's primarily used internally by ValidateToken, but can also be used
// for external checks or debugging.
//
// Returns false if the key is empty, true if the key is found in the blocklist.
func (b *Blocklist) Has(key string) (bool, error) {
	if len(key) == 0 {
		return false, ErrMissing
	}

	b.mu.RLock()
	_, ok := b.entries[key]
	b.mu.RUnlock()

	return ok, nil
}

// GC performs garbage collection by removing expired tokens from the blocklist.
//
// This method compares each token's expiration time against the current time
// and removes entries that have naturally expired. This prevents memory leaks
// in long-running applications.
//
// Returns the number of tokens that were removed.
//
// While automatic GC is typically enabled via NewBlocklist, this method can be
// called manually for:
//   - Applications with custom GC scheduling requirements
//   - Memory pressure situations requiring immediate cleanup
//   - Testing and debugging scenarios
//
// Example:
//
//	// Manual cleanup
//	removed := blocklist.GC()
//	log.Printf("Cleaned up %d expired tokens", removed)
func (b *Blocklist) GC() int {
	now := b.Clock().Round(time.Second).Unix()
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

// runGC is the internal goroutine that performs automatic garbage collection.
// It runs in a separate goroutine and can be stopped via context cancellation.
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
