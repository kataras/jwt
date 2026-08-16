package jwt

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
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
	// GetKey is a function which can be used how to extract
	// the unique identifier for a token, by default
	// it checks if the "jti" is not empty, if it's then the key is the token itself.
	GetKey func(token []byte, claims Claims) string

	// clockFn is what GC reads the current time from. Held in an atomic and reached
	// through SetClock because the sweeper goroutine loads it on every tick, and the
	// caller may replace it at any point.
	//
	// This was an exported Clock field, and no caller could set it without a data race
	// once automatic garbage collection was on: NewBlocklist starts the sweeper before it
	// returns, so there was no moment left in which the write was safe.
	clockFn atomic.Pointer[func() time.Time]

	entries map[string]int64 // key = token or its ID | value = expiration unix seconds (to remove expired).
	// ^ we could make it a map[*VerifiedToken]struct{} too
	// but let's have a more general usage here.
	mu sync.RWMutex

	stop      chan struct{}
	closeOnce sync.Once
}

// neverExpires marks an entry that garbage collection must never remove.
//
// A token with no "exp" is valid forever, so its revocation has to last forever too.
// Storing the claim's zero Expiry instead meant GC saw an entry that expired in 1970 and
// deleted it on the very next tick, while InvalidateToken had already returned nil. The
// caller was told the token was revoked and it was not.
const neverExpires int64 = 1<<63 - 1

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
		GetKey:  DefaultBlocklistKey,
		stop:    make(chan struct{}),
	}

	// Take a copy of the package-level Clock now rather than reading it on every tick.
	// The sweeper below outlives this call, and a test that swaps jwt.Clock while one is
	// running would otherwise be racing it.
	b.SetClock(Clock)

	if gcEvery > 0 {
		go b.runGC(ctx, gcEvery)
	}

	return b
}

// Close stops the garbage collection goroutine started by NewBlocklist.
//
// NewBlocklist passes context.Background(), so without this the goroutine and its ticker
// live for as long as the process does. Use it when blocklists are created per test, per
// tenant, or anywhere else that is not process-wide. Calling it more than once is safe,
// and the entries stay readable afterwards.
//
// Close always returns a nil error. It returns one so that callers can defer it in the
// same shape as anything else they close.
func (b *Blocklist) Close() error {
	b.closeOnce.Do(func() {
		if b.stop != nil {
			close(b.stop)
		}
	})

	return nil
}

// SetClock sets the clock garbage collection reads the current time from, replacing the
// package-level Clock for this blocklist alone. Pass nil to go back to it.
//
// This is a method rather than a field because automatic garbage collection reads the
// clock from a goroutine of its own, started before NewBlocklist returns. Calling this at
// any point is safe, including while that sweeper is mid-tick:
//
//	b := jwt.NewBlocklist(time.Hour)
//	b.SetClock(func() time.Time { return time.Now().UTC() })
func (b *Blocklist) SetClock(fn func() time.Time) {
	if fn == nil {
		b.clockFn.Store(nil)
		return
	}

	b.clockFn.Store(&fn)
}

// clock reports the current time, falling back to the package-level Clock so that a
// zero-value Blocklist works instead of panicking on a nil function.
func (b *Blocklist) clock() time.Time {
	if fn := b.clockFn.Load(); fn != nil {
		return (*fn)()
	}

	return Clock()
}

// getKey extracts the entry key for a token, falling back to DefaultBlocklistKey for the
// same reason as clock.
func (b *Blocklist) getKey(token []byte, c Claims) string {
	if b.GetKey != nil {
		return b.GetKey(token, c)
	}

	return DefaultBlocklistKey(token, c)
}

// DefaultBlocklistKey extracts the entry key for a token. It is what Blocklist.GetKey
// does unless you replace it.
//
// The key is the "jti" claim when the token carries one, and the whole token otherwise.
// That fallback is the part worth knowing about: an implementation that returns the "jti"
// unconditionally maps every token without one to the empty key, so revoking a single
// session blocks every session that also lacks a "jti". Storage backends written against
// this package have shipped that bug. Call this rather than reimplementing it.
//
// Give your tokens a "jti". The fallback keeps whole bearer credentials, signature
// included, in memory for as long as the entry lives.
func DefaultBlocklistKey(token []byte, c Claims) string {
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
	key := b.getKey(token, c)
	if err != nil {
		if errors.Is(err, ErrExpired) {
			// Opportunistic cleanup of an entry whose token has expired on its own, not the
			// revocation itself. The token is already refused by the error returned just
			// below, and that error has to reach the caller unchanged so that
			// errors.Is(err, ErrExpired) still holds, so there is nowhere here to report a
			// failure to. Del never returns one, and an entry left behind is collected by
			// the next GC pass.
			_ = b.Del(key)
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

	key := b.getKey(token, c)
	if key == "" {
		// An empty key cannot be looked up: Has refuses it with ErrMissing, so the entry
		// would sit in the map and match nothing. Storing it and returning nil is the
		// worst of both, and it is what happened with a GetKey that returned the "jti"
		// unconditionally: InvalidateToken reported success, the session stayed live, and
		// nothing anywhere said so.
		return fmt.Errorf("%w: the key function returned an empty key, so this token "+
			"cannot be blocked; give it a jti or use DefaultBlocklistKey", ErrMissing)
	}

	// A token with no usable "exp" never expires, so neither may its revocation.
	expiry := c.Expiry
	if expiry <= 0 {
		expiry = neverExpires
	}

	// Copy the key before it becomes a map key. When the token carries no "jti" the key
	// is BytesToString(token), which shares the caller's buffer: storing that string
	// header means a caller who reuses the buffer silently rewrites the contents of an
	// existing map key. Copying costs one allocation on a path that runs once per
	// revocation, not once per request.
	key = strings.Clone(key)

	b.mu.Lock()
	if b.entries == nil {
		b.entries = make(map[string]int64)
	}
	b.entries[key] = expiry
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
	now := b.clock().Round(time.Second).Unix()

	// One write lock for the whole sweep, and deletion while ranging, which Go allows.
	// The previous form collected under a read lock, released it, then took a write lock
	// per key: a token revoked in that window was deleted immediately afterwards and
	// silently stopped being blocked. Holding the lock for the sweep costs latency
	// proportional to the number of entries, which is the number of revocations still
	// inside their lifetime, and buys back a revocation that cannot be lost.
	b.mu.Lock()
	defer b.mu.Unlock()

	var n int
	for token, expiry := range b.entries {
		if expiry == neverExpires {
			continue
		}

		if now > expiry {
			delete(b.entries, token)
			n++
		}
	}

	return n
}

// runGC is the internal goroutine that performs automatic garbage collection.
// It runs in a separate goroutine and can be stopped via context cancellation.
func (b *Blocklist) runGC(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-b.stop:
			return
		case <-t.C:
			b.collect()
		}
	}
}

// collect runs one GC pass and swallows a panic from it.
//
// GC calls the clock from SetClock, which the caller owns. A panic there would otherwise
// travel up a goroutine nobody is recovering on and take the whole process down, which is
// an unreasonable outcome for a cleanup tick. Skipping one pass is not.
func (b *Blocklist) collect() {
	defer func() {
		_ = recover()
	}()

	b.GC()
}

// TokenBlocklist is the method set of *Blocklist.
//
// The concrete type is the only thing this package exported, so anything wanting to accept
// either the in-memory blocklist or its own Redis-backed one had to declare this interface
// itself. At least one downstream package did, in a file whose entire contents were this
// declaration.
//
// Accept this rather than *Blocklist:
//
//	func NewVerifier(keys jwt.Keys, blocklist jwt.TokenBlocklist) *Verifier
//
// An implementation of your own should call DefaultBlocklistKey rather than deriving the
// key itself. Getting that wrong has taken a production system down: returning the "jti"
// unconditionally maps every token without one to the empty key, so one logout blocked
// every session in the system.
type TokenBlocklist interface {
	TokenValidator

	// InvalidateToken revokes a token.
	InvalidateToken(token []byte, c Claims) error
	// Del removes an entry by key.
	Del(key string) error
	// Has reports whether a key is blocked.
	Has(key string) (bool, error)
	// Count reports how many entries are held.
	Count() (int64, error)
}

var _ TokenBlocklist = (*Blocklist)(nil)
