package jwt

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// FetchPublicKeys is a single GET with no cache, no expiry and no way to fetch again when
// a token names a key it has not seen. Every service that verifies tokens against somebody
// else's key set has to build that part itself, and the two that were studied both skipped
// it: one called FetchPublicKeys once inside a constructor, so the entire fleet failed with
// ErrUnknownKid until it was restarted whenever the issuer rotated its signing key, and the
// other gave up and pasted the provider's public key into a configuration file as PEM.
//
// A KeySet is that missing piece. It holds a Keys, refreshes it, and satisfies
// HeaderValidator so it drops straight into the verification call in place of the registry.

// ErrKeySetEmpty indicates that a fetch produced a key set with no usable keys in it.
var ErrKeySetEmpty = errors.New("jwt: key set is empty")

// KeySet is a Keys that keeps itself current.
//
// It is safe for concurrent use. Reads take no lock: the key map is swapped whole, and a
// verification in flight keeps reading the map it started with. That is the reason this
// exists as a separate type rather than as locking inside Keys, which would put a mutex on
// every verification to serve the minority of callers who rotate keys at runtime.
//
// The zero value is not usable. Build one with NewRemoteKeySet or NewCognitoKeySet.
type KeySet struct {
	sourceURL string
	fetch     func() (Keys, error)

	keys atomic.Pointer[Keys]

	refreshEvery    time.Duration
	minRefreshEvery time.Duration

	mu          sync.Mutex
	lastRefresh time.Time
	stop        chan struct{}
	closeOnce   sync.Once
}

// RemoteKeySetOption configures a KeySet.
type RemoteKeySetOption func(*KeySet)

// WithRefreshInterval sets how often the key set is fetched in the background.
//
// The default is one hour. Pass zero to disable background refreshing entirely and rely on
// the unknown-key refetch below, which is enough for a provider that rotates rarely.
func WithRefreshInterval(d time.Duration) RemoteKeySetOption {
	return func(ks *KeySet) {
		ks.refreshEvery = d
	}
}

// WithMinRefreshInterval sets the shortest gap between two fetches triggered by a token
// naming an unknown key.
//
// The default is one minute. Without a floor, a stream of tokens carrying a "kid" that
// does not exist, which is a request anyone can send, becomes a stream of outbound
// requests to the identity provider.
func WithMinRefreshInterval(d time.Duration) RemoteKeySetOption {
	return func(ks *KeySet) {
		ks.minRefreshEvery = d
	}
}

// WithHTTPClient sets the client used for the fetch. It defaults to one with a 15 second
// timeout that refuses to follow a redirect away from https.
func WithHTTPClient(client HTTPClient) RemoteKeySetOption {
	return func(ks *KeySet) {
		url := ks.sourceURL
		ks.fetch = func() (Keys, error) {
			set, err := FetchJWKS(client, url)
			if err != nil {
				return nil, err
			}

			return set.PublicKeys(), nil
		}
	}
}

// NewRemoteKeySet fetches a JWKS from url and keeps it current.
//
// The first fetch happens before this returns, so a URL that is wrong, unreachable or
// serving nothing usable is an error you see at startup rather than a verification failure
// later. After that the set refreshes on a timer, and again on demand when a token names a
// key it does not hold, rate limited by WithMinRefreshInterval.
//
//	keySet, err := jwt.NewRemoteKeySet("https://auth.example.com/.well-known/jwks.json")
//	if err != nil {
//	    return err
//	}
//	defer keySet.Close()
//
//	verifiedToken, err := jwt.VerifyWithHeaderValidator(nil, nil, token, keySet.ValidateHeader)
//
// Close it when you are done, or the refresh goroutine outlives whatever created it.
func NewRemoteKeySet(url string, options ...RemoteKeySetOption) (*KeySet, error) {
	ks := &KeySet{
		sourceURL:       url,
		refreshEvery:    time.Hour,
		minRefreshEvery: time.Minute,
		stop:            make(chan struct{}),
	}

	ks.fetch = func() (Keys, error) {
		return FetchPublicKeys(url)
	}

	for _, option := range options {
		if option != nil {
			option(ks)
		}
	}

	if err := ks.Refresh(); err != nil {
		return nil, err
	}

	if ks.refreshEvery > 0 {
		go ks.run()
	}

	return ks, nil
}

// NewCognitoKeySet builds a KeySet for an AWS Cognito user pool, and the validator that
// checks a token really came from it.
//
// A JWKS URL on its own is only half of what verifying a Cognito token needs. The returned
// validator checks the issuer against the pool, and the audience against the app client, so
// a token minted for a different app client in the same pool is refused. Both services
// studied verified the signature and the clock and nothing else, which means an ID token
// issued for another client of the same pool would have been accepted.
//
//	keySet, expected, err := jwt.NewCognitoKeySet("us-east-1", "us-east-1_abc123", appClientID)
//	if err != nil {
//	    return err
//	}
//	defer keySet.Close()
//
//	verifiedToken, err := jwt.VerifyWithHeaderValidator(nil, nil, token,
//	    keySet.ValidateHeader, expected, jwt.Skew(2*time.Minute))
//
// Cognito omits "nbf" and can run a little ahead, which is why Skew belongs in that list.
func NewCognitoKeySet(region, userPoolID, appClientID string, options ...RemoteKeySetOption) (*KeySet, Expected, error) {
	if err := checkCognitoField("region", region, false); err != nil {
		return nil, Expected{}, err
	}

	if err := checkCognitoField("user pool id", userPoolID, true); err != nil {
		return nil, Expected{}, err
	}

	url := fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json", region, userPoolID)

	keySet, err := NewRemoteKeySet(url, options...)
	if err != nil {
		return nil, Expected{}, err
	}

	expected := Expected{
		Issuer: fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s", region, userPoolID),
	}
	if appClientID != "" {
		expected.Audience = Audience{appClientID}
	}

	return keySet, expected, nil
}

// Keys returns the key set as it stands. The returned map must not be modified.
func (ks *KeySet) Keys() Keys {
	if keys := ks.keys.Load(); keys != nil {
		return *keys
	}

	return nil
}

// Refresh fetches the key set now, whatever the timers say.
//
// A failed fetch leaves the previous keys in place. A provider having a bad five minutes
// should not take verification down with it, and the keys already held are almost
// certainly still the right ones.
func (ks *KeySet) Refresh() error {
	keys, err := ks.fetch()
	if err != nil {
		return err
	}

	if len(keys) == 0 {
		// PublicKeys skips any key it cannot convert, so an endpoint serving a key set
		// this package does not understand produces an empty map and no error at all. The
		// operator then sees "unknown kid" on every request rather than "the key fetch is
		// broken".
		return ErrKeySetEmpty
	}

	ks.keys.Store(&keys)

	ks.mu.Lock()
	ks.lastRefresh = Clock()
	ks.mu.Unlock()

	return nil
}

// ValidateHeader implements HeaderValidator, so a KeySet can be used anywhere a Keys can.
//
// When the token names a key the set does not hold, it fetches once and tries again. That
// is what makes a rotation invisible: the new key appears in the provider's set before the
// first token signed with it arrives, and the refetch closes the gap without a restart.
// The refetch is rate limited, because a token naming a key that will never exist is a
// request anyone can send.
func (ks *KeySet) ValidateHeader(alg string, headerDecoded []byte) (Alg, PublicKey, InjectFunc, error) {
	keys := ks.Keys()

	resultAlg, key, decrypt, err := keys.ValidateHeader(alg, headerDecoded)
	if !errors.Is(err, ErrUnknownKid) {
		return resultAlg, key, decrypt, err
	}

	if !ks.mayRefresh() {
		return nil, nil, nil, err
	}

	if refreshErr := ks.Refresh(); refreshErr != nil {
		// Report the token's problem, not the fetch's. The caller asked about a token.
		return nil, nil, nil, err
	}

	return ks.Keys().ValidateHeader(alg, headerDecoded)
}

// Verify checks a token against the current key set.
func (ks *KeySet) Verify(token []byte, validators ...TokenValidator) (*VerifiedToken, error) {
	return VerifyWithHeaderValidator(nil, nil, token, ks.ValidateHeader, validators...)
}

// Close stops the background refresh. Calling it more than once is safe, and the keys stay
// readable afterwards.
func (ks *KeySet) Close() error {
	ks.closeOnce.Do(func() {
		if ks.stop != nil {
			close(ks.stop)
		}
	})

	return nil
}

// mayRefresh reports whether enough time has passed since the last fetch to allow one
// triggered by an unknown key.
func (ks *KeySet) mayRefresh() bool {
	if ks.minRefreshEvery <= 0 {
		return true
	}

	ks.mu.Lock()
	defer ks.mu.Unlock()

	if Clock().Sub(ks.lastRefresh) < ks.minRefreshEvery {
		return false
	}

	// Claim the slot here rather than after the fetch, so that a burst of tokens naming an
	// unknown key produces one outbound request rather than one per goroutine.
	ks.lastRefresh = Clock()

	return true
}

// run refreshes on a timer until Close.
func (ks *KeySet) run() {
	t := time.NewTicker(ks.refreshEvery)
	defer t.Stop()

	for {
		select {
		case <-ks.stop:
			return
		case <-t.C:
			ks.refreshQuietly()
		}
	}
}

// refreshQuietly runs one refresh and swallows both its error and any panic.
//
// This runs on a goroutine nobody is recovering on, and a failed refresh is not an event
// worth ending the process for: the previous keys are still in place and the next tick
// will try again.
func (ks *KeySet) refreshQuietly() {
	defer func() {
		_ = recover()
	}()

	_ = ks.Refresh()
}
