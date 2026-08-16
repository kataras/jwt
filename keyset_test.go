package jwt

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// rotatingClient serves a JWKS that the test can change, and counts fetches.
type rotatingClient struct {
	mu    sync.Mutex
	body  string
	fails bool

	fetches atomic.Int64
}

func (c *rotatingClient) Get(url string) (*http.Response, error) {
	c.fetches.Add(1)

	c.mu.Lock()
	body, fails := c.body, c.fails
	c.mu.Unlock()

	if fails {
		return &http.Response{
			StatusCode: http.StatusInternalServerError,
			Body:       io.NopCloser(strings.NewReader("upstream is unwell")),
		}, nil
	}

	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(body)),
	}, nil
}

func (c *rotatingClient) serve(body string, fails bool) {
	c.mu.Lock()
	c.body, c.fails = body, fails
	c.mu.Unlock()
}

// jwksFor builds a key set document from the test RSA key under the given identifiers.
func jwksFor(t *testing.T, kids ...string) string {
	t.Helper()

	_, rsaPublic := MustLoadRSA("./_testfiles/rsa_private_key.pem", "./_testfiles/rsa_public_key.pem")

	set := JWKS{}
	for _, kid := range kids {
		jwk, err := GenerateJWK(kid, "RS256", rsaPublic)
		if err != nil {
			t.Fatal(err)
		}
		set.Keys = append(set.Keys, jwk)
	}

	b, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}

	return string(b)
}

func TestKeySetRefetchesWhenAKeyIsUnknown(t *testing.T) {
	// The failure this prevents: an issuer rotates its signing key, every instance in the
	// fleet has a key set from before the rotation, and every request fails with
	// ErrUnknownKid until somebody restarts the process.
	rsaPrivate, _ := MustLoadRSA("./_testfiles/rsa_private_key.pem", "./_testfiles/rsa_public_key.pem")

	client := &rotatingClient{}
	client.serve(jwksFor(t, "key-one"), false)

	keySet, err := NewRemoteKeySet("https://auth.example.com/keys",
		WithHTTPClient(client),
		WithRefreshInterval(0),    // no background timer; this test drives it
		WithMinRefreshInterval(0), // and no rate limit, so the refetch is immediate
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := keySet.Close(); err != nil {
			t.Error(err)
		}
	})

	if got := client.fetches.Load(); got != 1 {
		t.Fatalf("expected one fetch at construction, got %d", got)
	}

	// A token under the key we already hold verifies without another fetch.
	oldToken, err := SignWithHeader(RS256, rsaPrivate, map[string]any{"sub": "user"},
		HeaderWithKid{Kid: "key-one", Alg: "RS256"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = keySet.Verify(oldToken); err != nil {
		t.Fatal(err)
	}
	if got := client.fetches.Load(); got != 1 {
		t.Fatalf("a known key must not trigger a fetch, got %d", got)
	}

	// The issuer rotates. A token under the new key arrives before anything told us.
	newToken, err := SignWithHeader(RS256, rsaPrivate, map[string]any{"sub": "user"},
		HeaderWithKid{Kid: "key-two", Alg: "RS256"})
	if err != nil {
		t.Fatal(err)
	}

	client.serve(jwksFor(t, "key-one", "key-two"), false)

	if _, err = keySet.Verify(newToken); err != nil {
		t.Fatalf("the rotated key should have been picked up: %v", err)
	}
	if got := client.fetches.Load(); got != 2 {
		t.Fatalf("expected a refetch for the unknown key, got %d fetches", got)
	}
}

func TestKeySetRateLimitsTheUnknownKeyRefetch(t *testing.T) {
	// A token naming a key that will never exist is a request anyone can send, so the
	// refetch it triggers has to have a floor under it.
	client := &rotatingClient{}
	client.serve(jwksFor(t, "key-one"), false)

	keySet, err := NewRemoteKeySet("https://auth.example.com/keys",
		WithHTTPClient(client),
		WithRefreshInterval(0),
		WithMinRefreshInterval(time.Hour),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := keySet.Close(); err != nil {
			t.Error(err)
		}
	})

	forged := craftToken(`{"kid":"never-existed","alg":"RS256"}`, `{"sub":"attacker"}`, "sig")

	for range 20 {
		if _, err = keySet.Verify(forged); !errors.Is(err, ErrUnknownKid) {
			t.Fatalf("expected ErrUnknownKid but got: %v", err)
		}
	}

	if got := client.fetches.Load(); got != 1 {
		t.Fatalf("20 tokens naming an unknown key produced %d fetches", got)
	}
}

func TestKeySetKeepsTheOldKeysWhenARefreshFails(t *testing.T) {
	// An identity provider having a bad five minutes must not take verification down with
	// it. The keys already held are almost certainly still correct.
	rsaPrivate, _ := MustLoadRSA("./_testfiles/rsa_private_key.pem", "./_testfiles/rsa_public_key.pem")

	client := &rotatingClient{}
	client.serve(jwksFor(t, "key-one"), false)

	keySet, err := NewRemoteKeySet("https://auth.example.com/keys",
		WithHTTPClient(client), WithRefreshInterval(0), WithMinRefreshInterval(0))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := keySet.Close(); err != nil {
			t.Error(err)
		}
	})

	client.serve("", true)

	if err = keySet.Refresh(); err == nil {
		t.Fatal("expected the failing fetch to be reported")
	}

	token, err := SignWithHeader(RS256, rsaPrivate, map[string]any{"sub": "user"},
		HeaderWithKid{Kid: "key-one", Alg: "RS256"})
	if err != nil {
		t.Fatal(err)
	}

	if _, err = keySet.Verify(token); err != nil {
		t.Fatalf("verification must survive a failed refresh: %v", err)
	}
}

func TestNewRemoteKeySetReportsAnEmptySetAtStartup(t *testing.T) {
	// PublicKeys skips every key it cannot convert and returns no error, so a provider
	// serving something this package does not understand used to look like a provider
	// with no keys, and the operator saw "unknown kid" on every request instead.
	client := &rotatingClient{}
	client.serve(`{"keys":[{"kty":"RSA","kid":"broken","n":"!!!","e":"AQAB"}]}`, false)

	if _, err := NewRemoteKeySet("https://auth.example.com/keys", WithHTTPClient(client)); !errors.Is(err, ErrKeySetEmpty) {
		t.Fatalf("expected ErrKeySetEmpty but got: %v", err)
	}

	// A failing endpoint is reported at construction too, rather than at the first
	// verification hours later.
	client.serve("", true)
	if _, err := NewRemoteKeySet("https://auth.example.com/keys", WithHTTPClient(client)); err == nil {
		t.Fatal("expected the unreachable endpoint to be reported")
	}
}

func TestNewCognitoKeySetBuildsTheIssuerAndAudienceChecks(t *testing.T) {
	client := &rotatingClient{}
	client.serve(jwksFor(t, "cognito-key"), false)

	keySet, expected, err := NewCognitoKeySet("us-east-1", "us-east-1_abc123", "the-app-client",
		WithHTTPClient(client), WithRefreshInterval(0))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := keySet.Close(); err != nil {
			t.Error(err)
		}
	})

	if expected.Issuer != "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_abc123" {
		t.Fatalf("issuer: %q", expected.Issuer)
	}
	if len(expected.Audience) != 1 || expected.Audience[0] != "the-app-client" {
		t.Fatalf("audience: %v", expected.Audience)
	}

	// A token minted for another app client of the same pool is refused, which is the
	// check both studied services were missing.
	rsaPrivate, _ := MustLoadRSA("./_testfiles/rsa_private_key.pem", "./_testfiles/rsa_public_key.pem")

	otherClient, err := SignWithHeader(RS256, rsaPrivate, map[string]any{
		"sub": "user",
		"iss": expected.Issuer,
		"aud": "a-different-app-client",
	}, HeaderWithKid{Kid: "cognito-key", Alg: "RS256"})
	if err != nil {
		t.Fatal(err)
	}

	if _, err = keySet.Verify(otherClient, expected); !errors.Is(err, ErrExpected) {
		t.Fatalf("expected ErrExpected but got: %v", err)
	}

	// The right app client passes.
	ours, err := SignWithHeader(RS256, rsaPrivate, map[string]any{
		"sub": "user",
		"iss": expected.Issuer,
		"aud": "the-app-client",
	}, HeaderWithKid{Kid: "cognito-key", Alg: "RS256"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = keySet.Verify(ours, expected); err != nil {
		t.Fatal(err)
	}

	// The region and pool are still validated before they reach a URL.
	if _, _, err = NewCognitoKeySet("evil.com/x", "us-east-1_abc", "client"); err == nil {
		t.Fatal("expected the region to be refused")
	}
}

func TestKeySetIsSafeUnderConcurrentUse(t *testing.T) {
	rsaPrivate, _ := MustLoadRSA("./_testfiles/rsa_private_key.pem", "./_testfiles/rsa_public_key.pem")

	client := &rotatingClient{}
	client.serve(jwksFor(t, "key-one"), false)

	keySet, err := NewRemoteKeySet("https://auth.example.com/keys",
		WithHTTPClient(client), WithRefreshInterval(0), WithMinRefreshInterval(0))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := keySet.Close(); err != nil {
			t.Error(err)
		}
	})

	token, err := SignWithHeader(RS256, rsaPrivate, map[string]any{"sub": "user"},
		HeaderWithKid{Kid: "key-one", Alg: "RS256"})
	if err != nil {
		t.Fatal(err)
	}

	// Verify from many goroutines while the key set is replaced underneath them. This is
	// the case that a plain map cannot survive, and the reason KeySet exists as its own
	// type rather than as a lock inside Keys.
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 200 {
				if _, err := keySet.Verify(token); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for range 50 {
			_ = keySet.Refresh()
		}
	}()

	wg.Wait()
}
