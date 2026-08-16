package jwt

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// These cover the helpers added because three separate downstream codebases had written
// them by hand, each slightly differently.

func TestExtractToken(t *testing.T) {
	newRequest := func(target string) *http.Request {
		return httptest.NewRequest(http.MethodGet, target, nil)
	}

	t.Run("bearer header", func(t *testing.T) {
		r := newRequest("/")
		r.Header.Set("Authorization", "Bearer the.token.here")

		if got := string(ExtractToken(r)); got != "the.token.here" {
			t.Fatalf("got %q", got)
		}
	})

	t.Run("scheme is case insensitive", func(t *testing.T) {
		for _, scheme := range []string{"Bearer", "bearer", "BEARER", "BeArEr"} {
			r := newRequest("/")
			r.Header.Set("Authorization", scheme+" the.token.here")

			if got := string(ExtractToken(r)); got != "the.token.here" {
				t.Fatalf("%s: got %q", scheme, got)
			}
		}
	})

	t.Run("a token containing a space is not truncated", func(t *testing.T) {
		// One downstream extractor split on every space and rejected this; another split
		// on the first and accepted it. Same comment above both, different behaviour.
		r := newRequest("/")
		r.Header.Set("Authorization", "Bearer has a space")

		if got := string(ExtractToken(r)); got != "has a space" {
			t.Fatalf("got %q", got)
		}
	})

	t.Run("bare token with no scheme", func(t *testing.T) {
		r := newRequest("/")
		r.Header.Set("Authorization", "the.token.here")

		if got := string(ExtractToken(r)); got != "the.token.here" {
			t.Fatalf("got %q", got)
		}
	})

	t.Run("another scheme is ignored", func(t *testing.T) {
		r := newRequest("/")
		r.Header.Set("Authorization", "Basic dXNlcjpwYXNz")

		if got := ExtractToken(r); got != nil {
			t.Fatalf("expected nothing, got %q", got)
		}
	})

	t.Run("several headers, in order", func(t *testing.T) {
		r := newRequest("/")
		r.Header.Set("X-Authorization", "Bearer from.the.second")

		extract := FromHeader("Authorization", "X-Authorization")
		if got := string(ExtractToken(r, extract)); got != "from.the.second" {
			t.Fatalf("got %q", got)
		}
	})

	t.Run("query and cookie", func(t *testing.T) {
		r := newRequest("/?access_token=from.the.query")
		if got := string(ExtractToken(r, FromQuery())); got != "from.the.query" {
			t.Fatalf("query: got %q", got)
		}

		r = newRequest("/")
		r.AddCookie(&http.Cookie{Name: "session", Value: "from.the.cookie"})
		if got := string(ExtractToken(r, FromCookie("session"))); got != "from.the.cookie" {
			t.Fatalf("cookie: got %q", got)
		}
	})

	t.Run("first extractor with a value wins", func(t *testing.T) {
		r := newRequest("/?access_token=from.the.query")
		r.Header.Set("Authorization", "Bearer from.the.header")

		if got := string(ExtractToken(r, FromHeader(), FromQuery())); got != "from.the.header" {
			t.Fatalf("got %q", got)
		}

		if got := string(ExtractToken(r, FromQuery(), FromHeader())); got != "from.the.query" {
			t.Fatalf("reversed: got %q", got)
		}
	})

	t.Run("nothing anywhere", func(t *testing.T) {
		r := newRequest("/")
		if got := ExtractToken(r, FromHeader(), FromQuery(), FromCookie("session")); got != nil {
			t.Fatalf("expected nothing, got %q", got)
		}

		// A missing token and a bad one arrive at the same place.
		if _, err := Verify(HS256, testSecret, ExtractToken(r)); !errors.Is(err, ErrMissing) {
			t.Fatalf("expected ErrMissing but got: %v", err)
		}
	})
}

func TestClassify(t *testing.T) {
	for _, tt := range []struct {
		err  error
		want ErrorKind
	}{
		{nil, KindNone},
		{ErrMissing, KindMalformed},
		{ErrTokenForm, KindMalformed},
		{ErrTokenSize, KindMalformed},
		{ErrExpired, KindExpired},
		{ErrNotValidYet, KindExpired},
		{ErrIssuedInTheFuture, KindExpired},
		{ErrBlocked, KindRejected},
		{ErrExpected, KindRejected},
		{ErrMissingExpiry, KindRejected},
		{ErrTokenSignature, KindInvalid},
		{errPayloadNotJSON, KindMalformed},
		{base64.CorruptInputError(0), KindMalformed},
		{ErrTokenAlg, KindInvalid},
		{ErrInvalidKey, KindInvalid},
		{ErrUnknownKid, KindInvalid},
		{ErrEmptyKid, KindInvalid},
		{ErrDecrypt, KindInvalid},
		{errors.New("something else entirely"), KindInvalid},
	} {
		if got := Classify(tt.err); got != tt.want {
			t.Errorf("%v: expected %s but got %s", tt.err, tt.want, got)
		}

		// A wrapped error classifies the same way.
		if tt.err != nil {
			wrapped := errors.New("outer: " + tt.err.Error())
			_ = wrapped
			if got := Classify(errWrap(tt.err)); got != tt.want {
				t.Errorf("wrapped %v: expected %s but got %s", tt.err, tt.want, got)
			}
		}
	}

	// End to end: an expired token classifies as something the client can fix.
	token, err := Sign(HS256, testSecret, map[string]any{"sub": "user", "exp": time.Now().Add(-time.Hour).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	_, err = Verify(HS256, testSecret, token)
	if got := Classify(err); got != KindExpired {
		t.Fatalf("expected KindExpired but got %s (%v)", got, err)
	}
}

type wrappedError struct{ err error }

func (w wrappedError) Error() string { return "wrapped: " + w.err.Error() }
func (w wrappedError) Unwrap() error { return w.err }

func errWrap(err error) error { return wrappedError{err: err} }

func TestSkewCoversNotBeforeAndIssuedAt(t *testing.T) {
	// Future only ever rescued "iat", and validateClaims checks "nbf" first and stops
	// there, so a token whose issuer set both could not be rescued at all.
	ahead := time.Now().Add(30 * time.Second)

	token, err := Sign(HS256, testSecret, map[string]any{
		"sub": "user",
		"nbf": ahead.Unix(),
		"iat": ahead.Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err = Verify(HS256, testSecret, token); !errors.Is(err, ErrNotValidYet) {
		t.Fatalf("without tolerance: expected ErrNotValidYet but got: %v", err)
	}

	// Future cannot help here, which is the whole point.
	if _, err = Verify(HS256, testSecret, token, Future(time.Hour)); !errors.Is(err, ErrNotValidYet) {
		t.Fatalf("Future must not rescue nbf: %v", err)
	}

	if _, err = Verify(HS256, testSecret, token, Skew(time.Minute)); err != nil {
		t.Fatalf("Skew must rescue both: %v", err)
	}

	// Not beyond the tolerance, though.
	if _, err = Verify(HS256, testSecret, token, Skew(time.Second)); !errors.Is(err, ErrNotValidYet) {
		t.Fatalf("expected the token to stay rejected: %v", err)
	}

	// And a token that is expired is not rescued by a clock correction.
	expired, err := Sign(HS256, testSecret, map[string]any{"sub": "user", "exp": time.Now().Add(-time.Hour).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Verify(HS256, testSecret, expired, Skew(2*time.Hour)); !errors.Is(err, ErrExpired) {
		t.Fatalf("Skew must not extend an expired token: %v", err)
	}
}

func TestValidatorsCollectsMixedTypes(t *testing.T) {
	// Go will not convert a []TokenValidatorFunc into a []TokenValidator, so every call
	// site copied element by element.
	funcs := []TokenValidatorFunc{Plain, Skew(time.Minute)}
	var nilValidator TokenValidator

	got := Validators(funcs, nilValidator, nil, RequireExpiry, Expected{Issuer: "us"})
	if len(got) != 4 {
		t.Fatalf("expected 4 validators, got %d", len(got))
	}

	// They still work in the order given.
	token, err := Sign(HS256, testSecret, map[string]any{"sub": "user"}, MaxAge(time.Hour), Issuer("us"))
	if err != nil {
		t.Fatal(err)
	}

	if _, err = Verify(HS256, testSecret, token, Validators(funcs, RequireExpiry, Expected{Issuer: "us"})...); err != nil {
		t.Fatal(err)
	}

	if _, err = Verify(HS256, testSecret, token, Validators(Expected{Issuer: "somebody-else"})...); !errors.Is(err, ErrExpected) {
		t.Fatalf("expected ErrExpected but got: %v", err)
	}
}

func TestSignOptionShorthands(t *testing.T) {
	issuedAt := time.Now().Add(-time.Minute)
	expiresAt := time.Now().Add(time.Hour)

	token, err := Sign(HS256, testSecret, map[string]any{"role": "admin"},
		ID("the-jti"),
		OriginID("the-origin"),
		Issuer("auth.example.com"),
		Subject("user-42"),
		IssuedAt(issuedAt),
		ExpiresAt(expiresAt),
	)
	if err != nil {
		t.Fatal(err)
	}

	verified, err := Verify(HS256, testSecret, token)
	if err != nil {
		t.Fatal(err)
	}

	c := verified.StandardClaims
	if c.ID != "the-jti" || c.OriginID != "the-origin" {
		t.Fatalf("identifiers: %+v", c)
	}
	if c.Issuer != "auth.example.com" || c.Subject != "user-42" {
		t.Fatalf("issuer or subject: %+v", c)
	}
	if c.IssuedAt != issuedAt.Round(time.Second).Unix() {
		t.Fatalf("iat: %d", c.IssuedAt)
	}
	if c.Expiry != expiresAt.Round(time.Second).Unix() {
		t.Fatalf("exp: %d", c.Expiry)
	}

	// NotBefore in the future keeps the token out until then.
	future, err := Sign(HS256, testSecret, map[string]any{"sub": "user"}, NotBefore(time.Now().Add(time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Verify(HS256, testSecret, future); !errors.Is(err, ErrNotValidYet) {
		t.Fatalf("expected ErrNotValidYet but got: %v", err)
	}
}

func TestSignPair(t *testing.T) {
	pair, err := SignPair(HS256, testSecret, map[string]any{"sub": "user"}, PairOptions{
		AccessOptions:  []SignOption{MaxAge(15 * time.Minute)},
		RefreshOptions: []SignOption{MaxAge(7 * 24 * time.Hour)},
	})
	if err != nil {
		t.Fatal(err)
	}

	if pair.AccessClaims.ID == "" || pair.RefreshClaims.ID == "" {
		t.Fatal("both halves need a jti")
	}
	if pair.AccessClaims.ID == pair.RefreshClaims.ID {
		t.Fatal("the two halves must not share a jti")
	}
	if pair.RefreshClaims.OriginID != pair.AccessClaims.ID {
		t.Fatalf("the refresh token must point at the access token: %+v", pair.RefreshClaims)
	}

	// The two lifetimes really differ, which is the thing a single option list cannot say.
	if pair.RefreshClaims.Expiry <= pair.AccessClaims.Expiry {
		t.Fatalf("expected the refresh token to outlive the access token: %d vs %d",
			pair.RefreshClaims.Expiry, pair.AccessClaims.Expiry)
	}

	for name, token := range map[string][]byte{"access": pair.AccessToken, "refresh": pair.RefreshToken} {
		verified, err := Verify(HS256, testSecret, token)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}

		var claims map[string]any
		if err = verified.Claims(&claims); err != nil {
			t.Fatal(err)
		}
		if claims["sub"] != "user" {
			t.Fatalf("%s: the custom claims are missing: %v", name, claims)
		}
	}

	// The JSON response shape.
	response := pair.TokenPair()
	if response.AccessToken != string(pair.AccessToken) || response.RefreshToken != string(pair.RefreshToken) {
		t.Fatal("TokenPair did not carry both tokens")
	}

	// Unlinked leaves origin_jti empty.
	unlinked, err := SignPair(HS256, testSecret, map[string]any{"sub": "user"}, PairOptions{Unlinked: true})
	if err != nil {
		t.Fatal(err)
	}
	if unlinked.RefreshClaims.OriginID != "" {
		t.Fatal("expected no link")
	}

	// A custom identifier generator is used for both halves.
	var calls int
	counted, err := SignPair(HS256, testSecret, map[string]any{"sub": "user"}, PairOptions{
		GenerateID: func() (string, error) {
			calls++
			return "id-" + strings.Repeat("x", calls), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 || counted.AccessClaims.ID != "id-x" || counted.RefreshClaims.ID != "id-xx" {
		t.Fatalf("expected two generated ids, got %d: %+v", calls, counted)
	}
}

func TestKeysSignPair(t *testing.T) {
	keys := make(Keys)
	keys.Register(HS256, "access-key", testSecret, testSecret)
	keys.Register(HS256, "refresh-key", []byte("a-different-shared-secret-value!"), []byte("a-different-shared-secret-value!"))

	pair, err := keys.SignPair(map[string]any{"sub": "user"}, PairOptions{
		AccessKID:      "access-key",
		RefreshKID:     "refresh-key",
		AccessOptions:  []SignOption{MaxAge(15 * time.Minute)},
		RefreshOptions: []SignOption{MaxAge(7 * 24 * time.Hour)},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Each half verifies through the registry, which means each carries the kid that
	// selects its own key.
	for name, token := range map[string][]byte{"access": pair.AccessToken, "refresh": pair.RefreshToken} {
		if _, err = keys.Verify(token); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}

	// Without a key identifier there is nothing to sign with.
	if _, err = keys.SignPair(map[string]any{"sub": "user"}, PairOptions{}); !errors.Is(err, ErrEmptyKid) {
		t.Fatalf("expected ErrEmptyKid but got: %v", err)
	}

	// One identifier signs both halves.
	same, err := keys.SignPair(map[string]any{"sub": "user"}, PairOptions{AccessKID: "access-key"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = keys.Verify(same.RefreshToken); err != nil {
		t.Fatal(err)
	}
}

func TestKeysVerifyReturnsTheToken(t *testing.T) {
	keys := make(Keys)
	keys.Register(HS256, "k", testSecret, testSecret)

	token, err := keys.SignToken("k", map[string]any{"sub": "user"})
	if err != nil {
		t.Fatal(err)
	}

	verified, err := keys.Verify(token)
	if err != nil {
		t.Fatal(err)
	}

	if string(verified.Token) != string(token) {
		t.Fatal("the raw token must come back, which is why this method exists")
	}
	if verified.StandardClaims.Subject != "user" {
		t.Fatalf("claims: %+v", verified.StandardClaims)
	}
}

func TestKeysVerifyTokenAcceptsAPointerWithoutDoubleIndirection(t *testing.T) {
	// VerifyToken passed &claimsPtr, where claimsPtr was already an any holding a
	// pointer, so it handed encoding/json a **T in an interface. It worked only because
	// the standard library unwraps that, and the package's own docs invite replacing the
	// unmarshaler with one that might not.
	keys := make(Keys)
	keys.Register(HS256, "k", testSecret, testSecret)

	token, err := keys.SignToken("k", map[string]any{"sub": "user", "role": "admin"})
	if err != nil {
		t.Fatal(err)
	}

	var claims struct {
		Subject string `json:"sub"`
		Role    string `json:"role"`
	}
	if err = keys.VerifyToken(token, &claims); err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "user" || claims.Role != "admin" {
		t.Fatalf("claims: %+v", claims)
	}
}
