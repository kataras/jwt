package jwt

import (
	"reflect"
	"testing"
	"time"
)

func TestValidateClaims(t *testing.T) {
	now := time.Now()
	claims := Claims{
		Expiry:    now.Add(time.Minute).Unix(),
		NotBefore: now.Unix(),
		IssuedAt:  now.Unix(),
	}
	if err := validateClaims(now, claims); err != nil {
		t.Fatal(err)
	}
}

func TestValidateClaimsNotBefore(t *testing.T) {
	now := time.Now()
	claims := Claims{
		NotBefore: now.Add(1 * time.Minute).Unix(),
	}
	if err := validateClaims(now, claims); err != ErrNotValidYet {
		t.Fatalf("expected token error: %v but got: %v", ErrNotValidYet, err)
	}
}

func TestValidateClaimsIssuedAt(t *testing.T) {
	now := time.Now()
	claims := Claims{
		IssuedAt: now.Unix(),
	}
	past := now.Add(-2 * time.Minute)
	// t.Logf("Now: %s", now.String())
	// t.Logf("Before now: %s", past.String())
	// t.Logf("Now Unix: %d", now.Unix())
	// t.Logf("Before now Unix: %d", past.Unix())

	if err := validateClaims(past, claims); err != ErrIssuedInTheFuture {
		t.Fatalf("expected token error: %v but got: %v", ErrIssuedInTheFuture, err)
	}
}

func TestValidateClaimsExpiry(t *testing.T) {
	now := time.Now()
	claims := Claims{
		Expiry: now.Add(20 * time.Second).Unix(),
	}

	if err := validateClaims(now.Add(21*time.Second), claims); err != ErrExpired {
		t.Fatalf("expected token error: %v but got: %v", ErrExpired, err)
	}
}

func TestApplyClaims(t *testing.T) {
	claims := Claims{
		NotBefore: 1,
		IssuedAt:  1,
		Expiry:    1,
		ID:        "id",
		Issuer:    "issuer",
		Subject:   "subject",
		Audience:  []string{"aud"},
	}

	var dest Claims
	claims.ApplyClaims(&dest)

	if !reflect.DeepEqual(claims, dest) {
		t.Fatalf("expected claims:\n%#+v\n\nbut got:\n%#+v", claims, dest)
	}
}

func TestMaxAge(t *testing.T) {
	maxAge := 10 * time.Minute
	now := Clock()
	var claims Claims
	expectedClaims := Claims{
		Expiry:   now.Add(maxAge).Unix(),
		IssuedAt: now.Unix(),
	}
	MaxAge(maxAge)(&claims)

	if !reflect.DeepEqual(claims, expectedClaims) {
		t.Fatalf("expected claims:\n%#+v\n\nbut got:\n%#+v", expectedClaims, claims)
	}

	// test not set.
	claims = Claims{}
	MaxAge(time.Second)(&claims)
	if !reflect.DeepEqual(claims, Claims{}) {
		t.Fatalf("expected Expiry and IssuedAt not be set because the given max age was less than a second")
	}
}

func TestMaxAgeMap(t *testing.T) {
	t.Cleanup(func() {
		Clock = time.Now
	})

	var (
		maxAge      = 10 * time.Minute
		now         = time.Date(2020, 10, 26, 1, 1, 1, 1, time.Local)
		expectedExp = now.Add(maxAge).Unix()
		expectedIat = now.Unix()
	)

	Clock = func() time.Time {
		return now
	}

	claims := make(Map)
	MaxAgeMap(maxAge, claims)

	if got := claims["exp"]; got != expectedExp {
		t.Fatalf("expected map[exp]: %v but got: %v", expectedExp, got)
	}

	if got := claims["iat"]; got != expectedIat {
		t.Fatalf("expected map[iat]: %v but got: %v", expectedIat, got)
	}

	// test no set.
	claims = make(Map)
	MaxAgeMap(time.Second, claims)
	if claims["exp"] != nil || claims["iat"] != nil {
		t.Fatalf("expected map's exp and iat not be set because the given max age was less than a second")
	}

	// test no panic if nil.
	MaxAgeMap(maxAge, nil)
}
