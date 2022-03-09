package jwt

import (
	"reflect"
	"testing"
	"time"
)

func TestValidateClaims(t *testing.T) {
	now := time.Now()
	expiresAt := now.Add(time.Minute)
	claims := Claims{
		Expiry:    expiresAt.Unix(),
		NotBefore: now.Unix(),
		IssuedAt:  now.Unix(),
	}
	if err := validateClaims(now, claims); err != nil {
		t.Fatal(err)
	}

	time.Sleep(2 * time.Second)
	if got := claims.Timeleft(); got >= time.Minute {
		t.Fatalf("expected timeleft to be lower than a minute but got: %s", got)
	}

	if expected, got := time.Minute, claims.Age(); expected != got {
		t.Fatalf("expected claim's total age to be: %v but got: %v", expected, got)
	}

	if expected, got := expiresAt.Unix(), claims.ExpiresAt().Unix(); expected != got {
		t.Fatalf("expected expires at to match: %d but got: %d", expected, got)
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
	prevClock := Clock
	defer func() {
		Clock = prevClock
	}()
	Clock = func() time.Time {
		return time.Date(2020, 10, 26, 1, 1, 1, 1, time.Local) // dupl the value just to resolve the test race cond.
	}

	var (
		maxAge      = 10 * time.Minute
		now         = time.Date(2020, 10, 26, 1, 1, 1, 1, time.Local)
		expectedExp = now.Add(maxAge).Unix()
		expectedIat = now.Unix()
	)

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

func TestClaimsSubAsInt(t *testing.T) {
	secret := "secret"
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEyMywibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.QzFnWiase0tPyeNzn8ecl-kVfDVEZ1ctbf9ztM0Qjqg"

	verifiedToken, err := Verify(HS256, []byte(secret), []byte(token))
	if err != nil {
		t.Fatal(err)
	}

	expectedClaims := Claims{NotBefore: 0, IssuedAt: 1516239022, Expiry: 0, ID: "", Issuer: "", Subject: "123", Audience: nil}
	if !reflect.DeepEqual(verifiedToken.StandardClaims, expectedClaims) {
		t.Fatalf("expected: %#+v but got: %#+v\n", expectedClaims, verifiedToken.StandardClaims)
	}
}
