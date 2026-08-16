package jwt

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// Timing claims decide when a token stops being a credential, so a claim the package
// cannot read has to fail the token rather than quietly read as absent.

func TestNegativeExpiryIsExpiredNotAbsent(t *testing.T) {
	// validateClaims tested "greater than zero", so a token carrying a negative "exp"
	// was treated as having no expiry at all rather than as one that expired in 1969.
	for _, exp := range []int64{-1, -1000, time.Now().Add(-time.Hour).Unix()} {
		token, err := Sign(HS256, testSecret, map[string]any{"sub": "user", "exp": exp})
		if err != nil {
			t.Fatal(err)
		}

		if _, err = Verify(HS256, testSecret, token); !errors.Is(err, ErrExpired) {
			t.Fatalf("exp %d: expected ErrExpired but got: %v", exp, err)
		}
	}
}

func TestUnreadableTimestampsFailTheToken(t *testing.T) {
	// These payloads do not fit the Claims struct, so verification falls back to the
	// lenient second-chance parse. That parse used to discard the conversion errors, and
	// a value no int64 can hold came out negative, failed the "greater than zero" test
	// and produced a token that never expired.
	for _, payload := range []string{
		`{"sub":"user","exp":1e400}`,
		`{"sub":"user","exp":-1e400}`,
		`{"sub":"user","nbf":1e400}`,
		`{"sub":"user","iat":1e400}`,
	} {
		token, err := Sign(HS256, testSecret, []byte(payload))
		if err != nil {
			t.Fatal(err)
		}

		verified, err := Verify(HS256, testSecret, token)
		if err == nil {
			t.Fatalf("%s: expected an error but the token verified with claims %+v", payload, verified.StandardClaims)
		}
		if !errors.Is(err, ErrTokenForm) {
			t.Fatalf("%s: expected ErrTokenForm but got: %v", payload, err)
		}
	}
}

func TestStructuredSubjectIsRefusedNotStringified(t *testing.T) {
	// A payload whose "sub" is an object used to be rendered with %v, so an application
	// reading StandardClaims.Subject as a principal identifier accepted the subject
	// "map[a:1]".
	for _, payload := range []string{
		`{"sub":{"a":1}}`,
		`{"sub":["a","b"]}`,
		`{"iss":{"a":1}}`,
	} {
		token, err := Sign(HS256, testSecret, []byte(payload))
		if err != nil {
			t.Fatal(err)
		}

		verified, err := Verify(HS256, testSecret, token)
		if err == nil {
			t.Fatalf("%s: expected an error but got the subject %q", payload, verified.StandardClaims.Subject)
		}
		if !errors.Is(err, ErrTokenForm) {
			t.Fatalf("%s: expected ErrTokenForm but got: %v", payload, err)
		}
		// The error may name the Go type it got, which is a bounded set of type names.
		// It must not carry the claim's contents, which are attacker supplied and end up
		// in whatever the caller logs.
		if strings.Contains(err.Error(), "map[a:") || strings.Contains(err.Error(), "[a b]") {
			t.Fatalf("%s: the claim's contents leaked into the error: %v", payload, err)
		}
	}
}

func TestNumericSubjectIsStillAccepted(t *testing.T) {
	// Issuers that write a numeric "sub" exist, and tolerating them is the reason the
	// second-chance parse is there. Only structured values are refused.
	token, err := Sign(HS256, testSecret, []byte(`{"sub":1194,"iss":42}`))
	if err != nil {
		t.Fatal(err)
	}

	verified, err := Verify(HS256, testSecret, token)
	if err != nil {
		t.Fatal(err)
	}

	if got := verified.StandardClaims.Subject; got != "1194" {
		t.Fatalf(`expected the subject "1194" but got %q`, got)
	}
	if got := verified.StandardClaims.Issuer; got != "42" {
		t.Fatalf(`expected the issuer "42" but got %q`, got)
	}
}

func TestRequireExpiry(t *testing.T) {
	withoutExpiry, err := Sign(HS256, testSecret, map[string]any{"sub": "user"})
	if err != nil {
		t.Fatal(err)
	}

	if _, err = Verify(HS256, testSecret, withoutExpiry); err != nil {
		t.Fatalf("without the validator the token still verifies: %v", err)
	}

	if _, err = Verify(HS256, testSecret, withoutExpiry, RequireExpiry); !errors.Is(err, ErrMissingExpiry) {
		t.Fatalf("expected ErrMissingExpiry but got: %v", err)
	}

	withExpiry, err := Sign(HS256, testSecret, map[string]any{"sub": "user"}, MaxAge(time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	if _, err = Verify(HS256, testSecret, withExpiry, RequireExpiry); err != nil {
		t.Fatalf("a token with an expiry must pass: %v", err)
	}
}

func TestAudienceContains(t *testing.T) {
	aud := Audience{"api.example.com", "web.example.com"}

	if !aud.Contains("web.example.com") {
		t.Fatal("expected the audience to be found")
	}
	if aud.Contains("other.example.com") {
		t.Fatal("expected an unrelated audience not to be found")
	}
	if aud.Contains("API.example.com") {
		t.Fatal("audience comparison must be case sensitive")
	}

	var empty Audience
	if empty.Contains("anything") {
		t.Fatal("an empty audience contains nothing")
	}
}

func TestPlainMustComeFirst(t *testing.T) {
	// Verify stops at the first validator that returns an error, so a validator only ever
	// receives a non-nil incoming error when it is first. Plain exists to clear the
	// payload-is-not-JSON error, so placed last it never runs. The doc comment recommended
	// placing it last until v1.0.0.
	token, err := Sign(HS256, testSecret, []byte("not json at all"))
	if err != nil {
		t.Fatal(err)
	}

	// Last: the validator ahead of it returns the payload error and the loop breaks.
	if _, err = Verify(HS256, testSecret, token, Expected{Issuer: "us"}, Plain); err == nil {
		t.Fatal("expected the payload error to survive when Plain is last")
	}

	// First: Plain clears it and the chain continues, so the next validator gets to speak.
	_, err = Verify(HS256, testSecret, token, Plain, Expected{Issuer: "us"})
	if !errors.Is(err, ErrExpected) {
		t.Fatalf("expected ErrExpected from the validator after Plain, got: %v", err)
	}

	// Alone, it accepts the non-JSON payload, which is the whole point of it.
	verified, err := Verify(HS256, testSecret, token, Plain)
	if err != nil {
		t.Fatalf("Plain alone must accept a non-JSON payload: %v", err)
	}
	if string(verified.Payload) != "not json at all" {
		t.Fatalf("payload: %q", verified.Payload)
	}
}
