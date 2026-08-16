package jwt

import (
	"errors"
	"testing"
	"time"
)

// TestValidatorsCollectsTokenValidatorFunc pins the type switch order in Validators.
//
// TokenValidatorFunc satisfies TokenValidator, so a case for the interface placed before
// the case for the func type swallows every func value. That is only visible through the
// nil handling: a nil TokenValidatorFunc is a non-nil TokenValidator, because the interface
// still carries a type, so the interface case would collect it and Verify would call a nil
// func.
func TestValidatorsCollectsTokenValidatorFunc(t *testing.T) {
	fn := TokenValidatorFunc(func(_ []byte, _ Claims, err error) error { return err })

	got := Validators(fn)
	if len(got) != 1 {
		t.Fatalf("expected a TokenValidatorFunc to be collected, got %d validators", len(got))
	}

	// The collected value is still the same validator, and it still runs.
	if err := got[0].ValidateToken(nil, Claims{}, ErrExpired); !errors.Is(err, ErrExpired) {
		t.Fatalf("expected the collected validator to pass the error through, got: %v", err)
	}

	// Bare funcs of the same underlying signature are a distinct type: they carry no
	// ValidateToken method, so they never match the TokenValidator case.
	bare := func(_ []byte, _ Claims, err error) error { return err }
	if got = Validators(bare); len(got) != 1 {
		t.Fatalf("expected a bare func to be collected, got %d validators", len(got))
	}
}

// TestValidatorsDropsTypedNilFuncs covers the nil that is not nil.
//
// A nil TokenValidatorFunc boxed in a TokenValidator interface compares != nil, so the
// interface case cannot drop it. Collecting one is a panic postponed to the first Verify.
func TestValidatorsDropsTypedNilFuncs(t *testing.T) {
	var nilFn TokenValidatorFunc
	var nilBare func(token []byte, standardClaims Claims, err error) error
	var nilIface TokenValidator

	got := Validators(nilFn, nilBare, nilIface, nil)
	if len(got) != 0 {
		t.Fatalf("expected every nil to be dropped, got %d validators", len(got))
	}

	// Same again from inside the slice cases, which recurse through the same switch.
	got = Validators([]TokenValidatorFunc{nil, Plain, nil}, []TokenValidator{nil, Plain})
	if len(got) != 2 {
		t.Fatalf("expected 2 validators from slices holding nils, got %d", len(got))
	}

	// And the collected ones are callable, which is what dropping the nils bought.
	token, err := Sign(HS256, testSecret, map[string]any{"sub": "user"}, MaxAge(time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	if _, err = Verify(HS256, testSecret, token, Validators(nilFn, []TokenValidatorFunc{nil})...); err != nil {
		t.Fatalf("a token with no validators left must still verify: %v", err)
	}
}
