package jwt

import (
	"errors"
	"fmt"
	"testing"
)

func TestExpected(t *testing.T) {
	expected := Expected{
		NotBefore: 2019,
		IssuedAt:  1193,
		Expiry:    2020,
		ID:        "my-jti",
		Issuer:    "my-iss",
		Subject:   "1194",
		Audience:  []string{"aud1", "aud2"},
	}

	err := fmt.Errorf("test err")
	if got := expected.ValidateToken(nil, Claims{}, err); err != got {
		t.Fatalf("expected to return the previous error but got: %v", got)
	}

	// Test all OK.
	err = expected.ValidateToken(nil, Claims{
		NotBefore: 2019,
		IssuedAt:  1193,
		Expiry:    2020,
		ID:        "my-jti",
		Issuer:    "my-iss",
		Subject:   "1194",
		Audience:  []string{"aud1", "aud2"},
	}, nil)
	if err != nil {
		t.Fatalf("expected nil error but got: %v", err)
	}

	// Test failures one by one, should stop on the first error.
	var getExpectedErr = func(field string) error {
		return fmt.Errorf("%w: %s", ErrExpected, field)
	}

	expectedErr := getExpectedErr("nbf")
	gotErr := expected.ValidateToken(nil, Claims{NotBefore: 1}, nil)
	if !errors.Is(gotErr, ErrExpected) {
		t.Fatalf("expected error to be ErrExpired but got: %#+v", gotErr)
	}
	if expectedErr.Error() != gotErr.Error() {
		t.Fatalf("expected error: %v but got: %v", expectedErr, gotErr)
	}

	expectedErr = getExpectedErr("iat")
	gotErr = expected.ValidateToken(nil, Claims{
		NotBefore: expected.NotBefore,
		IssuedAt:  1}, nil)
	if !errors.Is(gotErr, ErrExpected) {
		t.Fatalf("expected error to be ErrExpired but got: %#+v", gotErr)
	}
	if expectedErr.Error() != gotErr.Error() {
		t.Fatalf("expected error: %v but got: %v", expectedErr, gotErr)
	}

	expectedErr = getExpectedErr("exp")
	gotErr = expected.ValidateToken(nil, Claims{
		NotBefore: expected.NotBefore,
		IssuedAt:  expected.IssuedAt,
		Expiry:    1}, nil)
	if !errors.Is(gotErr, ErrExpected) {
		t.Fatalf("expected error to be ErrExpired but got: %#+v", gotErr)
	}
	if expectedErr.Error() != gotErr.Error() {
		t.Fatalf("expected error: %v but got: %v", expectedErr, gotErr)
	}

	expectedErr = getExpectedErr("jti")
	gotErr = expected.ValidateToken(nil, Claims{
		NotBefore: expected.NotBefore,
		IssuedAt:  expected.IssuedAt,
		Expiry:    expected.Expiry,
		ID:        "unmatched"}, nil)
	if !errors.Is(gotErr, ErrExpected) {
		t.Fatalf("expected error to be ErrExpired but got: %#+v", gotErr)
	}
	if expectedErr.Error() != gotErr.Error() {
		t.Fatalf("expected error: %v but got: %v", expectedErr, gotErr)
	}

	expectedErr = getExpectedErr("iss")
	gotErr = expected.ValidateToken(nil, Claims{
		NotBefore: expected.NotBefore,
		IssuedAt:  expected.IssuedAt,
		Expiry:    expected.Expiry,
		ID:        expected.ID,
		Issuer:    "unmatched"}, nil)
	if !errors.Is(gotErr, ErrExpected) {
		t.Fatalf("expected error to be ErrExpired but got: %#+v", gotErr)
	}
	if expectedErr.Error() != gotErr.Error() {
		t.Fatalf("expected error: %v but got: %v", expectedErr, gotErr)
	}

	expectedErr = getExpectedErr("sub")
	gotErr = expected.ValidateToken(nil, Claims{
		NotBefore: expected.NotBefore,
		IssuedAt:  expected.IssuedAt,
		Expiry:    expected.Expiry,
		ID:        expected.ID,
		Issuer:    expected.Issuer,
		Subject:   "unmatched"}, nil)
	if !errors.Is(gotErr, ErrExpected) {
		t.Fatalf("expected error to be ErrExpired but got: %#+v", gotErr)
	}
	if expectedErr.Error() != gotErr.Error() {
		t.Fatalf("expected error: %v but got: %v", expectedErr, gotErr)
	}

	expectedErr = getExpectedErr("aud (length)")
	gotErr = expected.ValidateToken(nil, Claims{
		NotBefore: expected.NotBefore,
		IssuedAt:  expected.IssuedAt,
		Expiry:    expected.Expiry,
		ID:        expected.ID,
		Issuer:    expected.Issuer,
		Subject:   expected.Subject,
		Audience:  []string{"aud1", "aud2", "aud3"}}, nil)
	if !errors.Is(gotErr, ErrExpected) {
		t.Fatalf("expected error to be ErrExpired but got: %#+v", gotErr)
	}
	if expectedErr.Error() != gotErr.Error() {
		t.Fatalf("expected error: %v but got: %v", expectedErr, gotErr)
	}

	expectedErr = getExpectedErr(`aud ("aud2")`)
	gotErr = expected.ValidateToken(nil, Claims{
		NotBefore: expected.NotBefore,
		IssuedAt:  expected.IssuedAt,
		Expiry:    expected.Expiry,
		ID:        expected.ID,
		Issuer:    expected.Issuer,
		Subject:   expected.Subject,
		Audience:  []string{"aud1", "aud3"}}, nil)
	if !errors.Is(gotErr, ErrExpected) {
		t.Fatalf("expected error to be ErrExpired but got: %#+v", gotErr)
	}
	if expectedErr.Error() != gotErr.Error() {
		t.Fatalf("expected error: %v but got: %v", expectedErr, gotErr)
	}
}
