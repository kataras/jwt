package jwt

import (
	"errors"
	"fmt"
)

// Expected is a TokenValidator that performs exact-match validation of standard JWT claims.
//
// It validates that the claims in a verified token exactly match the expected values.
// Only non-zero fields in the Expected struct are validated, allowing partial validation.
//
// This validator is useful for:
//   - Ensuring tokens come from a specific issuer
//   - Validating audience claims for API access control
//   - Checking that tokens have specific subjects or IDs
//   - Enforcing exact timing constraints
//
// Example:
//
//	expected := jwt.Expected{
//	    Issuer:   "my-auth-service",
//	    Audience: jwt.Audience{"api", "web"},
//	    Subject:  "user123",
//	}
//
//	verifiedToken, err := jwt.Verify(alg, key, token, expected)
//	if errors.Is(err, jwt.ErrExpected) {
//	    log.Printf("Token validation failed: %v", err)
//	}
type Expected Claims // Separate type for conceptual clarity, same structure as Claims

var _ TokenValidator = Expected{}

// ErrExpected indicates that a standard claim did not match the expected value.
// Use errors.Is() to check for this specific validation failure.
//
// Example:
//
//	verifiedToken, err := jwt.Verify(alg, key, token, expected)
//	if errors.Is(err, jwt.ErrExpected) {
//	    // Handle validation failure
//	    log.Printf("Claim validation failed: %v", err)
//	}
var ErrExpected = errors.New("jwt: field not match")

// ValidateToken implements the TokenValidator interface.
// It performs exact-match validation of standard claims against expected values.
//
// The validation logic:
//  1. If there's a previous validation error, return it unchanged
//  2. For each non-zero field in Expected, compare with the corresponding claim
//  3. Return ErrExpected with field details if any mismatch is found
//  4. Return nil if all specified fields match
//
// Only non-zero/non-empty fields in the Expected struct are validated,
// allowing flexible partial validation.
func (e Expected) ValidateToken(token []byte, c Claims, err error) error {
	if err != nil {
		return err
	}

	if v := e.NotBefore; v > 0 {
		if v != c.NotBefore {
			return fmt.Errorf("%w: nbf", ErrExpected)
		}
	}

	if v := e.IssuedAt; v > 0 {
		if v != c.IssuedAt {
			return fmt.Errorf("%w: iat", ErrExpected)
		}
	}

	if v := e.Expiry; v > 0 {
		if v != c.Expiry {
			return fmt.Errorf("%w: exp", ErrExpected)
		}
	}

	if v := e.ID; v != "" {
		if v != c.ID {
			return fmt.Errorf("%w: jti", ErrExpected)
		}
	}

	if v := e.Issuer; v != "" {
		if v != c.Issuer {
			return fmt.Errorf("%w: iss", ErrExpected)
		}
	}

	if v := e.Subject; v != "" {
		if v != c.Subject {
			return fmt.Errorf("%w: sub", ErrExpected)
		}
	}

	if n := len(e.Audience); n > 0 {
		if n != len(c.Audience) {
			return fmt.Errorf("%w: aud (length)", ErrExpected)
		}

		for i := range c.Audience {
			if v := e.Audience[i]; v != c.Audience[i] {
				return fmt.Errorf("%w: aud (%q)", ErrExpected, v)
			}
		}
	}

	return nil
}
