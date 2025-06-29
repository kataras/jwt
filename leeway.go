package jwt

import (
	"errors"
	"time"
)

// Leeway creates a TokenValidator that adds a buffer time before token expiration.
//
// This validator provides "leeway" by rejecting tokens that will expire within
// the specified duration, even if they are technically still valid. This is useful
// to prevent race conditions where a token expires between validation and use.
//
// The validation logic: if (now + leeway) > expiration_time, reject the token.
//
// Common use cases:
//   - Database operations that might take several seconds to complete
//   - API calls that involve multiple service hops
//   - Batch processing where token might expire during execution
//   - Network latency compensation in distributed systems
//
// Example:
//
//	// Reject tokens expiring within 30 seconds
//	leewayValidator := jwt.Leeway(30 * time.Second)
//
//	verifiedToken, err := jwt.Verify(alg, key, token, leewayValidator)
//	// Token is rejected if it expires within 30 seconds
//
// Note: This only affects tokens that have an "exp" claim. Tokens without
// expiration are not affected by leeway validation.
func Leeway(leeway time.Duration) TokenValidatorFunc {
	return func(_ []byte, standardClaims Claims, err error) error {
		if err == nil {
			if standardClaims.Expiry > 0 {
				if Clock().Add(leeway).Round(time.Second).Unix() > standardClaims.Expiry {
					return ErrExpired
				}
			}
		}

		return err
	}
}

// Future creates a TokenValidator that allows tokens issued slightly in the future.
//
// This validator provides tolerance for clock skew between different systems
// by accepting tokens that appear to be issued in the future, up to the specified duration.
// Without this tolerance, legitimate tokens might be rejected due to minor time differences
// between servers.
//
// The validation logic: if (now + duration) < issued_at_time, still reject the token.
// Otherwise, accept tokens that would normally be rejected for future issuance.
//
// Common use cases:
//   - Compensating for clock drift between authentication and resource servers
//   - Handling timezone discrepancies in distributed systems
//   - Allowing for minor network delays in token propagation
//   - Testing scenarios with slightly misaligned system clocks
//
// Example:
//
//	// Allow tokens issued up to 60 seconds in the future
//	futureValidator := jwt.Future(60 * time.Second)
//
//	verifiedToken, err := jwt.Verify(alg, key, token, futureValidator)
//	// Token is accepted even if "iat" is up to 60 seconds in the future
//
// Note: This only affects tokens that would otherwise fail with ErrIssuedInTheFuture.
// Tokens without "iat" claims or with past issuance times are unaffected.
func Future(dur time.Duration) TokenValidatorFunc {
	return func(_ []byte, standardClaims Claims, err error) error {
		if errors.Is(err, ErrIssuedInTheFuture) {
			if Clock().Add(dur).Round(time.Second).Unix() < standardClaims.IssuedAt {
				return ErrIssuedInTheFuture
			}

			return nil
		}

		return err
	}
}
