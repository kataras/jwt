package jwt

import (
	"errors"
	"time"
)

// ErrMissingExpiry indicates that a token carries no "exp" claim and the caller asked for
// one through RequireExpiry.
var ErrMissingExpiry = errors.New("jwt: token has no expiry")

// RequireExpiry rejects any token without an "exp" claim.
//
// Nothing in RFC 7519 makes "exp" mandatory, so a token without one verifies and stays
// valid until the signing key is retired. That is rarely what anyone wants from a bearer
// credential, and it is easy to arrive at by accident: MaxAge returns NoMaxAge for any
// duration of a second or less, and a KeyConfiguration with no MaxAge set skips the option
// entirely, so a zero value in a configuration file produces permanent tokens with no
// error anywhere.
//
// Blocklist has the same trouble from the other side. A revocation for a token with no
// expiry can never be collected, because there is no point at which it stops mattering.
//
// Pass it wherever you pass any other validator:
//
//	verifiedToken, err := jwt.Verify(jwt.HS256, key, token, jwt.RequireExpiry)
//
// It returns ErrMissingExpiry when the claim is absent. A token whose "exp" has passed
// fails earlier with ErrExpired, so this validator only ever sees the missing case.
var RequireExpiry = TokenValidatorFunc(func(token []byte, standardClaims Claims, err error) error {
	if err != nil {
		return err
	}

	if standardClaims.Expiry == 0 {
		return ErrMissingExpiry
	}

	return nil
})

// Skew tolerates a clock that runs ahead of ours, for both "nbf" and "iat".
//
// Future only ever rescued "iat", and validateClaims checks "nbf" first and returns as soon
// as it fails, so a token whose issuer set "nbf" equal to "iat" could not be rescued at all.
// Callers reaching for clock-skew tolerance were reliably reaching for the wrong tool: four
// call sites across two services depended on Future and worked only because the identity
// provider in question happens to omit "nbf".
//
// Validator order is load-bearing and easy to get wrong. Verify stops at the first
// validator that returns an error, so a rescuing validator has to come before any stricter
// one:
//
//	jwt.Verify(alg, key, token, jwt.Skew(2*time.Minute), jwt.Expected{Issuer: "us"})
//
// Reversed, the stricter validator never runs. Tolerance in the other direction, for a
// token that has just expired, is not offered: extending the life of an expired credential
// is a policy decision, not a clock correction.
func Skew(d time.Duration) TokenValidatorFunc {
	return func(_ []byte, standardClaims Claims, err error) error {
		if err == nil {
			return nil
		}

		if d <= 0 {
			return err
		}

		now := Clock().Round(time.Second).Add(d).Unix()

		switch {
		case errors.Is(err, ErrNotValidYet):
			if now >= standardClaims.NotBefore {
				return nil
			}
		case errors.Is(err, ErrIssuedInTheFuture):
			if now >= standardClaims.IssuedAt {
				return nil
			}
		}

		return err
	}
}

// Validators collects token validators of mixed types into one slice.
//
// Go will not convert a []TokenValidatorFunc into a []TokenValidator, so anything holding
// a slice of one and calling a function that wants the other copies it element by element
// at every call site. It accepts TokenValidator and TokenValidatorFunc values, and drops
// nils, which is the other half of that same loop.
//
//	jwt.Verify(alg, key, token, jwt.Validators(app.Validators, jwt.Skew(time.Minute))...)
//
// Order is preserved, and order matters: see Skew.
func Validators(values ...any) []TokenValidator {
	out := make([]TokenValidator, 0, len(values))

	var add func(v any)
	add = func(v any) {
		switch value := v.(type) {
		case nil:
			return
		// TokenValidatorFunc has a ValidateToken method, so it satisfies TokenValidator and
		// this case has to come first. Behind the interface case it is unreachable, and the
		// nil check goes with it: a nil TokenValidatorFunc held in a TokenValidator is not a
		// nil interface, because the interface still carries a type, so it would be collected
		// and Verify would call a nil func. Compared as a func type here, it is caught.
		case TokenValidatorFunc:
			if value != nil {
				out = append(out, value)
			}
		case TokenValidator:
			if value != nil {
				out = append(out, value)
			}
		case func(token []byte, standardClaims Claims, err error) error:
			if value != nil {
				out = append(out, TokenValidatorFunc(value))
			}
		case []TokenValidator:
			for _, item := range value {
				add(item)
			}
		case []TokenValidatorFunc:
			for _, item := range value {
				add(item)
			}
		}
	}

	for _, v := range values {
		add(v)
	}

	return out
}
