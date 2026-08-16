package jwt

import (
	"encoding/base64"
	"errors"
)

// ErrorKind names the category a verification failure falls into.
//
// This package returns a dozen distinct sentinel errors, and every service that puts it
// behind an HTTP handler ends up writing the same hand-maintained list of them to decide
// on a status code. Those lists drift: one downstream copy enumerated fifteen sentinels
// and had already fallen out of step with the twelve its own alias file re-exported.
//
// Classify collapses them into the four answers an application actually acts on.
type ErrorKind uint8

const (
	// KindNone means there was no error.
	KindNone ErrorKind = iota
	// KindMalformed means the token is not a usable JWT: wrong shape, bad base64, a
	// payload that is not JSON, or one larger than MaxTokenSize. Nothing about the
	// credential can be trusted, and retrying will not help.
	KindMalformed
	// KindInvalid means the token is well formed but is not ours: the signature does not
	// check out, the algorithm is not the expected one, the key is unusable, or the "kid"
	// names nothing. Treat it as an authentication failure.
	KindInvalid
	// KindExpired means the token was valid and its time has passed, or has not yet come.
	// This is the one worth distinguishing, because the client can fix it by refreshing.
	KindExpired
	// KindRejected means the token verified but a policy check turned it away: it was
	// revoked, a claim did not match what was expected, or a required claim was missing.
	KindRejected
)

// String returns the kind's name, in lowercase.
func (k ErrorKind) String() string {
	switch k {
	case KindNone:
		return "none"
	case KindMalformed:
		return "malformed"
	case KindInvalid:
		return "invalid"
	case KindExpired:
		return "expired"
	case KindRejected:
		return "rejected"
	default:
		return "unknown"
	}
}

// Classify sorts an error from this package into one of a handful of kinds.
//
// Use it to choose a response without enumerating sentinels yourself:
//
//	switch jwt.Classify(err) {
//	case jwt.KindExpired:
//	    http.Error(w, "token expired", http.StatusUnauthorized) // the client can refresh
//	case jwt.KindNone:
//	    // carry on
//	default:
//	    http.Error(w, "unauthorized", http.StatusUnauthorized)
//	}
//
// It uses errors.Is, so a wrapped error still classifies. An error this package did not
// produce comes back as KindInvalid, because the safe reading of an unrecognised failure
// during verification is that the token is not acceptable.
//
// Send the same body for every failing kind if the client is not yours. Telling an
// attacker whether a token is expired, forged or revoked is free information.
func Classify(err error) ErrorKind {
	if err == nil {
		return KindNone
	}

	// A segment that is not base64 at all arrives as a base64.CorruptInputError rather
	// than as one of this package's sentinels, and a payload that is not JSON arrives as
	// an unexported one. Both are malformed tokens by any reading, and leaving them to
	// the default meant Classify disagreed with its own documentation.
	var corrupt base64.CorruptInputError
	if errors.As(err, &corrupt) {
		return KindMalformed
	}

	switch {
	case errors.Is(err, ErrMissing),
		errors.Is(err, ErrTokenForm),
		errors.Is(err, ErrTokenSize),
		errors.Is(err, ErrNotJSONObject),
		errors.Is(err, errPayloadNotJSON):
		return KindMalformed

	case errors.Is(err, ErrExpired),
		errors.Is(err, ErrNotValidYet),
		errors.Is(err, ErrIssuedInTheFuture):
		return KindExpired

	case errors.Is(err, ErrBlocked),
		errors.Is(err, ErrExpected),
		errors.Is(err, ErrMissingKey),
		errors.Is(err, ErrMissingExpiry):
		return KindRejected

	default:
		// ErrTokenSignature, ErrTokenAlg, ErrInvalidKey, ErrEmptyKid, ErrUnknownKid,
		// ErrDecrypt, and anything a custom validator returned.
		return KindInvalid
	}
}
