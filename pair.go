package jwt

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// An access token and a refresh token are issued together, and the pair has to be linked:
// revoking the access token has to revoke the refresh token that would mint another one.
// Nothing here expressed that, so callers built it by hand.
//
// The shape that emerged downstream is worth describing, because it shows what was missing.
// The signing function generated two identifiers, copied the access token's "jti" into the
// refresh token's "origin_jti", ran every sign option twice against two separate Claims
// values, and signed twice. On top of that sat two option wrappers whose entire job was to
// work out which half of the pair was being signed, which they did by checking whether
// "origin_jti" happened to be empty. Roughly 129 lines, and a second, subtly different
// implementation of the same idea in a neighbouring package.

// SignedPair is an access token and the refresh token issued with it.
type SignedPair struct {
	// AccessToken is the short-lived credential.
	AccessToken []byte
	// RefreshToken is the long-lived credential that mints the next access token.
	RefreshToken []byte
	// AccessClaims are the standard claims written into the access token, including the
	// generated "jti".
	AccessClaims Claims
	// RefreshClaims are the standard claims written into the refresh token. Its
	// "origin_jti" is the access token's "jti".
	RefreshClaims Claims
}

// TokenPair converts the pair into the JSON response shape.
func (p SignedPair) TokenPair() TokenPair {
	return NewTokenPair(p.AccessToken, p.RefreshToken)
}

// PairOptions configures SignPair.
//
// The zero value is usable for the package-level SignPair: it generates both identifiers,
// links them, and applies no options to either half.
type PairOptions struct {
	// AccessKID and RefreshKID name the registry entries to sign each half with. They are
	// used by Keys.SignPair and ignored by the package-level SignPair.
	//
	// Leave RefreshKID empty to sign both halves with AccessKID. Separate keys are worth
	// the trouble: the refresh key is used once per session rather than once per request,
	// so it can be held somewhere the access key cannot.
	AccessKID      string
	RefreshKID     string
	AccessOptions  []SignOption
	RefreshOptions []SignOption

	// GenerateID produces the "jti" for each half. It defaults to 22 characters of
	// base64url-encoded randomness, which is 128 bits.
	//
	// Replace it to use your own identifier scheme, a UUID for instance, when something
	// downstream needs to recognise the format.
	GenerateID func() (string, error)

	// Unlinked leaves the refresh token's "origin_jti" empty.
	//
	// The link is the default because without it there is no way, given a revoked access
	// token, to find the refresh token that will replace it. Set this only when the two
	// halves genuinely have nothing to do with each other.
	Unlinked bool
}

// SignPair signs an access token and a refresh token from the same claims.
//
// Both halves get a generated "jti", and the refresh token's "origin_jti" names the access
// token's, so a blocklist that revokes one can find the other. Options are applied per
// half, which is the part that is awkward to do by hand: the two tokens want different
// lifetimes, and a single option list cannot express that.
//
//	pair, err := jwt.SignPair(jwt.HS256, key, userClaims, jwt.PairOptions{
//	    AccessOptions:  []jwt.SignOption{jwt.MaxAge(15 * time.Minute)},
//	    RefreshOptions: []jwt.SignOption{jwt.MaxAge(7 * 24 * time.Hour)},
//	})
//	if err != nil {
//	    return err
//	}
//
//	json.NewEncoder(w).Encode(pair.TokenPair())
//
// The custom claims are written into both halves. Put nothing in a refresh token that you
// would not want read by whoever holds it for a week.
func SignPair(alg Alg, key PrivateKey, claims any, opts PairOptions) (SignedPair, error) {
	return signPair(claims, opts, func(_ string, c any, o ...SignOption) ([]byte, error) {
		return Sign(alg, key, c, o...)
	})
}

// SignPair signs a linked access and refresh token using keys from the registry.
//
// It is the package-level SignPair with the keys chosen by identifier, so each half can be
// signed with a different key and each token carries the "kid" that selects it again on
// the way back in.
//
//	pair, err := keys.SignPair(userClaims, jwt.PairOptions{
//	    AccessKID:      "access",
//	    RefreshKID:     "refresh",
//	    AccessOptions:  []jwt.SignOption{jwt.MaxAge(15 * time.Minute)},
//	    RefreshOptions: []jwt.SignOption{jwt.MaxAge(7 * 24 * time.Hour)},
//	})
func (keys Keys) SignPair(claims any, opts PairOptions) (SignedPair, error) {
	if opts.AccessKID == "" {
		return SignedPair{}, fmt.Errorf("jwt: sign pair: %w", ErrEmptyKid)
	}

	if opts.RefreshKID == "" {
		opts.RefreshKID = opts.AccessKID
	}

	return signPair(claims, opts, keys.SignToken)
}

// signPair holds the logic both entry points share. The sign function takes a key
// identifier so the registry version can route each half to its own key, and the
// package-level one ignores it.
func signPair(claims any, opts PairOptions, sign func(kid string, claims any, options ...SignOption) ([]byte, error)) (SignedPair, error) {
	generate := opts.GenerateID
	if generate == nil {
		generate = newTokenID
	}

	accessID, err := generate()
	if err != nil {
		return SignedPair{}, fmt.Errorf("jwt: sign pair: access id: %w", err)
	}

	refreshID, err := generate()
	if err != nil {
		return SignedPair{}, fmt.Errorf("jwt: sign pair: refresh id: %w", err)
	}

	// Apply each half's options to its own Claims so the caller can read back what was
	// written, and so the identifiers cannot be overwritten by an option that happens to
	// set one.
	accessClaims := Claims{ID: accessID}
	for _, option := range opts.AccessOptions {
		if option != nil {
			option.ApplyClaims(&accessClaims)
		}
	}
	accessClaims.ID = accessID

	refreshClaims := Claims{ID: refreshID}
	for _, option := range opts.RefreshOptions {
		if option != nil {
			option.ApplyClaims(&refreshClaims)
		}
	}
	refreshClaims.ID = refreshID

	if !opts.Unlinked {
		refreshClaims.OriginID = accessID
	}

	accessToken, err := sign(opts.AccessKID, claims, accessClaims)
	if err != nil {
		return SignedPair{}, fmt.Errorf("jwt: sign pair: access token: %w", err)
	}

	refreshToken, err := sign(opts.RefreshKID, claims, refreshClaims)
	if err != nil {
		return SignedPair{}, fmt.Errorf("jwt: sign pair: refresh token: %w", err)
	}

	return SignedPair{
		AccessToken:   accessToken,
		RefreshToken:  refreshToken,
		AccessClaims:  accessClaims,
		RefreshClaims: refreshClaims,
	}, nil
}

// newTokenID returns 128 bits of randomness as 22 base64url characters.
//
// It returns an error rather than panicking, unlike the Must family in hmac.go, because it
// runs inside a signing call where an error already has somewhere to go.
func newTokenID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}
