/*
Package jwt signs and verifies JSON Web Tokens.

It implements RFC 7519 (JWT) over RFC 7515 (JWS), with the algorithms of RFC 7518 (JWA) and
the key formats of RFC 7517 (JWK). It has no dependencies outside the standard library.

# Signing and verifying

Sign takes an algorithm, a key and your claims. Verify takes the algorithm and key you
expect, and the token.

	var sharedKey = []byte("sercrethatmaycontainch@r$32chars")

	type User struct {
		Username string `json:"username"`
	}

	token, err := jwt.Sign(jwt.HS256, sharedKey, User{Username: "kataras"}, jwt.MaxAge(15*time.Minute))
	if err != nil {
		return err
	}

	verifiedToken, err := jwt.Verify(jwt.HS256, sharedKey, token)
	if err != nil {
		return err
	}

	var user User
	if err = verifiedToken.Claims(&user); err != nil {
		return err
	}

The algorithm is an argument, never something read out of the token. Verify compares the
token's header against a precomputed byte sequence for the algorithm you named, so a token
whose header says HS256 cannot be verified by a call that pinned RS256, and a token claiming
the unsecured algorithm cannot be verified by a call that pinned anything else. That is the
defence against algorithm confusion, and it costs one byte comparison.

# Claims

Claims can be a struct, a map, a jwt.Map, or raw JSON bytes. The standard claims live in the
Claims type, which is also a SignOption, so it can be passed alongside your own:

	token, err := jwt.Sign(jwt.HS256, sharedKey, myClaims, jwt.Claims{
		Issuer:   "auth.example.com",
		Audience: jwt.Audience{"api.example.com"},
	}, jwt.MaxAge(15*time.Minute))

Verification checks exp, nbf and iat when they are present. None of the three is required by
RFC 7519, so a token with no expiry verifies. RequireExpiry rejects one if that is not what
you want.

# Algorithms

HMAC (HS256, HS384, HS512) takes a []byte shared secret, which means every verifier can also
mint tokens. RSA (RS256, RS384, RS512), RSA-PSS (PS256, PS384, PS512), ECDSA (ES256, ES384,
ES512) and EdDSA take a key pair, so a verifier holding only the public half cannot sign.
NONE produces an unsecured token under the name "none" from RFC 7518 section 3.6, and is for
testing.

Implement Alg to add your own. Its Name is checked before it reaches the header.

# Multiple keys

Keys is a registry indexed by the "kid" header, for rotation and for multi-tenant setups:

	keys := make(jwt.Keys)
	keys.Register(jwt.RS256, "current", publicKey, privateKey)

	token, err := keys.SignToken("current", myClaims, jwt.MaxAge(time.Hour))

	verifiedToken, err := keys.Verify(token)

Keys.ValidateHeader binds the "kid" to the algorithm registered for that key, so neither can
be chosen by whoever sent the token. Keys itself is a plain map with no lock: build it at
startup. For keys that change while the process runs, use KeySet.

# JWKS

Publish a key set with Keys.JWKS, and consume one with NewRemoteKeySet, which refreshes on a
timer and again when a token names a key it has not seen:

	keySet, err := jwt.NewRemoteKeySet("https://auth.example.com/.well-known/jwks.json")
	if err != nil {
		return err
	}
	defer keySet.Close()

	verifiedToken, err := keySet.Verify(token)

NewCognitoKeySet does the same for an AWS Cognito user pool and returns the issuer and
audience checks alongside it, because verifying only the signature and the clock would accept
a token minted for a different app client of the same pool.

# Validators

Anything satisfying TokenValidator runs after the standard claims are checked. Expected
compares registered claims, Blocklist refuses revoked tokens, Skew tolerates a clock that
runs ahead, and RequireExpiry insists on an "exp".

	verifiedToken, err := jwt.Verify(jwt.HS256, sharedKey, token,
		jwt.Skew(time.Minute),
		jwt.Expected{Issuer: "auth.example.com"},
		jwt.RequireExpiry,
	)

Order matters. Verification stops at the first validator that returns an error, so one that
rescues an error has to come before one that is stricter.

# Errors

Verification returns one of a set of sentinel errors: ErrMissing, ErrTokenForm, ErrTokenSize,
ErrTokenAlg, ErrTokenSignature, ErrInvalidKey, ErrExpired, ErrNotValidYet,
ErrIssuedInTheFuture, ErrBlocked, ErrExpected, ErrMissingExpiry, ErrEmptyKid, ErrUnknownKid
and ErrDecrypt. Compare with errors.Is.

Classify sorts any of them into four kinds, so an HTTP handler does not have to enumerate
them:

	switch jwt.Classify(err) {
	case jwt.KindNone:
		// verified
	case jwt.KindExpired:
		// the client can fix this by refreshing
	default:
		// everything else is an authentication failure
	}

# Tokens over HTTP

ExtractToken reads a token from a request, from the Authorization header by default:

	token := jwt.ExtractToken(r)
	verifiedToken, err := jwt.Verify(jwt.HS256, sharedKey, token)

FromHeader, FromQuery and FromCookie select where to look. SignPair issues a linked access
and refresh token, where the refresh token's "origin_jti" names the access token it was
issued with.

# Extension points

Clock, CompareHeader, ReadFile, Marshal and Unmarshal are package-level variables you can
replace: a fixed clock for tests, an embedded filesystem for keys, a faster JSON codec. They
are read on the hot path without synchronization, so set them during startup, before
anything verifies concurrently.

# What this package does not do

It does not implement JWE. SignEncrypted and VerifyEncrypted encrypt the payload with
AES-GCM before signing, which is useful and is not RFC 7516: the result does not
interoperate with anything expecting JWE.

It does not decide whether a token that verifies should be honoured. A signature proves that
a holder of the key produced those exact bytes. The audience check, the issuer check, the
revocation list and the session model are yours.

# More

The _examples directory covers basic usage, custom headers, multiple key ids, HTTP
middleware, blocklisting, the JSON required tag and AWS Cognito verification. The book under
book/ covers the same ground at length, including a chapter on this package's sharp edges.
*/
package jwt
