---
name: jwt
description: "Development guide for the jwt JSON Web Token library for Go
  (github.com/kataras/jwt). Use this skill when signing or verifying JWTs, choosing a
  signing algorithm (HMAC, RSA, RSA-PSS, ECDSA, EdDSA), reading or validating standard or
  custom claims, setting expiry and clock-skew tolerance, rotating keys with a kid-based
  registry, fetching or publishing a JWKS, blocklisting (revoking) tokens, encrypting a
  payload, or extracting a token from an HTTP request."
tags: [go, jwt, jws, jwk, jwks, authentication, security, tokens]
---

# The jwt library for Go

`github.com/kataras/jwt` is a zero-dependency JWT and JWKS implementation for Go, built on RFC 7519 (JWT) and RFC 7518 (JWA). It signs and verifies compact tokens over HMAC, RSA, RSA-PSS, ECDSA and EdDSA, decodes claims into a struct or a map, and ships the pieces most applications end up writing by hand: a kid-based multi-key registry, JWKS fetch and publish, a server-side blocklist, standard-claims validators, and HTTP token extraction.

## Quick start

```go
package main

import (
    "fmt"
    "time"

    "github.com/kataras/jwt"
)

// Generate this once and keep it outside source control (env var, secret manager).
// 32 bytes is the RFC 7518 minimum for HS256.
var sharedKey = jwt.MustGenerateRandom(32)

type FooClaims struct {
    Foo string `json:"foo"`
}

func main() {
    token, err := jwt.Sign(jwt.HS256, sharedKey, FooClaims{Foo: "bar"}, jwt.MaxAge(15*time.Minute))
    if err != nil {
        panic(err)
    }

    verifiedToken, err := jwt.Verify(jwt.HS256, sharedKey, token)
    if err != nil {
        panic(err)
    }

    var claims FooClaims
    if err = verifiedToken.Claims(&claims); err != nil {
        panic(err)
    }

    fmt.Println(claims.Foo) // bar
}
```

- Module path: `github.com/kataras/jwt`
- Go 1.26+, no third-party dependencies in the root module

## Rules that prevent the common mistakes

The algorithm is always a parameter you supply to `Sign` and `Verify`, never a value read out of the token. `Verify` checks the token's header against the literal algorithm name you passed; passing a fixed algorithm you chose (never one derived from client input) is what stops the classic RS256/HS256 algorithm-confusion attack. A custom `HeaderValidator` that trusts the token's own `"alg"` field reopens it.

HMAC key length is not checked. `Sign` and `Verify` for HS256/384/512 only type-assert the key to `[]byte`; a two-byte secret works and is brute-forceable. RFC 7518 wants 32/48/64 bytes; use `jwt.MustGenerateRandom(32)` (or larger) rather than a short literal.

`jwt.NONE` is a real, selectable algorithm that produces and accepts an empty signature. Never let request input choose the `alg` argument to `Verify`. `Enrich` and `UnverifiedToken.Enrich` refuse it explicitly, but `Sign` and `Verify` do not stop you from passing it yourself.

`Claims`' expiry field is named `Expiry` (JSON `"exp"`), not `ExpiresAt`. `ExpiresAt()` is a method that reads `Expiry` as a `time.Time`. `jwt.Claims{ExpiresAt: ...}` does not compile; `Claims` has no such field.

`TokenValidator` order is significant. `Verify` runs validators in order and stops at the first one that returns a non-nil error; a validator meant to rescue an error (`Skew`, `Future`) has to be listed before any stricter validator (`Expected`, `RequireExpiry`, your own), or the stricter one already saw the unrescued error and returned before the rescuer ran.

`Keys`, the kid-based registry, is not safe for concurrent writes. Register every key during startup, before any goroutine calls `Verify`/`SignToken`/`VerifyToken` concurrently.

`Blocklist.InvalidateToken` keys on the token's `"jti"` claim. A token with no `"jti"` falls back to using the whole raw token, signature included, as the map key, so blocklisting it pins a full bearer credential in memory until expiry. Give any token you might revoke a `"jti"`.

Verifying a token against a fetched JWKS checks the signature only. It does not check that the token was issued to *your* application rather than some other client of the same identity provider; add `jwt.Expected{Issuer: ..., Audience: ...}` yourself, or use `jwt.NewCognitoKeySet` for AWS Cognito, which returns one already populated. Prefer `jwt.KeySet` (`NewRemoteKeySet`/`NewCognitoKeySet`) over calling `FetchPublicKeys`/`FetchJWKS` yourself on a timer; it already handles background refresh, rate-limited refresh on an unrecognized `kid`, and safe concurrent reads.

None of the exported symbols' doc comments are compiled or tested: this package has no `func Example*` tests, so a code sample inside a doc comment (including in `doc.go`, which is prose, not code) is illustrative, not verified. Do not assert that a symbol exists or has a given signature without checking the `.go` source yourself. When a reference document below disagrees with the source, the source wins and the document is a bug.

## Reference index

Load the one that matches the task; each is self-contained.

| Reference | Load it when |
| --- | --- |
| [api-map.md](references/api-map.md) | Writing code against the library and you need the real signature of an exported symbol, grouped by task |
| [security.md](references/security.md) | Choosing an algorithm, sizing a key, reviewing algorithm-confusion/none/expiry-skew risk, or checking what `Verify` does and does not validate for you |
| [keys-and-jwks.md](references/keys-and-jwks.md) | Managing more than one signing key, rotating keys by `kid`, fetching or publishing a JWKS, or verifying tokens from Auth0, AWS Cognito, Google or Microsoft |
| [validators.md](references/validators.md) | Composing `TokenValidator`s, using `Blocklist`/`Expected`/`Leeway`/`Skew`/`RequireExpiry`, or mapping a verification error to an HTTP response with `Classify` |
| [testing.md](references/testing.md) | Writing or running a test, overriding `jwt.Clock`, or understanding the `-tags safe` build |
