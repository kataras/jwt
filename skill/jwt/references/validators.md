# Validators, blocklisting and error classification

For exact signatures, see the "Validators, blocklist, classification" section of `api-map.md`.
This document covers how validators compose, because getting the order wrong produces a validator
that silently never runs, and how to turn a verification failure into an HTTP response.

## The `TokenValidator` contract

```go
type TokenValidator interface {
    ValidateToken(token []byte, standardClaims Claims, err error) error
}
```

`Verify` (and its `*Encrypted`/`*WithHeaderValidator` siblings) calls the validators you pass, in
order, threading a single `err` value through the chain:

1. `err` starts as whatever `validateClaims` produced from `nbf`/`iat`/`exp` (`nil`,
   `ErrNotValidYet`, `ErrIssuedInTheFuture`, or `ErrExpired`).
2. Each validator receives the token, the parsed standard claims, and the current `err`, and
   returns a (possibly different) error.
3. The loop stops at the first validator that returns a **non-nil** error; that becomes the final
   result, and no later validator runs at all.
4. If every validator runs to completion, the last one's return value (`nil` if it agreed nothing
   is wrong) is the final result.

Every builtin validator except `Skew`/`Future` follows the same pattern: `if err != nil { return
err }` at the top, i.e. "if something upstream already failed, do not override it, just pass it
through." That is precisely what makes ordering load-bearing: since a validator that only ever
*passes through* a non-nil error also causes the loop to `break` on it, any validator meant to
*rescue* that error must run strictly before every validator (yours or built-in) that would
otherwise just propagate it and end the chain.

```go
// Correct: Skew gets first look at ErrNotValidYet/ErrIssuedInTheFuture and can clear it.
jwt.Verify(alg, key, token, jwt.Skew(2*time.Minute), jwt.Expected{Issuer: "us"})

// Wrong: Expected sees the unrescued error first, returns it unchanged, and the loop
// stops there. Skew never runs.
jwt.Verify(alg, key, token, jwt.Expected{Issuer: "us"}, jwt.Skew(2*time.Minute))
```

`jwt.Validators(values ...any)` exists because Go will not implicitly convert a
`[]TokenValidatorFunc` into a `[]TokenValidator` at a call site expecting the latter; it flattens
a mix of `TokenValidator`, `TokenValidatorFunc`, a bare matching function, and nested slices of
either into one `[]TokenValidator`, preserving order (order still matters after flattening) and
dropping nils.

## Built-in validators

| Validator | Behavior |
| --- | --- |
| `jwt.Expected{...}` | `type Expected Claims`. Compares each **non-zero** field of the value you construct against the token's parsed claims; a zero field is simply not checked. `Audience` is membership, not equality: every audience you list in `Expected.Audience` must be *present in* the token's `Audience` (RFC 7519 §4.1.3), not equal to it element-for-element. Returns `ErrExpected` (wrapped with the field name) on the first mismatch |
| `jwt.Leeway(d)` | Only acts when `err == nil` so far. Rejects with `ErrExpired` if the token will expire within `d` from now, even though it has not expired yet. Use to avoid a token expiring mid-request (e.g., between an auth check and a slow database call) |
| `jwt.Skew(d)` | Rescues `ErrNotValidYet` or `ErrIssuedInTheFuture` when the claim is within `d` of "now" as measured by `Clock()`. Tolerates a *sender's* clock that runs ahead. Does nothing to an already-`ErrExpired` token; extending the life of an expired credential is treated as a policy decision, not a clock correction, and is not offered |
| `jwt.Future(d)` | Narrower predecessor of `Skew`: rescues only `ErrIssuedInTheFuture`, not `ErrNotValidYet`. Prefer `Skew` unless you specifically need the narrower behavior |
| `jwt.RequireExpiry` | Rejects (`ErrMissingExpiry`) a token that verified fine but carries no `"exp"` at all. Nothing in RFC 7519 makes `"exp"` mandatory, and it is easy to end up with a permanent token by accident (`MaxAge` with a duration under a second returns `NoMaxAge`; a `KeyConfiguration` with no `max_age` set skips the option entirely) |
| `jwt.Plain` | Only relevant when the payload is not JSON at all. Turns the internal "payload is not JSON" condition into success so `Verify` returns a `*VerifiedToken` whose `Claims()` will not work but whose `.Payload` holds the raw bytes. Put it last: anything after it that inspects `standardClaims` sees zero values |
| `*jwt.Blocklist` | See below |

## Blocklist as a validator

```go
blocklist := jwt.NewBlocklist(1 * time.Hour) // GC sweep interval; 0 disables auto-GC
defer blocklist.Close()                       // stop the GC goroutine when you are done with it

verifiedToken, err := jwt.Verify(jwt.HS256, key, token, blocklist)
// err == jwt.ErrBlocked if this exact token/jti was invalidated earlier

// On logout, or any other forced-invalidation event:
blocklist.InvalidateToken(verifiedToken.Token, verifiedToken.StandardClaims)
```

`ValidateToken` only checks the blocklist when the chain's `err` is already `nil` (a token that
failed for some other reason, e.g. expiry, is reported as that reason, not as blocked); if the
incoming error was `ErrExpired`, it also opportunistically removes the entry, since an expired
token can no longer be presented anyway. `Has`, `Del`, and `Count` are available for direct
inspection outside the validator path. See `security.md` for the `"jti"`-vs-whole-token key
tradeoff and for why `Close`/`NewBlocklistContext` matter for anything shorter-lived than the
whole process.

`jwt.TokenBlocklist` is the interface (`TokenValidator` plus `InvalidateToken`/`Del`/`Has`/`Count`)
to accept in your own function signatures instead of the concrete `*jwt.Blocklist`, so a
Redis-backed or otherwise distributed implementation can stand in later without changing callers.
An implementation of your own should derive its key via `jwt.DefaultBlocklistKey` rather than
reinventing it; getting the `"jti"`-empty fallback wrong (returning `""` unconditionally, for
instance) has, per the package's own comments, taken down a production system by mapping every
session without a `"jti"` onto the same blocked key.

## Writing a custom validator

A function literal satisfies `TokenValidatorFunc`, which implements `TokenValidator`:

```go
onlyAdmins := jwt.TokenValidatorFunc(func(token []byte, claims jwt.Claims, err error) error {
    if err != nil {
        return err // respect whatever already failed
    }
    if claims.Subject == "" {
        return errors.New("token has no subject")
    }
    return nil
})

verifiedToken, err := jwt.Verify(alg, key, token, onlyAdmins)
```

Follow the same convention every builtin validator does: check the incoming `err` first, and
return it unchanged unless your validator specifically knows how to rescue that exact condition.
A validator that swallows an unrelated error (returns `nil` regardless of what `err` was) silently
disables every check that ran before it in the chain.

## Turning an error into a response

```go
verifiedToken, err := jwt.Verify(alg, key, token, jwt.Expected{Issuer: "us"}, blocklist)
switch jwt.Classify(err) {
case jwt.KindNone:
    // proceed
case jwt.KindExpired:
    http.Error(w, "token expired", http.StatusUnauthorized) // worth distinguishing: client can refresh
case jwt.KindMalformed, jwt.KindInvalid, jwt.KindRejected:
    http.Error(w, "unauthorized", http.StatusUnauthorized)
}
```

`Classify` uses `errors.Is`, so a wrapped error still classifies correctly. It groups this
package's dozen-odd sentinel errors into four buckets plus "none": `KindMalformed`
(`ErrMissing`, `ErrTokenForm`, `ErrTokenSize`, `ErrNotJSONObject`: the token itself is unusable),
`KindExpired` (`ErrExpired`, `ErrNotValidYet`, `ErrIssuedInTheFuture`), `KindRejected`
(`ErrBlocked`, `ErrExpected`, `ErrMissingKey`, `ErrMissingExpiry`: the token is well-formed and
genuine but a policy check declined it), and `KindInvalid` for everything else, including
`ErrTokenSignature`, `ErrTokenAlg`, `ErrInvalidKey`, `ErrEmptyKid`, `ErrUnknownKid`, `ErrDecrypt`,
and any error your own validators return.

Send the same response body for every failing kind if the caller is not one of your own trusted
services. Telling an untrusted client whether its token was expired, forged, or revoked is free
reconnaissance; `KindExpired` is the one case worth surfacing distinctly, specifically because "go
refresh your token" is an actionable response for a legitimate client.
