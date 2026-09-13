# Chapter 8: Validators

`Verify` checks a signature and three timestamps. Every other question your application has
about a token, which issuer minted it, which audience it names, whether somebody logged out
two minutes ago, arrives through one interface with one method. This chapter covers that
interface, the validators the package ships, and one property of the loop that runs them: it
stops at the first error. That decides the order your validators have to be in, and getting
it backwards produces a chain that reads correctly and never runs.

## Table of Contents

- [The interface and its function form](#the-interface-and-its-function-form)
- [The chaining rule](#the-chaining-rule)
- [Expected, field by field](#expected-field-by-field)
- [Plain, for a payload that is not JSON](#plain-for-a-payload-that-is-not-json)
- [Leeway, Skew, Future and RequireExpiry](#leeway-skew-future-and-requireexpiry)
- [Collecting validators with Validators](#collecting-validators-with-validators)
- [Writing your own](#writing-your-own)
- [Classify, and what to tell the client](#classify-and-what-to-tell-the-client)
- [Summary](#summary)
- [Further Reading](#further-reading)

## The interface and its function form

Two declarations, both in `verify.go`:

```go
type TokenValidator interface {
	ValidateToken(token []byte, standardClaims Claims, err error) error
}

type TokenValidatorFunc func(token []byte, standardClaims Claims, err error) error

func (fn TokenValidatorFunc) ValidateToken(token []byte, standardClaims Claims, err error) error
```

`token` is the whole token exactly as it arrived: header, payload and signature, dots
included, not the payload and not decoded. `standardClaims` is the parsed `Claims` value, the
seven registered claims plus `origin_jti`, and nothing else from the payload reaches you here.

`err` is the third parameter and the one that makes this interface unusual. It is the verdict
so far: whatever claims validation produced, or whatever the previous validator returned. A
validator receives the state of the decision and returns the new one, which is what lets it
clear an error rather than only add one.

`TokenValidatorFunc` is the closure form. `Leeway`, `Future` and `Skew` each return one,
`RequireExpiry` and `Plain` are one, and `Expected` and `*Blocklist` are types carrying the
method. All go in the same variadic slot of `Verify`, and none ever runs for a token whose
signature failed, since `decodeToken` returns early on any signature or format problem.

## The chaining rule

The whole mechanism is the last third of `verifyToken` in `verify.go`:

```go
if err == nil { // do not proceed if we have a JSON error.
	err = validateClaims(Clock(), standardClaims)
}
for _, validator := range validators {
	// A token validator can skip the builtin validation and return a nil error.
	if err = validator.ValidateToken(token, standardClaims, err); err != nil {
		break
	}
}
```

Read the assignments rather than the shape. Going into the loop, `err` holds one of three
things: nil, `errPayloadNotJSON` if the payload would not parse, or a timing error from
`validateClaims`. Note the guard on that call: when the payload is not JSON the timing checks
never run at all, which matters two sections from here. Inside the loop, `err` is both the
value passed in and the variable assigned, and whatever comes out is what `Verify` returns. So
trace the first iteration. Validator one returns non-nil, the loop breaks, nothing else runs.
Validator one returns nil, so validator two is handed nil. There is no third path.

**A validator only ever receives a non-nil error when it is first in the list.** Stated as a
program rather than an argument, over a token that expired an hour ago:

```go
spy := func(name string) jwt.TokenValidatorFunc {
	return func(_ []byte, _ jwt.Claims, err error) error {
		fmt.Printf("%s saw err=%v\n", name, err)
		return err
	}
}
jwt.Verify(jwt.HS256, key, expired, spy("first"), spy("second"), spy("third"))
// prints exactly one line: first saw err=jwt: token expired
```

The second and third spies print nothing. On a token that passes, all three run and all three
see nil. Three consequences follow.

**A rescuing validator has to come first.** `Skew`, `Future` and `Plain` work by turning one
specific error into nil. Anywhere but position one they are handed nil, and returning nil for
nil changes nothing:

```go
// Correct: Skew clears the nbf failure, then Expected checks the subject.
jwt.Verify(jwt.HS256, key, token, jwt.Skew(2*time.Minute), jwt.Expected{Subject: "u1"}) // <nil>
// Wrong: Expected passes ErrNotValidYet through, the loop breaks, Skew never runs.
jwt.Verify(jwt.HS256, key, token, jwt.Expected{Subject: "u1"}, jwt.Skew(2*time.Minute))
// -> jwt: token not valid yet
```

Both compile and both look like a validator chain, and the second silently rejects every token
from an issuer whose clock is a minute fast.

**A later validator cannot repair an earlier failure.** Once any validator returns an error
verification is over, and nothing downstream can overturn that decision.

**The prologue every built-in validator opens with is unreachable except in position one.**
`Expected`, `RequireExpiry` and `*Blocklist` all start with `if err != nil { return err }`.
Write it in your own anyway: it is correct where it runs, and whoever reorders the chain next
year will not read your code first.

The package's own documentation got this wrong until v0.2.0. The doc comment on `Plain` said
to place it last, "so it can catch JSON errors that other validators might depend on". Run
`jwt.Verify(jwt.HS256, key, plain, jwt.Expected{Issuer: "us"}, jwt.Plain)` over a non-JSON
payload and the result is `jwt: payload is not a type of JSON`: `Expected` returned the error
it was handed, and `Plain` never executed. The comment now says the opposite, which is the
useful reminder that advice about ordering is worth testing rather than trusting.

## Expected, field by field

`Expected` is a distinct type over the same struct as `Claims`, so you fill it the same way:

```go
type Expected Claims

func (e Expected) ValidateToken(token []byte, c Claims, err error) error
```

Each field is checked only when it is set, which is what makes partial validation possible,
and the error names the claim:

| Field | Claim | Checked when | Error |
| --- | --- | --- | --- |
| `NotBefore` | `nbf` | `> 0` | `jwt: field not match: nbf` |
| `IssuedAt` | `iat` | `> 0` | `jwt: field not match: iat` |
| `Expiry` | `exp` | `> 0` | `jwt: field not match: exp` |
| `ID` | `jti` | non-empty | `jwt: field not match: jti` |
| `Issuer` | `iss` | non-empty | `jwt: field not match: iss` |
| `Subject` | `sub` | non-empty | `jwt: field not match: sub` |
| `Audience` | `aud` | non-empty | `jwt: field not match: aud ("admin")` |

All of them wrap `ErrExpected`, so `errors.Is(err, jwt.ErrExpected)` matches and `Classify`
returns `KindRejected`. `OriginID` has no check: the field exists because `Expected` is
`Claims`, and `ValidateToken` never reads it. The timestamp fields are exact equality against
a Unix second, useful in a test over a token you minted and rarely what a handler wants.

The audience row is the one entry in that table that is not equality. Each audience you ask for
has to appear somewhere in the token's list, which is what RFC 7519 section 4.1.3 asks of a
recipient, so neither order nor extra audiences matter:

```go
for _, expected := range e.Audience {
	if !c.Audience.Contains(expected) {
		return fmt.Errorf("%w: aud (%q)", ErrExpected, expected)
	}
}
// Token carries aud: ["api", "web", "mobile"].
jwt.Verify(jwt.HS256, key, token, jwt.Expected{Audience: jwt.Audience{"web"}})           // <nil>
jwt.Verify(jwt.HS256, key, token, jwt.Expected{Audience: jwt.Audience{"mobile", "api"}}) // <nil>
jwt.Verify(jwt.HS256, key, token, jwt.Expected{Audience: jwt.Audience{"admin"}})
// -> jwt: field not match: aud ("admin")
```

This used to compare the two lists for equal length and equal order, so an identity provider
adding a second audience broke every recipient at once. What the membership test does not do
is tell you the token was meant only for you: `["api", "partner-api"]` passes a check for
`api`, the RFC's intent. If your rule is stricter, compare `StandardClaims.Audience` yourself.

**A zero-value `Expected` validates nothing, and the call site cannot tell.** The line
`jwt.Verify(jwt.HS256, key, token, jwt.Expected{})` returns nil for any token that verifies.
It has a validator in it, it passes review, and it checks no claim. The usual route to it is a
config struct whose `Issuer` was never populated, so check that the string is non-empty when
you load your configuration. The validator will not complain on your behalf.

## Plain, for a payload that is not JSON

Nothing in RFC 7515 requires a JWS payload to be JSON. This package assumes it is, and when
the assumption fails it sets an unexported error before the validator loop, so the only way to
act on it is with a validator:

```go
var errPayloadNotJSON = errors.New("jwt: payload is not a type of JSON")

var Plain = TokenValidatorFunc(func(token []byte, standardClaims Claims, err error) error {
	if err == errPayloadNotJSON {
		return nil // skip this error entirely.
	}
	return err
})
```

Pass it first and the payload comes back raw: for a token signed over `just some text`,
`jwt.Verify(jwt.HS256, key, plain, jwt.Plain)` returns nil and `verifiedToken.Payload` is
that text.

**Understand what you gave up.** `validateClaims` is guarded by `if err == nil` and runs before
the loop, so when the payload does not parse the timing checks never happened, and `Plain`
clearing the error afterwards does not send the verifier back to run them. A token verified
with `Plain` has a checked signature and no time bound at all, which also makes `Plain`
followed by any claim-based validator pointless. `Plain` then `Expected{Issuer: "us"}` returns
`jwt: field not match: iss`, and `Plain` then `RequireExpiry` returns `jwt: token has no
expiry`, both from the zero `Claims`. `errPayloadNotJSON` is not a name `Classify` knows, so it
comes back as `KindInvalid` rather than `KindMalformed`.

Reach for `Plain` when you verify tokens some other system minted with a non-JSON payload, and
not to make a parse failure go away in your own tokens, where it is the finding.

## Leeway, Skew, Future and RequireExpiry

Four validators that exist because of clocks and defaults. Chapter 4 works through the timing
rules; here is what the chaining rule adds to them.

```go
func Leeway(leeway time.Duration) TokenValidatorFunc
func Skew(d time.Duration) TokenValidatorFunc
func Future(dur time.Duration) TokenValidatorFunc
var RequireExpiry = TokenValidatorFunc(...)
```

`Leeway` reads like a tolerance and behaves as the opposite. Its whole body is one comparison,
which moves the clock forward and then asks whether the token has expired:

```go
if Clock().Add(leeway).Round(time.Second).Unix() > standardClaims.Expiry {
	return ErrExpired
}
```

A token minted with `MaxAge(30*time.Second)` verifies on its own and returns `jwt: token
expired` under `jwt.Leeway(time.Minute)`. The name comes from the caller's problem rather than
the token's: you are about to start something slow, and beginning it with a credential that
dies halfway through leaves a partial write and a 401 you cannot retry. Two guards. It does
nothing for a token with no `exp`, and it is wrapped in `if err == nil`, so it only refuses.

`Skew(d)` rescues both `ErrNotValidYet` and `ErrIssuedInTheFuture` when the claim falls within
`d` of now. `Future(dur)` rescues only `ErrIssuedInTheFuture`, and since `validateClaims`
checks `nbf` first and returns at the first failure, an issuer that sets `nbf` equal to `iat`
produces a skewed token `Future` cannot help: with `nbf` and `iat` a minute ahead,
`jwt.Future(2*time.Minute)` still returns `jwt: token not valid yet` while
`jwt.Skew(2*time.Minute)` returns nil.

Both rescue, so both belong first, and a non-positive `d` makes `Skew` a no-op that passes the
error through. `RequireExpiry` is a value rather than a function, so it takes no arguments: it
returns `ErrMissingExpiry` for a token whose `Expiry` is zero, catching a `MaxAge` of zero
quietly producing permanent tokens. It refuses rather than rescues, so put it after anything
that rescues.

## Collecting validators with Validators

```go
func Validators(values ...any) []TokenValidator
```

This exists because of a Go rule that surprises people once each. `TokenValidatorFunc`
implements `TokenValidator`, but a `[]TokenValidatorFunc` is not assignable to a
`[]TokenValidator`: one element is a function value, the other a two-word interface value, so
converting the slice would mean building a new backing array. Go declines to do that
implicitly, and every call site holding one kind and needing the other grew the same copy loop:

```go
jwt.Verify(alg, key, token, jwt.Validators(app.Validators, jwt.Skew(time.Minute))...)
```

It accepts a `TokenValidator`, a `TokenValidatorFunc`, a bare
`func(token []byte, standardClaims Claims, err error) error`, a `[]TokenValidator` or a
`[]TokenValidatorFunc`, flattens the slices and drops nils, preserving order.

The cost is in the signature: `values ...any` means the compiler checks nothing. Pass a
`string`, or a typed nil matching none of the cases, and it is dropped without a word. A chain
that silently lost its blocklist looks like one that never had it, so if you build validator
lists dynamically, compare `len()` against what you expected.

## Writing your own

A validator sees only the registered claims, so checking one of your own means decoding the
payload inside the validator:

```go
// ErrWrongTenant reports a token minted for a different tenant.
var ErrWrongTenant = errors.New("myapp: token is for another tenant")

// TenantValidator accepts only tokens whose "tenant" claim matches Want.
type TenantValidator struct{ Want string }

// ValidateToken implements jwt.TokenValidator.
func (v TenantValidator) ValidateToken(token []byte, standardClaims jwt.Claims, err error) error {
	if err != nil {
		return err
	}
	decoded, err := jwt.Decode(token)
	if err != nil {
		return err
	}

	var claims struct {
		Tenant string `json:"tenant"`
	}
	if err = decoded.Claims(&claims); err != nil {
		return err
	}
	if claims.Tenant != v.Want {
		return fmt.Errorf("%w: %q", ErrWrongTenant, claims.Tenant)
	}
	return nil
}
```

Over a token carrying `"tenant": "acme"`, `TenantValidator{Want: "acme"}` returns nil and
`TenantValidator{Want: "globex"}` returns `myapp: token is for another tenant: "acme"`.

`jwt.Decode` verifies nothing, and chapter 1 tells you not to trust what it returns. Inside a
validator the situation is different: `decodeToken` already checked the signature over these
exact bytes, so the payload you re-read is the payload your key covered. The cost is a second
base64 decode and JSON parse per request, small next to the signature check, and there is no
cheaper hook, because the parsed payload is not handed to validators. `VerifyEncrypted`
decrypts after `decodeToken`, so a validator calling `jwt.Decode(token)` there gets ciphertext.

The error wraps a sentinel with `%w` and names the package that produced it, so callers can use
`errors.Is(err, ErrWrongTenant)`. What you cannot do from outside is make `Classify` return a
category of your choosing: anything it does not recognise comes back as `KindInvalid`. To land
in `KindRejected` alongside `ErrBlocked` and `ErrExpected`, wrap both, which Go 1.20 allows:

```go
return fmt.Errorf("%w: %w", ErrWrongTenant, jwt.ErrExpected)
// errors.Is matches both; jwt.Classify returns KindRejected
```

The cost is a message reading `myapp: token is for another tenant: jwt: field not match`. Use
it when the classification drives a response you care about.

## Classify, and what to tell the client

Verification fails in about a dozen distinct ways, and a handler mapping them to status codes
ends up maintaining a list of sentinels that drifts. `Classify` collapses them into five
values, `KindNone` for success and the four below, and `ErrorKind.String()` gives the
lowercase name for a log line or a metric label:

| Kind | Meaning | Examples |
| --- | --- | --- |
| `KindMalformed` | Not a usable JWT. | `ErrMissing`, `ErrTokenForm`, `ErrTokenSize` |
| `KindInvalid` | Well formed, not ours. | `ErrTokenSignature`, `ErrTokenAlg`, anything custom |
| `KindExpired` | Right token, wrong time. | `ErrExpired`, `ErrNotValidYet`, `ErrIssuedInTheFuture` |
| `KindRejected` | Verified, refused by policy. | `ErrBlocked`, `ErrExpected`, `ErrMissingExpiry` |

`Classify` uses `errors.Is`, so a wrapped error still classifies, and the default arm is
`KindInvalid` because the conservative reading of an unrecognised verification failure is that
the token is unacceptable.

**Return the same body for every failing kind.** The kinds are for your logs, your metrics and
your own decisions, not for the response:

```go
if kind := jwt.Classify(err); kind != jwt.KindNone {
	log.Printf("rejected token: kind=%s err=%v", kind, err)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
	return
}
```

Telling somebody their token was expired rather than forged, or revoked rather than signed by
a key you do not hold, hands them a free oracle: they learn whether a token they carry was ever
real, and whether a stolen session has been noticed. The defensible exception is a first-party
client that must know when to refresh, and even there the distinction belongs in a field you
control rather than in two error strings.

## Summary

A validator is one method taking the token bytes, the parsed registered claims and the error
so far, and returning the new error. `Verify` runs them in order, hands each one the previous
result, and breaks at the first non-nil error, so a validator only ever receives a non-nil
error when it is first in the list. Rescuing validators (`Skew`, `Future`, `Plain`) must come
first or they do nothing, and no validator can undo an earlier failure. That rule is why the
package's own advice to place `Plain` last was wrong, and why it changed in v0.2.0.

`Expected` checks each field only when it is set, and its audience check is membership per RFC
7519 section 4.1.3, so extra audiences and a different order both pass. A zero-value `Expected`
validates nothing while looking at the call site as though it does. `Plain` clears
`errPayloadNotJSON` and with it every timing check. `Leeway(d)` is stricter than its name: it
rejects tokens expiring within the next `d`.

`Validators(values ...any)` exists because Go will not convert `[]TokenValidatorFunc` to
`[]TokenValidator`; it flattens, preserves order and drops nils, at the cost of compile-time
checking. Your own validator decodes the payload with `jwt.Decode` and wraps a sentinel of its
own. `Classify` sorts the result into five kinds for your logs, and the client gets the same
body whichever kind it was.

## Further Reading

- [RFC 7519 section 4.1.3](https://www.rfc-editor.org/rfc/rfc7519#section-4.1.3): the `aud`
  claim, and the sentence that makes the recipient's check a membership test.
- [RFC 8725](https://www.rfc-editor.org/rfc/rfc8725): section 3.1, on validating every claim.
- [pkg.go.dev/github.com/kataras/jwt#TokenValidator](https://pkg.go.dev/github.com/kataras/jwt#TokenValidator):
  the generated reference for the interface and every built-in implementation.
- [go.dev/blog/go1.13-errors](https://go.dev/blog/go1.13-errors): `errors.Is` and `%w`.

---

**Next Chapter**: [Revoking Tokens](09-revoking-tokens.md) - Why a signed token outlives your decision to stop trusting it, and what a blocklist costs.
