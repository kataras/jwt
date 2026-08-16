# Chapter 2: Signing and Verifying

Two functions carry almost all of the traffic in this package: `Sign` produces a token, and
`Verify` turns one back into claims or refuses to. Everything else is either a variation on
those two or a way of choosing the key they use. This chapter covers both in full, and then
spends most of its length on one design decision that follows from Chapter 1: the algorithm
is something you pass in, and it is never read out of the token you are checking.

## Table of Contents

- [The two functions](#the-two-functions)
- [A complete program](#a-complete-program)
- [Why the algorithm is a parameter](#why-the-algorithm-is-a-parameter)
- [What compareHeader actually does](#what-compareheader-actually-does)
- [What a VerifiedToken gives you](#what-a-verifiedtoken-gives-you)
- [Decode versus Verify](#decode-versus-verify)
- [The errors a failed verification returns](#the-errors-a-failed-verification-returns)
- [A custom header replaces the whole header](#a-custom-header-replaces-the-whole-header)
- [What Sign accepts as claims](#what-sign-accepts-as-claims)
- [The size ceiling](#the-size-ceiling)
- [Summary](#summary)
- [Further Reading](#further-reading)

## The two functions

Here are both signatures, copied from the source rather than from memory:

```go
func Sign(alg Alg, key PrivateKey, claims any, opts ...SignOption) ([]byte, error)

func Verify(alg Alg, key PublicKey, token []byte, validators ...TokenValidator) (*VerifiedToken, error)
```

The first two parameters have the same shape in both, in the same order, because signing and
verifying are the same operation seen from two sides. Both return byte slices rather than
strings, since a token is going into an HTTP header or a cookie and `Sign` joins three byte
slices to build it anyway.

`PrivateKey` and `PublicKey` are declared as `= any`. They are aliases, not distinct types,
so the compiler will not stop you handing an `*rsa.PrivateKey` to `Verify`. The price is a
runtime failure instead of a build failure: a mismatched key comes back as `ErrInvalidKey`,
and passing `"secret"` where `[]byte("secret")` was needed produces `expected a string: jwt:
invalid key`. What you get is one function covering HMAC secrets, RSA and ECDSA key pairs
and Ed25519 keys with no generics and no per-algorithm entry points. Chapter 5 goes through
which key type each algorithm wants.

## A complete program

This compiles and runs against the package as it stands. Nothing has been elided.

```go
package main

import (
	"fmt"
	"log"
	"time"

	"github.com/kataras/jwt"
)

type userClaims struct {
	Username string `json:"username"`
	Role     string `json:"role"`
}

func main() {
	sharedKey := []byte("sercrethatmaycontainch@r$")

	token, err := jwt.Sign(jwt.HS256, sharedKey,
		userClaims{Username: "kataras", Role: "admin"},
		jwt.MaxAge(15*time.Minute))
	if err != nil {
		log.Fatal(err)
	}

	verified, err := jwt.Verify(jwt.HS256, sharedKey, token)
	if err != nil {
		log.Fatal(err)
	}

	var claims userClaims
	if err := verified.Claims(&claims); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("token: %s\n", token)
	fmt.Printf("user:  %s (%s)\n", claims.Username, claims.Role)
	fmt.Printf("left:  %s\n", verified.StandardClaims.Timeleft())
}
```

```text
token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImthdGFyYXMiLCJyb2xlIjoiYWRtaW4iLCJpYXQiOjE3ODY4NzQ4NjAsImV4cCI6MTc4Njg3NTc2MH0.6I8OqoqQPJffSoY3NphOfS5ntrYcoLACpYHe58xUWPk
user:  kataras (admin)
left:  15m0s
```

Three things there are worth naming. `jwt.HS256` appears twice, once on each side, and both
are written out by you: that is the subject of the next section. `jwt.MaxAge(15 *
time.Minute)` is a `SignOption`, and it sets `exp` and `iat` from the current time, which is
why the payload holds two claims the struct never declared (Chapter 3 covers sign options,
Chapter 4 covers time). And `verified.Claims(&claims)` unmarshals the payload a second time:
`Verify` already parsed it once into `StandardClaims`, but it has no idea what your struct
looks like, so your own claims cost one more `json.Unmarshal`.

## Why the algorithm is a parameter

A JWT header names its own algorithm. The obvious implementation reads that name and picks
the verifier to match. Do not write that implementation, and this package makes it awkward
to write by accident.

Consider a service that verifies with an RSA public key and reads `alg` from the token to
decide what to do. An attacker takes a genuine token, replaces the header with
`{"alg":"HS256","typ":"JWT"}`, and computes an HMAC-SHA256 signature over the new
header-and-payload using the RSA public key bytes as the shared secret. The public key is
public: it is on your JWKS endpoint, or in a certificate, or in a repository.

The service now does exactly what it was told. The header says HS256, so it runs
HMAC-SHA256, and the key it has to hand is the RSA public key. The MAC matches, because the
attacker computed it with the same bytes. One asymmetric key pair has become a shared secret
everybody already has, and the attacker can mint any claims they like.

That is the algorithm-confusion attack. It has been in the JWT security literature since
2015 and keeps reappearing, because the vulnerable design reads as the reasonable one: the
token says how it was signed, so believe it.

This package will not let you believe it. `Verify` takes `alg` as its first argument, and
the token's header never chooses the verifier. Pass `jwt.RS256` and an RSA public key, hand
the forged token to it, and the result is `ErrTokenAlg`, returned before any signature is
computed. The forged signature is never checked against anything, because the header did not
survive the earlier test.

The trade-off is that you have to know your own algorithm at the call site. For a service
issuing its own tokens that is free. For one consuming tokens from an identity provider that
rotates algorithms it is not, and that is what `VerifyWithHeaderValidator` and the `Keys`
registry exist for (Chapters 6 and 7). Both still keep the choice explicit: a
`HeaderValidator` returns the `Alg` to use, so the selection is code you can read rather
than a lookup keyed on attacker-controlled text.

## What compareHeader actually does

The check that rejects the forged header is `compareHeader` in `token.go`, and it does not
parse JSON at all.

At package initialisation, `token.go` fills a map called `fixedHeaders`, one `fixedHeader`
entry per built-in algorithm. Each entry holds three byte slices: `raw`, the header JSON,
`encoded`, its base64url form, and `reversed`, the same JSON with the two fields in the
opposite order. For HS256, `raw` and `reversed` are `{"alg":"HS256","typ":"JWT"}` and
`{"typ":"JWT","alg":"HS256"}`, both 27 bytes. Verification base64-decodes the incoming
header and runs `bytes.Equal` against one of them. There is no `alg` field to extract,
because nothing is ever extracted.

Two cheap tests decide which form to compare against. A decoded header shorter than 25 bytes
is accepted only at exactly 15, the length of `{"alg":"HS256"}`, a header with no `typ` at
all. Otherwise, if byte index 2 is `t` the header started `{"typ"` and the reversed form is
used. Everything else goes against the standard order. Then `bytes.Equal`, and `ErrTokenAlg`
if it differs.

This is strict, and it is worth seeing how strict. Each of these was signed with the correct
HS256 key and passed to `jwt.Verify(jwt.HS256, key, token)`:

| Header | Result |
| --- | --- |
| `{"alg":"HS256","typ":"JWT"}` | accepted |
| `{"typ":"JWT","alg":"HS256"}` | accepted |
| `{"alg":"HS256"}` | accepted |
| `{"alg":"HS256","typ":"jwt"}` | `ErrTokenAlg` |
| `{"alg":"HS256", "typ":"JWT"}` | `ErrTokenAlg` |
| `{"typ":"JWT","alg":"HS256","kid":"a"}` | `ErrTokenAlg` |

One space and a lowercase `jwt` are both fatal, and so is a `kid`, which is a perfectly
ordinary header field. That is a real cost: a token from another implementation that formats
its header differently is rejected even though its signature is fine. What you get for it is
that the parsing step an attacker would need to influence does not exist. There is no field
ordering to confuse, no duplicate-key handling to exploit, no Unicode escape to smuggle a
second `alg` through. The comparison is against 27 bytes your process chose at startup.

When you need the flexibility back, supply a `HeaderValidator`:

```go
type HeaderValidator func(alg string, headerDecoded []byte) (Alg, PublicKey, InjectFunc, error)
```

The package-level `CompareHeader` variable holds the strict implementation and is used when
you pass none. Replacing it is how `kid` support works, and it is why a validator returns a
`PublicKey` too: having read the header, it can also choose the key.

## What a VerifiedToken gives you

`Verify` returns `*VerifiedToken`, which is five fields and one method.

```go
type VerifiedToken struct {
	Token          []byte
	Header         []byte
	Payload        []byte
	Signature      []byte
	StandardClaims Claims
}

func (t *VerifiedToken) Claims(dest any) error
```

`Token` is the original bytes you passed in, unchanged. Keep it if you will pass the token
onward or key a blocklist entry on it. `Signature` is the decoded signature, 32 bytes for
HS256, useful mainly for logging.

`Header` and `Payload` are base64-decoded JSON. For the program above they read
`{"alg":"HS256","typ":"JWT"}` and
`{"username":"kataras","role":"admin","iat":1786874860,"exp":1786875760}`. This header is
trustworthy in a way the one from `Decode` is not, because the signature covered it and the
signature verified. `StandardClaims` is a `Claims` struct filled from the payload during
verification, with its time claims already checked. Chapter 3 walks its fields.

`Claims(dest)` unmarshals `Payload` into anything JSON can fill: a tagged struct, a
`jwt.Map`, a type with its own `UnmarshalJSON`. It calls the package-level `Unmarshal`
variable, so replacing that replaces the behaviour everywhere, which is how
`UnmarshalWithRequired` is switched on in Chapter 3. It re-parses on every call, so if you
need three views of one payload, unmarshal once into a struct holding all three sets of
fields.

## Decode versus Verify

`Decode` splits a token and base64-decodes the pieces. It checks no signature, no expiry and
no algorithm. The result is an `UnverifiedToken`, with `Header`, `Payload` and `Signature`
fields, its own `Claims(dest any) error`, and two header helpers that cache what they read:

```go
func Decode(token []byte) (*UnverifiedToken, error)

func (t *UnverifiedToken) Alg() (Alg, error)
func (t *UnverifiedToken) Kid() (string, error)
```

There are two honest uses for this.

**Deciding which key to fetch.** You cannot verify until you have the key, and the `kid`
naming that key is inside the token, so reading it first is unavoidable. What makes it safe
is that the value is used only as a lookup, and the verification that follows decides
whether the token is real. A `kid` naming a key you do not have produces `ErrUnknownKid`,
and a `kid` naming the wrong key produces a signature failure.

**Reporting on tokens you rejected.** When verification fails and you want to log which
issuer the token claimed, `Decode` is the only way to see it. Log it as a claim, not a fact.

Everything else is a mistake waiting for its incident. `unverified.Claims(&user)` followed
by trusting `user.Role` is the whole vulnerability, in two lines that look like normal code.
If your reason for reaching for `Decode` is that the token comes from a trusted internal
source, "internal" describes your network and the payload describes what somebody typed.

## The errors a failed verification returns

Verification can fail in about a dozen ways, and services that map them to HTTP status codes
end up maintaining a list of sentinels that drifts out of date. `Classify` in `classify.go`
collapses them into the five values an application actually branches on:

```go
func Classify(err error) ErrorKind

switch jwt.Classify(err) {
case jwt.KindNone:
	// carry on
case jwt.KindExpired:
	http.Error(w, "token expired", http.StatusUnauthorized) // the client can refresh
default:
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}
```

Here is what the common failures produce. Every row was run.

| Failure | Error | `Classify` |
| --- | --- | --- |
| `Verify(alg, key, nil)` | `ErrMissing` | `KindMalformed` |
| Not three dot-separated parts | `ErrTokenForm` | `KindMalformed` |
| Longer than `MaxTokenSize` | `ErrTokenSize` | `KindMalformed` |
| Header does not match | `ErrTokenAlg` | `KindInvalid` |
| Payload altered, or the wrong secret | `ErrTokenSignature` | `KindInvalid` |
| Key of the wrong type | `ErrInvalidKey` | `KindInvalid` |
| `exp` in the past | `ErrExpired` | `KindExpired` |
| `nbf` in the future | `ErrNotValidYet` | `KindExpired` |
| `iat` in the future | `ErrIssuedInTheFuture` | `KindExpired` |
| `Expected{Issuer: ...}` did not match | `ErrExpected` | `KindRejected` |
| A required claim was absent | `ErrMissingKey` | `KindRejected` |

`Classify` uses `errors.Is`, so a wrapped error still classifies, and anything it does not
recognise comes back as `KindInvalid`, the conservative reading of an unrecognised
verification failure. Two categories land somewhere you might not expect: a payload that is
not JSON, and a base64 error out of a segment that is not base64 at all, both come back
`KindMalformed`. Neither is one of this package's sentinel errors: the first is unexported
and the second is a `base64.CorruptInputError`, so `Classify` matches them specially.

`KindExpired` is the one distinction worth surfacing to a client of your own, since
refreshing is a fix the client can apply. For anybody else, return the same body for every
failing kind. Telling an attacker whether a token was expired, forged or revoked is
information given away for nothing.

## A custom header replaces the whole header

`SignWithHeader` lets you put your own fields in the header:

```go
func SignWithHeader(alg Alg, key PrivateKey, claims any, customHeader any, opts ...SignOption) ([]byte, error)
```

The package's own documentation describes those fields as being merged with the standard
ones. They are not. Here is the whole implementation from `token.go`:

```go
func createCustomHeader(header any) ([]byte, error) {
	b, err := Marshal(header)
	if err != nil {
		return nil, err
	}

	return Base64Encode(b), nil
}
```

Your value is marshalled and encoded. Nothing adds `alg`, nothing adds `typ`, and whatever
you pass is the entire header.

```go
token, _ := jwt.SignWithHeader(jwt.HS256, sharedKey, jwt.Map{"sub": "1"},
	jwt.Map{"kid": "key-1"})

unverified, _ := jwt.Decode(token)
fmt.Printf("%s\n", unverified.Header) // {"kid":"key-1"}
```

That token is signed correctly, and `jwt.Verify(jwt.HS256, sharedKey, token)` rejects it
with `ErrTokenAlg`, because the strict comparison from earlier finds no match. Restating the
standard fields does not save you, for a reason worth knowing about:

```go
jwt.SignWithHeader(jwt.HS256, sharedKey, claims,
	jwt.Map{"alg": "HS256", "typ": "JWT", "kid": "key-1"})
// header: {"alg":"HS256","kid":"key-1","typ":"JWT"}
```

`encoding/json` sorts map keys, so `kid` lands between `alg` and `typ` and the byte
comparison fails. Raw JSON in the exact standard order fares no better: the header is then
`{"alg":"HS256","typ":"JWT","kid":"key-1"}`, still not one of the three forms
`compareHeader` knows.

The conclusion is short. Signing with a custom header commits you to verifying with a
`HeaderValidator`. `VerifyWithHeaderValidator` takes one, and `Keys.ValidateHeader` is a
ready-made one that reads `kid` and picks the key. Chapter 7 covers it.

## What Sign accepts as claims

The `claims` parameter is `any`, and it goes through the package-level `Marshal` variable:

```go
var Marshal = func(v any) ([]byte, error) {
	if b, ok := v.([]byte); ok {
		return b, nil
	}

	return json.Marshal(v)
}
```

Three cases follow from those five lines.

**A struct.** Tag the fields and `json.Marshal` handles it. Embed `jwt.Claims` to get the
registered claims into the same object.

**A map.** `jwt.Map` is `= map[string]any`, an alias, so any `map[string]any` works with no
conversion. Key order in the payload is alphabetical, which is what `encoding/json` does
with maps.

**Raw bytes.** A `[]byte` is returned unchanged and becomes the payload verbatim: the fast
path for a payload you already hold, and unvalidated. This signs and hands out a token whose
payload is not JSON:

```go
token, err := jwt.Sign(jwt.HS256, sharedKey, []byte(`{"not":"validated"`))
// err is nil
```

Verifying it returns `jwt: payload is not a type of JSON`, which `jwt.Plain` exists to
suppress if a non-JSON payload is what you meant. If you would rather find out at signing
time, pass at least one `SignOption`: that routes the value through `Merge`, which runs
`json.Valid` on raw strings and byte slices and returns `ErrNotJSONObject`. Chapter 3 goes
into `Merge`.

## The size ceiling

`Decode` and every `Verify` variant refuse a token longer than `MaxTokenSize`, declared as
`var MaxTokenSize = 64 * 1024`, before parsing it.

Verification allocates in proportion to the token it is handed, and the token arrives from
whoever is calling. Without a ceiling, one unauthenticated request can ask your process for
as much memory as it can send. The refusal is `ErrTokenSize`, which classifies as
`KindMalformed`.

The default of 65536 bytes sits far above anything ordinary. A JWT with a handful of claims
is a few hundred bytes, and one carrying an `x5c` certificate chain in its header might
reach a few kilobytes. If you know your own tokens are small, set `jwt.MaxTokenSize = 8 *
1024` during startup, before any concurrent verification begins. It is a plain package
variable read without a lock, so changing it while requests are in flight is a data race.

## Summary

`Sign(alg, key, claims, opts...)` and `Verify(alg, key, token, validators...)` are the two
calls, and the algorithm is the first argument to both because you choose it, not the token.

That choice closes the algorithm-confusion attack, where a token's header is rewritten to
HS256 and signed with the RSA public key everybody already has. The mechanism is
`compareHeader`, which base64-decodes the header and runs `bytes.Equal` against one of three
precomputed forms for the algorithm you named. It never parses `alg`, so there is no parse
to influence, and it is strict enough that one extra space or a `kid` is a rejection.

A `VerifiedToken` carries the original bytes, the decoded header, payload and signature, a
populated `StandardClaims`, and a `Claims(dest)` method. `Decode` gives you the same pieces
with nothing checked, which is right for reading a `kid` before you have a key and wrong for
everything you act on. `Classify` sorts a dozen sentinel errors into five kinds, and
`KindExpired` is the one worth telling a client about.

A custom header replaces the whole header rather than merging into it, so signing with one
commits you to a `HeaderValidator`. Raw `[]byte` claims are passed through unvalidated
unless a `SignOption` sends them via `Merge`.

## Further Reading

- [RFC 7519 section 6](https://www.rfc-editor.org/rfc/rfc7519#section-6): unsecured JWTs,
  and why `alg: none` needs a deliberate decision rather than a default.
- [RFC 8725: JSON Web Token Best Current Practices](https://www.rfc-editor.org/rfc/rfc8725):
  section 3.1 is the algorithm-confusion attack and the recommendation this package
  implements.
- [RFC 7515 section 4.1.1](https://www.rfc-editor.org/rfc/rfc7515#section-4.1.1): the `alg`
  header parameter, including the requirement that recipients reject algorithms they do not
  expect.
- [pkg.go.dev/github.com/kataras/jwt](https://pkg.go.dev/github.com/kataras/jwt): the
  generated reference, which cannot drift from the source the way prose can.
- [encoding/json](https://pkg.go.dev/encoding/json): the marshalling rules behind
  `jwt.Marshal`, including the map key ordering that breaks a restated custom header.

---

**Next Chapter**: [Claims](03-claims.md) - The registered claims, your own, and how the two get combined into one payload.
