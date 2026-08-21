# Chapter 3: Claims

A payload is a JSON object, and the names in it are claims. Seven of them are registered by
RFC 7519 and this package models those in a struct called `Claims`; everything else is
yours. The interesting part is not either half on its own but how the two get joined into
one object, because the answer explains a performance choice, a duplicate key you may see in
your own tokens, and a parser that will accept a numeric `sub` but refuses a structured one.

## Table of Contents

- [The Claims struct, field by field](#the-claims-struct-field-by-field)
- [Custom claims in a struct of your own](#custom-claims-in-a-struct-of-your-own)
- [Combining custom claims with standard ones](#combining-custom-claims-with-standard-ones)
- [The sign-option shorthands](#the-sign-option-shorthands)
- [How Merge splices](#how-merge-splices)
- [The Audience type](#the-audience-type)
- [The second-chance parser](#the-second-chance-parser)
- [Required fields](#required-fields)
- [Summary](#summary)
- [Further Reading](#further-reading)

## The Claims struct, field by field

Here is the whole type from `claims.go`, tags included:

```go
type Claims struct {
	NotBefore int64    `json:"nbf,omitzero"`
	IssuedAt  int64    `json:"iat,omitzero"`
	Expiry    int64    `json:"exp,omitzero"`
	ID        string   `json:"jti,omitempty"`
	OriginID  string   `json:"origin_jti,omitempty"`
	Issuer    string   `json:"iss,omitempty"`
	Subject   string   `json:"sub,omitempty"`
	Audience  Audience `json:"aud,omitempty"`
}
```

The three timestamp fields are `omitzero`, not `omitempty`. Under the encoding/json this
package used through Go 1.26 the two are the same for a plain `int64`: both omit the Go
zero value. They stop agreeing once `Marshal` moves to `encoding/json/v2` (below), because
v2's `omitempty` only omits a value that already encodes to an empty JSON value, and a
numeric `0` is not one of those. `omitzero` was chosen deliberately to keep an unset `exp`
absent from the payload rather than emitting `"exp":0`.

The Go names and the JSON names differ on purpose. The three-letter forms are what goes on
the wire, because that is what RFC 7519 registered and what every other implementation looks
for. The longer forms are what you read in your own code.

| Field | Claim | What it holds |
| --- | --- | --- |
| `NotBefore` | `nbf` | Seconds since the epoch before which the token is not valid. |
| `IssuedAt` | `iat` | Seconds since the epoch at which the token was signed. |
| `Expiry` | `exp` | Seconds since the epoch after which the token is refused. |
| `ID` | `jti` | A unique identifier for this token. |
| `OriginID` | `origin_jti` | The `jti` of the token this one came from. |
| `Issuer` | `iss` | Whoever minted the token. |
| `Subject` | `sub` | The principal the token is about, usually a user. |
| `Audience` | `aud` | Who the token is for, as an `Audience`. |

Every tag carries `omitempty`, so a zero field is left out of the payload rather than written
as `0` or `""`. That is what makes a `Claims` value usable as a partial template, and it is
also why validation treats zero as absent. Chapter 4 covers what that means for time.

**`origin_jti` is not a registered claim.** The other seven are in the IANA JSON Web Token
Claims registry. This one is a convention of this package: it links a refresh token to the
access token issued alongside it, so revoking one can revoke the other. `SignPair` sets it
for you and Chapter 9 covers the revocation side. Send a token carrying `origin_jti` to
somebody else's service and expect them to ignore it.

Three methods read the time fields, all covered in Chapter 4:

```go
func (c Claims) Age() time.Duration      // Expiry - IssuedAt, the designed lifetime
func (c Claims) ExpiresAt() time.Time    // time.Unix(c.Expiry, 0)
func (c Claims) Timeleft() time.Duration // Expiry - Clock().Unix()
```

## Custom claims in a struct of your own

Your own claims are an ordinary Go struct with JSON tags. Nothing in the package needs to
know about the type. Pass a value of it to `Sign`, and read it back with
`VerifiedToken.Claims`:

```go
type sessionClaims struct {
	Username string   `json:"username"`
	Scopes   []string `json:"scopes"`
}

token, err := jwt.Sign(jwt.HS256, sharedKey,
	sessionClaims{Username: "kataras", Scopes: []string{"read", "write"}},
	jwt.MaxAge(15*time.Minute))

verified, err := jwt.Verify(jwt.HS256, sharedKey, token)

var claims sessionClaims
err = verified.Claims(&claims)
```

`Claims` takes a pointer and hands it to the package-level `Unmarshal`. Fields the payload
does not mention are left at their zero value, which is the standard `encoding/json`
behaviour and is why the next-to-last section of this chapter exists: if absence has to be an
error, you have to ask for that.

A `jwt.Map` works too, and is right when the claim set is not known at compile time:

```go
var m jwt.Map
err = verified.Claims(&m)
fmt.Printf("%T\n", m["iat"]) // json.Number
```

Numbers come back as `json.Number`, not `float64`, because the default `Unmarshal` decodes
through `encoding/json/v2` with a custom unmarshal hook that reproduces what
`json.Decoder.UseNumber()` gave `encoding/json` (v1): a number decoded into an `any`
destination stays a string-backed `json.Number` rather than losing precision to `float64`.
Call `.Int64()` on the result rather than asserting to `float64`.

## Combining custom claims with standard ones

You have two ways to get registered claims into the same payload as your own.

**Embed `jwt.Claims`.** The fields are promoted and `encoding/json` inlines them, so one
struct marshals to one flat object:

```go
type userClaims struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.Claims
}

token, err := jwt.Sign(jwt.HS256, sharedKey, userClaims{
	Username: "kataras",
	Role:     "admin",
	Claims:   jwt.Claims{Subject: "user-42", Issuer: "auth.example.com"},
}, jwt.MaxAge(time.Hour))
```

```text
{"username":"kataras","role":"admin","iss":"auth.example.com","sub":"user-42","iat":1700000000,"exp":1700003600}
```

**Pass them as sign options.** That is the variadic fourth parameter of `Sign`, and a
`SignOption` is one method:

```go
func Sign(alg Alg, key PrivateKey, claims any, opts ...SignOption) ([]byte, error)

type SignOption interface {
	ApplyClaims(*Claims)
}

type SignOptionFunc func(*Claims)
```

`signToken` starts with a zero `Claims`, calls `ApplyClaims` on each option in the order you
gave them, and merges the result with your claims. Because each option writes into the same
struct, a later option overwrites an earlier one that sets the same field:

```go
jwt.Sign(jwt.HS256, key, jwt.Map{}, jwt.Issuer("first"), jwt.Issuer("second"))
// payload: {"iss":"second"}
```

`Claims` itself implements `SignOption`, through an `ApplyClaims` that copies only the fields
that are set:

```go
func (c Claims) ApplyClaims(dest *Claims) {
	if v := c.NotBefore; v > 0 {
		dest.NotBefore = v
	}
	// ... and so on for the other seven fields
}
```

The test is `> 0` for the numbers and non-empty for the strings, so `jwt.Claims{}` as an
option contributes nothing and a partially filled one contributes only what it names. That
is what lets you keep a package-level template of your issuer and audience and pass it to
every call.

One asymmetry follows. `ApplyClaims` will not write a zero, so a `Claims` option cannot clear
a field an earlier option set. `NoMaxAge` exists precisely because of that: it is a
`SignOptionFunc` assigning `0` to `Expiry` and `IssuedAt` directly, which no `Claims` value
can do.

```go
jwt.Sign(jwt.HS256, key, jwt.Map{"a": 1}, jwt.MaxAge(time.Hour), jwt.NoMaxAge)
// payload: {"a":1}
```

## The sign-option shorthands

Before `signoptions.go`, the only sign options were `MaxAge`, `NoMaxAge`, `Audience` and
`Claims`. Setting a `jti` or an `iss` on its own meant writing a `SignOptionFunc` by hand,
and downstream packages did, which put this library's type into signatures that were meant
to hide it. Seven shorthands now set one field of `Claims` each:

```go
func ID(id string) SignOptionFunc
func OriginID(id string) SignOptionFunc
func Issuer(issuer string) SignOptionFunc
func Subject(subject string) SignOptionFunc
func NotBefore(t time.Time) SignOptionFunc
func IssuedAt(t time.Time) SignOptionFunc
func ExpiresAt(t time.Time) SignOptionFunc
```

The three taking a `time.Time` call `t.Round(time.Second).Unix()`, so a timestamp with
nanoseconds in it lands on a whole second, which is what the format stores anyway.

Alongside them are the four originals. `MaxAge(d)` sets `exp` to now plus `d` and `iat` to
now, both from the `Clock` variable. `NoMaxAge` clears both. `Audience` is the `[]string`
type itself, which implements `ApplyClaims` so you can pass it directly. And `Claims`, as
above. One behaviour of `MaxAge` is worth stating outright: if `maxAge <= time.Second` it
returns `NoMaxAge`, so `jwt.MaxAge(500 * time.Millisecond)` produces a token with no expiry
at all rather than one that expires immediately. Chapter 4 comes back to it.

Put together:

```go
token, err := jwt.Sign(jwt.HS256, sharedKey, jwt.Map{"role": "admin"},
	jwt.MaxAge(15*time.Minute),
	jwt.Issuer("auth.example.com"),
	jwt.Subject("user-42"),
	jwt.ID("tok-1"),
	jwt.OriginID("tok-0"),
	jwt.Audience{"api.example.com"},
	jwt.NotBefore(time.Unix(1700000000, 0)),
)
```

```text
{"role":"admin","nbf":1700000000,"iat":1700000000,"exp":1700000900,"jti":"tok-1","origin_jti":"tok-0","iss":"auth.example.com","sub":"user-42","aud":["api.example.com"]}
```

Your claims come first, then the accumulated standard ones in the field order of the `Claims`
struct. That is not `encoding/json` being clever. It is the next section.

## How Merge splices

`Merge` is what joins your claims to the standard ones, and it does not build a map and
re-encode it:

```go
func Merge(values ...any) ([]byte, error)
```

For each value it obtains JSON bytes, checks that the first byte is `{` and the last is `}`,
strips both, and keeps the inside. At the end it joins the pieces with commas and wraps the
lot in one pair of braces. Two objects go in and one comes out, with no intermediate
`map[string]any` and no reparse. That is why it is fast, and it is also why this happens:

```go
jwt.Merge(jwt.Map{"iss": "a"}, jwt.Claims{Issuer: "b"})
// {"iss":"a","iss":"b"}
```

The claim appears twice, because nothing looked at the names: looking at the names is the
expensive part that was skipped on purpose.

Be clear about what that costs. RFC 8259 says the names in an object "should be unique" and
that behaviour is unpredictable when they are not, so a payload like this is legal JSON but
not what the specification prefers. `encoding/json` resolves it last-wins, so Go reads `b`,
and so does anything else built on `encoding/json`, including `VerifiedToken.StandardClaims`:

```go
token, _ := jwt.Sign(jwt.HS256, key, jwt.Map{"iss": "from-claims"}, jwt.Issuer("from-option"))
// payload:  {"iss":"from-claims","iss":"from-option"}
verified, _ := jwt.Verify(jwt.HS256, key, token)
// verified.StandardClaims.Issuer == "from-option"
```

A first-wins parser elsewhere reads `from-claims`, and both parsers are within their rights.
If a token you issue is going to be read by something you did not write, do not put the same
claim in two places. Set `iss` in your claims object or in a sign option, not in both.

`Merge` does check the two cases it cannot vouch for. A `string` or a `[]byte` is spliced in
verbatim rather than marshalled, so those two are run through `json.Valid`:

```go
_, err := jwt.Merge(`{"broken"}`)
// part: 1: jwt: value is not a JSON object
```

That is `ErrNotJSONObject`, which `Classify` reports as `KindMalformed`. The error names the
part number rather than the value, because claims carry personal data and formatting the
offending value into an error puts it in whatever you log. Anything that came out of
`json.Marshal` skips the `json.Valid` scan, since it is valid by construction.

Nil values are skipped and empty objects are dropped, so `Merge(nil, jwt.Map{}, jwt.Map{"a":
1})` returns `{"a":1}` and merging nothing at all returns `{}`.

## The Audience type

`aud` is the one registered claim whose type is ambiguous in the specification. RFC 7519
section 4.1.3 says it is an array of strings, then says that in the special case of one value
it "MAY be a single case-sensitive string". Both forms are in the wild, so `Audience`, which
is a `[]string`, gives itself an `UnmarshalJSON` that looks at the first byte and branches:

```go
switch data[0] {
case '"': // it's a single string.
	// unmarshal into a string, wrap it in a one-element slice
case '[': // it's an array of strings.
	// unmarshal into []string directly
}
```

So `"aud":"api.example.com"` and `"aud":["api.example.com"]` both arrive as
`Audience{"api.example.com"}`, and your code never has to care which the sender used.
Anything else, a number or an object, falls through the switch and leaves the audience nil
without an error. That is a quiet outcome for a malformed claim, and worth a length check or
an `Expected` validator if `aud` matters to you.

Marshalling only goes one way. `jwt.Claims{Audience: jwt.Audience{"one"}}` writes
`{"aud":["one"]}`, an array even for a single value, which is the form the specification
prefers.

`Contains` is the membership test RFC 7519 section 4.1.3 actually asks for:

```go
func (aud Audience) Contains(value string) bool

if !verified.StandardClaims.Audience.Contains("api.example.com") {
	return errors.New("token is for somebody else")
}
```

The rule in the specification is that the recipient must identify itself with a value in the
audience. Not that it is the only value, and not that it is the first. A token good for
`["api.example.com", "admin"]` is good for the API and good for the admin panel, and each of
them checks for its own name. Comparison is exact and case sensitive, because audience values
are identifiers rather than prose: `Audience{"api.example.com"}.Contains("API.example.com")`
is false. `Expected` calls `Contains` for you if you would rather express the check as a
validator, and `String` joins the values with spaces for logging.

## The second-chance parser

`verifyToken` unmarshals the payload into a `Claims` struct with the standard library. When
that fails, it tries once more with a looser struct before giving up:

```go
type claimsSecondChance struct {
	NotBefore json.Number `json:"nbf,omitempty"`
	IssuedAt  json.Number `json:"iat,omitempty"`
	Expiry    json.Number `json:"exp,omitempty"`
	ID        string      `json:"jti,omitempty"`
	OriginID  string      `json:"origin_jti,omitempty"`
	Issuer    any         `json:"iss,omitempty"`
	Subject   any         `json:"sub,omitempty"`
	Audience  Audience    `json:"aud,omitempty"`
}
```

`json.Number` for the timestamps and `any` for the two identity claims. `toClaims` then
converts, and what it accepts and refuses is the point.

**A float timestamp is accepted.** Some authorities emit `"exp":2000000000.5`, off by a
fraction of a second. `toUnix` parses through `Float64` and truncates, so that arrives as
`2000000000`. This is the case the loose struct was written for.

**A numeric identity claim is accepted and rendered as text.** `{"sub":12345}` gives you
`Subject` of `"12345"`. Issuers that write a numeric subject exist, and tolerating them is
the other reason for the second pass.

**A structured identity claim is refused.** `{"sub":{"a":1}}` returns `ErrTokenForm`, as
`jwt: invalid token form: sub: expected a string but got map[string]interface {}`. That is a
fix rather than a feature: the conversion used to format the value with `%v`, which turned
that payload into the subject `map[a:1]`, so an application treating `Subject` as a principal
identifier accepted a token whose subject was not a principal at all. A boolean fails the
same way.

**A timestamp no `int64` can hold is refused.** `{"exp":1e30}` returns `jwt: invalid token
form: exp: out of range: 1e30`. This is the other repair, and it mattered more.
`json.Number.Float64` reports an error for text `float64` cannot hold, and Go leaves a
float-to-integer conversion undefined when the value does not fit. Both used to be discarded.
An `exp` of `1e400` came out as a negative `int64`, failed the "greater than zero" test the
old validation used, and was read as no expiry at all. A token claiming an absurd expiry
became a token that never expired. `toUnix` now checks `math.IsNaN`, `math.IsInf` and both
`int64` bounds before converting.

When the second pass also fails to parse, verification reports an unexported error whose
message is `jwt: payload is not a type of JSON`. `jwt.Plain` is the validator that suppresses
it, for tokens whose payload is deliberately not JSON. `{"iat":"notanumber"}` lands here,
since a string will not go into a `json.Number`.

## Required fields

`encoding/json` has no notion of a required field. A claim that is absent leaves your struct
field at its zero value, and a missing `username` is indistinguishable from an empty one.

The package adds an opt-in check driven by a `required` option in the JSON tag. Switch it on
by replacing the package-level `Unmarshal`, which every `Claims` method routes through:

```go
func UnmarshalWithRequired(payload []byte, dest any) error

jwt.Unmarshal = jwt.UnmarshalWithRequired

type strictClaims struct {
	Username string `json:"username,required"`
	Role     string `json:"role"`
}
```

It unmarshals normally and then walks the destination with reflection, descending into nested
structs. Any exported field whose tag contains `,required` and whose value is zero produces
`jwt: token is missing a required field: "Username"`. That is `ErrMissingKey`, which
`Classify` reports as `KindRejected`. `HasRequiredJSONTag` exposes the tag test if you want
to run it yourself over a `reflect.StructField`.

Two limits are worth stating. The check is on the Go value rather than the JSON, so a claim
present but empty (`"username":""`) fails exactly as an absent one does. And the message
names the Go field, `Username`, rather than the JSON name `username`, which is a nuisance
when you are matching an error against a payload. Set `jwt.Unmarshal` once at startup, for
the same reason as `MaxTokenSize`: it is a package variable read without a lock.

## Summary

`Claims` holds the seven registered claims RFC 7519 defines, under Go names that differ from
the wire names (`Expiry` is `exp`, `ID` is `jti`), plus `OriginID`, which serializes as
`origin_jti` and is this package's own convention for linking a refresh token to its access
token. Every field carries `omitempty`, so zero means absent throughout.

Your own claims are any struct with JSON tags, read back with `VerifiedToken.Claims(&dest)`.
Combine them with the registered ones by embedding `jwt.Claims`, or by passing sign options:
`Claims` implements `SignOption` through an `ApplyClaims` that copies only non-zero fields,
and `signoptions.go` adds `ID`, `OriginID`, `Issuer`, `Subject`, `NotBefore`, `IssuedAt` and
`ExpiresAt` for setting one claim at a time. Later options win.

`Merge` joins the two objects by stripping braces and splicing raw JSON, which is why it is
quick and why a claim set in two places appears twice in the payload. Go reads the last one,
a first-wins parser somewhere else reads the first, so set each claim in exactly one place.
Raw `string` and `[]byte` fragments are checked with `json.Valid` and rejected with
`ErrNotJSONObject`.

`Audience` unmarshals from either a string or an array, always marshals as an array, and
`Contains` is the RFC 7519 section 4.1.3 membership test. The second-chance parser tolerates
a float timestamp and a numeric `sub`, returning `ErrTokenForm` for a structured `sub` or a
timestamp no `int64` can hold, and `UnmarshalWithRequired` turns a `,required` tag into
`ErrMissingKey`.

## Further Reading

- [RFC 7519 section 4.1](https://www.rfc-editor.org/rfc/rfc7519#section-4.1): the registered
  claim names, one subsection each. Section 4.1.3 is the audience rule that `Contains`
  implements.
- [IANA JSON Web Token Claims registry](https://www.iana.org/assignments/jwt/jwt.xhtml): the
  live list of registered names, and the place to check before inventing one.
- [RFC 8259 section 4](https://www.rfc-editor.org/rfc/rfc8259#section-4): JSON objects, and
  the paragraph on duplicate names that explains why `Merge` output is parser-dependent.
- [encoding/json](https://pkg.go.dev/encoding/json): struct tags, `omitempty`, embedded
  struct inlining, and the last-wins behaviour on duplicate keys.
- [json.Number](https://pkg.go.dev/encoding/json#Number): what `UseNumber` gives you and why
  `.Int64()` beats a `float64` assertion on a timestamp.

---

**Next Chapter**: [Expiry and Time](04-expiry-and-time.md) - What the three time claims mean, the Clock variable, and the leeway you will eventually need.
