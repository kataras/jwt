# Chapter 7: JWKS

Chapter 6 gave every key a name and put that name in the header. This chapter is about how the
names and the keys travel between machines. A JSON Web Key Set is the format almost every
identity provider uses to publish its public keys over HTTP, and this package can produce one,
consume one, and keep a consumed one current while the process runs. It also refuses several
things when fetching, and each refusal exists because of a specific way the naive version
fails.

## Table of Contents

- [What a key set is](#what-a-key-set-is)
- [Publishing your own keys](#publishing-your-own-keys)
- [Generating a single JWK](#generating-a-single-jwk)
- [Fetching somebody else's keys](#fetching-somebody-elses-keys)
- [What the fetch refuses to do](#what-the-fetch-refuses-to-do)
- [KeySet keeps the keys current](#keyset-keeps-the-keys-current)
- [AWS Cognito](#aws-cognito)
- [Summary](#summary)
- [Further Reading](#further-reading)

## What a key set is

RFC 7517 defines two things. A JWK is a JSON object describing one cryptographic key. A JWKS is
a JSON object with a single member, `keys`, holding an array of them. That is the whole
container:

```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "signing-2024-01",
      "use": "sig",
      "alg": "RS256",
      "n": "uGCsN_H_19DmAEz-OokW7VzP07cZHp41zfShi37N80IPhwaT_JSGzerqjVxt0p2lerBIJg2BPFtOLTQ",
      "e": "AQAB"
    },
    {
      "kty": "EC",
      "kid": "signing-2024-06",
      "use": "sig",
      "alg": "ES256",
      "crv": "P-256",
      "y": "P9N3oC-gFahsyubWhsH-ELO3c6KLh8UCVDIY8NtR6SI",
      "x": "7z0-SC3-OWY_b0ihYuayoh67zt70l-tXsyZKUGIQoho"
    }
  ]
}
```

The Go type is `JWK`. Four members appear on every key and the rest depend on the key type:

| Member | Applies to | Meaning |
| --- | --- | --- |
| `kty` | all | Key type: `RSA`, `EC` or `OKP`. It decides which of the members below are present. |
| `kid` | all | The identifier a token's `kid` header names. This is the link back to Chapter 6. |
| `use` | all | `sig` for signature keys, `enc` for encryption. This package always writes `sig`. |
| `alg` | all | The algorithm the key is for: `RS256`, `ES256`, `EdDSA` and so on. |
| `crv` | EC, OKP | Curve name: `P-256`, `P-384`, `P-521` or `Ed25519`. |
| `n`, `e` | RSA | Modulus and public exponent, base64url encoded. `e` is almost always `AQAB`, which is 65537. |
| `x`, `y` | EC | The coordinates of the public point, base64url encoded. |
| `x` | OKP | The 32-byte Ed25519 public key itself. There is no `y`. |

Members that do not apply to a key type are omitted, not emitted empty. That is what the
`omitempty` tags on `Crv`, `N`, `E`, `Y` and `X` are for. An earlier version published EC keys
with empty `n` and `e` and RSA keys with an empty `crv`, which RFC 7517 does not permit and which
some consumers reject outright. The four common members carry no `omitempty`, so they are always
present. The values are base64url without padding, the same encoding Chapter 1 covered, applied
to the big-endian bytes of each number.

Nothing in a JWKS is secret: these are public keys, and their purpose is to be downloadable by
anyone who needs to check a signature. What matters is integrity, not confidentiality, which is
why the transport rules later in this chapter are strict.

## Publishing your own keys

If you issue tokens that other services verify, publish a key set and let them fetch it. The
alternative is emailing PEM files around, which works exactly once and then becomes the reason
nobody rotates.

One method converts a registry into a key set. Only the public halves are read, so a registry
holding private keys is safe to pass. The convention is to serve the result at
`/.well-known/jwks.json`, and to build the body once at startup rather than per request, because
the document changes only when a key is added or retired:

```go
func (keys Keys) JWKS() (*JWKS, error)

func jwksHandler(keys jwt.Keys) (http.HandlerFunc, error) {
	set, err := keys.JWKS()
	if err != nil {
		return nil, err
	}

	body, err := json.Marshal(set)
	if err != nil {
		return nil, err
	}

	sum := sha256.Sum256(body)
	etag := `"` + hex.EncodeToString(sum[:8]) + `"`

	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/jwk-set+json")
		w.Header().Set("ETag", etag)
		w.Header().Set("Cache-Control", "public, max-age=3600")

		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}

		w.Write(body)
	}, nil
}
```

RFC 7517 registers `application/jwk-set+json` for this document. Most providers send
`application/json` instead, and no consumer this package talks to checks either way, so send the
registered one.

**On the ordering.** `Keys` is a map, and ranging over a map in Go yields a different order each
time, so `JWKS()` sorts the result by `kid` with `slices.SortFunc` and `strings.Compare` before
returning it. Without that sort the same registry produced a different byte sequence on every
call. Any ETag computed from the body would then change on every request, every conditional
request would miss, and a document that genuinely changes twice a year would be re-downloaded by
every client on every poll. Sorting makes the body a pure function of the registry, which is
what makes the handler above work.

One limit carried over from Chapter 6: a registry containing an HMAC key fails here with
`unsupported public key type: []uint8`, because a shared secret has no public half to publish.
Keep symmetric keys in a separate registry from the one you serve.

## Generating a single JWK

The per-key conversion is exported, for when you are assembling a set by hand or publishing one
key from a store this package does not manage:

```go
func GenerateJWK(kid string, alg string, publicKey PublicKey) (*JWK, error)

jwk, err := jwt.GenerateJWK("2024-06", "ES256", &privateKey.PublicKey)
// {"kty":"EC","kid":"2024-06","use":"sig","alg":"ES256","crv":"P-256","y":"LnZi...","x":"quCA..."}
```

It accepts `*rsa.PublicKey`, `*ecdsa.PublicKey`, `ecdsa.PublicKey` and `ed25519.PublicKey`, and
returns `unsupported public key type: %T` for anything else. The `alg` argument is passed
through untouched for RSA and ECDSA, so it is on you to pass one that matches the key: nothing
stops you labelling a P-256 key `ES512`, and a consumer that trusts the label will then reject
every token it signs. Ed25519 ignores the argument and always writes `EdDSA`, because there is
nothing else it could be.

## Fetching somebody else's keys

Two functions read a key set over HTTP:

```go
func FetchJWKS(client HTTPClient, rawURL string) (*JWKS, error)
func FetchPublicKeys(url string) (Keys, error)
```

`FetchPublicKeys` is the whole job in one call: fetch, parse, convert. It returns a `Keys`, the
same registry type from Chapter 6, so everything that worked there works here:

```go
keys, err := jwt.FetchPublicKeys("https://auth.example.com/.well-known/jwks.json")
if err != nil {
	return err
}

var claims userClaims
err = keys.VerifyToken(token, &claims)
```

`FetchJWKS` is the lower half, returning the parsed `*JWKS` before conversion. Use it when you
want the raw set, or when you need control over the request. Its first argument is an interface
with one method, which `*http.Client` satisfies, and so does a wrapper of your own that adds an
`Authorization` header for a private endpoint, records a metric, or returns a canned response in
a test. Passing nil uses the package's own client, described in the next section.

```go
type HTTPClient interface {
	Get(string) (*http.Response, error)
}

func (set *JWKS) PublicKeys() Keys
```

`PublicKeys` is the conversion step. It walks the array, resolves each `alg` against the built-in
algorithms, converts the key material, and builds a `Key` with the `kid` as its identifier. Keys
it cannot handle are skipped silently: an unrecognised `alg`, an unsupported `kty`, base64url
that does not decode. That is deliberate, so a set containing one key type you do not support
still yields the ones you do. It is also why a set this package understands nothing in comes back
as an empty map with no error at all, and `KeySet` below turns exactly that case into an error.

## What the fetch refuses to do

The fetching path is small and most of it is refusals. Each one replaced a default that was wrong
in a specific way.

**A 15 second timeout.** The default client used to be `http.DefaultClient`, which has no timeout
at all. An endpoint that accepted the connection and then said nothing held the calling goroutine
for the lifetime of the process. If you pass your own `HTTPClient`, set a timeout on it yourself,
because the package cannot reach inside your implementation to add one.

**HTTPS, except on loopback.** A key set fetched over plain HTTP can be replaced in transit by
anyone on the path, and the replacement keys will then verify the attacker's tokens, which turns
the whole verification step into theatre. Loopback is allowed because that is where a local
identity provider runs while you develop, and the exemption is exactly four hostnames:
`localhost`, `127.0.0.1`, `::1` and `[::1]`.

```go
_, err := jwt.FetchJWKS(nil, "http://auth.example.com/.well-known/jwks.json")
// jwt: jwks: refusing to fetch keys over "http": use https
```

**At most five redirects, each re-checked.** `http.Client` follows up to ten redirects by
default and does not care where they go, including from HTTPS to plain HTTP. The package's
client caps at five and runs the same scheme check on every hop, so a provider cannot be
redirected off a secure origin partway through.

**One megabyte, on both reads.** `MaxJWKSSize` is `1 << 20`. The response length is chosen by
the host being fetched from, which on this path is precisely the host whose keys you have not
established yet, so an unbounded `io.ReadAll` hands a stranger control of your memory. The limit
wraps the body before both the error read and the JSON decode. A key set of a few dozen keys is a
handful of kilobytes, so a megabyte leaves room to spare.

```go
body := io.LimitReader(resp.Body, MaxJWKSSize)
if resp.StatusCode >= 400 {
	b, _ := io.ReadAll(body) // a truncated body is still worth reporting.
	return nil, &HTTPError{StatusCode: resp.StatusCode, Body: b}
}
```

**The error body is on a field, not in the message.** A status of 400 or above returns an
`*HTTPError`, whose `Error()` is `jwt: jwks: status code: 404` and nothing more:

```go
type HTTPError struct {
	StatusCode int
	Body       []byte
}

var httpErr *jwt.HTTPError
if errors.As(err, &httpErr) && httpErr.StatusCode == http.StatusNotFound {
	return errors.New("no key set at that address")
}
```

Keeping those bytes out of the message is the point. An error string almost always ends up in a
log, and the remote host chooses every byte of that body, newlines and terminal escape sequences
included. Putting it in the message hands a stranger a log line to write. Read the field
yourself when you want the detail, and treat it as untrusted text when you do. The type was
unexported until recently, which meant callers could not tell a 404 from a 503 even though the
package's own documentation showed them doing it.

## KeySet keeps the keys current

`FetchPublicKeys` is one GET. It has no cache, no expiry, and no way to fetch again when a token
names a key it has not seen. Every service verifying against somebody else's keys has to build
that part, and two that were examined did not: one called `FetchPublicKeys` inside a constructor,
so the whole fleet failed with `ErrUnknownKid` until restarted whenever the issuer rotated, and
the other pasted the provider's public key into a configuration file as PEM. `KeySet` is that
missing piece:

```go
func NewRemoteKeySet(url string, options ...RemoteKeySetOption) (*KeySet, error)

keySet, err := jwt.NewRemoteKeySet("https://auth.example.com/.well-known/jwks.json",
	jwt.WithRefreshInterval(15*time.Minute),
	jwt.WithMinRefreshInterval(time.Minute),
)
if err != nil {
	return err
}
defer keySet.Close()

verifiedToken, err := keySet.Verify(token, jwt.Expected{Issuer: "https://auth.example.com/"})
```

The first fetch happens before the constructor returns, so a URL that is wrong, unreachable or
serving nothing usable fails at startup rather than on the first request. Three options adjust it:

| Option | Default | Effect |
| --- | --- | --- |
| `WithRefreshInterval(d)` | 1 hour | How often the background goroutine refetches. Zero disables the timer entirely, which is reasonable for a provider that rotates rarely. |
| `WithMinRefreshInterval(d)` | 1 minute | The shortest gap between two fetches triggered by an unknown key. |
| `WithHTTPClient(c)` | the 15 second client above | The client used for every fetch. |

The methods are few. `Keys` returns the current map, which you must not modify. `Refresh` fetches
now regardless of the timers. `ValidateHeader` is the same interface `Keys` implements in Chapter
6, so a `KeySet` drops into `jwt.VerifyWithHeaderValidator` anywhere a registry did, and `Verify`
is that call with the nils already filled in. `Close` stops the background goroutine, is safe to
call more than once, and leaves the keys readable afterwards.

```go
func (ks *KeySet) Keys() Keys
func (ks *KeySet) Refresh() error
func (ks *KeySet) ValidateHeader(alg string, headerDecoded []byte) (Alg, PublicKey, InjectFunc, error)
func (ks *KeySet) Verify(token []byte, validators ...TokenValidator) (*VerifiedToken, error)
func (ks *KeySet) Close() error
```

**Two triggers, and why the second is rate limited.** The timer is the ordinary one. The
interesting trigger is in `ValidateHeader`: when the current map has no key for the token's
`kid`, it refetches once and tries again. That is what makes somebody else's rotation invisible
to you. The provider publishes the new key before signing with it, and the first token carrying
the new `kid` causes the refetch that closes the gap, with no restart and no configuration change.

That second trigger is an outbound request caused by an inbound one, which is a shape worth being
careful with. A token naming a key that will never exist is a request anybody can send, so
without a floor a stream of them becomes a stream of requests to your identity provider, from
your address, at whatever rate the sender chooses. `WithMinRefreshInterval` is that floor, and
the slot is claimed before the fetch rather than after, so a burst of goroutines all hitting an
unknown `kid` produces one request between them rather than one each.

Reads take no lock. The map is swapped whole through an `atomic.Pointer`, and a verification
already in flight keeps reading the map it started with. That is the reason this is a separate
type instead of locking inside `Keys`: a mutex there would cost every verification in every
program to serve the callers who rotate at runtime.

**Failures are quiet on purpose.** A failed refresh leaves the previous keys in place, because a
provider having a bad five minutes should not take your verification down with it, and the keys
you already hold are almost certainly still correct. The background goroutine swallows both the
error and any panic, since nothing is recovering above it, so if you want to know about refresh
failures, call `Refresh` yourself on your own schedule and handle its error.

**`ErrKeySetEmpty`.** `PublicKeys` skips keys it cannot convert, so an endpoint serving a set
this package does not understand yields an empty map and no error. `Refresh` treats a zero-length
result as a failed refresh and returns `ErrKeySetEmpty`, which `NewRemoteKeySet` surfaces at
startup. Without it the operator sees `unknown kid` on every request and goes looking for a token
problem, when the actual fault is that the key fetch is returning nothing usable.

## AWS Cognito

Cognito publishes a key set per user pool, at a URL built from the region and the pool
identifier. Fetching it once is one call:

```go
func FetchAWSCognitoPublicKeys(region, userPoolID string) (Keys, error)
```

It returns an `AWSCognitoError` when Cognito answers with a status of 400 or above and a JSON body
this package can parse, carrying the status and the message Cognito sent. That message is quoted
and prefixed, `jwt: aws cognito: status code: 400: "User pool does not exist."`, for the same
reason `HTTPError` keeps its body off the message: the text comes from a remote host and ends up
in your logs. Like `FetchPublicKeys`, it fetches once and never again, so a pool that rotates its
signing key leaves the result stale until you call again.

**The character allowlist.** Both arguments are interpolated into the URL that is then fetched,
so both are checked first. A region of `evil.com/x` would move the request to a host of the
caller's choosing, and whatever came back would be used to verify tokens. The check is an
allowlist rather than an escape, because neither field has any business containing something
that needs escaping: letters, digits and hyphens, plus underscore for the pool identifier, since
Cognito writes those as `us-east-1_AbC123`:

```go
_, _, err := jwt.NewCognitoKeySet("us east 1", "us-east-1_AbC123", appClientID)
// jwt: aws cognito: region contains an unexpected character ' '
```

For anything longer-lived than a script, use the `KeySet` constructor instead. Its middle return
value is the part that matters: an `Expected` validator holding the issuer,
`https://cognito-idp.{region}.amazonaws.com/{userPoolId}`, and the audience, which is your app
client identifier.

```go
func NewCognitoKeySet(region, userPoolID, appClientID string, options ...RemoteKeySetOption) (*KeySet, Expected, error)

keySet, expected, err := jwt.NewCognitoKeySet("us-east-1", "us-east-1_AbC123", appClientID)
if err != nil {
	return err
}
defer keySet.Close()

verifiedToken, err := jwt.VerifyWithHeaderValidator(nil, nil, token,
	keySet.ValidateHeader, expected, jwt.Skew(2*time.Minute))
```

**Why the signature and the clock are not enough.** A Cognito user pool can have many app
clients, and every one of them gets tokens signed by the same pool key. A token minted for a
different app client of the same pool therefore has a valid signature under a key in your key
set, an issuer you recognise, and an expiry in the future. If you check only the signature and
the timestamps, you accept it, and whatever that other client is allowed to do, its users can now
do to you. Both services examined for this chapter verified the signature and the clock and
nothing else, which is why the constructor hands you the checks rather than leaving them as an
exercise. `Skew` is in the example because Cognito omits `nbf` and its clock can run slightly
ahead of yours; Chapter 4 covers what that allowance costs. If you pass an empty `appClientID`,
the returned `Expected` carries only the issuer, and you are back to accepting tokens for any
client in the pool.

## Summary

A JWKS is a JSON object with one member, `keys`, holding JWK objects. Each JWK carries `kty`,
`kid`, `use` and `alg`, plus the members its key type needs: `n` and `e` for RSA, `crv`, `x` and
`y` for EC, `crv` and `x` for Ed25519. Members that do not apply are omitted rather than emitted
empty.

`Keys.JWKS()` builds a set from a registry, reading only public halves and sorting by `kid` so
the serialized body is stable between calls, which is what makes ETag caching work. Serve it at
`/.well-known/jwks.json`, built once at startup. `GenerateJWK` does one key at a time.
`FetchPublicKeys` fetches, parses and converts in one call, returning the same `Keys` type
Chapter 6 used; `FetchJWKS` is the half below it and takes an `HTTPClient`; `JWKS.PublicKeys()`
skips anything it cannot convert rather than failing the whole set.

The fetch enforces a 15 second timeout, HTTPS outside loopback, five redirects each re-checked,
and a one megabyte cap on both the error body and the decode. `HTTPError` carries the response
body on a field rather than in the message, because a remote host chooses those bytes and error
strings end up in logs.

`KeySet` keeps a fetched set current. It refreshes on a timer and again when a token names an
unknown `kid`, with the second trigger rate limited because anybody can send such a token. Reads
are lock-free, failed refreshes keep the previous keys, and an empty result is `ErrKeySetEmpty`.
`NewCognitoKeySet` returns the key set together with the issuer and audience checks, because a
Cognito token minted for a different app client of the same pool has a valid signature under a
key you hold.

## Further Reading

- [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517): JSON Web Key and JSON Web Key Set. Section
  4 is the member list; appendix A has worked examples of each key type.
- [RFC 7518 section 6](https://www.rfc-editor.org/rfc/rfc7518#section-6): how the key material
  is encoded per key type, including why `e` is normally `AQAB`.
- [RFC 8037](https://www.rfc-editor.org/rfc/rfc8037): the `OKP` key type and the `Ed25519` curve.
- [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638): JWK thumbprints, a way to derive a `kid`
  from the key material so two parties compute the same one.
- [RFC 9110 section 8.8.3](https://www.rfc-editor.org/rfc/rfc9110#section-8.8.3): ETag, and what
  a strong validator means for the handler above.
- [Verifying a JSON Web Token (AWS)](https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-verifying-a-jwt.html):
  Amazon's own list of the checks a Cognito token needs, including the audience check.
- [pkg.go.dev/github.com/kataras/jwt](https://pkg.go.dev/github.com/kataras/jwt): the generated
  reference for every signature quoted here.

---

**Next Chapter**: [Validators](08-validators.md) - The TokenValidator interface, the checks that ship with the package, and how to write one that fails closed.
