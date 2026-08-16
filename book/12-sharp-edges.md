# Chapter 12: Sharp Edges

Every library has places where the obvious reading of an API is not what it does. Most
documentation leaves you to find them. This chapter is the list for this package: the
defaults that are surprising, the names that read the wrong way round, the fast paths that
carry a hazard, and the things that were outright broken until recently. Some of these have
been fixed and are recorded here because the fix changed behaviour you may have depended
on. The rest are live, and you should know about them before they find you.

## Table of Contents

- [Names that read the wrong way round](#names-that-read-the-wrong-way-round)
- [Defaults that are quieter than you want](#defaults-that-are-quieter-than-you-want)
- [The package-level variables](#the-package-level-variables)
- [Keys is a plain map](#keys-is-a-plain-map)
- [Merge splices JSON and can emit a duplicate key](#merge-splices-json-and-can-emit-a-duplicate-key)
- [The unsafe string conversion](#the-unsafe-string-conversion)
- [What Enrich used to be](#what-enrich-used-to-be)
- [Behaviour that changed in v0.2.0](#behaviour-that-changed-in-v020)
- [Summary](#summary)
- [Further Reading](#further-reading)

## Names that read the wrong way round

**`Leeway` is stricter, not more lenient.** The word suggests tolerance for a clock that
runs a little fast. What it does is reject a token that expires within the duration you
give it:

```go
func Leeway(leeway time.Duration) TokenValidatorFunc {
	return func(_ []byte, standardClaims Claims, err error) error {
		if err == nil {
			if standardClaims.Expiry > 0 {
				if Clock().Add(leeway).Round(time.Second).Unix() > standardClaims.Expiry {
					return ErrExpired
				}
			}
		}

		return err
	}
}
```

`Leeway(time.Minute)` turns away a token with fifty seconds left. It is useful when a
request will take a while and you want the token to still be valid at the end of it. It is
not clock-skew tolerance. `Skew` is.

**`SignWithHeader` replaces the header rather than merging into it.** The name suggests you
are adding fields alongside the standard ones. `createCustomHeader` marshals what you hand
it and uses the result as the entire header:

```go
func createCustomHeader(header any) ([]byte, error) {
	b, err := Marshal(header)
	if err != nil {
		return nil, err
	}

	return Base64Encode(b), nil
}
```

So `SignWithHeader(HS256, key, claims, map[string]any{"kid": "k1"})` produces a token whose
header is `{"kid":"k1"}` with no `alg` at all. If you use a custom header, include `alg`
and `typ` yourself, or use `HeaderWithKid`, which has both fields.

**`UnverifiedToken.Enrich` verifies nothing.** That is what the type name says, and it is
easy to skim past when the method is called `Enrich` and the package-level `Enrich` does
verify. The unverified one exists for callers who have already established authenticity
some other way.

## Defaults that are quieter than you want

**`MaxAge` of a second or less produces a token that never expires.** Read it:

```go
func MaxAge(maxAge time.Duration) SignOptionFunc {
	if maxAge <= time.Second {
		return NoMaxAge
	}
	// ...
}
```

`NoMaxAge` zeroes both `exp` and `iat`. So a configuration file with `max_age: 0`, or a
duration that arrived as zero because a field name was misspelled in YAML, gives you
permanent tokens and no error anywhere. `RequireExpiry` on the verifying side is the
defence.

**A zero-value `Expected` validates nothing.** Every check inside it is guarded on the
field being non-empty, so `jwt.Expected{}` passed to `Verify` returns nil for any token. It
looks like validation at the call site. It is not.

**`LoadHMAC` treats a path that does not exist as the key itself.**

```go
func LoadHMAC(filenameOrRaw string) ([]byte, error) {
	if fileExists(filenameOrRaw) {
		return ReadFile(filenameOrRaw)
	}

	return []byte(filenameOrRaw), nil
}
```

That is convenient when you want to accept either form. It also means a typo in a path
turns the path into your HMAC secret: `/etc/secrets/jwt.key` is twenty bytes of guessable
ASCII, and nothing errors. If the key comes from configuration, read the file yourself and
fail when it is not there.

**A token with no `exp` is valid forever.** RFC 7519 makes the claim optional and this
package follows the RFC. `RequireExpiry` is one line and worth adding.

## The package-level variables

Five exported variables change behaviour for the whole process:

| Variable | Default | Read on |
| --- | --- | --- |
| `Clock` | `time.Now` | every claim validation |
| `CompareHeader` | `compareHeader` | every verification |
| `ReadFile` | `os.ReadFile` | every key load |
| `Marshal` | a function that passes `[]byte` through | every sign |
| `Unmarshal` | `defaultUnmarshal` | every claim decode |

They are useful. `Clock` makes time-dependent tests deterministic, `ReadFile` lets keys
come from an embedded filesystem, and `Unmarshal` can be swapped for a faster codec.

They are also read without any synchronisation, on paths that run concurrently. The
documented rule is to set them during startup, before any goroutine verifies anything, and
nothing enforces it. Assigning `jwt.Clock` from a test that runs in parallel with another
test that verifies a token is a data race, and the race detector will say so.

`CompareHeader` deserves singling out. It is the algorithm check. Any package in your
dependency graph can replace it for your entire process, and nothing will report that it
happened.

There is a second trap that has nothing to do with races. Anything that captures one of
these at construction time, rather than calling through the variable, will not see a later
change:

```go
// This reads the variable once, when the middleware is built.
unmarshal := jwt.Unmarshal
```

A later `jwt.Unmarshal = something` has no effect on that middleware. That is a real
pattern from a real codebase, and it took a while to work out why the replacement was being
ignored.

## Keys is a plain map

`Keys` is `map[string]*Key`. `Register` writes to it with no lock, and `Get` and
`ValidateHeader` read from it on the verification path. Building the registry at startup
and reading it afterwards is fine. Registering a key while requests are in flight is a
concurrent map write, which is not a race the runtime tolerates: it is
`fatal error: concurrent map read and map write`, and it takes the process down with no
recovery.

This is deliberate. Putting a mutex inside `Keys` would put a lock acquisition on every
verification to serve the minority of callers who rotate at runtime. `KeySet` from chapter
7 is the type for that case: it swaps the whole map atomically, so readers take no lock at
all.

If you need to add a key to a plain `Keys` at runtime, build a new map and swap the
reference under your own synchronisation, or use `KeySet`.

## Merge splices JSON and can emit a duplicate key

`Merge` is what combines your custom claims with the standard ones. It does not unmarshal
and remarshal. It takes each value, checks that it is a JSON object, strips the outer
braces and joins the insides with commas:

```go
inner := jsonBytes[1 : len(jsonBytes)-1]
parts = append(parts, inner)
```

That is why signing is fast. It is also why merging `{"role":"admin"}` with
`{"role":"user"}` produces `{"role":"admin","role":"user"}`, which is legal JSON that
different parsers read differently. Go's `encoding/json` takes the last occurrence.
Several other languages take the first. A token signed by this package can therefore mean
one thing to your Go service and another to a Python service reading the same bytes.

The practical rule is to not restate a claim you have already set. If you need to override
one, set it once in the value that wins for your reader, and be aware that a different
reader may disagree.

Raw `string` and `[]byte` values are spliced in as they are, so they are checked with
`json.Valid` first and rejected with `ErrNotJSONObject` otherwise. Before that check
existed, a fragment like `{"broken"}` was spliced in happily and the result was a properly
signed token whose payload is not JSON.

## The unsafe string conversion

`BytesToString` converts a byte slice to a string without copying:

```go
func BytesToString(b []byte) string {
	return unsafe.String(unsafe.SliceData(b), len(b))
}
```

The returned string shares memory with the slice. If the slice changes, the string changes
with it, which is not something a Go string is ever supposed to do. Build with `-tags safe`
to get the allocating version instead.

The place this matters most is the blocklist. Without a `jti`, the entry key is the whole
token, produced by exactly this conversion. Storing that string as a map key would mean a
caller who reuses the buffer, which is what a pooled HTTP read buffer does, silently
rewrites the contents of a live key. `InvalidateToken` therefore copies the key with
`strings.Clone` before storing it, and the lookup path keeps the zero-copy version, because
a map lookup does not retain the string.

If you write your own code that keeps the result of `BytesToString` beyond the lifetime of
the bytes, copy it.

## What Enrich used to be

This one is worth knowing about even though it is fixed, because it explains the shape of
the current API and because you may still have code written against the old one.

`Enrich` adds claims to a token by re-signing it. Until v0.2.0 it took the signing
algorithm from the header of the token it was given, spliced that token's payload into the
new one, reused the header verbatim, and verified nothing at all. The signature it produced
was made with your private key.

So a service that enriched a token it had received would sign whatever header and payload
the sender chose. `parseAlg` resolves the unsecured algorithm, so the sender could also ask
for a token with no signature. There was no attack required beyond sending a token.

The current API takes the algorithm as its first argument, checks the signature before
re-signing, and refuses the unsecured algorithm outright:

```go
func Enrich(alg Alg, key PrivateKey, accessToken []byte, extraClaims any) ([]byte, error)
```

The verification costs about eight allocations. If you have already verified the token and
want them back, `Decode` followed by `UnverifiedToken.Enrich` skips the second check and
leaves the safety argument with you. That method builds a fresh header from `alg` rather
than copying the one it was handed, which is why a `kid` on its input is dropped.

## Behaviour that changed in v0.2.0

If you are upgrading, these change the bytes on the wire or the errors you get back.

| What changed | Before | Now |
| --- | --- | --- |
| The unsecured algorithm's name | `NONE`, which no other implementation accepts | `none`, as RFC 7518 section 3.6 requires |
| `Enrich` and `UnverifiedToken.Enrich` | took no algorithm and verified nothing | take an `Alg` first and verify |
| `Expected.Audience` | required equal length and identical order | membership, per RFC 7519 section 4.1.3 |
| A token with `exp: -1` | treated as having no expiry | expired |
| A JWK for a key type | carried empty `n`, `e`, `crv` members | omits members that do not apply |
| `Keys.JWKS()` for an ECDSA key | failed with `unsupported public key type` | works |
| `Keys.JWKS()` ordering | map order, different on every call | sorted by key id |
| `GenerateEdDSA` | declared `ed25519.PublicKey` and returned PEM | returns `[]byte` |
| `NewTokenPair(nil, nil)` | `{"access_token":"","refresh_token":""}` | `{}` |
| `BytesQuote` | exported | removed |
| An unknown algorithm name in a `KeysConfiguration` | silently became RS256 | an error naming the key |
| A structured `sub` claim | became the string `map[a:1]` | `ErrTokenForm` |

The `none` rename is the one most likely to affect you, and only if you were producing
unsecured tokens with this package and reading them back with it. Tokens carrying the old
`NONE` header will no longer verify.

## Summary

The sharp edges here cluster into four kinds. Names that suggest the opposite of what the
code does, and `Leeway` is the worst of them. Defaults that are quiet when they should
complain, of which `MaxAge` collapsing to no expiry and `LoadHMAC` turning a path into a
secret are the two that have cost people real time. Fast paths that carry a hazard,
specifically the unsafe string conversion and the raw JSON splice in `Merge`, both of which
are deliberate and both of which have a rule attached. And a set of behaviour changes in
v0.2.0, most of which exist because the previous behaviour was wrong rather than merely
different.

None of this is an argument against the package. It is the argument for reading this
chapter before you are debugging at two in the morning.

## Further Reading

- [RFC 7518 section 3.6](https://www.rfc-editor.org/rfc/rfc7518#section-3.6): the unsecured
  algorithm, and the spelling of its name.
- [RFC 7519 section 4.1.3](https://www.rfc-editor.org/rfc/rfc7519#section-4.1.3): the
  audience claim, and what a recipient is asked to check.
- [unsafe.String](https://pkg.go.dev/unsafe#String): the conversion behind `BytesToString`,
  and the guarantees it does not make.
- [Go maps are not safe for concurrent use](https://go.dev/doc/faq#atomic_maps): why a
  concurrent write to `Keys` is a fatal error rather than a race you can survive.
- [json.Valid](https://pkg.go.dev/encoding/json#Valid): the check `Merge` applies to raw
  fragments, and what it does not check.

---

**Next Chapter**: [Testing](13-testing.md) - Controlling the clock, faking the network, and golden tests that are worth having.
