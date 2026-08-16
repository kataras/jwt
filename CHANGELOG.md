# Changelog

All notable changes to this project are recorded here. Versions follow
[semantic versioning](https://semver.org), and dates are ISO 8601.

## v0.2.0 - 2026-08-16

The first release since v0.1.17, and much the largest. The whole exported surface was
audited symbol by symbol against its own documentation, and the defects that came out of
that are below.

Read [Upgrading](#upgrading) before you take it. This release breaks things, which is what
the minor bump is for: under semantic versioning a leading zero means the API is not yet
stable, and going to 0.2.0 rather than 0.1.18 is the part that says so out loud. Most of the
breaks exist because the previous behaviour was wrong rather than merely different, and each
is listed with what it did before.

Several of the defects below reported success while failing, which is the expensive kind: a
revocation that returned `nil` and then evaporated, a build mode documented for years that
had never compiled, and an enrichment path that signed an attacker's header with your
private key and handed back a valid token.

### Breaking

**`Enrich` and `UnverifiedToken.Enrich` take an algorithm as their first argument.** They
read it out of the token's own header before, which is the security fix below. Every call
site gains one argument.

**The unsecured algorithm is named `none`.** It was `NONE`, which RFC 7518 section 3.6 does
not permit and no other implementation accepts. Tokens this package produced under the old
name will no longer verify here, and tokens from anywhere else now can.

**`Expected.Audience` checks membership rather than exact equality.** It required the two
lists to have the same length and the same order, so an issuer adding a second audience
broke every recipient at once. RFC 7519 section 4.1.3 asks a recipient to check that it is
among the audiences, which is what it now does. `Audience.Contains` is exported for callers
who check the claim themselves.

**A token whose `exp` is negative is expired.** `validateClaims` tested for greater than
zero, so `exp: -1` was read as having no expiry at all rather than as having expired in
1969. Zero still means absent, because the fields are `int64` with `omitempty` and nothing
else can distinguish "not set" from "set to the epoch".

**`GenerateEdDSA` returns `[]byte`.** It declared `ed25519.PublicKey` and
`ed25519.PrivateKey` and returned PEM text. That compiled only because both types are
defined over `[]byte`, and the result could not be used for signing: it failed the key
length check in `Sign`.

**`BytesQuote` is removed and `TokenPair` fields are strings.** `TokenPair` carried
`json.RawMessage` fields filled by `BytesQuote`, which returns two quote characters for no
input, so `omitempty` never fired and every response contained `"access_token":""` whether
or not a token was issued. `BytesQuote` itself built a JSON string by concatenation with no
escaping and its own documentation recommended it for other uses. `TokenPair` gains an
`IDToken` field, because no OpenID Connect response matched the two-field shape.

**An unrecognised algorithm name in a `KeysConfiguration` is an error.** `Load` started at
`RS256` and kept it when nothing matched, so a typo produced a silently mis-configured key
and confusing verification failures much later. The error names the offending key id.

**A structured `sub` or `iss` claim is refused.** A payload of `{"sub":{"a":1}}` was
rendered with `%v` and produced the subject `map[a:1]`, which an application reading the
subject as a principal identifier accepted. A numeric subject is still accepted and rendered
as text, which is what the lenient parser is for.

**JWK members that do not apply to a key type are omitted.** An RSA key carried an empty
`crv`, `x` and `y`; an EC key carried an empty `n` and `e`. RFC 7517 does not allow that and
some consumers reject it.

**`Blocklist.Clock` is unexported and `Blocklist.SetClock` replaces it.** Garbage collection
read that field on every tick from a goroutine `NewBlocklist` starts before it returns, so
there was no moment left in which a caller could assign it without a data race. `go test
-race` reported one against this package's own suite. `SetClock` stores the function
atomically and may be called at any time, including while a sweep is running. `GetKey` stays
a field, because nothing in the package reads it from a goroutine of its own.

### Security

**`Enrich` was a signing oracle.** It took the signing algorithm from the header of the
token it was given, spliced that token's payload into the new one, reused its header
verbatim, and verified nothing. A service that enriched a token it had received therefore
signed whatever header and payload the sender chose, with its own private key. `parseAlg`
resolves the unsecured algorithm, so the sender could also ask for a token with no
signature. `Keys.EnrichToken` inherited all of it, because it looked the key up by `kid` and
handed the unverified token straight on.

The algorithm is now the caller's and never the token's, `NONE` is refused everywhere, and
both verifying entry points check the signature before re-signing. A header that survived
verification is carried through intact so a `kid` is not lost; `UnverifiedToken.Enrich`
builds a fresh header instead, because by its own name it has verified nothing.

**A revocation for a token without `exp` was silently discarded.** `InvalidateToken` stored
the claim's `Expiry` and returned `nil`. For a token with no `exp` that value is `0`, which
garbage collection read as "expired in 1970" and deleted on the very next tick. The caller
was told the session was revoked; a tick later it was live again, with nothing reporting a
problem. Such entries are now stored as never expiring.

**A typed-nil public key crashed the process.** A `*rsa.PublicKey(nil)` stored in an
interface is not nil, so it passed every nil check, asserted successfully and dereferenced
inside `crypto/rsa`. Any token naming that `kid` took the process down. Every key assertion
in `rsa.go`, `rsapss.go` and `ecdsa.go` now checks the pointer, and `eddsa.go` checks the
length before calling `Public()`, which slices at `[32:]`.

**The JWKS fetch path had no limits of any kind.** `http.DefaultClient` has no timeout, so a
JWKS endpoint that accepted the connection and then said nothing blocked the calling
goroutine for the life of the process. The URL was never checked, so verification keys could
be fetched over plain http and replaced in transit, and redirects were followed anywhere
including from https back to http. Neither the error body nor the JSON decode was bounded.
The entire remote response body went into the error message, handing a remote host control
of a log line.

Now: a 15 second timeout, https required except on loopback, at most five redirects each
re-checked, a 1 MB ceiling through `MaxJWKSSize`, and the body on a field rather than in the
message.

**`FetchAWSCognitoPublicKeys` interpolated its arguments into a URL unchecked.** A region of
`evil.com/x` moved the request to another host entirely, and whatever keys came back were
used to verify tokens. Both fields now go through a character allowlist.

**Five slice expressions and nil interfaces were reachable from untrusted input.** A
ciphertext shorter than the 12-byte GCM nonce, an ASN.1 octet string under two bytes in an
Ed25519 PEM, a nil `Alg` when neither the caller nor the header validator named one, and a
`Key` registered without an algorithm all panicked. `fileExists` dereferenced a nil
`os.FileInfo` on a branch that only `os.IsExist` never being true for `os.Stat` kept from
firing.

**`Base64Decode` wrote past the end of the caller's buffer.** It appended `=` bytes to reach
a multiple of four. `bytes.Split` does not cap the capacity of the last part it returns, so
the signature segment still owned the whole token's spare capacity and that append landed in
memory beyond the token. With a pooled HTTP read buffer, which is how most servers hand a
token to this package, that is a write into memory the next request is about to use.

It trims padding now and decodes with `base64.RawURLEncoding`. That is also faster:
verification dropped from 22 allocations to 18, and from 1632 to 1376 bytes.

**A token is bounded before it is parsed.** `MaxTokenSize`, 64 KB by default, applies to
`Decode` and the whole `Verify` family. Verification allocates in proportion to a token that
arrives from whoever is calling.

**An algorithm name is checked before it reaches the header.** The header is built by
concatenating `Alg.Name()` into a JSON literal, and `Alg` is an exported interface, so a
third-party implementation returning a name containing a quote could add header fields to a
token signed with somebody else's key.

**`Merge` validates raw fragments.** It checked only the first and last byte, so a `string`
or `[]byte` value reading `{"broken"}` was spliced in and the result was a properly signed
token whose payload is not JSON. Its error no longer formats the offending value either,
which used to put claims into whatever the caller logged.

**A panic in a caller-supplied clock no longer kills the process.** `Blocklist`'s garbage
collection goroutine had no `recover`, and `NewBlocklist` passes `context.Background()`, so
the goroutine and its ticker also lived for the life of the process. `Blocklist.Close` stops
it.

### Fixed

**The `safe` build tag had never compiled.** `util.go` declared `BytesToString` with no
build constraint while `util_safe.go` declared it under `//go:build safe`, so the two
collided: `go vet -tags safe .` failed with `BytesToString redeclared in this block`. The
mode has been documented at `util_safe.go:18` and unbuildable the whole time. CI now builds
and tests under the tag.

**`Keys.JWKS()` failed for every ECDSA key.** `GenerateJWK` matched `ecdsa.PublicKey`, the
value type, while every ECDSA key this package produces is a `*ecdsa.PublicKey`. A service
publishing `/.well-known/jwks.json` from a registry containing an ES256 key got
`unsupported public key type` instead.

**`Keys.JWKS()` returned its keys in map order**, so the same registry produced a different
body on every call and defeated ETag caching on a document that changes only when a key is
rotated. It sorts by key id now.

**The documented HMAC registration did not work.** `Register(HS256, "k", nil, secret)` is
the package's own example, and it stored a nil public key, so every verification for that
kid failed with `ErrInvalidKey`. `Register` fills a nil public key from the private one for
HMAC, where they are the same key.

**`Keys.EnrichToken` failed for any custom `Alg`.** It read the `kid` through
`UnverifiedToken.Kid`, which also resolves the algorithm name against the built-in list. A
token signed and verified perfectly well through the registry, and failed only at
enrichment.

**`Keys.VerifyToken` passed a double pointer.** It called `verifiedToken.Claims(&claimsPtr)`
where `claimsPtr` was already an interface holding a pointer. It worked only because
`encoding/json` unwraps that, and this package's own documentation invites replacing the
unmarshaler with one that might not.

**An out-of-range timestamp produced a token that never expired.** The lenient claim parser
discarded every error it could, so an `exp` of `1e400` overflowed to a negative `int64`,
failed the greater-than-zero test and read as having no expiry.

**`MustGenerateRandomString` reused random bytes.** It refilled its buffer on one modulus and
read it on another, so for any length of four or more the tail of every buffer went unread
while the head was read repeatedly. The generated strings had less entropy than their length
suggested.

**`GenerateEdDSA` discarded the error from `ed25519.GenerateKey`.**

**Blocklist garbage collection could drop a live revocation.** It collected keys under a read
lock, released it, then took a write lock per key. A token revoked in that window was deleted
immediately after being added. The sweep now holds one write lock and deletes while ranging.

**The blocklist stored an aliased map key.** Without a `jti` the key is
`BytesToString(token)`, which shares the caller's buffer, so a reused buffer rewrote the
contents of a live key. `InvalidateToken` copies it now; lookups keep the zero-copy path.

**`_examples/generate-ed25519` used `%w` in `log.Fatalf`,** which does not support it.

**An EC JWK could carry a short `x` or `y`.** The coordinates came from `big.Int.Bytes()`,
which returns the minimal big-endian encoding and so drops leading zero bytes. RFC 7518
section 6.2.1.2 requires the full width of the curve, 32 bytes on P-256, 48 on P-384 and 66
on P-521. Roughly one P-256 key in 256 has a leading zero in a coordinate and produced a JWK
that other implementations reject. The coordinates are now read out of the SEC 1
uncompressed point, which is already padded, and that also drops a use of
`ecdsa.PublicKey.X` and `.Y`, deprecated in Go 1.26.

**`Validators` had an unreachable branch.** `case TokenValidatorFunc` sat after
`case TokenValidator` in the same type switch, and the func type satisfies the interface, so
the earlier case always matched first.

### Added

Taken from reading what three real consumers are forced to write around this package, ranked
by how much each removes.

**`KeySet`, a key set that keeps itself current.** `FetchPublicKeys` is a single GET with no
cache and no way to fetch again when a token names a key it has not seen, so one service
called it once inside a constructor and its whole fleet failed with `ErrUnknownKid` until
restart whenever the issuer rotated. Another pasted the provider's public key into a config
file as PEM instead. `NewRemoteKeySet` refreshes on a timer and again on demand when a token
names an unknown `kid`, rate limited so that a token naming a key that will never exist is
not an outbound request per attempt. It satisfies `HeaderValidator`, so it drops into a
verification call in place of a `Keys`.

**`NewCognitoKeySet`,** which also returns the issuer and audience checks. Verifying only
the signature and the clock is not enough for Cognito: a token minted for a different app
client of the same pool would otherwise verify.

**`SignPair` and `Keys.SignPair`,** for a linked access and refresh token. The hand-written
version ran to about 129 lines, plus two option wrappers whose only job was to work out
which half was being signed by checking whether `origin_jti` was empty.

**`FromHeader`, `FromQuery`, `FromCookie` and `ExtractToken`.** Three Bearer parsers existed
across two repositories and two of them disagreed: one split on every space and rejected a
token containing one, the other split on the first and accepted it.

**`Keys.Verify`,** which returns the `*VerifiedToken`. `VerifyToken` throws it away, so
every caller needing the raw bytes hand-wrote `VerifyWithHeaderValidator(nil, nil, ...)`.

**`Skew`,** which tolerates clock skew on both `nbf` and `iat`. `Future` only ever rescued
`iat`, and claim validation checks `nbf` first and stops there, so four call sites across
two services worked only because their identity provider omits `nbf`.

**`Classify` and `ErrorKind`,** which sort a verification failure into malformed, invalid,
expired or rejected. One consumer enumerated fifteen sentinels by hand and had already
drifted out of step with the twelve its own alias file re-exported.

**`RequireExpiry` and `ErrMissingExpiry`,** for the case RFC 7519 leaves optional.

**`Validators`,** which collects mixed validator types, because Go will not convert
`[]TokenValidatorFunc` to `[]TokenValidator`.

**`TokenBlocklist` and `DefaultBlocklistKey`.** One downstream package declared that
interface in a file that contained nothing else, and a Redis backend that re-derived the key
function returned the `jti` unconditionally, mapping every token without one to the empty
key: a single logout blocked every session in the system.

**Sign options for individual claims:** `ID`, `OriginID`, `Issuer`, `Subject`, `NotBefore`,
`IssuedAt` and `ExpiresAt`.

**`Audience.Contains`, `MaxTokenSize`, `MaxJWKSSize`, `HTTPError`, `ErrTokenSize`,
`ErrNotJSONObject`, `ErrKeySetEmpty`, `Blocklist.Close`, `Blocklist.SetClock`.**

### Changed

`HTTPError` was the unexported `httpError`, which the package's own documentation told
callers to type-assert. Its message carries the status code only; the body is on a field,
because those bytes are chosen by a remote host and an error string ends up in a log.

`Blocklist`'s zero value works: an unset clock, a nil `GetKey` and a nil map are all handled.

CI runs `go vet` and a second test pass under `-tags safe`.

### Documentation

The package's own documentation contained a dozen examples that could not compile: a
`HeaderValidator` signature used five times that does not exist, `jwt.Blocklist(...)` called
as a function, `GCM` shown with two return values four times, `jwt.RegisteredClaims`
referenced three times as a type that has never existed, and `jwt.Verify(alg, keys, token)`
shown three times, which compiles and always fails at runtime. Those are corrected.

Godoc has no emphasis syntax, so the 1,068 `**bold**` markers across eight files rendered as
literal asterisks, and six `##` headings in `doc.go` rendered as literal text.

New in the repository:

- `book/`, a fourteen chapter book with its own module, rendered to one self-contained HTML
  file and printed to PDF. Chapter 12 is the honest list of this package's sharp edges.
- `brand/`, the mark and every export, generated from one definition. See `brand/BRAND.md`.
- `skill/`, agent skills including an API map whose every signature was checked against
  `go doc`.
- `testdata/golden.json`, pinning the exact bytes this package emits.

### Upgrading

Most callers need three changes: add an `Alg` as the first argument to any `Enrich` call,
stop relying on `NONE` in a header, and check whether anything depended on `Expected.Audience`
requiring an exact list. If you read `TokenPair` fields as `json.RawMessage`, they are
strings now.
