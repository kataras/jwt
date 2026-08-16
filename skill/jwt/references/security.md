# Security

Every claim below was checked against `alg.go`, `hmac.go`, `rsa.go`, `rsapss.go`, `ecdsa.go`,
`eddsa.go`, `none.go`, `token.go`, `claims.go`, `jwk.go`, `kid_keys.go`, `blocklist.go`,
`enrich.go` and `gcm.go`. Terse and verified, for agent use; re-check against the source before
repeating a claim that surprises you.

## Algorithm confusion

`Verify(alg, key, token, ...)` never reads the algorithm to use for verification from the token
itself. `decodeToken` compares the token's decoded header, byte for byte, against the fixed
literal header for `alg.Name()` (the algorithm the caller passed in), via the package-level
`CompareHeader` variable. A token whose header names a different algorithm fails with
`ErrTokenAlg` before the signature is even looked at.

That single design choice is what stops the classic attack, where a service expecting RS256
is handed a token whose header says `"HS256"` and whose "signature" is an HMAC computed with the
RSA public key (which the attacker knows, since it is public) used as the HMAC secret. As long as
your code hardcodes the expected algorithm at each call site, per algorithm/key pair, this cannot
happen here.

It reopens if you write your own `HeaderValidator` (the `headerValidator` parameter of
`VerifyWithHeaderValidator`) that trusts the header's own `"alg"` field without pinning it to
something the caller already decided. `Keys.ValidateHeader` is the one shipped example of doing
this safely: it requires the header's `"alg"` to equal the algorithm registered for that
specific `"kid"`, so the token's own header narrows the set of *keys* to try, never the set of
*algorithms* accepted for a given key.

## `none`

`jwt.NONE` is a real, exported `Alg` value. Its `Sign` returns an empty signature and its
`Verify` accepts only an empty signature; nothing else in `Sign`/`Verify` refuses it. If request
input (a query parameter, a config value, anything not chosen by your own code at compile time)
ever reaches the `alg` argument of `Verify`, an attacker who can set that input to `jwt.NONE`
gets an unsecured, self-signed token accepted as genuine.

`Enrich` and `UnverifiedToken.Enrich` are the exception: both explicitly refuse `alg == NONE`
(and `alg == nil`) with `ErrTokenAlg`, because both re-sign attacker-influenced content with your
key and a `NONE` output there would be silently unsigned. `Sign` and `Verify` carry no such
guard; `NONE`'s only legitimate use is a hardcoded choice for genuinely non-security-sensitive,
client-inspectable data (the package doc comment's example is UI preferences stored client-side).

`checkAlgName` also matters if you implement a custom `Alg`: an algorithm `Name()` containing a
`"`, used with `SignWithHeader`'s custom-header path or otherwise reachable, could otherwise
inject fields into a header built by string concatenation. The check restricts a `Name()` to
`[A-Za-z0-9\-+._]`, 1 to 64 characters, for every algorithm, not just the built-in ones.

## Key sizes are not enforced

Nothing in `algHMAC.Sign`/`Verify` checks key length; the code only performs a type assertion to
`[]byte`. RFC 7518 §3.2 requires a key at least as long as the hash output: 32 bytes for HS256,
48 for HS384, 64 for HS512. A shorter key signs and verifies successfully and is brute-forceable
offline. Generate with `jwt.MustGenerateRandom(32)` (or 48/64) rather than a short literal or a
password.

RSA key size is likewise not checked; a 512-bit RSA key signs and verifies. 2048 bits is the
practical floor, 3072+ preferred for new deployments. `rsa.GenerateKey(rand.Reader, 2048)` (or
larger) at generation time is the only enforcement point there is.

ECDSA and EdDSA keys are fixed-size by construction (the curve/key type determines the size), so
this class of mistake does not apply to them the same way.

## Typed-nil keys

`rsa.go`, `ecdsa.go` and `rsapss.go` each guard against a `(*rsa.PublicKey)(nil)` (or ECDSA
equivalent) boxed into the `PublicKey` interface: a bare type assertion on such a value succeeds
(the interface itself is non-nil) and then panics deep inside `crypto/rsa`/`crypto/ecdsa`. Each
`Verify` method checks the pointer explicitly and returns `ErrInvalidKey` instead. This matters
if you build a `Key` or a `HeaderValidator` result from a lookup that can return a typed nil (a
map miss into a struct field, for instance); the library will not panic on it, but the resulting
`ErrInvalidKey` is easy to mistake for "wrong key" rather than "no key was actually supplied."

## Expiry and clock skew

`validateClaims` checks `NotBefore`, `IssuedAt` and `Expiry` only when the field is non-zero;
zero means "claim absent" (the JSON tag is `omitempty`, so there is no other way to distinguish
"not set" from "set to the Unix epoch"). This also means a claim set to a *negative* number is
still checked (and, for `Expiry`, already expired) rather than treated as absent. `toUnix` (used
when a token's numeric claims arrive as JSON floats from a second-chance parse path) rejects
`NaN`, `Inf`, and any value outside `int64`'s range, rather than letting an out-of-range exponent
silently produce a token that never expires.

`Clock` (default `time.Now`) is the single source of "now" for every one of these checks and for
`MaxAge`/`Leeway`/`Skew`. Override it for tests; do not leave it overridden in production code
paths.

Nothing here adds tolerance for clock skew by default: a token whose issuer's clock runs a few
seconds ahead can fail with `ErrNotValidYet` or `ErrIssuedInTheFuture` on a receiver whose clock
is exactly correct. Add `jwt.Skew(d)` (or the narrower `jwt.Future(d)`) as a validator if your
deployment spans machines that are not tightly synchronized; see `validators.md` for the ordering
rule that makes this actually work.

## What `Verify` validates for you, and what it does not

Validated automatically, on every call: token size (`<= MaxTokenSize`, default 64 KiB), the
three-segment `header.payload.signature` shape, the signature itself, the header's algorithm
against the one you specified, and `nbf`/`iat`/`exp` when present.

Not validated unless you ask: `iss`, `sub`, `aud`, `jti` uniqueness/replay, and any custom claim
(add `jwt.Expected{...}` for the standard ones, or check custom fields yourself after
`VerifiedToken.Claims`; `,required` + `UnmarshalWithRequired` covers presence-only checks). Token
revocation is not automatic either: wire a `jwt.Blocklist` (or your own `TokenBlocklist`) in as a
validator if a token must be invalidatable before its natural expiry. `FetchJWKS`/`FetchPublicKeys`
themselves fetch once per call, with no caching and no background refresh; `jwt.KeySet`
(`NewRemoteKeySet`/`NewCognitoKeySet`, see `keys-and-jwks.md`) is the built-in answer to key
freshness and should be preferred over hand-rolling a refresh loop around the one-shot fetch.

Verifying an external provider's token against nothing but its JWKS checks the signature only.
Nothing about a bare signature check distinguishes a token meant for your application from one the
same identity provider issued to a *different* application (a different OAuth client, a different
Cognito app client, a different Auth0 API): both can be signed by the same key. Add
`jwt.Expected{Issuer: ..., Audience: ...}` yourself, or use `jwt.NewCognitoKeySet`, which returns
one pre-populated for the pool and app client you asked for.

## Payload confidentiality

Base64url is an encoding, not encryption. Anyone holding a token can read every claim in it
without any key. If the payload itself must stay confidential from whoever holds the token (or
from something on the wire between issuer and verifier), use `SignEncrypted`/`VerifyEncrypted`
with `jwt.GCM`. `GCM` implements AES-GCM (authenticated encryption) and the package follows an
encrypt-then-sign flow: encrypt the claims first, then sign the encrypted result. `ErrDecrypt` is
returned uniformly for a wrong key, corrupted ciphertext, or a failed authentication tag; do not
try to distinguish these to a caller, and do not build a padding-oracle-shaped API around GCM's
result.

There is no JWE (RFC 7516) support; `token_jwe.go` is a design note, not code. `SignEncrypted` +
`GCM` is the extent of payload confidentiality this library offers, and it protects the payload
only, not the header.

## `Keys` (multi-key registry) concurrency

`Keys` is a plain `map[string]*Key`. `Register` is a map write with no locking. Build the
registry once during startup (or under your own mutex) before any goroutine calls `Verify`,
`SignToken`, `VerifyToken`, or reads the map any other way. `Keys.ValidateHeader`/`SignToken`
etc. only read, so concurrent verification traffic against an already-built, no-longer-mutated
registry is fine.

`Keys.ValidateHeader` requiring the header's algorithm to equal the *specific* key's registered
algorithm (not merely "some algorithm this registry knows about") is what keeps key rotation from
becoming an algorithm-confusion vector: a token naming `kid: "old-hmac-key"` cannot be re-verified
as if it were `kid: "new-rsa-key"`, because each `kid` is bound to one algorithm at `Register`
time.

## Blocklist

Revocation is keyed on the token's `"jti"` claim by default (`DefaultBlocklistKey`). A token
issued without one falls back to using the entire raw token, signature included, as the map key.
Blocklisting such a token keeps a complete, replayable bearer credential in the process's memory
for as long as the entry lives, i.e. until the token's own expiry (or forever, for a token with no
`"exp"`, via the internal `neverExpires` sentinel). Give every token you might need to revoke a
`"jti"`.

`NewBlocklist` starts its garbage-collection goroutine against `context.Background()`; it lives
for the process's lifetime unless you call `(*Blocklist).Close()` or use `NewBlocklistContext`
with a context you cancel. This matters most in tests and in any per-tenant or per-request
blocklist instantiation: without `Close`, each one leaks a ticker and a goroutine.

## JWKS fetching

`FetchJWKS`'s default client (used when you pass `nil`) refuses plain `http://` except to
`localhost`/`127.0.0.1`/`::1` (for local development against a self-hosted identity provider);
everything else must be `https://`. It also enforces a 15-second timeout, caps redirects at 5 and
re-validates the scheme on every hop, and reads the response body through
`io.LimitReader(resp.Body, MaxJWKSSize)` (1 MiB) so a misbehaving or hostile endpoint cannot hand
back an unbounded response. A `>= 400` response becomes `*HTTPError`; its `Error()` string
deliberately reports only the status code, because `Body` is chosen by the remote host and an
error string is the kind of thing that ends up verbatim in a log line. Read `err.Body` yourself
(via `errors.As`) if you need it, and treat it as untrusted text if you display or log it.

`FetchAWSCognitoPublicKeys` validates `region` and `userPoolID` against a character allowlist
before building the request URL from them, so neither can redirect the fetch to an attacker-
chosen host. `jwt.KeySet` (`NewRemoteKeySet`/`NewCognitoKeySet`) inherits all of the above by
default, since it fetches through `FetchPublicKeys`/`FetchJWKS` unless you override the client
with `WithHTTPClient`; it adds its own rate limit (`WithMinRefreshInterval`, default one minute)
on refreshes triggered by an unrecognized `"kid"`, so that a request costing an attacker nothing
to send (a token naming a `kid` that will never exist) cannot be turned into a flood of outbound
requests toward the identity provider.

## Logging and error messages

`HTTPError` and `AWSCognitoError` both keep remote-supplied content (`Body`, `Message`) out of
their primary error text for the same reason: that text tends to end up in a log line, and the
content is chosen by whatever host you just queried.

Nothing in this package logs a key, a token, or a claim on your behalf; it has no logging
integration at all. Whatever you log around it (a signing key, a raw token, a rejected payload)
is your own choice to get wrong. Do not log a signing/verification key, and think twice before
logging a raw token: it is itself a bearer credential.
