# Suggested commits

Staged work mapped to conventional commits, in an order where each one builds and tests on its
own. Commit them granularly or squash them; the grouping is a suggestion, not a constraint.

Nothing here has been committed. Every entry is staged and waiting for you.

---

## 1. `test: pin generated output with golden tests and record a benchmark baseline`

```
test: pin generated output with golden tests and record a benchmark baseline

Adds testdata/golden.json, 50 recorded outputs covering every algorithm header, the
deterministic tokens, base64, JWK and JWKS generation, the PEM encoders, Merge and
TokenPair. Regenerate with: go test -run TestGolden -update

The file records current behaviour, including behaviour that is wrong and fixed in later
commits, so that each fix shows up as a reviewable golden diff rather than passing
silently.

PASS-LEDGER.md carries the benchmark baseline the rest of the work is measured against.
```

Files: `golden_test.go`, `testdata/golden.json`, `PASS-LEDGER.md`

## 2. `fix: make the documented "safe" build tag compile`

```
fix: make the documented "safe" build tag compile

util.go declared BytesToString with no build constraint while util_safe.go declared it
under "//go:build safe", so the two collided and "go vet -tags safe ." failed with
"BytesToString redeclared in this block". The safe build mode has been documented at
util_safe.go:18 and unbuildable the whole time.

Adds the missing "!safe" constraint, and a CI step that builds and tests under the tag so
it cannot rot again. CI also gains a go vet step.
```

Files: `util.go`, `.github/workflows/ci.yml`

## 3. `fix: guard the slice expressions and nil interfaces reachable from untrusted input`

```
fix: guard the slice expressions and nil interfaces reachable from untrusted input

Five places sliced or dereferenced before checking, and panicked on input a caller does
not control:

  gcm.go        a ciphertext shorter than the 12-byte nonce panicked instead of failing
                authentication
  eddsa.go      ParsePrivateKeyEdDSA sliced the ASN.1 octet string at [2:] with no length
                check, so a hand-crafted PEM panicked
  token.go      decodeToken called alg.Verify on a nil interface when neither the caller
                nor the header validator named an algorithm
  kid_keys.go   ValidateHeader and Key.Configuration read Alg.Name() on keys registered
                without one
  hmac.go       fileExists dereferenced a nil FileInfo on its error branch; only
                os.IsExist never being true for Stat kept it from firing

bounds_test.go covers each one. Removing any single guard turns its test into a panic.
```

Files: `gcm.go`, `eddsa.go`, `token.go`, `kid_keys.go`, `hmac.go`, `bounds_test.go`

## 4. `fix!: Enrich verifies before it re-signs, and takes the algorithm as a parameter`

```
fix!: Enrich verifies before it re-signs, and takes the algorithm as a parameter

BREAKING CHANGE: Enrich and UnverifiedToken.Enrich take an Alg as their first argument.

Enrich read the signing algorithm out of the token's own header and verified nothing, so
a service that enriched a token it had received would sign an attacker's header and
payload with its own private key. parseAlg resolves NONE, so the same input could also
drive the output to a token with no signature at all. Keys.EnrichToken inherited both,
because it looked the key up by "kid" and then handed the unverified token straight on.

The algorithm is now the caller's, never the token's, and NONE is refused everywhere.
Enrich derives the verification key from the signing key and checks the signature first;
Keys.EnrichToken verifies through Keys.ValidateHeader, which binds "kid" to the algorithm
registered for that key. A header that survived verification is carried through intact so
a "kid" is not lost. UnverifiedToken.Enrich verifies nothing, by name and by contract, so
it builds a fresh header rather than signing one it was handed.

Enrich costs 47 allocations against 39 before, all of it the signature check. Callers who
have already verified can use Decode plus UnverifiedToken.Enrich.
```

Files: `enrich.go`, `token.go`, `kid_keys.go`, `enrich_test.go`, `enrich_security_test.go`

## 5. `fix!: stop losing revocations for tokens without an expiry`

```
fix!: stop losing revocations for tokens without an expiry

InvalidateToken stored the claim's Expiry and returned nil. For a token with no "exp"
that value is 0, which GC read as "expired in 1970" and deleted on the very next tick.
The caller was told the session was revoked; a tick later it was live again, with nothing
reporting a problem. Such entries are now stored as never expiring, because a token that
never expires needs a revocation that never expires.

Alongside it, in the same file:

  GC now sweeps under a single write lock and deletes while ranging. Collecting under a
  read lock and deleting under a later one could drop an entry added in between, which
  un-revoked a live session.

  InvalidateToken copies the key before storing it. Without a "jti" the key is
  BytesToString(token), which shares the caller's buffer, so a reused buffer rewrote the
  contents of a live map key. Lookups keep the zero-copy path.

  Blocklist gained Close. NewBlocklist passes context.Background(), so its goroutine and
  ticker previously lived as long as the process.

  A panic in a caller-supplied clock no longer escapes the GC goroutine and kills the
  process.

  BREAKING: Blocklist.Clock is unexported and SetClock replaces it. GC read the field on
  every tick from a goroutine NewBlocklist starts before it returns, so no caller could
  assign it without a data race, and the package's own test suite tripped -race on CI.
  GetKey stays a field: no goroutine inside the package reads it.

  The zero value works: an unset clock, nil GetKey and a nil map are all handled.

  ValidateToken uses errors.Is for ErrExpired.

  defaultGetKey is exported as DefaultBlocklistKey. A downstream Redis backend re-derived
  it, returned the "jti" unconditionally, and mapped every token without one to the empty
  key, so a single logout blocked every session in the system.
```

Files: `blocklist.go`, `blocklist_test.go`, `blocklist_revocation_test.go`

## 6. `fix!: reject unreadable timing claims and coerced subjects`

```
fix!: reject unreadable timing claims and coerced subjects

BREAKING CHANGE: Expected.Audience now checks membership rather than exact equality,
and a token whose "exp" is negative is expired rather than treated as having none.

The lenient second-chance claim parser discarded every error it could:

  an "exp" of 1e400 overflowed to a negative int64, failed the "greater than zero" test
  in validateClaims, and produced a token that never expired

  validateClaims tested "greater than zero", so a token carrying "exp": -1 was read as
  having no expiry rather than as having expired in 1969

  a "sub" that was an object was rendered with %v, so an application reading it as a
  principal identifier accepted the subject "map[a:1]"

Numbers that no int64 can hold and structured issuers and subjects are now refused. A
numeric "sub" is still accepted and rendered as text, which is why that parser exists.

Expected.Audience follows RFC 7519 section 4.1.3: each expected audience must appear among
the token's. It required the two lists to have equal length and order, so an issuer adding
a second audience broke every recipient at once. Audience.Contains is exported for callers
who check the claim themselves.

Adds RequireExpiry, a validator for the case RFC 7519 leaves optional.
```

Files: `claims.go`, `expected.go`, `verify.go`, `validators.go`, `claims_time_test.go`, `expected_test.go`

## 7. `fix: harden the JWKS fetch path`

```
fix: harden the JWKS fetch path

The path that fetches verification keys had no limits of any kind:

  http.DefaultClient has no timeout, so a JWKS endpoint that accepted the connection and
  then said nothing blocked the calling goroutine for the life of the process

  the URL was never checked, so keys could be fetched over plain http and replaced in
  transit, and redirects were followed anywhere including from https back to http

  neither the error body nor the JSON decode was bounded, so the response size was chosen
  by the host being fetched from

  the entire remote body went into the error message, handing a remote party control of a
  log line, newlines and terminal escapes included

  FetchAWSCognitoPublicKeys interpolated region and user pool id into a URL with no
  validation, so a region of "evil.com/x" moved the request to another host entirely and
  whatever keys came back were used to verify tokens

Now: a 15 second timeout, https required except on loopback, at most five redirects each
re-checked, a 1 MB ceiling through MaxJWKSSize, the body on a field rather than in the
message, and a character allowlist on both Cognito fields.

httpError is exported as HTTPError, which the package own documentation already told
callers to type-assert.

jwk_fetch_test.go is the first test coverage this file has had. The suite stays hermetic:
it goes through the HTTPClient interface, which is what that interface is for.
```

Files: `jwk.go`, `jwk_aws_cognito.go`, `jwk_fetch_test.go`

## 8. `fix!: correct names and types that contradicted the code`

```
fix!: correct names and types that contradicted the code

BREAKING CHANGE: the unsecured algorithm is named "none", GenerateEdDSA returns []byte,
and an unknown algorithm name in a KeysConfiguration is an error.

  none.go returned "NONE". RFC 7518 section 3.6 says "none", so tokens this package
  produced were not valid unsecured JWTs anywhere else and conforming ones were never
  accepted here.

  GenerateJWK matched ecdsa.PublicKey, the value type, while every ECDSA key this package
  produces is a pointer. Keys.JWKS therefore failed for every ES256, ES384 and ES512 key.

  GenerateEdDSA declared ed25519.PublicKey and ed25519.PrivateKey and returned PEM text.
  It compiled only because both are defined over []byte, and the result could not be
  signed with. It also discarded the error from ed25519.GenerateKey.

  KeysConfiguration.Load started at RS256 and kept it when no algorithm name matched, so a
  typo produced a silently mis-configured key. Its parse errors now name the key.

  MustGenerateRandomString refilled its buffer on one modulus and read it on another, so
  the tail of every buffer went unread and the head was read repeatedly.

  JWK members that do not apply to a key type were emitted as empty strings, which RFC
  7517 does not allow.

  Keys.JWKS returned its keys in map order, so a served /.well-known/jwks.json had a
  different body on every request.
```

Files: `none.go`, `jwk.go`, `eddsa.go`, `kid_keys.go`, `hmac.go`, `none_test.go`, `naming_test.go`, `_examples/generate-ed25519/main.go`

## 9. `fix!: stop Base64Decode writing past the end of the token, and bound the input`

```
fix!: stop Base64Decode writing past the end of the token, and bound the input

BREAKING CHANGE: BytesQuote is removed and TokenPair fields are strings.

Base64Decode appended '=' bytes to reach a multiple of four. bytes.Split does not cap the
capacity of the last part it returns, so the signature segment still owns the whole token
spare capacity and that append wrote past the end of the buffer it was given. With a
pooled HTTP read buffer, which is how most servers hand a token to this package, that is a
write into memory the next request is about to use.

Trimming instead, and decoding with base64.RawURLEncoding, fixes it and is faster:
verification drops from 22 allocations to 18 and from 1632 to 1376 bytes, about 12 percent
off the time. The safest version was also the fastest one.

Alongside it:

  MaxTokenSize, 64 KB by default, bounds Decode and the Verify family. Verification
  allocates in proportion to a token that arrives from whoever is calling.

  Alg.Name() is checked before it is concatenated into the header literal. Alg is an
  exported interface, so an implementation returning a name containing a quote could add
  header fields to a token signed with somebody else key.

  Merge validates raw string and []byte fragments with json.Valid. It checked only the
  first and last byte, so a fragment reading {"broken"} was spliced in and the result was
  a signed token whose payload is not JSON. The check costs nothing measurable: anything
  from json.Marshal is valid by construction and skips it.

  Merge error no longer formats the offending value, which put claims into logs.

  TokenPair carried json.RawMessage fields filled by BytesQuote, which returns two quote
  characters for no input, so omitempty never fired and every response contained an empty
  access_token whether or not a token was issued. The fields are strings now, an IDToken
  field is added for OpenID Connect, and BytesQuote is gone: it built a JSON string by
  concatenation with no escaping and its own documentation recommended it for other uses.
```

Files: `token.go`, `claims.go`, `tokenpair.go`, `tokenpair_test.go`, `input_test.go`

## 10. `feat: add the helpers three downstream codebases each wrote by hand`

```
feat: add the helpers three downstream codebases each wrote by hand

Taken from reading what pnoe-core-go, pnoe-nut-go and iris-private are forced to write
around this package, ranked by how many lines each removes.

  KeySet, a Keys that refreshes itself, satisfies HeaderValidator and refetches when a
  token names a key it does not hold. FetchPublicKeys is a single GET with no cache and no
  refetch, so one service called it once inside a constructor and its whole fleet failed
  with ErrUnknownKid until restarted whenever the issuer rotated; the other pasted the
  provider public key into a config file as PEM instead. NewCognitoKeySet also returns the
  issuer and audience checks, which neither service was performing: a token minted for a
  different app client of the same pool verified.

  SignPair signs a linked access and refresh token, each with its own options. The
  hand-written version ran to about 129 lines, plus two option wrappers whose only job was
  to work out which half was being signed by checking whether origin_jti was empty.

  FromHeader, FromQuery, FromCookie and ExtractToken. Three Bearer parsers existed across
  two repositories and two of them disagreed: one split on every space and rejected a
  token containing one, the other split on the first and accepted it.

  Keys.Verify returns the VerifiedToken. VerifyToken throws it away, so every caller
  needing the raw bytes hand-wrote VerifyWithHeaderValidator(nil, nil, ...) instead.

  Skew tolerates clock skew on both nbf and iat. Future only ever rescued iat, and
  validateClaims checks nbf first and stops there, so four call sites across two services
  worked only because their identity provider omits nbf.

  Classify sorts an error into malformed, invalid, expired or rejected. One consumer
  enumerated fifteen sentinels by hand and had already drifted out of step with the twelve
  its own alias file re-exported.

  Validators collects mixed validator types, since Go will not convert
  []TokenValidatorFunc to []TokenValidator.

  ID, OriginID, Issuer, Subject, NotBefore, IssuedAt and ExpiresAt sign options.

  TokenBlocklist, the interface one downstream package declared in a file that contained
  nothing else. DefaultBlocklistKey is exported alongside it, because a backend that
  re-derived it got it wrong and one logout blocked every session in the system.

  Keys.VerifyToken passed the address of an interface that already held a pointer. It
  worked only because encoding/json unwraps that, and this package own documentation
  invites replacing the unmarshaler with one that might not.
```

Files: `keyset.go`, `pair.go`, `extract.go`, `classify.go`, `signoptions.go`, `validators.go`, `blocklist.go`, `kid_keys.go`, and their tests

## 11. `fix: correct the documentation that described an API this package does not have`

```
fix: correct the documentation that described an API this package does not have

The package doc and the per-symbol comments were written at scale and never compiled
against the code, so they had drifted into describing things that do not exist:

  a HeaderValidator example signature used five times, taking a map[string]any, when the
  real type takes (alg string, headerDecoded []byte)

  jwt.Blocklist(revokedTokens) called as a function, twice. Blocklist is a struct.

  GCM shown with two return values, four times. It returns three.

  jwt.RegisteredClaims referenced three times as a type that has never existed

  jwt.Verify(jwt.RS256, keys, token) shown three times. It compiles, because PublicKey is
  any, and it fails at runtime every time: the default header comparison returns a nil key
  and the Keys map reaches the algorithm's type assertion.

  jwt.Verify(alg, key, token, &claims) shown twice, passing a claims destination where the
  variadic parameter takes validators, and reading one return value from two.

  jwt.CompareHeader = jwt.compareHeader offered as the way back to the default. That symbol
  is unexported and no caller can name it.

Godoc has no emphasis syntax, so 532 asterisk pairs across nine files rendered as literal
punctuation, and six "##" headings in doc.go rendered as literal text.

doc.go is rewritten rather than edited. It opened with a performance comparison to other
libraries, described "zero-allocation parsing" that does not exist, documented testing
utilities the package does not ship, and defined an example type shadowing the package's own
TokenValidator.
```

Files: `doc.go`, `alg.go`, `claims.go`, `hmac.go`, `jwk.go`, `jwt.go`, `sign.go`, `token.go`, `verify.go`, `kid_keys.go`

## 12. `fix: publish a key set from a registry that also holds an HMAC key`

```
fix: publish a key set from a registry that also holds an HMAC key

Keys.JWKS returned "unsupported public key type: []uint8" and refused the whole set if the
registry contained a single HMAC key, and Keys.Configuration did the same. A registry with
one symmetric key alongside several asymmetric ones is an ordinary thing to have.

JWKS now skips symmetric keys. That is the correct semantic rather than a workaround: a key
set publishes public keys, and putting an HMAC secret in a document served at
/.well-known/jwks.json would hand out the ability to mint tokens.

Configuration exports them, because a configuration file is where a shared secret
legitimately lives and KeysConfiguration.Load already accepts one. The round trip is tested.

Also in this commit:

  The EC members of a JWK are emitted as x then y. The struct field order decided the JSON
  order and put y first, which is legal and reads as a mistake against RFC 7518.

  SignToken's doc comment claimed the key's MaxAge takes precedence over a caller-supplied
  one. The key's is prepended to the option list, so the caller's applies afterwards and
  wins, which is the useful way round.

  Classify documented KindMalformed as covering a bad base64 segment and a payload that is
  not JSON, and the switch named neither, so both came back KindInvalid. It matches
  base64.CorruptInputError and the unexported errPayloadNotJSON now.

Each of these was found by somebody reading the code to write about it, rather than by a
test.
```

Files: `kid_keys.go`, `jwk.go`, `classify.go`, `naming_test.go`, `helpers_test.go`, `testdata/golden.json`

## 13. `build: give the examples their own module and cover them in CI`

```
build: give the examples their own module and cover them in CI

_examples/multiple-kids imports gopkg.in/yaml.v3 and had no go.mod of its own, so it
resolved against the library's zero-dependency module and did not build. Nothing in CI
compiled it, so nobody noticed. _examples is its own module now, which also means a sample
needing a dependency can never put one into the library's go.mod.

CI gains: go vet, a second test pass under -tags safe, builds of _examples, brand/ and
book/, and a gofmt check. Directories beginning with an underscore are invisible to ./...,
and brand/ and book/ are separate modules on top of that, so nothing above compiled any of
them.
```

Files: `_examples/go.mod`, `_examples/go.sum`, `_examples/generate-ed25519/main.go`, `.github/workflows/ci.yml`

## 14. `feat: add the brand kit`

```
feat: add the brand kit

A key whose three teeth are the three dot-separated segments of a JWT, with the last one
gold because the last segment is the signature. Chosen from six directions, each rendered
at 160, 48, 32 and 16 pixels on both fields and looked at before any of them was presented;
three were redrawn afterwards, because the first Meander collapsed into a plain square, the
first gopher read as a bear, and the shield's cut vanished by 32 pixels.

brand/ is its own Go module with no dependencies. The mark is defined once in mark.go and
everything else is derived from it: the on-dark and monochrome variants, the lockup, the
hero, seventeen PNGs and a favicon.ico assembled from three frames with encoding/binary.
Rasterization shells out to a Chromium-family browser; without one it writes the SVGs, says
so and exits zero.

The small-size cut takes over below 48 pixels. Its ring stroke is thinner than the full
cut's and its radius larger, which is counterintuitive and load-bearing: what has to survive
is the light gap between the hole and the ring, and at 16 pixels that gap was about one
pixel and closed into a grey smear that took the whole bow with it.

brand/BRAND.md documents the palette, the cut boundary, the inline-safety rules, which
generated filenames are load-bearing outside the module, and the rebuild commands.

The README gains the mark with <br clear="left"/> after the intro paragraph, rendered at 900
and 1800 pixel container widths and looked at. Its coverage badge is removed: a hardcoded
image claiming 92 percent, linking to a dead travis-ci.org job, while jwk.go and kid_keys.go
had no tests at all.
```

Files: `brand/**`, `README.md`

## 15. `docs: add the book`

```
docs: add the book

Fourteen chapters and an epilogue in book/, rendered to one self-contained HTML file and
printed to PDF through a headless browser. Its own Go module, so its three dependencies
cannot reach the library's go.mod, which still has none.

The output has nothing external in it: the fonts, the pagination polyfill, the stylesheet
and the brand mark are inlined. The cover reads the mark from brand/ at build time rather
than keeping a copy, so the two cannot drift.

validate.go enforces the chapter skeleton at build time, because a chapter that breaks it
fails quietly rather than loudly: a missing Summary stops mid-thought, and a contents link
whose anchor does not resolve simply goes nowhere. The chapter number in each H1 is checked
against the spine, which is how a book avoids two chapter sevens.

Chapter 12 is the honest list of this library's sharp edges: the names that read the wrong
way round, the defaults that are quieter than you want, the fast paths that carry a hazard,
and everything that changed in v0.2.0.

There is no version anywhere in the book. The library's changes with every release and the
book does not.
```

Files: `book/**`

## 16. `docs: add the writing standard and apply it`

```
docs: add the writing standard and apply it

skill/human-writing/ carries the standard for every markdown file here and a scanner in
both PowerShell and shell that checks it. The scanner is fence aware, blanks inline code
spans and link targets before matching, skips YAML front matter, and exits non-zero while
findings remain.

Applied to the whole corpus: the book, the brand notes, the changelog, the README and the
skill documents. Twenty-seven files, zero findings. The README also loses six line-number
anchors into alg.go that were stale by between 370 and 750 lines and pointed into unrelated
comment prose; they point at the file now, which cannot rot.

The standard passes its own scanner, which took two fixes to the scanner rather than an
exemption: front matter is metadata rather than prose, and a double-backtick code span
contains single backticks and so has to be matched first.
```

Files: `skill/human-writing/**`, `README.md`

## 17. `docs: add the changelog and the pass notes`

```
docs: add the changelog and the pass notes

CHANGELOG.md covers v0.2.0, grouped Breaking, Security, Fixed, Added, Changed and
Documentation, with each entry leading with what was wrong rather than which file moved.

PASS-LEDGER.md and COMMIT-PLAN.md are working notes: every decision taken on the author's
behalf with its reasoning and what it costs if it is wrong, the benchmark baseline and every
measurement against it, and the before and after of each deliberate output change. Delete
them once this is committed.
```

Files: `CHANGELOG.md`, `PASS-LEDGER.md`, `COMMIT-PLAN.md`
