# Chapter 5: Choosing an Algorithm

The `alg` argument you pass to `Sign` and `Verify` decides more than which mathematics runs.
It decides who can mint tokens, how large every token is, whether the same claims produce
the same bytes twice, and what your key material looks like on disk. This chapter goes
through the six families the package implements, states what each one requires and costs,
and ends with a recommendation you can disagree with on purpose.

## Table of Contents

- [The six families](#the-six-families)
- [Symmetric or asymmetric](#symmetric-or-asymmetric)
- [Key types and wrong keys](#key-types-and-wrong-keys)
- [Sizes and cost](#sizes-and-cost)
- [Determinism and golden tests](#determinism-and-golden-tests)
- [The none algorithm](#the-none-algorithm)
- [Writing your own Alg](#writing-your-own-alg)
- [What to pick](#what-to-pick)
- [Summary](#summary)
- [Further Reading](#further-reading)

## The six families

Every algorithm in the package is a package-level variable of type `Alg`, and the interface
has three methods:

```go
type Alg interface {
	Name() string
	Sign(key PrivateKey, headerAndPayload []byte) ([]byte, error)
	Verify(key PublicKey, headerAndPayload []byte, signature []byte) error
}
```

`PrivateKey` and `PublicKey` are both aliases for `any`. That is what lets one interface
carry a `[]byte` secret and an `*rsa.PrivateKey`, and it is also why a key of the wrong type
is a runtime error rather than a compile error. The next section deals with that.

| Family | Names | Sign key | Verify key | RFC |
| --- | --- | --- | --- | --- |
| HMAC-SHA2 | `HS256` `HS384` `HS512` | `[]byte` | the same `[]byte` | 7518 3.2 |
| RSA PKCS#1 v1.5 | `RS256` `RS384` `RS512` | `*rsa.PrivateKey` | `*rsa.PublicKey` | 7518 3.3 |
| ECDSA | `ES256` `ES384` `ES512` | `*ecdsa.PrivateKey` | `*ecdsa.PublicKey` | 7518 3.4 |
| RSA-PSS | `PS256` `PS384` `PS512` | `*rsa.PrivateKey` | `*rsa.PublicKey` | 7518 3.5 |
| Unsecured | `NONE` | ignored | ignored | 7518 3.6 |
| EdDSA | `EdDSA` | `ed25519.PrivateKey` | `ed25519.PublicKey` | 8037 |

The number in an HMAC, RSA or PSS name is the SHA-2 variant and nothing else. `RS512` is not
a bigger RSA key than `RS256`: both use whatever key you hand them and both produce a
signature the width of the modulus. ECDSA is the exception, because the curve and the hash
move together:

```go
ES256 Alg = &algECDSA{"ES256", crypto.SHA256, 32, 256}
ES384 Alg = &algECDSA{"ES384", crypto.SHA384, 48, 384}
ES512 Alg = &algECDSA{"ES512", crypto.SHA512, 66, 521}
```

The last two fields are the coordinate width in bytes and the curve size in bits. Note the
final line: `ES512` uses P-521, not a 521-typo and not a 512-bit curve. The name follows the
hash, the curve does not, and 66 bytes is what 521 bits rounds up to.

RSA-PSS is the same RSA key as PKCS#1 v1.5, with different padding:

```go
PS256 Alg = &algRSAPSS{"PS256", &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: crypto.SHA256}}
```

A `*rsa.PrivateKey` works with both families. What you cannot do is verify a `PS256` token
with `RS256` or the reverse: the padding differs, so the signature does not check out, and
the header comparison would refuse it first anyway.

## Symmetric or asymmetric

This is the decision. Everything else in the chapter is detail.

With HMAC, the key that verifies a token is the key that signs one. There is no separate
public half. Any service you give the verification key to can mint tokens indistinguishable
from yours, and your `Verify` call will accept them, because they are correct.

Say that plainly, because it is easy to walk past. If you run an auth service and six APIs,
and all seven share an HS256 secret, then all seven are your auth service. A bug in the
least careful of them, a leaked environment variable in a container image, a contractor with
read access to one repository: any of those is a signing key. Nothing in the token can tell
you afterwards which of the seven produced it, because the signature proves possession of a
key that all seven possess.

With RSA, ECDSA or EdDSA the split is real. The issuer holds the private key and mints
tokens; everybody else holds the public key and can only check them. That public key can be
published, put in a config map, served from a JWKS endpoint, or checked into a repository.

The trade is honest in both directions. Asymmetric verification costs more CPU and produces
larger tokens, and you now have a key pair to generate, distribute and rotate, which is
Chapters 6 and 7. HMAC is faster, the key is a byte slice you can generate with one call,
and there is nothing to parse. The question is not which is stronger. It is whether
everything that verifies your tokens is allowed to issue them.

**HMAC is a reasonable choice inside one trust boundary.** One process signing and verifying
its own session tokens, or two services under the same deployment with the same owner, is a
fine place for HS256. The moment a third party verifies, or a verifier lives somewhere you
would not put a signing key, you want the split. And note the thing HMAC cannot do at all:
every holder of the key is equally the author, so if you ever have to answer "which service
issued this token", the token itself will not tell you.

## Key types and wrong keys

Each `Sign` and `Verify` begins with a type assertion, and a wrong type yields `ErrInvalidKey`.

```go
func (a *algHMAC) Sign(key PrivateKey, headerAndPayload []byte) ([]byte, error) {
	secret, ok := key.([]byte)
	if !ok {
		return nil, fmt.Errorf("expected a string: %w", ErrInvalidKey)
	}
	// ...
}
```

The most common mistake in the whole package is right there. `HS256` wants `[]byte`, and a
Go string is not a `[]byte`:

```go
_, err := jwt.Sign(jwt.HS256, "my-secret", claims)         // ErrInvalidKey
_, err = jwt.Sign(jwt.HS256, []byte("my-secret"), claims)  // fine
```

The error text reads "expected a string", which is misleading, since a string is exactly
what it will not take. Match on the wrapped error rather than the message:
`errors.Is(err, jwt.ErrInvalidKey)`.

The asymmetric implementations follow the same shape with one addition. RSA, ECDSA and EdDSA
all check for a nil key after the assertion:

```go
publicKey, ok := key.(*rsa.PublicKey)
if !ok || publicKey == nil {
	if privateKey, ok := key.(*rsa.PrivateKey); ok && privateKey != nil {
		publicKey = &privateKey.PublicKey
	} else {
		return ErrInvalidKey
	}
}
```

The nil test is not decoration. A nil pointer stored in an interface makes the interface
itself non-nil, so an `*rsa.PublicKey(nil)` passes the assertion and then panics inside
`crypto/rsa`. It got there through a registered `Key` whose `Public` field was a typed nil,
and from that point any token naming that `kid` crashed the process. EdDSA has the matching
version: `ed25519.PrivateKey.Public()` slices the key at `[32:]`, so the length check has to
run before the call rather than after.

The fallback in that snippet is deliberate. All three asymmetric families accept a private
key where a public one is expected and extract the public half themselves, which is a
convenience for the single-process case where you hold both. It does not work in reverse.
There is no way to sign with a public key.

Two more refusals worth knowing. `algECDSA.Sign` compares the key's curve against the
algorithm's `curveBits` and returns `ErrInvalidKey` when they differ, so signing with
`ES256` and a P-384 key fails outright rather than producing something a verifier rejects
later. And `algECDSA.Verify` checks `len(signature) != 2*a.keySize` before doing any
arithmetic, because the JWS form is the fixed-width `r || s` concatenation rather than a DER
structure.

## Sizes and cost

Signature width is fixed by the algorithm, so token size is predictable. These were measured
by signing the same three-claim payload with each algorithm, using a freshly generated
2048-bit RSA key:

| Algorithm | Signature | Whole token |
| --- | --- | --- |
| `none` | 0 bytes | 105 chars |
| `HS256` | 32 bytes | 149 chars |
| `HS384` | 48 bytes | 170 chars |
| `HS512` | 64 bytes | 192 chars |
| `ES256` | 64 bytes | 192 chars |
| `EdDSA` | 64 bytes | 192 chars |
| `ES384` | 96 bytes | 234 chars |
| `ES512` | 132 bytes | 282 chars |
| `RS256` and `PS256` | 256 bytes | 448 chars |

RSA is the outlier, and the reason is structural: an RSA signature is the width of the
modulus, so a 2048-bit key gives 256 bytes whatever the hash, and a 4096-bit key gives 512.
An RS256 token is roughly three times the size of an ES256 one carrying identical claims.
For a token that rides in a header on every request that is real bandwidth, and for anything
that has to fit in a 4 KB cookie it can be the deciding constraint.

For cost, the package's benchmark suite covers HS256 only. On windows/arm64:

```text
BenchmarkSign_Map-12       489426     2500 ns/op    1528 B/op    23 allocs/op
BenchmarkSign_Struct-12    580483     2179 ns/op    1392 B/op    21 allocs/op
BenchmarkVerify-12         431294     2620 ns/op    1376 B/op    18 allocs/op
```

Almost all of that is JSON and base64, not HMAC. The same suite measures `golang-jwt` at
4713 ns/op and `go-jose` at 7460 ns/op for the equivalent verification, which tells you
about the packages rather than about SHA-256.

Per-algorithm numbers are not in the suite, so measure them on your own hardware rather than
trusting a table in a book. What you can rely on is the shape, which follows from the
mathematics rather than the implementation. HMAC is the cheapest at both ends by a wide
margin, because it is one hash. RSA is lopsided: signing performs a private-key operation
across the full modulus and is the slowest operation in the set, while verification uses the
public exponent, usually 65537, and is among the fastest. ECDSA is the reverse, cheap to
sign and dearer to verify. EdDSA is quick at both and needs no entropy at signing time.

Pick on the ratio your system actually has. A gateway verifying ten thousand tokens a second
against an issuer minting fifty cares about verification cost; a batch job minting a million
tokens cares about the other end.

## Determinism and golden tests

Sign the same header and payload twice with the same key. Do you get the same token? It
depends on the family, and the answer was measured rather than assumed:

| Family | Same bytes twice? |
| --- | --- |
| HMAC | Yes |
| RSA PKCS#1 v1.5 | Yes |
| EdDSA (Ed25519) | Yes |
| RSA-PSS | No |
| ECDSA | No |

HMAC is a hash of the input. PKCS#1 v1.5 padding is fixed, so `rsa.SignPKCS1v15` is
deterministic even though it takes an `io.Reader`. Ed25519 derives its nonce from the
message and the private key by design, which is one of the reasons the scheme exists: there
is no per-signature random value to get wrong. PSS and ECDSA both draw from `rand.Reader` on
every call, PSS to salt the padding and ECDSA to pick a nonce, and in both cases repeating
that value would leak the private key. The randomness is not optional and not a flaw.

The consequence lands in your test suite. A golden test that pins an expected token string
works for HS256, RS256 and EdDSA, and cannot work for ES256 or PS256:

```go
// Fine for HS256, RS256, EdDSA.
if string(token) != want {
	t.Fatalf("token changed:\n got %s\nwant %s", token, want)
}

// Required for ES256, PS256: verify instead of comparing.
if _, err := jwt.Verify(jwt.ES256, publicKey, token); err != nil {
	t.Fatal(err)
}
```

The package's own golden tests take exactly this split: where they can pin bytes they pin
bytes, which is what caught the header casing bug in the next section, and where they cannot
they verify and check the claims. If you are choosing partly for testability, the
deterministic algorithms are easier to assert on, which is a genuine if minor point in
favour of EdDSA over ECDSA.

## The none algorithm

RFC 7518 section 3.6 defines an unsecured JWT: the `alg` header reads `none`, the signature
segment is empty, and nothing is proved. The package implements it in three short methods,
of which this is the interesting one:

```go
func (a *algNONE) Name() string {
	return "none"
}
```

Lowercase, because that is what the RFC says. It returned `"NONE"` until v1.0.0, which no
other implementation recognises, so tokens produced here were not valid unsecured JWTs
anywhere else and conforming tokens naming `none` were never accepted here. Both directions
were broken, which is a small argument for byte-exact golden tests. `Sign` returns
`nil, nil`, and `Verify` returns `ErrTokenSignature` unless the signature is empty.

Now the part that matters. The classic JWT attack is to take a signed token, rewrite its
header to `{"alg":"none"}`, drop the signature, and hand it back. It works against any
library that reads the algorithm out of the token. This one does not:

```go
verifiedToken, err := jwt.Verify(jwt.HS256, key, token)
```

The algorithm is an argument. The default `CompareHeader` builds the expected header from
that argument and compares bytes:

```go
expectedHeader := createHeaderRaw(alg)
if !bytes.Equal(expectedHeader, headerDecoded) {
	return nil, nil, nil, ErrTokenAlg
}
```

`createHeaderRaw("HS256")` is the 27-byte literal `{"alg":"HS256","typ":"JWT"}`. There is no
parse and no lookup. A header reading `{"alg":"none","typ":"JWT"}` is 26 bytes that cannot
equal those 27, so it fails with `ErrTokenAlg` before any signature check runs. The
comparison also accepts the reversed field order some libraries emit, and a 15-byte header
with no `typ`, but each of those is likewise built from the algorithm you pinned. **A
`Verify` call that named a real algorithm can never accept an `alg: none` token.**

`Enrich` refuses `NONE` outright, both in the package-level function and in
`UnverifiedToken.Enrich`:

```go
if alg == NONE {
	return nil, fmt.Errorf("%w: refusing to enrich under the unsecured algorithm", ErrTokenAlg)
}
```

Enriching means adding claims and signing the result. Doing that under `none` produces a
token with your claims, your structure and no signature: the shape of a credential without
being one. There is no legitimate use, so it is refused rather than documented.

If you genuinely want an unsecured token, for a client-side preferences blob where tampering
costs nothing, pass `jwt.NONE` to `Sign` and `Verify` explicitly and be certain no
authorization decision reads it. The source file listing the algorithms marks `NONE`, and
also `HS256`, `HS384` and `HS512`, with the comment `// Not recommended.`

## Writing your own Alg

`Alg` is exported, so you can implement it. Reasons that come up: an HSM or KMS that holds
the private key and exposes a signing call, an algorithm the package does not ship, or a
wrapper around one that already works. The wrapper is the easiest case, because embedding
`jwt.Alg` supplies the two methods you are not changing:

```go
// timed wraps an algorithm and reports how long each signing operation took.
type timed struct {
	jwt.Alg
	observe func(name string, d time.Duration)
}

func (a timed) Sign(key jwt.PrivateKey, headerAndPayload []byte) ([]byte, error) {
	start := time.Now()
	defer func() { a.observe(a.Alg.Name(), time.Since(start)) }()

	return a.Alg.Sign(key, headerAndPayload)
}
```

Pass it as you would any algorithm: `jwt.Sign(timed{Alg: jwt.ES256, observe: record}, key,
claims)`. `Name` and `Verify` come from the embedded value, so the header still reads
`ES256` and the token verifies with plain `jwt.ES256` anywhere else. A KMS-backed
implementation is the same shape with a real `Sign` body, and it has to return the JWS
signature form, which for ES256 is the 64-byte `r || s` concatenation rather than the DER
structure most signing APIs hand back.

Three things to get right.

**The name goes into the header, and the header is built by concatenation.** Nothing escapes
it, so `Name()` is validated before it gets there. `encodeToken` opens with `checkAlgName`,
which requires a name of 1 to 64 characters drawn only from `a-z`, `A-Z`, `0-9` and the four
punctuation marks `-`, `+`, `.` and `_`, returning a wrapped `ErrTokenAlg` otherwise. That
is the character set JWA uses for algorithm names, not an allowlist of the built-in ones, so
a sensible custom name still works. Without the check, an implementation returning a name
containing a double quote could inject header fields of its own choosing into a token signed
with somebody else's key. Your `Name()` should return a constant.

**Verification must be constant time in whatever you compare.** If you compare bytes
yourself, use `hmac.Equal` or `crypto/subtle`, not `bytes.Equal`.

**Implement `AlgParser` if your keys come from files or a registry.** It is the optional
second interface, and `Keys` uses it to turn PEM bytes into key objects:

```go
type AlgParser interface {
	Parse(private, public []byte) (PrivateKey, PublicKey, error)
}
```

All the built-in asymmetric algorithms implement it. `HS256` does not, because there is
nothing to parse.

One limit to note: `UnverifiedToken.Alg()` resolves a name through `parseAlg`, which only
searches the built-in list, so it returns `ErrTokenAlg` for a custom name. Signing and
verification are unaffected, since you pass the `Alg` value directly. Code that inspects an
unverified token to decide what to do with it is affected, and the fix is a custom
`HeaderValidator`. Chapter 6 covers those.

## What to pick

**EdDSA, when you control both ends.** 64-byte signatures, 32-byte public keys, fast at
both signing and verification, deterministic, and no per-signature randomness to get wrong.
It is the newest of the set, which is the whole of its downside: older JWT libraries may not
support it, and HSM coverage is thinner than for RSA and ECDSA. If your issuer and your
verifiers are all your own Go services, that downside does not apply to you.

**RS256 or ES256, when you must interoperate.** RS256 is the most widely implemented
asymmetric JWT algorithm in existence; every library, every gateway, every identity provider
handles it. Choose it when an unknown third party has to verify, or when you are consuming
tokens from a provider that offers it. ES256 gives you the same interoperability almost
everywhere with a token a third of the size, so prefer it when you can check that your
consumers support it. Both are fine choices, and the difference between them is bandwidth
rather than strength.

**HMAC only inside one trust boundary.** HS256 is fast, simple, and requires a key at least
32 bytes of real entropy, which `jwt.MustGenerateRandom(32)` will give you. Use it when the
same owner runs everything that touches the key, and stop using it the moment that stops
being true. A password, a config default, or a phrase somebody typed is not a key; RFC 7518
requires a key at least as long as the hash output for a reason.

**PS256 over RS256 when both ends are modern.** PSS has better proofs and no known
weaknesses in its padding, where PKCS#1 v1.5 has a long history of implementation problems.
The catch is support: PSS is less widely implemented, and OpenSSL uses distinct key OIDs to
stop a key being reused across the two schemes. Pick PSS for a new closed system, and
RS256 when interoperability decides.

**ES384, ES512, HS512 and the rest: only if something requires them.** Larger hashes and
curves cost bytes and cycles and buy margin above what the rest of your system provides. If
a compliance document names one, use it. Otherwise the 256-bit variants are not the weak
link. **NONE: no.**

Whatever you choose, pin it: pass the algorithm to `Verify` rather than letting a header
choose. And write the choice down with its reason, because the next person to touch it will
otherwise change it to whatever the first search result recommends.

## Summary

Six families: HMAC (`HS256`, `HS384`, `HS512`), RSA PKCS#1 v1.5 (`RS*`), RSA-PSS (`PS*`),
ECDSA (`ES256`, `ES384`, `ES512`), EdDSA (Ed25519), and `NONE`. The number names the hash,
except in ECDSA where it moves with the curve, and `ES512` uses P-521.

The real decision is symmetric or asymmetric. With HMAC every verifier can also mint tokens
that your own `Verify` will accept, and nothing in the token says which holder produced it.

Key types are checked by assertion at the top of every `Sign` and `Verify`, and a wrong type
returns `ErrInvalidKey`. A Go string for an HMAC key is the common case. The asymmetric
implementations also check for typed nils, because a nil pointer in an interface asserts
successfully and then panics.

Signatures are 32 to 64 bytes for HMAC, 64 to 132 for ECDSA, 64 for Ed25519, and the width
of the modulus for RSA, which is 256 bytes at 2048 bits. RSA signing is the slowest
operation in the set and RSA verification among the fastest. HMAC, RSA PKCS#1 v1.5 and
Ed25519 produce identical bytes for identical input; RSA-PSS and ECDSA randomise, so golden
tests that pin a token string cannot be written for them.

`NONE` names itself `none`, per RFC 7518 section 3.6. Because header comparison is
byte-exact against the algorithm you pinned, an `alg: none` token can never be accepted by a
`Verify` call naming a real algorithm, and `Enrich` refuses `NONE` outright.

Recommendation: EdDSA where you control both ends, RS256 or ES256 where you must
interoperate, HMAC only inside one trust boundary.

## Further Reading

- [RFC 7518: JSON Web Algorithms](https://www.rfc-editor.org/rfc/rfc7518): sections 3.2 to
  3.6 define every algorithm here, including the minimum HMAC key lengths and the
  `none` algorithm.
- [RFC 8037](https://www.rfc-editor.org/rfc/rfc8037): how Ed25519 is used in JOSE, which is
  where the name `EdDSA` comes from.
- [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032): Ed25519 itself, including why its
  signatures are deterministic.
- [RFC 8725 section 3.1](https://www.rfc-editor.org/rfc/rfc8725#section-3.1): perform
  algorithm verification, which is the practice this package enforces by making `alg` an
  argument. Section 3.2 covers choosing among them.
- [NIST SP 800-57 Part 1](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final): the key-length
  equivalence tables, if you want to argue about 2048-bit RSA against P-256 with numbers.
- [pkg.go.dev/crypto/ed25519](https://pkg.go.dev/crypto/ed25519) and
  [pkg.go.dev/crypto/ecdsa](https://pkg.go.dev/crypto/ecdsa): the Go implementations these
  algorithms call, including the key types you have to supply.

---

**Next Chapter**: [Keys and Rotation](06-keys-and-rotation.md) - Where key material comes from, and how to replace it without dropping requests.
