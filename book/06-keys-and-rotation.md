# Chapter 6: Keys and Rotation

A system with one signing key has no way to replace it. Every token in flight was signed with
that key, every verifier holds that key, and the moment you swap it every outstanding token
becomes invalid at once. This chapter is about the mechanism that removes the constraint: a
key identifier in the header, a registry mapping identifiers to keys and algorithms, and the
ordering that lets a new key take over while the old one is still verifying traffic.

## Table of Contents

- [The flag day problem](#the-flag-day-problem)
- [The kid header and the Keys registry](#the-kid-header-and-the-keys-registry)
- [Signing and verifying through the registry](#signing-and-verifying-through-the-registry)
- [ValidateHeader binds the kid to an algorithm](#validateheader-binds-the-kid-to-an-algorithm)
- [HMAC in a registry](#hmac-in-a-registry)
- [Enriching a token the registry signed](#enriching-a-token-the-registry-signed)
- [Keys from a configuration file](#keys-from-a-configuration-file)
- [Loading keys from PEM](#loading-keys-from-pem)
- [MustLoadHMAC will not tell you the file was missing](#mustloadhmac-will-not-tell-you-the-file-was-missing)
- [The registry is a plain map](#the-registry-is-a-plain-map)
- [A rotation in four steps](#a-rotation-in-four-steps)
- [Summary](#summary)
- [Further Reading](#further-reading)

## The flag day problem

Chapters 2 and 3 passed the key as an argument: `jwt.Sign(jwt.HS256, secret, claims)` on one
side, `jwt.Verify(jwt.HS256, secret, token)` on the other. That works until you need a different
key, and then there are two ways to replace it and both are bad. Deploy the new key everywhere
at the same instant, and every process that verifies must restart in lockstep with every process
that signs, while any token issued a moment before the switch fails on the other side. Or accept
a window where verification is broken and hope it is short.

That coordinated restart is a flag day. It scales with the number of services holding the key,
it cannot be rehearsed safely, and it turns key replacement into an event rather than a routine.
The predictable result is that keys never get replaced, so a leaked key has no recovery path
except the flag day you have been avoiding. What breaks the deadlock is letting a verifier hold
several keys, and letting the token say which one signed it.

## The kid header and the Keys registry

`kid` is a header parameter registered by RFC 7515 section 4.1.4. It is a hint, not a
credential: it names a key, and the receiver decides what that name means. The value is an
arbitrary case-sensitive string, so dates, version counters and random identifiers all work.
What matters is that it stays stable for the life of a key and is never reused for another.
The registry is a map, and each entry is a `Key`:

```go
type Keys map[string]*Key

type Key struct {
	ID      string        // Unique identifier for this key
	Alg     Alg           // Algorithm implementation for this key
	Public  PublicKey     // Public key for verification (can be nil for HMAC)
	Private PrivateKey    // Private key for signing (required for signing)
	MaxAge  time.Duration // Optional: automatic token expiration
	Encrypt InjectFunc    // Optional: payload encryption function
	Decrypt InjectFunc    // Optional: payload decryption function
}
```

| Field | What it holds |
| --- | --- |
| `ID` | The `kid` written into the header when this key signs, and the map key it is found under. `Register` keeps the two in agreement. |
| `Alg` | An `Alg` value such as `jwt.RS256`, not a string. The most important field here: it binds one algorithm to this key, on your side rather than the sender's. |
| `Public`, `Private` | The key material. Both types are aliases for `any`, so the concrete type is whatever the algorithm expects: `*rsa.PrivateKey` for `RS256`, `*ecdsa.PrivateKey` for `ES256`, `ed25519.PrivateKey` for `EdDSA`, `[]byte` for the HMAC family. A verify-only registry leaves `Private` nil. |
| `MaxAge` | When greater than zero, adds an expiry to every token this key signs, which saves repeating `jwt.MaxAge(...)` at each call site. |
| `Encrypt`, `Decrypt` | A payload cipher, covered in Chapter 11. Setting either one makes this key unusable for enrichment and for configuration export, both of which need the plain payload. |

Registering takes four arguments, and `Get` reads a key back:

```go
func (keys Keys) Register(alg Alg, kid string, pubKey PublicKey, privKey PrivateKey)
func (keys Keys) Get(kid string) (*Key, bool)

keys := make(jwt.Keys)
keys.Register(jwt.RS256, "signing-2024-01", &rsaPrivate.PublicKey, rsaPrivate)
keys.Register(jwt.ES256, "signing-2024-06", &ecdsaPrivate.PublicKey, ecdsaPrivate)
```

`Register` overwrites an existing entry with the same identifier without complaint. That is
deliberate, and it also means a copy-pasted line with an unedited `kid` silently discards a
key, surfacing later as `ErrUnknownKid` on tokens you expected to verify. `Get` returns a
pointer into the map, so mutating the result mutates the registry, which is the supported way
to set `MaxAge`, `Encrypt` or `Decrypt` after `Register`.

## Signing and verifying through the registry

Signing names the key. The header it produces carries both parameters, `kid` first, and an
unregistered identifier returns `ErrUnknownKid` before any crypto runs:

```go
func (keys Keys) SignToken(kid string, claims any, opts ...SignOption) ([]byte, error)

token, err := keys.SignToken("signing-2024-06", userClaims{Sub: "u-1", Role: "admin"},
	jwt.MaxAge(15*time.Minute))
// header: {"kid":"signing-2024-06","alg":"ES256"}
```

**On MaxAge precedence.** `SignToken` prepends the key's `MaxAge` to the options you passed,
and options apply in order, so the last one wins. A key registered with a one hour `MaxAge` and
signed with `jwt.MaxAge(time.Minute)` produces a token expiring in one minute. The method's own
doc comment claims the opposite. What is written here is what the code does, measured by
reading `exp` off the signed token.

Verification does not name a key. It reads one out of the header. `VerifyToken` unmarshals into
your struct and hands back only an error; `Verify` returns the token itself, for when you need
the raw bytes to forward, a claim outside the standard set, or `StandardClaims` to give to a
blocklist:

```go
func (keys Keys) VerifyToken(token []byte, claimsPtr any, validators ...TokenValidator) error
func (keys Keys) Verify(token []byte, validators ...TokenValidator) (*VerifiedToken, error)

verifiedToken, err := keys.Verify(token)
if err != nil {
	return err
}
var claims userClaims
err = verifiedToken.Claims(&claims)
```

Both run the same path. `Verify` exists because without it every caller who wanted the token
hand-wrote `jwt.VerifyWithHeaderValidator(nil, nil, token, keys.ValidateHeader, validators...)`,
including the two leading nils, which are the algorithm and key arguments the header validator
makes redundant.

Three errors are worth knowing by name: `ErrEmptyKid` when the header carries no `kid`,
`ErrUnknownKid` when it carries one you have not registered, and `ErrTokenAlg` when the
header's algorithm disagrees with the registered one. All three are decided before any
signature work happens.

## ValidateHeader binds the kid to an algorithm

Everything above rests on one method, which satisfies the `HeaderValidator` function type.
Given a decoded header it parses `kid` and `alg`, looks the key up, and returns the algorithm,
the public key and the decryption function to use. A key registered with no algorithm returns
`ErrInvalidKey` rather than dereferencing a nil interface. The line that matters is the last
one here:

```go
func (keys Keys) ValidateHeader(alg string, headerDecoded []byte) (Alg, PublicKey, InjectFunc, error)

if h.Alg != key.Alg.Name() {
	return nil, nil, nil, ErrTokenAlg
}
```

The algorithm comes from the registry, and the header's `alg` is only permitted to agree with
it. Consider what that prevents. An attacker takes a token whose `kid` is `signing-2024-06`, a
key you registered as `ES256`, rewrites the header to say `RS256`, and signs with an RSA key
of their own. A naive implementation reads `RS256` from the header, fetches the key material
for that `kid`, and attempts a verification it was never meant to attempt. Here the header is
rejected with `jwt: unexpected token algorithm` before the signature is examined. The same
check covers the downgrade where `alg` is replaced with `none`, and the RS256-to-HS256
confusion where a published public key is submitted as an HMAC secret.

This is the security property of the whole chapter, and it fits in one line: **the token
chooses which key, and the registry chooses which algorithm**. The sender picks an entry from a
list you wrote, and everything about that entry comes from your side. The `alg` parameter is a
further constraint: when it is not empty the header must match it as well, which pins
verification to a single algorithm across a registry holding several.

## HMAC in a registry

HMAC signs and verifies with the same bytes, so an `HS256` key has no separate public half.
`Register` accepts nil there and fills it in:

```go
keys.Register(jwt.HS256, "internal", nil, []byte("sercrethatmaycontainch@r$"))

// inside Register:
if pubKey == nil {
	if _, symmetric := alg.(*algHMAC); symmetric {
		pubKey = privKey
	}
}
```

Without that, nil travelled from `Register` through `ValidateHeader` into `algHMAC.Verify`,
whose type assertion on `[]byte` failed, and every token naming that identifier was rejected
with `ErrInvalidKey`. The package's own documented example passed nil. The substitution happens
only for HMAC: passing nil as the public key for `RS256` leaves it nil, which is correct, since
an RSA key with no public half can sign and cannot verify.

Mixing symmetric and asymmetric keys in one registry works for signing and verifying, and breaks
two export paths. `Keys.JWKS()` and `Keys.Configuration()` both walk every entry and fail on the
first they cannot encode: `unsupported public key type: []uint8` from the first and
`jwt: unsupported private key type: []uint8` from the second. An HMAC secret has no PEM
encoding and no place in a public key set, so refusing is right. It is also all or nothing, so
if you plan to publish a JWKS, keep HMAC keys in a separate registry.

## Enriching a token the registry signed

Chapter 3 introduced `Enrich`, which adds claims by verifying a token and signing a new one.
The registry has its own version, taking no key and no algorithm:

```go
func (keys Keys) EnrichToken(plainToken []byte, extraClaims any) ([]byte, error)

enriched, err := keys.EnrichToken(token, jwt.Map{"tenant": "acme"})
```

The missing parameters are the point. It calls `keys.ValidateHeader`, which checks the signature
under the registered key and binds the `kid` to the registered algorithm, and only then
re-signs. An earlier version signed the incoming header and payload with a registered private
key before checking anything, which made the method a signing oracle for anyone who could reach
it. The verified header is carried through unchanged, so the enriched token still names the same
key and verifies through the same registry on the way back in. Keys with `Encrypt` or `Decrypt`
set are refused, because enrichment merges claims into a payload it has to read.

## Keys from a configuration file

Keys usually arrive as text rather than as Go values. Two types cover that:

```go
type KeysConfiguration []KeyConfiguration

type KeyConfiguration struct {
	ID            string        `json:"id" yaml:"ID" toml:"ID" ini:"id"`
	Alg           string        `json:"alg" yaml:"Alg" toml:"Alg" ini:"alg"`
	Private       string        `json:"private" yaml:"Private" toml:"Private" ini:"private"`
	Public        string        `json:"public" yaml:"Public" toml:"Public" ini:"public"`
	MaxAge        time.Duration `json:"max_age" yaml:"MaxAge" toml:"MaxAge" ini:"max_age"`
	EncryptionKey string        `json:"encryption_key" yaml:"EncryptionKey" toml:"EncryptionKey" ini:"encryption_key"`
}
```

The four tag sets mean one document loads from JSON, YAML, TOML or INI without a wrapper type.
Note the asymmetry: JSON and INI use lowercase names with underscores, YAML and TOML use the Go
field names, so check the struct rather than guessing. `Load` turns the text into keys, and
`MustLoad` is the same with a panic instead of an error, for keys embedded in the binary where
a failure means the process cannot start anyway. Three things about `Load` deserve attention.

```go
func (c KeysConfiguration) Load() (Keys, error)
func (c KeysConfiguration) MustLoad() Keys
```

**An unrecognised algorithm name is an error, and the error names the key.** The loop over the
built-in algorithms used to start at `RS256` and keep it when nothing matched, so
`"alg": "RSA256"` produced a working `RS256` key and confusing failures much later. Parse
failures are labelled the same way, which matters once a file holds five keys:

```text
jwt: load keys: id="api": unknown algorithm "RSA256"
jwt: load keys: id="api" alg="RS256": parse: RSA: private key: private key: malformed or missing PEM format (RSA)
```

**`EncryptionKey` must be hex-encoded.** It goes through `hex.DecodeString` before reaching
`GCM`, so the string in your file is twice the length of the key it represents: 32 hex
characters for AES-128, 48 for AES-192, 64 for AES-256. Anything else fails at load with
`jwt: load keys: decode encryption key (hex): encoding/hex: invalid byte: U+007A 'z'`.

**Quoted strings are unquoted.** `Public` and `Private` are each passed through
`strconv.Unquote`, and the result is used when it succeeds, which is what lets a PEM block sit
on one line with `\n` escapes inside a JSON file.

Two convenience methods round out the type. `Get` is a linear scan by identifier. `Clone` copies
the slice and every entry, so `production.Clone()` gives you a development variant you can edit
without touching the original. Every field is a string or a `time.Duration`, so that copy is
deep in the way that matters, and `KeyConfiguration.Clone` does the same for one entry.

```go
func (c KeysConfiguration) Get(kid string) (KeyConfiguration, bool)
func (c KeysConfiguration) Clone() KeysConfiguration
```

## Loading keys from PEM

When keys are files on disk, each algorithm family has a loader. The RSA set is
representative:

```go
func MustLoadRSA(privateKeyFilename, publicKeyFilename string) (*rsa.PrivateKey, *rsa.PublicKey)
func LoadPrivateKeyRSA(filename string) (*rsa.PrivateKey, error)
func LoadPublicKeyRSA(filename string) (*rsa.PublicKey, error)
func ParsePrivateKeyRSA(key []byte) (*rsa.PrivateKey, error)
func ParsePublicKeyRSA(key []byte) (*rsa.PublicKey, error)
```

The pattern repeats per family. `Parse*` takes bytes, `Load*` reads a file and calls `Parse*`,
`MustLoad*` loads a pair and panics on failure. ECDSA has `MustLoadECDSA`,
`LoadPrivateKeyECDSA`, `LoadPublicKeyECDSA`, `ParsePrivateKeyECDSA` and `ParsePublicKeyECDSA`.
EdDSA has `MustLoadEdDSA`, `LoadPrivateKeyEdDSA`, `LoadPublicKeyEdDSA`, `ParsePrivateKeyEdDSA`
and `ParsePublicKeyEdDSA`. Reading goes through a package variable, `jwt.ReadFile`, defaulting
to `os.ReadFile`; replacing it loads keys from an embedded filesystem or a secret manager
without touching the call sites.

The accepted formats are wider than the names suggest. `ParsePrivateKeyRSA` tries PKCS#1 and
falls back to PKCS#8. `ParsePublicKeyRSA` and `ParsePublicKeyECDSA` try PKIX and fall back to
parsing the block as a certificate and taking the public key out of it, so a `.crt` file works
where you might expect a bare public key. Going the other way, RSA private keys come out as
PKCS#1 (`RSA PRIVATE KEY`), ECDSA as SEC1 (`EC PRIVATE KEY`), Ed25519 as PKCS#8
(`PRIVATE KEY`), and all three public types as PKIX (`PUBLIC KEY`). Those two encoders are
what `Configuration` is built on, the inverse of `Load`:

```go
func EncodePrivateKeyToPEM(key PrivateKey) (string, error)
func EncodePublicKeyToPEM(key PublicKey) (string, error)

func (key *Key) Configuration() (KeyConfiguration, error)
func (keys Keys) Configuration() (KeysConfiguration, error)
```

The result marshals straight to JSON, and the round trip holds: keys exported this way and
reloaded verify tokens signed by the originals. Keys with encryption attached are refused,
since `Encrypt` and `Decrypt` are functions and cannot be written to a file, and a key with no
`Alg` is refused with `ErrInvalidKey`.

## MustLoadHMAC will not tell you the file was missing

The HMAC loaders break the pattern above, and the difference is dangerous. The argument is a
filename or the key itself, and the whole implementation is short enough to read at once:

```go
func LoadHMAC(filenameOrRaw string) ([]byte, error) {
	if fileExists(filenameOrRaw) {
		// load contents from file.
		return ReadFile(filenameOrRaw)
	}

	// otherwise just cast the argument to []byte
	return []byte(filenameOrRaw), nil
}
```

Now read it against a typo. Two calls, one with the right path and one with the last two
letters transposed:

```go
key, err := jwt.LoadHMAC("_testfiles/hmac.key")
// err = <nil>, len(key) = 32
key, err = jwt.LoadHMAC("_testfiles/hmac.kye")
// err = <nil>, key = "_testfiles/hmac.kye"
```

The second call succeeds. Your HMAC secret is now the 19-byte string `_testfiles/hmac.kye`, built
entirely from characters an attacker can guess, and nothing reported a problem. Tokens sign,
tokens verify, tests pass. The only symptom is that anybody who knows your repository layout can
forge tokens. `MustLoadHMAC` is affected identically, because its panic can only fire on an error
and there is no error to fire on. A deployment that lost its mounted secret volume gets a
guessable key rather than a crash, the reverse of what a `Must` function is for.

**Do not pass a path to these functions.** If the key lives in a file, call `os.ReadFile`
yourself and check both the error and the length, rejecting anything under 32 bytes for
`HS256`. Keep `LoadHMAC` for what it is good at: a key supplied inline, from an environment
variable, where there is no file to be wrong about.

## The registry is a plain map

`Keys` is `map[string]*Key` with no mutex anywhere near it. Concurrent reads are fine, and
reading is all verification does. Concurrent writes are not, and neither is a write racing a
read. `Register` writes. The intended shape is to build the registry during startup, from a
`KeysConfiguration.Load` or a series of `Register` calls, and never touch it again. After that
every goroutine reads, and no lock is needed because nothing writes.

This is a real constraint and the package does not pretend otherwise. A mutex inside `Keys`
would put a lock acquisition on every verification in every program, to serve the minority who
change keys at runtime. Chapter 7 covers `KeySet`, which is the type for that minority: it
holds a `Keys` behind an atomic pointer, swaps the whole map on refresh, and satisfies the
same `HeaderValidator` interface, so it drops into the same call sites. If your keys come from
somebody else's JWKS endpoint, that is the type you want. For runtime registration against a
local registry, build a new `Keys`, populate it, and swap the whole value behind your own
`atomic.Pointer` or `sync.RWMutex`. Mutating the live map is the thing to avoid.

## A rotation in four steps

Here is the sequence that makes a key replacement invisible to traffic. The property being
exploited throughout is that verifiers can hold many keys while signers use exactly one.

**Step one: add the new key, verify only.** Deploy it to every service that verifies,
alongside the old one. Nothing signs with it yet. Wait until this deployment has reached every
verifier, because skipping the wait is the only way to break a rotation.

```go
keys := make(jwt.Keys)
keys.Register(jwt.ES256, "2024-01", &oldPublic, nil)
keys.Register(jwt.ES256, "2024-06", &newPublic, nil)
```

**Step two: start signing with the new key.** On the issuing service, change one string, so
that `keys.SignToken("2024-06", claims, jwt.MaxAge(15*time.Minute))` replaces the call naming
`2024-01`. From that instant new tokens name `2024-06`, and every verifier already knows it.
Tokens signed a second earlier name `2024-01` and still verify. There is no window.

**Step three: wait out the old tokens.** The longest-lived token signed with the old key
expires after its `MaxAge`. Wait longer than that. If you issue refresh tokens with a seven-day
lifetime under the same key, the wait is seven days, not fifteen minutes. Chapter 4 has the
arithmetic once skew allowances are involved.

**Step four: retire the old key.** Remove the registration and deploy. Tokens still naming
`2024-01` now fail with `ErrUnknownKid`, the correct answer for a credential signed by a key you
deliberately withdrew.

The whole sequence is three deploys of ordinary code. Nothing has to happen at the same instant,
each step is reversible until step four, and at no point is a valid token rejected. Practise it
on a schedule and it stays routine; leave it until a key leaks and you will be doing it for the
first time under pressure. A leak is a different problem, incidentally: you want the old key to
stop working immediately, so you run steps one, two and four back to back and accept that every
token signed with it is rejected. That is the outcome you were avoiding in the planned case, and
here it is the point.

## Summary

A single signing key cannot be replaced without a coordinated restart of everything holding it,
which is why keys that cannot be rotated usually are not. `kid` in the header names the key.
`Keys` maps those names to a `Key` holding an algorithm, key material, an optional `MaxAge` and
optional payload encryption. `Register` adds one and fills in the public half for HMAC, where
both halves are the same bytes. `SignToken` writes the identifier into the header; `VerifyToken`
and `Verify` read it back out.

`ValidateHeader` is where the safety comes from. The token selects a key by name, the algorithm
comes from the registry, and the header's `alg` is only ever allowed to agree with what you
registered. A rewritten `alg` is rejected with `ErrTokenAlg` before any signature is examined.

`KeysConfiguration` loads keys from JSON, YAML, TOML or INI. An unknown algorithm name is an
error naming the offending key, and `EncryptionKey` must be hex-encoded. `Configuration` goes
the other way, through `EncodePrivateKeyToPEM` and `EncodePublicKeyToPEM`. `LoadHMAC` and
`MustLoadHMAC` treat a path that does not exist as the key itself and return no error, so read
the file yourself.

`Keys` has no lock and is meant to be built at startup. For keys that change while the process
runs, use `KeySet`. A rotation is: publish the new key to verifiers, switch signing to it, wait
out the old tokens, remove the old key.

## Further Reading

- [RFC 7515 section 4.1.4](https://www.rfc-editor.org/rfc/rfc7515#section-4.1.4): the `kid`
  header parameter in full. It is four sentences long, and the one about the value being a
  case-sensitive string is the one people get wrong.
- [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518): the algorithm names this package matches
  against, and the key size requirements for each.
- [RFC 8017](https://www.rfc-editor.org/rfc/rfc8017): PKCS#1, the format `ParsePrivateKeyRSA`
  tries first. [RFC 5958](https://www.rfc-editor.org/rfc/rfc5958) is PKCS#8, the format it
  falls back to and the one Ed25519 private keys use here.
- [pkg.go.dev/crypto/x509](https://pkg.go.dev/crypto/x509): the parsers underneath every
  `Parse*` function. [pkg.go.dev/github.com/kataras/jwt](https://pkg.go.dev/github.com/kataras/jwt)
  is the generated reference for every signature quoted here.

---

**Next Chapter**: [JWKS](07-jwks.md) - Publishing your public keys as JSON, consuming somebody else's, and keeping the set current without a restart.
