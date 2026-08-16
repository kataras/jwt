# Chapter 11: Encrypting the Payload

Chapter 1 made the point once and this chapter is what follows from it: a JWT payload is
base64url text, and anyone holding the token can read it. Signing settles who wrote the
bytes and hides nothing from the person carrying them. This package can encrypt the payload
with AES-GCM before signing, which changes that, and this chapter covers how, what the
result is not, and why the answer is usually to store an identifier and keep the data on
your own side.

## Table of Contents

- [What signing does not do](#what-signing-does-not-do)
- [GCM and the two functions it returns](#gcm-and-the-two-functions-it-returns)
- [Signing and verifying an encrypted token](#signing-and-verifying-an-encrypted-token)
- [The order of operations](#the-order-of-operations)
- [Additional authenticated data](#additional-authenticated-data)
- [The nonce and the error you do not get](#the-nonce-and-the-error-you-do-not-get)
- [Encryption in the key registry](#encryption-in-the-key-registry)
- [This is not JWE](#this-is-not-jwe)
- [What it costs](#what-it-costs)
- [When to keep the data on the server instead](#when-to-keep-the-data-on-the-server-instead)
- [Summary](#summary)
- [Further Reading](#further-reading)

## What signing does not do

A signature answers one question: did a holder of this key produce these exact bytes. It says
nothing about who may read them. The payload of an ordinary token is public to every party
that touches it, which is the client, the browser extension the client installed, whatever
proxy the request crosses, and every log line the token lands in.

Encryption changes the audience. With an encrypted payload the claims are readable only by a
party holding the AES key, so the client can present the token and the token still verifies,
but the client cannot see what is inside. That is the whole feature, and it is narrower than
it sounds: the header stays public, the token's shape stays public, and the signing key still
governs who can mint one. The case where this earns its place is a token that has to carry something the holder should
not read and that you cannot look up server-side: a tenant-internal identifier that leaks your
customer count, a routing hint that names an internal service, an entitlement flag whose name
tells the holder which feature to go looking for. The last section of this chapter argues that
most of what people reach for encryption to solve is solved better by leaving it out.

## GCM and the two functions it returns

```go
func GCM(key, additionalData []byte) (encrypt, decrypt InjectFunc, err error)
type InjectFunc func(plainPayload []byte) ([]byte, error)
```

`GCM` builds an AES cipher in Galois/Counter Mode and returns the two halves of it as
`InjectFunc` values. `InjectFunc` is the package's general hook for transforming a payload
between marshaling and encoding; encryption is one use of it, and compression and redaction
are others.

The key must be 16, 24 or 32 bytes, selecting AES-128, AES-192 or AES-256. Anything else
comes back from `crypto/aes` as `crypto/aes: invalid key size 20`, which you should treat as
a startup failure. There is no attack here that distinguishes AES-128 from AES-256, so use 32
bytes because it costs nothing on any processor with AES instructions, and generate it from a
random source rather than a passphrase:

```go
encKey := jwt.MustGenerateRandom(32) // AES-256
sigKey := jwt.MustGenerateRandom(32) // HMAC
encrypt, decrypt, err := jwt.GCM(encKey, nil)
```

Keep the two keys separate. The signing key goes wherever a token has to be verified, and the
encryption key goes only where the payload has to be read; those are different sets, and if
one value serves both jobs then every verifier can read every payload and the encryption
bought you nothing.

## Signing and verifying an encrypted token

Four functions carry the `encrypt` and `decrypt` values through:

```go
func SignEncrypted(alg Alg, key PrivateKey, encrypt InjectFunc, claims any, opts ...SignOption) ([]byte, error)
func SignEncryptedWithHeader(alg Alg, key PrivateKey, encrypt InjectFunc, claims any, customHeader any, opts ...SignOption) ([]byte, error)
func VerifyEncrypted(alg Alg, key PublicKey, decrypt InjectFunc, token []byte, validators ...TokenValidator) (*VerifiedToken, error)
func VerifyEncryptedWithHeaderValidator(alg Alg, key PublicKey, decrypt InjectFunc, token []byte, headerValidator HeaderValidator, validators ...TokenValidator) (*VerifiedToken, error)
```

Apart from the extra parameter they behave exactly like `Sign`, `SignWithHeader`, `Verify`
and `VerifyWithHeaderValidator`. Sign options apply the same way, validators run the same way,
and `VerifiedToken.Payload` holds the decrypted JSON rather than the ciphertext.

```go
claims := jwt.Map{"user_id": "12345", "role": "admin"}
token, err := jwt.SignEncrypted(jwt.HS256, sigKey, encrypt, claims, jwt.MaxAge(15*time.Minute))
verifiedToken, err := jwt.VerifyEncrypted(jwt.HS256, sigKey, decrypt, token)
```

The result still looks like a JWT, because it is one. Its header decodes to the usual
`{"alg":"HS256","typ":"JWT"}`, and its middle segment decodes to 96 bytes that are neither
JSON nor text.

**A token verified without its decrypt function does not fail cleanly.** The signature checks
out, because the signature covers the ciphertext. What fails is the claims parse, and the
error is the internal "payload is not JSON" one that the `Plain` validator exists to
suppress. Pass `jwt.Plain` and verification succeeds with `Payload` holding raw ciphertext
and `StandardClaims` entirely empty, expiry included. That combination is a way to accept an
expired token without noticing.

## The order of operations

Encrypt, then sign. Verify, then decrypt.

On the way out, `signToken` in `sign.go` marshals the claims to JSON, hands the JSON to
`encrypt`, and only then calls `encodeToken`, which base64url encodes the result and signs
the header and payload together:

```go
	if encrypt != nil {
		payload, err = encrypt(payload)
		if err != nil {
			return nil, err
		}
	}
	return encodeToken(alg, key, payload, customHeader)
```

On the way in there are two places the decryption can happen. `decodeToken` in `token.go` is
the first. Its signature check, `alg.Verify(key, headerPayload, signatureDecoded)`, sits a few
lines above what follows, so the payload is only decoded and decrypted once the signature has
already held:

```go
	payload, err = Base64Decode(payload)
	if err != nil {
		return nil, nil, nil, err
	}
	if decrypt != nil {
		payload, err = decrypt(payload)
		if err != nil {
			return nil, nil, nil, err
		}
	}
```

That is the path the key registry takes, because `Keys.ValidateHeader` returns the matched
key's `Decrypt` as its third result. `verifyToken` in `verify.go` is the second: it calls
`decodeToken`, and then applies the `decrypt` you passed to `VerifyEncrypted` before parsing
the standard claims.

Encrypt-then-sign is the order that makes the signature cover the ciphertext. A modified
ciphertext is rejected by the cheap signature check before the AES-GCM authentication tag is
ever examined, and an attacker cannot move a payload between two tokens, because the
signature is over these bytes in this token.

The two decryption sites are also a hazard worth naming. Call
`VerifyEncryptedWithHeaderValidator` with both an explicit `decrypt` and a header validator
that returns one, and the payload is decrypted twice: the second call fails with `ErrDecrypt`
on plaintext that is perfectly correct. Pick one. With the registry, pass `nil` for `decrypt`
and let `ValidateHeader` supply it.

## Additional authenticated data

The second argument to `GCM` is additional authenticated data, and it differs from the
plaintext in one important respect: it is covered by the authentication tag, it is not
encrypted, and it is not stored in the ciphertext at all. Both sides supply the same bytes
independently, and if they differ by one byte then `Open` fails with `ErrDecrypt`. That makes
it a binding rather than a payload: it ties a ciphertext to a context.

Suppose one AES key serves several tenants, and a payload encrypted for tenant `acme` should
be undecryptable in a request routed to tenant `globex`. Build the pair per tenant with
`jwt.GCM(encKey, []byte("tenant=acme"))`, and a token produced by the `acme` encrypt function
fails against a decrypt function built from `tenant=globex`.

The constraint that decides whether this is usable is that the verifying side has to
reconstruct the same bytes without reading the payload, since the payload is what it is
trying to open. So the additional data can only come from what is visible outside the
ciphertext: a header field, a hostname, a path segment, a deployment constant. If the tenant
name appears only inside the encrypted claims, you cannot use it. Passing `nil`, which is
what the key registry does, gives plain authenticated encryption with no context binding.

## The nonce and the error you do not get

GCM needs a nonce that is never reused with the same key. The encrypt function generates 12
random bytes per call and prepends them, so the segment on the wire is nonce, then ciphertext,
then a 16-byte tag:

```go
ciphertext := gcm.Seal(nonce, nonce, payload, additionalData)
```

Decryption slices those 12 bytes back off. A ciphertext shorter than the nonce cannot carry
one, and slicing it would panic, so the length is checked first:

```go
if len(ciphertext) < gcm.NonceSize() {
	return nil, ErrDecrypt
}
```

Note what that returns: not `ErrTooShort`, not a wrapped `io.ErrUnexpectedEOF`, but the same
`ErrDecrypt` a failed authentication tag returns. A distinct error there would tell an
attacker the difference between a truncated payload and a forged one, which is the difference
between "you cut this token short" and "your key is wrong". One distinguishable error is one
bit of feedback per attempt, and that is how padding oracles are built.

In the ordinary path an attacker never reaches the decryption step, because the signature
check comes first. The uniform error matters where that is not true: a service holding the
signing key but not the encryption key can mint tokens whose ciphertext it chooses, and the
`InjectFunc` values can be called outside this package entirely.

One limit on the random nonce is worth stating in numbers. Twelve random bytes give a 96-bit
nonce, and collision probability grows with the square of the message count, so NIST SP
800-38D puts the ceiling for random nonces at 2^32 invocations under one key. Four billion
tokens is not a limit you meet by accident, but it is a reason to rotate the encryption key
rather than treat it as permanent.

## Encryption in the key registry

`Key` carries the two functions alongside the key material:

```go
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

When they are set, `Keys.SignToken` and `Keys.Verify` use them without being asked:
`SignToken` calls `SignEncryptedWithHeader` with `k.Encrypt`, and `ValidateHeader` hands
`k.Decrypt` back to `decodeToken`. From the caller's side the code is identical to the
unencrypted case, which is the argument for configuring encryption here rather than threading
`InjectFunc` values through your own call sites.

In a configuration file the field is `KeyConfiguration.EncryptionKey`, a hex string.
`KeysConfiguration.Load` runs it through `hex.DecodeString`, calls `GCM` with a `nil`
additional data argument, and stores both halves on the `Key`. Hex rather than base64 because
a 32-byte key is 64 hex characters that survive being pasted into YAML, TOML and INI without
quoting rules getting involved. The decoded length still has to be 16, 24 or 32 bytes, and a
20-byte value fails at load time rather than at the first signature. Note the `nil`: there is
no way to set additional authenticated data through configuration.

Two restrictions follow from a key having encryption attached. `Key.Configuration` refuses to
export it, because the `InjectFunc` values are closures and there is nothing to serialize.
And `Keys.EnrichToken` refuses to enrich a token signed with such a key, because enrichment
merges claims into a plain payload and the payload it has is ciphertext.

## This is not JWE

RFC 7516 defines JSON Web Encryption: a five-segment compact serialization, a content
encryption key wrapped per recipient, and `alg` and `enc` header fields naming the key
management and content encryption algorithms. This package implements none of it. `token_jwe.go`
exists and contains no code, only a comment beginning "TODO? Add support for JWS and JWE.
Currently, Out of this package's scope". What you get is a three-segment JWS whose payload
segment happens to be ciphertext, and four consequences follow.

**Nothing else can read it.** A library expecting RFC 7516 will not decrypt it, and a library
expecting a plain JWT will verify the signature and then fail to parse the payload. Both ends
of every exchange have to be this package, or code written against it.

**The header is not encrypted.** `alg`, `typ` and any `kid` you set are visible, so tenant or
environment identifiers placed in a custom header are public.

**The standard claims are inside the ciphertext.** `exp`, `iss` and `aud` are encrypted along
with everything else, so nothing without the AES key can check them. An API gateway that
today rejects expired tokens at the edge stops being able to.

**There is one recipient.** JWE wraps a content encryption key per recipient so several
parties can decrypt with different private keys. Here there is one symmetric key, so every
party that can decrypt can also encrypt, and therefore forge a payload for anyone else who
shares it.

## What it costs

The token gets longer. Here is the same claim set both ways, measured rather than estimated:

| | Payload bytes | Token bytes |
| --- | --- | --- |
| `Sign` | 68 | 172 |
| `SignEncrypted` | 96 | 209 |

The 28-byte payload difference is fixed, 12 bytes of nonce plus a 16-byte tag, regardless of
how large the claims are, and base64url turns 28 raw bytes into 37 characters of token. For a
cookie with a 4 KB budget that is noise. For a header on every request of a chatty API it is
a number you can multiply out.

The bigger cost is key management. You now have two key lifecycles, and rotating either one
means a window where tokens signed or encrypted under the old key are still in flight, which
Chapter 6 covers for signing keys and which is the same problem again here. Symmetric
encryption also has no equivalent of a public key, so with one key doing both jobs you cannot
give a service the ability to verify without the ability to mint.

There is also a failure mode that only appears in production. Misconfigure the encryption key
on one instance out of ten and that instance verifies signatures correctly, then fails every
claims parse. The error is `ErrDecrypt`, `Classify` reports `KindInvalid`, the log says the
token was invalid, and nothing points at the encryption key.

## When to keep the data on the server instead

The usual answer is to put an identifier in the token and store the data behind it. A `sub`
claim and a lookup gets you a payload with nothing to hide and no second key lifecycle;
revocation that works, since changing a row takes effect on the next request; data you can
change, rather than a role the user keeps for up to fifteen minutes after you remove it; and
a verifier that can check `exp` and `aud` without being trusted with the contents.

The cost is one round trip to a store you almost certainly already query for the request.
Tokens carry claims to avoid that round trip, and if a claim is sensitive enough to encrypt,
the round trip is usually the right trade.

Reach for encryption when the lookup is genuinely unavailable: a stateless service with no
data store, a token that has to survive an offline period, or a payload that must cross a
party you do not control and cannot be reduced to an opaque identifier. Those exist. They are
rarer than the number of systems encrypting JWT payloads suggests.

## Summary

`GCM(key, additionalData)` returns an encrypt and a decrypt `InjectFunc` built on AES-GCM,
with a key of 16, 24 or 32 bytes. `SignEncrypted` and `VerifyEncrypted` carry those through
the ordinary signing and verification paths, and the `WithHeader` variants do the same
alongside custom headers.

The order is encrypt then sign, and verify then decrypt. The encryption happens in `signToken`
before `encodeToken`; the decryption happens either in `decodeToken`, when a header validator
supplies the function, or in `verifyToken`, when you pass it yourself. Supplying it both ways
decrypts twice and fails.

Additional authenticated data is authenticated but not encrypted and not transmitted, so both
sides must derive it identically. A 12-byte random nonce is prepended to each ciphertext, and
a ciphertext too short to hold one returns `ErrDecrypt` rather than a distinct error, so
nothing distinguishes a truncated payload from a forged one. The registry does all of this
through `Key.Encrypt`, `Key.Decrypt` and a hex-encoded `KeyConfiguration.EncryptionKey`.

None of it is JWE. It does not interoperate, the header stays public, the token grows by 37
characters, and the AES key becomes a second key management problem beside the signing one.
Before taking that on, check whether an identifier in the token and the data on your server
answers the same question. It usually does.

## Further Reading

- [RFC 7516: JSON Web Encryption](https://www.rfc-editor.org/rfc/rfc7516): the standard this
  chapter is not. Section 3 shows the five-segment serialization.
- [NIST SP 800-38D](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf):
  the GCM specification, the nonce rules, and the 2^32 limit on random nonces under one key.
- [crypto/cipher.NewGCM](https://pkg.go.dev/crypto/cipher#NewGCM): what `Seal` and `Open` do
  with the destination slice.
- [RFC 5116](https://www.rfc-editor.org/rfc/rfc5116): authenticated encryption with associated
  data as an interface, where the additional data argument comes from.

---

**Next Chapter**: [Sharp Edges](12-sharp-edges.md) - The bugs this package has shipped, the ones still in the API, and the defaults that surprise people.
