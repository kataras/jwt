# JWT

[![build status](https://img.shields.io/github/actions/workflow/status/kataras/jwt/ci.yml?style=for-the-badge)](https://github.com/kataras/jwt/actions) [![report card](https://img.shields.io/badge/report%20card-a%2B-ff3333.svg?style=for-the-badge)](https://goreportcard.com/report/github.com/kataras/jwt) [![godocs](https://img.shields.io/badge/go-%20docs-488AC7.svg?style=for-the-badge)](https://pkg.go.dev/github.com/kataras/jwt)

<img align="left" width="72" height="72" src="brand/export/jwt-mark-256.png" alt="">

Zero-dependency, lightweight and fast [JWT](https://jwt.io/#libraries-io) and JWKS implementation written in [Go](https://go.dev/dl/). It was designed with security, performance and simplicity in mind, and it protects your tokens from [critical vulnerabilities found in other libraries](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries).

<br clear="left"/>

[![Time per operation against golang-jwt and go-jose, lower is better](_benchmarks/benchmarks.svg)](_benchmarks)

Please [star](https://github.com/kataras/jwt/stargazers) this open source project to attract more developers so that together we can improve it even more!

> **Ask AI about jwt.** Google's free [Code Wiki for jwt](https://codewiki.google/github.com/kataras/jwt) is generated from this repository and stays in sync with it, commit by commit. Browse the architecture with diagrams, or ask its chat plain-language questions about the codebase and get answers grounded in the actual source. For an assistant that writes jwt code with you, [Plexon AI](https://plexon.ai), the desktop assistant built by the author of jwt, ships the [jwt skill](skill/) built in; see [AI Tools for jwt](#ai-tools-for-jwt) below.

## The Book

A fourteen chapter book on this library lives in [`book/`](book/), rendered to one
self-contained HTML file and printed to PDF.

It is not a reference. `go doc` is the reference, and it is generated from the source so it
cannot drift. The book is the part `go doc` cannot give you: the order to do things in, why
a default is what it is, and the failure that made somebody choose it. Chapter 12 is the
honest list of this library's sharp edges.

**[Read the PDF](book/output/jwt-book.pdf)** (121 pages), or start with the
[preface](book/README.md) and read the chapters as Markdown:

| | Chapter | What it covers |
| --- | --- | --- |
| | [Preface](book/README.md) | Who the book is for, and how its code was checked |
| 1 | [What a Token Is](book/01-what-a-token-is.md) | The three segments, base64url, and what a signature actually proves |
| 2 | [Signing and Verifying](book/02-signing-and-verifying.md) | `Sign` and `Verify`, and why the algorithm is an argument |
| 3 | [Claims](book/03-claims.md) | Standard and custom claims, sign options, `Merge` |
| 4 | [Expiry and Time](book/04-expiry-and-time.md) | `exp`, `nbf`, `iat`, `MaxAge`, and clock skew |
| 5 | [Choosing an Algorithm](book/05-choosing-an-algorithm.md) | HMAC, RSA, RSA-PSS, ECDSA, EdDSA, and who can mint tokens |
| 6 | [Keys and Rotation](book/06-keys-and-rotation.md) | The `kid` registry, key configuration, and a worked rotation |
| 7 | [JWKS](book/07-jwks.md) | Publishing a key set, consuming one, and `KeySet` |
| 8 | [Validators](book/08-validators.md) | The chaining rule, `Expected`, and writing your own |
| 9 | [Revoking Tokens](book/09-revoking-tokens.md) | Blocklists, `jti`, and a distributed backend |
| 10 | [Tokens over HTTP](book/10-tokens-over-http.md) | Extraction, middleware, and access and refresh pairs |
| 11 | [Encrypting the Payload](book/11-encrypting-the-payload.md) | AES-GCM, and when the answer is not encryption |
| 12 | [Sharp Edges](book/12-sharp-edges.md) | The surprising defaults and the fast paths that carry a hazard |
| 13 | [Testing](book/13-testing.md) | Controlling the clock, faking the network, golden tests |
| 14 | [Performance](book/14-performance.md) | Where the time goes, and what buys the speed |
| | [Epilogue](book/epilogue.md) | The pattern behind most of the defects found here |

Rebuild it with `cd book && go run .`, or `go run . -format html` for a version that needs
no browser. See [book/README_EBOOK.md](book/README_EBOOK.md).

## Installation

The only requirement is the [Go Programming Language](https://go.dev/dl/).

```sh
$ go get github.com/kataras/jwt@latest
```

Import as `import "github.com/kataras/jwt"` and use it as `jwt.XXX`.

## Table of Contents

* [Getting started](#getting-started)
* [Sign a Token](#sign-a-token)
    * [The standard Claims](#the-standard-jwt-claims)
* [Verify a Token](#verify-a-token)
    * [Decode custom Claims](#decode-custom-claims)
    * [JSON Required Tag](#json-required-tag)
        * [Standard Claims Validators](#standard-claims-validators)
* [Block a Token](#block-a-token)
* [Token Pair](#token-pair)
* [JSON Web Algorithms](#json-web-algorithms)
    * [Choose the right Algorithm](#choose-the-right-algorithm)
    * [Use your own Algorithm](#use-your-own-algorithm)
    * [Generate keys](#generate-keys)
    * [Load and parse keys](#load-and-parse-keys)
* [Encryption](#encryption)
* [Benchmarks](_benchmarks)
* [Examples](_examples)
    * [Amazon AWS Cognito Verification](_examples/aws-cognito-verify/main.go) **NEW**
    * [Basic](_examples/basic/main.go)
    * [Custom Header](_examples/custom-header/main.go)
    * [Multiple Key IDs](_examples/multiple-kids/main.go)
    * [HTTP Middleware](_examples/middleware/main.go)
    * [Blocklist](_examples/blocklist/main.go)
    * [JSON Required Tag](_examples/required/main.go)
    * [Custom Validations](_examples/custom-validations/main.go)
    * [Advanced: Iris Middleware](https://github.com/kataras/iris/tree/master/middleware/jwt)
    * [Advanced: Redis Blocklist](https://github.com/kataras/iris/tree/master/middleware/jwt/blocklist/redis/blocklist.go)
* [AI Tools](#ai-tools-for-jwt)
* [References](#references)
* [License](#license)

## Getting Started

Sign and generate a token with the `Sign` method, returns the token in compact form. Optionally set an expiration, if `"exp"` is missing from the payload use the `jwt.MaxAge` helper. Verify the token with the `Verify` method, returns a `VerifiedToken` value. Decode the custom claims with the `VerifiedToken.Claims` method. Extremely easy!

```go
package main

import (
	"time"

	"github.com/kataras/jwt"
)

// Keep it secret.
var sharedKey = []byte("sercrethatmaycontainch@r$32chars")

type FooClaims struct {
	Foo string `json:"foo"`
}

func main() {
	// Generate a token which expires at 15 minutes from now:
	myClaims := FooClaims{
		Foo: "bar",
	} // can be a map too.

	token, err := jwt.Sign(jwt.HS256, sharedKey, myClaims, jwt.MaxAge(15*time.Minute))
	if err != nil {
		panic(err)
	}

	// Verify and extract claims from a token:
	verifiedToken, err := jwt.Verify(jwt.HS256, sharedKey, token)
	if err != nil {
		panic(err)
	}

	var claims FooClaims
	err = verifiedToken.Claims(&claims)
	if err != nil {
		panic(err)
	}

	print(claims.Foo)
}
```

The package contains comments on each one of its exported functions, structures and variables, therefore, for a more detailed technical documentation please refer to [godocs](https://pkg.go.dev/github.com/kataras/jwt).

## Sign a Token

Signing and Verifying a token is an extremely easy process.

Signing a Token is done through the `Sign` package-level function.

```go
var sharedKey = []byte("sercrethatmaycontainch@r$32chars")
```

```go
type User struct {
    Username string `json:"username"`
}
```

```go
userClaims := User {
    Username:"kataras",
}

token, err := jwt.Sign(jwt.HS256, sharedkey, userClaims, jwt.MaxAge(15 *time.Minute))
```

`[1]` The first argument is the signing [algorithm](#choose-the-right-algorithm) to create the signature part. 
`[2]` The second argument is the private key (or shared key, when symmetric algorithm was chosen) will be used to create the signature. 
`[3]` The third argument is the JWT claims. The JWT claims is the payload part and it depends on your application's requirements, there you can set custom fields (and expiration) that you can extract to another request of the same authorized client later on. Note that the claims can be **any Go type**, including custom `struct`, `map` and raw `[]byte`. `[4]` The last variadic argument is a type of `SignOption` (`MaxAge` function and `Claims` struct are both valid sign options), can be used to merge custom claims with the standard ones.  `Returns` the encoded token, ready to be sent and stored to the client.

The `jwt.MaxAge` is a helper which sets the `jwt.Claims.Expiry` and `jwt.Claims.IssuedAt` for you.

Example Code to manually set all claims using a standard `map`:

```go
now := time.Now()
claims := map[string]any{
    "iat": now.Unix(),
    "exp": now.Add(15 * time.Minute).Unix(),
    "foo": "bar",
}

token, err := jwt.Sign(jwt.HS256, sharedKey, claims)
```

> See `SignWithHeader` too.

Example Code to merge map claims with standard claims:

```go
customClaims := jwt.Map{"foo": "bar"}

now := time.Now()
standardClaims := jwt.Claims{
    Expiry:   now.Add(15 * time.Minute).Unix(),
    IssuedAt: now.Unix(), 
    Issuer:   "my-app",
}

token, err := jwt.Sign(jwt.HS256, sharedKey, customClaims, standardClaims)
```

> The `jwt.Map` is just a _type alias_, a _shortcut_, of `map[string]any`.

At all cases, the `iat(IssuedAt)` and `exp(Expiry/MaxAge)` (and `nbf(NotBefore)`) values will be validated automatically on the [`Verify`](#verify-a-token) method.

Example Code to Sign & Verify a non-JSON payload:

```go
token, err := jwt.Sign(jwt.HS256, sharedkey, []byte("raw payload - no json here"))
```

> If the payload is not a JSON one, then merging with standard claims is not possible, therefore options like `jwt.MaxAge` are not available.

```go
verifiedToken, err := jwt.Verify(jwt.HS256, sharedKey, token, jwt.Plain)
// verifiedToken.Payload == raw contents
```

> Again, if the received payload is not a JSON one, options like `jwt.Expected` or `jwt.NewBlocklist` are not available as well.

### The standard JWT Claims

The `jwt.Claims` shown above looks like this:

```go
type Claims struct {
    // The opposite of the exp claim. A number representing a specific
    // date and time in the format “seconds since epoch” as defined by POSIX.
    // This claim sets the exact moment from which this JWT is considered valid.
    // The current time (see `Clock` package-level variable)
    // must be equal to or later than this date and time.
    NotBefore int64 `json:"nbf,omitempty"`

    // A number representing a specific date and time (in the same
    // format as exp and nbf) at which this JWT was issued.
    IssuedAt int64 `json:"iat,omitempty"`

    // A number representing a specific date and time in the
    // format “seconds since epoch” as defined by POSIX6.
    // This claims sets the exact moment from which
    // this JWT is considered invalid. This implementation
    // allow for a certain skew between clocks
    // (by considering this JWT to be valid for a few minutes
    // after the expiration date, modify the `Clock` variable).
    Expiry int64 `json:"exp,omitempty"`

    // A string representing a unique identifier for this JWT.
    // This claim may be used to differentiate JWTs with
    // other similar content (preventing replays, for instance).
    ID string `json:"jti,omitempty"`

    // A string or URI that uniquely identifies the party
    // that issued the JWT.
    // Its interpretation is application specific
    // (there is no central authority managing issuers).
    Issuer string `json:"iss,omitempty"`

    // A string or URI that uniquely identifies the party
    // that this JWT carries information about.
    // In other words, the claims contained in this JWT
    // are statements about this party.
    // The JWT spec specifies that this claim must be unique in
    // the context of the issuer or,
    // in cases where that is not possible, globally unique. Handling of
    // this claim is application specific.
    Subject string `json:"sub,omitempty"`

    // Either a single string or URI or an array of such
    // values that uniquely identify the intended recipients of this JWT.
    // In other words, when this claim is present, the party reading
    // the data in this JWT must find itself in the aud claim or
    // disregard the data contained in the JWT.
    // As in the case of the iss and sub claims, this claim is
    // application specific.
    Audience []string `json:"aud,omitempty"`
}
```

## Verify a Token

Verifying a Token is done through the `Verify` package-level function.

```go
verifiedToken, err := jwt.Verify(jwt.HS256, sharedKey, token)
```

> See `VerifyWithHeaderValidator` too.

The `VerifiedToken` carries the token decoded information: 

```go
type VerifiedToken struct {
    Token          []byte // The original token.
    Header         []byte // The header (decoded) part.
    Payload        []byte // The payload (decoded) part.
    Signature      []byte // The signature (decoded) part.
    StandardClaims Claims // Standard claims extracted from the payload.
}
```

### Decode custom Claims

To extract any custom claims, given on the `Sign` method, we use the result of the `Verify` method, which is a `VerifiedToken` pointer. This VerifiedToken has a single method, the `Claims(dest any) error` one, which can be used to decode the claims (payload part) to a value of our choice. Again, that value can be a `map` or any `struct`.

```go
var claims = struct {
    Foo string `json:"foo"`
}{} // or a map.

err := verifiedToken.Claims(&claims)
```

By default expiration set and validation is done through `time.Now()`. You can change that behavior through the `jwt.Clock` variable, e.g. 

```go
jwt.Clock = time.Now().UTC
```

### JSON required tag

When more than one token with different claims can be generated based on the same algorithm and key, somehow you need to invalidate a token if its payload misses one or more fields of your custom claims structure. Using the same algorithm and key for two different kinds of token is not recommended, but you can do it, and to avoid invalid claims to be retrieved by your application's route handler this package offers the JSON **`,required`** tag field. It checks if the claims extracted from the token's payload meet the requirements of the expected **struct** value.

The first thing we have to do is to change the default `jwt.Unmarshal` variable to the `jwt.UnmarshalWithRequired`, once at the init of the application:

```go
func init() {
    jwt.Unmarshal = jwt.UnmarshalWithRequired
}
```

The second thing, is to add the `,required` json tag field to our struct, e.g.

```go
type userClaims struct {
    Username string `json:"username,required"`
}
```

That is all. The `VerifiedToken.Claims` method returns an `ErrMissingKey` if the given token's payload does not meet the requirements.

### Standard Claims Validators

A more performance-wise alternative to `json:"XXX,required"` is to add validators to check the standard claims values through a `TokenValidator` or to check the custom claims manually after the `VerifiedToken.Claims` method.

The `TokenValidator` interface looks like this:

```go
type TokenValidator interface {
	ValidateToken(token []byte, standardClaims Claims, err error) error
}
```

The last argument of `Verify`/`VerifyEncrypted` optionally accepts one or more `TokenValidator`. Available builtin validators:
- `Leeway(time.Duration)`
- `Expected`
- `Blocklist`

The `Leeway` adds validation for a leeway expiration time.
If the token was not expired then a comparison between
this "leeway" and the token's "exp" one is expected to pass instead (now+leeway > exp).
Example of use case: disallow tokens that are going to be expired in 3 seconds from now,
this is useful to make sure that the token is valid when the when the user fires a database call:

```go
verifiedToken, err := jwt.Verify(jwt.HS256, sharedKey, token, jwt.Leeway(3*time.Second))
if err != nil {
   // err == jwt.ErrExpired
}
```

The `Expected` performs simple checks between standard claims values. For example, disallow tokens that their `"iss"` claim does not match the `"my-app"` value:

```go
verifiedToken, err := jwt.Verify(jwt.HS256, sharedKey, token, jwt.Expected{
    Issuer: "my-app",
})
if err != nil {
    // errors.Is(jwt.ErrExpected, err)
}
```

## Block a Token

When a user logs out, the client app should delete the token from its memory. This would stop the client from being able to make authorized requests. But if the token is still valid and somebody else has access to it, the token could still be used. Therefore, a server-side invalidation is indeed useful for cases like that. When the server receives a logout request, take the token from the request and store it to the `Blocklist` through its `InvalidateToken` method. For each authorized request the `jwt.Verify` will check the `Blocklist` to see if the token has been invalidated. To keep the search space small, the expired tokens are automatically removed from the Blocklist's in-memory storage.

Enable blocklist by following the three simple steps below.

**1.** Initialize a blocklist instance, clean unused and expired tokens every 1 hour.
```go
blocklist := jwt.NewBlocklist(1 * time.Hour)
```
**2.** Add the `blocklist` instance to the `jwt.Verify`'s last argument, to disallow blocked entries.
```go
verifiedToken, err := jwt.Verify(jwt.HS256, sharedKey, token, blocklist)
// [err == jwt.ErrBlocked when the token is valid but was blocked]
```
**3.** Call the `blocklist.InvalidateToken` whenever you want to block a specific authorized token. The method accepts the token and the expiration time should be removed from the blocklist.
```go
blocklist.InvalidateToken(verifiedToken.Token, verifiedToken.StandardClaims)
```

By default the unique identifier is retrieved through the `"jti"` (`Claims{ID}`) and when that is empty the raw token is used as the map key instead. To change that behavior simply modify the `blocklist.GetKey` field before the `InvalidateToken` method.

## Token Pair

A Token pair helps us to handle refresh tokens. It is a structure which holds both Access Token and Refresh Token. Refresh Token is long-live and access token is short-live. The server sends both of them at the first contact. The client uses the access token to access an API. The client can renew its access token by hitting a special REST endpoint to the server. The server verifies the refresh token and **optionally** the access token which should return `ErrExpired`, if it has expired or will expire within some window from now (`Leeway`), and renders a new generated token to the client. There are countless resources online and different kind of methods for using a refresh token. This `jwt` package offers just a helper structure which holds both the access and refresh tokens and it is ready to be sent to and received from a client.

```go
type ClientClaims struct {
    ClientID string `json:"client_id"`
}
```

```go
accessClaims := ClientClaims{ClientID: "client-id"}
accessToken, err := jwt.Sign(alg, secret, accessClaims, jwt.MaxAge(10*time.Minute))
if err != nil {
    // [handle error...]
}

refreshClaims := jwt.Claims{Subject: "client", Issuer: "my-app"}
refreshToken, err := jwt.Sign(alg, secret, refreshClaims, jwt.MaxAge(time.Hour))
if err != nil {
    // [handle error...]
}

tokenPair := jwt.NewTokenPair(accessToken, refreshToken)
```

The `tokenPair` is JSON-compatible value, you can render it to a client and read it from a client HTTP request.

## JSON Web Algorithms

There are several types of signing algorithms available according to the JWA(JSON Web Algorithms) spec. The specification requires a single algorithm to be supported by all conforming implementations:

- HMAC using SHA-256, called `HS256` in the JWA spec.

The specification also defines a series of recommended algorithms:

- RSASSA PKCS1 v1.5 using SHA-256, called `RS256` in the JWA spec.
- ECDSA using P-256 and SHA-256, called `ES256` in the JWA spec.

The implementation supports **all** of the above plus `RSA-PSS` and the new `Ed25519`. Navigate to the [alg.go](alg.go) source file for details. In-short:

|Algorithm              | `jwt.Sign`                               | `jwt.Verify`        |
|-----------------------|------------------------------------------|---------------------|
| [jwt.HS256 / HS384 / HS512](alg.go) | []byte             | The same sign key   |
| [jwt.RS256 / RS384 / RS512](alg.go) | [*rsa.PrivateKey](https://golang.org/pkg/crypto/rsa/#PrivateKey)    | [*rsa.PublicKey](https://golang.org/pkg/crypto/rsa/#PublicKey)    |
| [jwt.PS256 / PS384 / PS512](alg.go) | [*rsa.PrivateKey](https://golang.org/pkg/crypto/rsa/#PrivateKey)  | [*rsa.PublicKey](https://golang.org/pkg/crypto/rsa/#PublicKey)  |
| [jwt.ES256 / ES384 / ES512](alg.go) | [*ecdsa.PrivateKey](https://golang.org/pkg/crypto/ecdsa/#PrivateKey)  | [*ecdsa.PublicKey](https://golang.org/pkg/crypto/ecdsa/#PublicKey)  |
| [jwt.EdDSA](alg.go)             | [ed25519.PrivateKey](https://golang.org/pkg/crypto/ed25519/#PrivateKey) | [ed25519.PublicKey](https://golang.org/pkg/crypto/ed25519/#PublicKey) |

### Choose the right Algorithm

Choosing the best algorithm for your application needs is up to you, however, my recommendations follows.

- Already work with RSA public and private keys? Choose RSA(RS256/RS384/RS512/PS256/PS384/PS512) (length of produced token characters is bigger).
- If you need the separation between public and private key, choose ECDSA(ES256/ES384/ES512) or EdDSA. ECDSA and EdDSA produce smaller tokens than RSA.
- If you need performance and well-tested algorithm, choose HMAC(HS256/HS384/HS512) - **the most common method**.

The basic difference between symmetric and an asymmetric algorithm
is that symmetric uses one shared key for both signing and verifying a token,
and the asymmetric uses private key for signing and a public key for verifying.
In general, asymmetric data is more secure because it uses different keys
for the signing and verifying process, but it is slower than the symmetric ones.

### Use your own Algorithm

If you ever need to use your own JSON Web algorithm, just implement the [Alg](alg.go) interface. Pass it to `jwt.Sign` and `jwt.Verify` and you are ready to go.

### Generate keys

Keys can be generated via [OpenSSL](https://www.openssl.org) or through Go's standard library.

```go
import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/elliptic"
    "crypto/ed25519"
)
```

```go
// Generate HMAC
sharedKey := make([]byte, 32)
_, _ = rand.Read(sharedKey)

// Generate RSA
bitSize := 2048
privateKey, _ := rsa.GenerateKey(rand.Reader, bitSize)
publicKey := &privateKey.PublicKey

// Generace ECDSA
c := elliptic.P256()
privateKey, _ := ecdsa.GenerateKey(c, rand.Reader)
publicKey := &privateKey.PublicKey

// Generate EdDSA
publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
```

> Converting keys to PEM files is kind of easy task using the Go Programming Language, take a quick look at the [PEM example for ed25519](_examples/generate-ed25519/main.go).

### Load and Parse keys

This package contains all the helpers you need to load and parse PEM-formatted keys.

All the available helpers:

```go
// HMAC
MustLoadHMAC(filenameOrRaw string) []byte
```

```go
// RSA
MustLoadRSA(privFile, pubFile string) (*rsa.PrivateKey, *rsa.PublicKey)
LoadPrivateKeyRSA(filename string) (*rsa.PrivateKey, error)
LoadPublicKeyRSA(filename string) (*rsa.PublicKey, error) 
ParsePrivateKeyRSA(key []byte) (*rsa.PrivateKey, error)
ParsePublicKeyRSA(key []byte) (*rsa.PublicKey, error)
```

```go
// ECDSA
MustLoadECDSA(privFile, pubFile string) (*ecdsa.PrivateKey, *ecdsa.PublicKey)
LoadPrivateKeyECDSA(filename string) (*ecdsa.PrivateKey, error)
LoadPublicKeyECDSA(filename string) (*ecdsa.PublicKey, error) 
ParsePrivateKeyECDSA(key []byte) (*ecdsa.PrivateKey, error)
ParsePublicKeyECDSA(key []byte) (*ecdsa.PublicKey, error)
```

```go
// EdDSA
MustLoadEdDSA(privFile, pubFile string) (ed25519.PrivateKey, ed25519.PublicKey)
LoadPrivateKeyEdDSA(filename string) (ed25519.PrivateKey, error)
LoadPublicKeyEdDSA(filename string) (ed25519.PublicKey, error)
ParsePrivateKeyEdDSA(key []byte) (ed25519.PrivateKey, error)
ParsePublicKeyEdDSA(key []byte) (ed25519.PublicKey, error)
```

Example Code:

```go
import "github.com/kataras/jwt"
```

```go
privateKey, publicKey := jwt.MustLoadEdDSA("./private_key.pem", "./public_key.pem")
```

```go
claims := jwt.Map{"foo": "bar"}
maxAge := jwt.MaxAge(15 * time.Minute)

token, err := jwt.Sign(jwt.EdDSA, privateKey, claims, maxAge)
```

```go
verifiedToken, err := Verify(EdDSA, publicKey, token)
```

> Embedded keys? No problem, just integrate the `jwt.ReadFile` variable which is just a type of `func(filename string) ([]byte, error)`.

## Encryption

[JWE](https://tools.ietf.org/html/rfc7516#section-3) (encrypted JWTs) is outside the scope of this package, a wire encryption of the token's payload is offered to secure the data instead. If the application requires to transmit a token which holds private data then it needs to encrypt the data on Sign and decrypt on Verify. The `SignEncrypted` and `VerifyEncrypted` package-level functions can be called to apply any type of encryption.

The package offers one of the most popular and common way to secure data; the `GCM` mode + AES cipher. We follow the `encrypt-then-sign` flow which most researchers recommend (it is safer, because it prevents _padding oracle attacks_).

In-short, you need to call the `jwt.GCM` and pass its result to the `jwt.SignEncrypted` and `jwt.VerifyEncrypted`:

```go
// Replace with your own keys and keep them secret.
// The "encKey" is used for the encryption and
// the "sigKey" is used for the selected JSON Web Algorithm
// (shared/symmetric HMAC in that case).
var (
    encKey = MustGenerateRandom(32)
    sigKey = MustGenerateRandom(32)
)

func main(){
    encrypt, decrypt, err := GCM(encKey, nil)
    if err != nil {
        // [handle error...]
    }
    // Encrypt and Sign the claims:
    token, err := SignEncrypted(jwt.HS256, sigKey, encrypt, claims, jwt.MaxAge(15 * time.Minute))
    // [...]

    // Verify and decrypt the claims:
    verifiedToken, err := VerifyEncrypted(jwt.HS256, sigKey, decrypt, token)
    // [...]
}
```

Read more about GCM at: https://en.wikipedia.org/wiki/Galois/Counter_Mode

## AI Tools for jwt

Two AI tools know this library specifically, beyond what a general model knows about Go and JWT.

[Plexon AI](https://plexon.ai) is a desktop assistant for Windows, macOS and Linux, built by the author of this library, and it is the recommended way to write jwt code with an assistant. It ships the jwt skill: the `Sign`/`Verify` surface with real signatures, algorithm choice and key sizing, the `kid`-based key registry and JWKS refresh, validator composition, blocklisting, and the security rules, in reference documents the assistant loads on demand while it writes your code. Turn the skill on from the Skills panel, or install the [Software Developer persona](https://plexon.ai/personas/software-developer/), which enables it alongside the rest of its engineering tooling. [Download Plexon AI](https://plexon.ai/download/).

The [live AI wiki](https://codewiki.google/github.com/kataras/jwt) is free and runs in your browser: browse the architecture with diagrams, or ask its chat about the codebase.

Using Claude Code? This repository is a plugin marketplace, so the CLI installs the same skill and keeps it updated:

```sh
claude plugin marketplace add kataras/jwt
claude plugin install jwt@kataras-jwt
```

Codex, Cursor, Copilot and anything else that reads Markdown instructions can vendor [`skill/jwt/`](skill/) and point at `skill/jwt/SKILL.md`. See [skill/README.md](skill/README.md) for every installation route.

## References

Here is what helped me to implement JWT in Go:

- The JWT RFC: https://tools.ietf.org/html/rfc7519
- The JWK RFC: See https://tools.ietf.org/html/rfc7517#section-5
- The official JWT book, all you need to learn: https://auth0.com/resources/ebooks/jwt-handbook
- Create Your JWTs From Scratch (PHP): https://dzone.com/articles/create-your-jwts-from-scratch
- How to make your own JWT (Javascript): https://medium.com/code-wave/how-to-make-your-own-jwt-c1a32b5c3898
- Encode and Decode keys: https://golang.org/src/crypto/x509/x509_test.go (and its variants)
- The inspiration behind the "Blacklist" feature (I prefer to chose the word "Blocklist" instead): https://blog.indrek.io/articles/invalidate-jwt/
- We need JWT in the modern web: https://medium.com/swlh/why-do-we-need-the-json-web-token-jwt-in-the-modern-web-8490a7284482
- Best Practices of using JWT with GraphQL: https://hasura.io/blog/best-practices-of-using-jwt-with-graphql/

## License

This software is licensed under the [MIT License](LICENSE).
