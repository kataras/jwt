# JWT

[![build status](https://img.shields.io/travis/com/kataras/jwt/master.svg?style=for-the-badge&logo=travis)](https://travis-ci.com/github/kataras/jwt) [![report card](https://img.shields.io/badge/report%20card-a%2B-ff3333.svg?style=for-the-badge)](https://goreportcard.com/report/github.com/kataras/jwt) [![godocs](https://img.shields.io/badge/go-%20docs-488AC7.svg?style=for-the-badge)](https://pkg.go.dev/github.com/kataras/jwt)

Fast and simple [JWT](https://jwt.io/) implementation written in [Go](https://golang.org/dl).

## Installation

The only requirement is the [Go Programming Language](https://golang.org/dl).

```sh
$ go get github.com/kataras/jwt
```

Import as `import "github.com/kataras/jwt"` and use it as `jwt.XXX`.

## Table of Contents

* [Sign a token](#sign-a-token)
   * [The standard Claims](#the-standard-jwt-claims)
* [Verify a token](#verify-a-token)
   * [Decode custom Claims](#decode-custom-claims)
   * [JSON Required Tag](#json-required-tag)
* [Block a Token](#block-a-token)
* [Choosing the right algorithm](#choose-the-right-algorithm)
* [Benchmarks](_benchmarks)
* [Examples](_examples)
   * [Basic](_examples/basic/main.go)
   * [HTTP Middleware](_examples/middleware/main.go)
   * [Blocklist](_examples/blocklist/main.go)
   * [JSON Required Tag](_examples/required/main.go)
* [References](#references)
* [TODO](#todo)
* [License](#license)

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

`[1]` The first argument is the signing algorithm to create the signature part.
`[2]` The second argument is the private key (or shared key, when symmetric algorithm was chosen) will be used to create the signature.
`[3]` The third argument is the JWT claims. The JWT claims is the payload part and it depends on your application's requirements, there you can set custom fields (and expiration) that you can extract to another request of the same authorized client later on. Note that the claims can be **any Go type**, including custom structs. `[4]` The last variadic argument is a type of `SignOption` (`MaxAge` function and `Claims` struct are both valid sign options), can be used to merge custom claims with the standard ones.  `Returns` the encoded token, ready to be sent and stored to the client.

The `jwt.MaxAge` is a helper which sets the `jwt.Claims.Expiry` and `jwt.Claims.IssuedAt` for you.

Example Code to manually set all claims using a standard `map`:

```go
now := time.Now()
claims := map[string]interface{}{
    "iat": now.Unix(),
    "exp": now.Add(15 * time.Minute).Unix(),
    "foo": "bar",
}

token, err := jwt.Sign(jwt.HS256, sharedKey, claims)
```

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

> The `jwt.Map` is just a _type alias_, a _shortcut_, of `map[string]interface{}`.

At all cases, the `iat(IssuedAt)` and `exp(Expiry/MaxAge)` (and `nbf(NotBefore)`) values will be validated automatically on the [`Verify`](#verify-a-token) method.

### The standard JWT Claims

The `jwt.Claims` we've shown above, looks like this:

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

To extract any custom claims, given on the `Sign` method, we use the result of the `Verify` method, which is a `VerifiedToken` pointer. This VerifiedToken has a single method, the `Claims(dest interface{}) error` one, which can be used to decode the claims (payload part) to a value of our choice. Again, that value can be a `map` or any `struct`.

```go
var claims = struct {
	Foo string `json:"foo"`
}{} // or a map.

err := verifiedToken.Claims(&claims)
```

### JSON required tag

When more than one token with different claims can be generated based on the same algorithm and key, somehow you need to invalidate a token if its payload misses one or more fields of your custom claims structure. Although it's not recommended to use the same algorithm and key for generating two different types of tokens, you can do it, and to avoid invalid claims to be retrieved by your application's route handler this package offers the JSON **`,required`** tag field. It checks if the claims extracted from the token's payload meet the requirements of the expected **struct** value.

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

That's all, the `VerifiedToken.Claims` method will throw an `ErrMissingKey` if the given token's payload does not meet the requirements.

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
blocklist.InvalidateToken(verifiedToken.Token, verifiedToken.StandardClaims.Expiry)
```

## Choose the right algorithm

## References

Here is what helped me to implement JWT in Go:

- The JWT RFC: https://tools.ietf.org/html/rfc7519
- The JWE (protected & encrypted JWT) RFC: https://tools.ietf.org/html/rfc7516#section-3
- The official JWT book, all you need to learn: https://auth0.com/resources/ebooks/jwt-handbook
- Create Your JWTs From Scratch (PHP): https://dzone.com/articles/create-your-jwts-from-scratch
- How to make your own JWT (Javascript): https://medium.com/code-wave/how-to-make-your-own-jwt-c1a32b5c3898
- Encode and Decode keys: https://golang.org/src/crypto/x509/x509_test.go (and its variants)
- The inspiration behind the "Blacklist" feature (I prefer to chose the word "Blocklist" instead): https://blog.indrek.io/articles/invalidate-jwt/
- We need JWT in the modern web: https://medium.com/swlh/why-do-we-need-the-json-web-token-jwt-in-the-modern-web-8490a7284482

## License

This software is licensed under the [MIT License](LICENSE).
