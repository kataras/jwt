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
* [Verify a token](#verify-a-token)
   * [Decode custom claims](#decode-custom-claims)
* [Choosing the right algorithm](#choose-the-right-algorithm)
* [Examples](_examples)
   * [Basic](_examples/basic/main.go)
   * [HTTP Middleware](_examples/middleware/main.go)
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
now := time.Now()
token, err := jwt.Sign(jwt.HS256, sharedKey, map[string]interface{}{
    "iat": now.Unix(),
    "exp": now.Add(15 * time.Minute).Unix(),
    "foo": "bar",
})
```

`[1]` The first argument is the signing algorithm to create the signature part.
`[2]` The second argument is the private key (or shared key, when symmetric algorithm was chosen) will be used to create the signature.
`[3]` The third argument is the JWT claims. The JWT claims is the payload part and it depends on your application's requirements, there you can set custom fields (and expiration) that you can extract to another request of the same authorized client later on. Note that the claims can be **any Go type**, including custom structs. `Returns` the encoded token, ready to be sent and store to the client.

There is one more way to create a token if you don't like to set the expiration or standard JWT claims manually:

```go
customClaims := map[string]interface{}{ // or jwt.Map
   "foo":"bar",
}

standardClaims := jwt.Claims{
   MaxAge: 15 * time.Minute,
   Issuer: "my-app",
}

token, err := jwt.Sign(jwt.HS256, sharedKey, 
   jwt.Merge(customClaims, standardClaims))
```

The `jwt.Claims.MaxAge` field is a helper field which sets the `jwt.Claims.Expiry` and `jwt.Claims.IssuedAt` for you. The `jwt.Merge` function is just a helper to merge your custom fields with the standard `jwt.Claims` structure one. There is also the `jwt.Map` type alias, which is just a plain shortcut of a `map[string]interface{}`.

On both examples above, the `iat(IssuedAt)` and `exp(Expiry/MaxAge)` (and `nbf(NotBefore)`) values will be validated automatically on the `Verify` method below.

## Verify a Token

Verifying a Token is done through the `Verify` package-level function.

```go
verifiedToken, err := jwt.Verify(jwt.HS256, sharedKey, token)
```

### Decode custom Claims

To extract any custom claims, given on the `Sign` method, we use the result of the `Verify` method, which is a `VerifiedToken` pointer. This VerifiedToken has a single method, the `Claims(dest interface{}) error` one, which can be used to decode the claims (payload part) to a value of our choice. Again, that value can be a `map` or any `struct`.

```go
var claims = struct {
	Foo string `json:"foo"`
}{} // or a map.

err := verifiedToken.Claims(&claims)
```

## Choose the right algorithm

## References

## TODO

- [ ] Add a `blocklist` to be able to invalidate tokens at server-side.
- [ ] Add a special `json:"..., required"` tag field to make custom fields required on the `VerifiedToken.Claims` (may require a type of Optional argument there).
- [ ] If requested, add support for [JWE](https://tools.ietf.org/html/rfc7516#section-3).

## License

This software is licensed under the [MIT License](LICENSE).
