# Chapter 10: Tokens over HTTP

A token has to travel from the client to your handler, and there are three places it can
ride: a header, a query string, or a cookie. Each leaks differently, and the twenty lines
that pull the token back out are the lines every service rewrites from memory. This chapter
covers the extractors this package ships, a middleware that compiles, the mapping from a
verification failure to a status code, and the token pair a login endpoint hands back.

## Table of Contents

- [Where a token lives in a request](#where-a-token-lives-in-a-request)
- [The extractors](#the-extractors)
- [What FromHeader gets right](#what-fromheader-gets-right)
- [A middleware that compiles](#a-middleware-that-compiles)
- [Why the context key is not a string](#why-the-context-key-is-not-a-string)
- [From error to status code](#from-error-to-status-code)
- [Access and refresh tokens](#access-and-refresh-tokens)
- [The response shape](#the-response-shape)
- [A refresh endpoint](#a-refresh-endpoint)
- [Summary](#summary)
- [Further Reading](#further-reading)

## Where a token lives in a request

| Location | Sent by the browser on its own | What it costs you |
| --- | --- | --- |
| `Authorization: Bearer ...` | No | The client must store the token and attach it |
| `?access_token=...` | No | Written to every access log and to browser history |
| `Cookie: session=...` | Yes, on every request to the origin | CSRF protection of its own |

The `Authorization` header with the `Bearer` scheme is the default answer, and RFC 6750
defines it. It is sent only when the client chooses to send it, so a form submitted from
another origin cannot carry it, and proxies do not log request headers by default. The cost
is that whatever can read the client's storage reads the token: in a browser, any script on
the page.

A query parameter is the option to reach for last. A URL is written to the access log of every
proxy and web server between the client and you, and it stays in browser history and in the
address bar. There are places where nothing else works: an `EventSource` connection cannot set
a header, and neither can a download link the browser follows on its own. `FromQuery` exists
for those, and such a token should expire before anyone reads the log.

A cookie is sent automatically, which is the convenience and also the whole problem. A form on
an unrelated site can point at your endpoint and the browser attaches the cookie. That is
cross-site request forgery, and no amount of signature checking catches it, because the token
really is yours and really is valid. The mitigations sit outside this package: `HttpOnly`,
`Secure`, `SameSite=Lax` or `Strict`, and an anti-forgery token for what `SameSite` misses.

## The extractors

Four declarations cover all three locations:

```go
type TokenExtractor func(r *http.Request) []byte
const BearerPrefix = "Bearer"

func FromHeader(names ...string) TokenExtractor
func FromQuery(names ...string) TokenExtractor
func FromCookie(name string) TokenExtractor
func ExtractToken(r *http.Request, extractors ...TokenExtractor) []byte
```

Each returns `nil` when the request carries no token where it looked, and `ExtractToken`
returns the first non-empty result. `FromHeader()` reads `Authorization`, `FromQuery()` reads
`access_token` and then `token`, and `ExtractToken` with no extractors behaves as though you
passed `FromHeader()`.

```go
token := jwt.ExtractToken(r)
verifiedToken, err := jwt.Verify(jwt.HS256, key, token)
```

No nil check sits between those two lines because `Verify` returns `ErrMissing` for an empty
token, so an absent credential and a forged one reach the same handler rather than two. Pass
extractors when a token can arrive in more than one place, as in
`jwt.ExtractToken(r, jwt.FromHeader(), jwt.FromCookie("session"))`: the first one that finds
something wins, and a `nil` entry is skipped rather than dereferenced.

## What FromHeader gets right

Two details in the header parser are the reason it is worth using rather than rewriting. The
first is that the scheme comparison ignores case: RFC 7235 section 2.1 says the scheme is
case-insensitive, so `bearer`, `Bearer` and `BEARER` are the same and clients send all three,
while a parser built on `strings.HasPrefix(value, "Bearer ")` rejects two of them. The second
is that the value is split on the first space only:

```go
scheme, token, found := strings.Cut(value, " ")
if !found {
	return []byte(value) // A bare token with no scheme. Several gateways send this.
}
if !strings.EqualFold(scheme, BearerPrefix) {
	continue
}
if token = strings.TrimSpace(token); token != "" {
	return []byte(token)
}
```

`strings.Cut` returns everything after the first space, whatever is in it. The alternative
people write, `strings.Split(value, " ")` followed by taking element one, truncates at the
second space and hands verification a token missing its tail. The signature then fails, the
log says the signature failed, and whoever is debugging it goes to look at keys.

Three hand-written versions of this parser across two codebases disagreed about exactly that.
One truncated, one did not, and the third accepted a bare token with no scheme while the
others rejected it, so the same credential was valid on one service and invalid on the next.
That is a missing primitive rather than three separate bugs. Accepting a bare token is itself
a leniency, since some gateways strip the scheme before forwarding; if your own edge always
sends `Bearer`, write a `TokenExtractor` of your own, because the type is one function.

## A middleware that compiles

Extract, verify, store the claims on the request context, and read them back through a typed
accessor.

```go
package auth

import (
	"context"
	"net/http"

	"github.com/kataras/jwt"
)

// claimsKey is unexported and has a type of its own, so no other package can read this
// value out of the context or overwrite it.
type claimsKey struct{}

type UserClaims struct {
	UserID string   `json:"user_id"`
	Roles  []string `json:"roles"`
}

func Middleware(key []byte) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := jwt.ExtractToken(r)
			verifiedToken, err := jwt.Verify(jwt.HS256, key, token)
			if err != nil {
				writeAuthError(w, err)
				return
			}
			var claims UserClaims
			if err = verifiedToken.Claims(&claims); err != nil {
				writeAuthError(w, err)
				return
			}
			ctx := context.WithValue(r.Context(), claimsKey{}, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ClaimsOf returns the claims the middleware stored. The second result is false when the
// request did not pass through Middleware, which is a routing mistake.
func ClaimsOf(r *http.Request) (UserClaims, bool) {
	claims, ok := r.Context().Value(claimsKey{}).(UserClaims)
	return claims, ok
}
```

A handler behind it writes `claims, ok := auth.ClaimsOf(r)` and gets a `UserClaims`, with no
type assertion of its own. Keep the `ok` result even though the middleware always sets the
value: it is false exactly when a route was registered without the middleware in front of it,
and 401 beats a nil dereference in production.

## Why the context key is not a string

`context.WithValue` takes an `any` as the key and compares keys with `==`, so two string keys
with the same text are equal. Store the claims under `"claims"` and any package in the
process, including one you did not write, can read them back with `Value("claims")` and
replace them with another `WithValue` under the same word. A middleware from an unrelated
library that happens to use that word wins, and the collision is silent: the type assertion
in your accessor fails, `ok` is false, and the request is refused for a reason nobody can
find. `go vet` flags a basic type used as a context key for exactly this.

An empty struct type settles it. `claimsKey{}` compares equal only to another `claimsKey{}`,
`claimsKey` is unexported so no other package can construct one, and an empty struct occupies
zero bytes. An unexported `int` constant works the same way and is common in the standard
library; the struct form cannot be produced by accident from an untyped constant.

## From error to status code

This package returns more than a dozen sentinel errors, and enumerating them at the HTTP
boundary is how the lists that drift get written: one downstream copy enumerated fifteen while
the alias file it came from re-exported twelve. `Classify(err error) ErrorKind` collapses
them into the answers an application acts on.

| Kind | What happened | Reasonable response |
| --- | --- | --- |
| `KindNone` | No error | Carry on |
| `KindMalformed` | Not a usable JWT: wrong shape, bad base64, oversized | 400 |
| `KindInvalid` | Well formed but not yours: bad signature, wrong alg, unknown `kid` | 401 |
| `KindExpired` | Valid, and its time has passed or has not yet come | 401 |
| `KindRejected` | Verified, then a policy check refused it: revoked, claim mismatch | 403 |

`Classify` uses `errors.Is`, so a wrapped error still classifies. Anything it does not
recognise, an error your own validator returned included, comes back as `KindInvalid`: the
safe reading of an unrecognised verification failure is that the token is not acceptable.

```go
func writeAuthError(w http.ResponseWriter, err error) {
	status := http.StatusUnauthorized
	switch jwt.Classify(err) {
	case jwt.KindMalformed:
		status = http.StatusBadRequest
	case jwt.KindRejected:
		status = http.StatusForbidden
	}
	w.Header().Set("WWW-Authenticate", `Bearer realm="api"`)
	http.Error(w, "unauthorized", status)
}
```

The body is the same string in every branch, and that is the point. Telling a caller whether
the token was expired, forged or revoked is free information for whoever is probing you:
"expired" confirms the token was once real, "revoked" confirms the account exists, "forged"
confirms neither, and someone who can tell those apart can grind through candidates. The
trade-off is real, since the status code still varies across three values; if that bothers
you, return 401 for everything. Distinguishing pays with a client you wrote, since
`KindExpired` means it can refresh rather than send the user back to a login form. Put that
in a `WWW-Authenticate` parameter, never in a different body.

## Access and refresh tokens

An access token should be short-lived, because a leaked one is valid until it expires and
nothing in the token can shorten that. A short life means the client needs a way to get
another one without a password prompt, which is the refresh token: a longer-lived credential
presented to exactly one endpoint. The two have to be linked, because revoking an access
token accomplishes nothing if the refresh token that mints its replacement still works.
Before `SignPair`, callers built that by hand: two generated identifiers, the access token's
`jti` copied into the refresh token's `origin_jti`, every sign option run twice against two
separate `Claims` values, and two signings. Roughly 129 lines, plus two option wrappers whose
only job was to guess which half was being signed from whether `origin_jti` was empty.

```go
func SignPair(alg Alg, key PrivateKey, claims any, opts PairOptions) (SignedPair, error)
func (keys Keys) SignPair(claims any, opts PairOptions) (SignedPair, error)
func (p SignedPair) TokenPair() TokenPair

type SignedPair struct {
	AccessToken []byte
	RefreshToken []byte
	AccessClaims Claims
	RefreshClaims Claims
}
```

`AccessClaims` and `RefreshClaims` hold the standard claims actually written into each half,
generated `jti` included. `PairOptions` has five fields and a usable zero value:

- **`AccessKID`** and **`RefreshKID`** name the registry entries to sign each half with.
  `Keys.SignPair` uses them and the package-level `SignPair` ignores them; an empty
  `RefreshKID` signs both halves with `AccessKID`. Separate keys are worth the trouble, since
  the refresh key is used once per session rather than once per request.
- **`AccessOptions`** and **`RefreshOptions`** are `[]SignOption` applied to each half
  separately. This is the awkward part by hand: the two tokens want different lifetimes and
  one option list cannot say so.
- **`GenerateID`** is `func() (string, error)` and produces the `jti` for each half,
  defaulting to a version 7 UUID (time-ordered, from the standard library's `uuid`
  package, 36 characters). Replace it when something downstream expects a different
  format, including the 22-character base64url identifier this package generated by
  default before v0.3.0.
- **`Unlinked`** leaves the refresh token's `origin_jti` empty. The link is the default,
  because without it there is no way, given a revoked access token, to find the refresh token
  that replaces it.

```go
pair, err := jwt.SignPair(jwt.HS256, key, userClaims, jwt.PairOptions{
	AccessOptions:  []jwt.SignOption{jwt.MaxAge(15 * time.Minute)},
	RefreshOptions: []jwt.SignOption{jwt.MaxAge(7 * 24 * time.Hour)},
})
```

The link runs one way. The refresh token's `origin_jti` holds the access token's `jti`, so
given a refresh token you can name the access token it came with and revoke both against one
blocklist; given only an access token you cannot walk back without an index of your own. The
refresh token is presented rarely, so it is the half that can afford the extra claim. Custom
claims go into both halves verbatim, so put nothing in a refresh token you would mind being
read by whoever holds it for a week.

## The response shape

`TokenPair` is the JSON body, and it uses the OAuth2 field names so a standard client library
reads it without a custom decoder.

```go
type TokenPair struct {
	AccessToken string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken string `json:"id_token,omitempty"`
}
func NewTokenPair(accessToken, refreshToken []byte) TokenPair
```

The body on the wire is `{"access_token":"eyJhbGci...","refresh_token":"eyJhbGci..."}`. Either
token may be empty, and an empty one is left out of the JSON entirely. That part is newer than
the struct: the fields used to be `json.RawMessage` filled by a helper that returned two quote
characters for no input, so an empty token was never empty as far as `omitempty` was concerned
and the response carried `"access_token":""` instead.

`IDToken` is the OpenID Connect field, carrying identity claims about the user rather than an
authorization to call an API. Providers that issue one return all three together, and a
two-field struct matched no real provider response, so callers declared their own type
instead of using this one.

## A refresh endpoint

The endpoint verifies the refresh token, spends it, and issues a new pair. Spending it
matters: a refresh token that survives its own use is a long-lived credential an attacker who
copied it can keep using alongside the real client. `Server` here holds `SignKey` and
`RefreshKey` as `[]byte`, a `*jwt.Blocklist`, and `Issuer` as a `jwt.SignOptionFunc`.

```go
func (s *Server) Refresh(w http.ResponseWriter, r *http.Request) {
	var body struct {
		RefreshToken string `json:"refresh_token"`
	}
	// Bound the body: this endpoint is reachable without a credential.
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8*1024))
	if err := dec.Decode(&body); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	verifiedToken, err := jwt.Verify(jwt.HS256, s.RefreshKey, []byte(body.RefreshToken),
		jwt.Expected{Issuer: "auth.example.com"}, s.Blocklist)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	var claims UserClaims
	if err = verifiedToken.Claims(&claims); err != nil {
		writeAuthError(w, err)
		return
	}
	// Spend the refresh token, and revoke the access token it was issued with, which
	// "origin_jti" names. The token argument is there only because InvalidateToken
	// refuses an empty one: the blocklist key comes from the claims.
	standard := verifiedToken.StandardClaims
	origin := jwt.Claims{ID: standard.OriginID, Expiry: standard.Expiry}
	if err = errors.Join(
		s.Blocklist.InvalidateToken(verifiedToken.Token, standard),
		s.Blocklist.InvalidateToken(verifiedToken.Token, origin),
	); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	pair, err := jwt.SignPair(jwt.HS256, s.SignKey, claims, jwt.PairOptions{
		AccessOptions:  []jwt.SignOption{jwt.MaxAge(15 * time.Minute), s.Issuer},
		RefreshOptions: []jwt.SignOption{jwt.MaxAge(7 * 24 * time.Hour), s.Issuer},
	})
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(pair.TokenPair())
}
```

Three things in there are choices. A separate refresh key means this endpoint is the only
place that needs it, at the price of one more key to rotate. Blocking the old access token on
every refresh logs the user out of any request already in flight with it, a stream of
spurious failures if clients refresh eagerly rather than on a 401. And passing `s.Blocklist`
as a validator is what makes a spent refresh token fail; without it, `InvalidateToken` writes
entries nothing reads. That blocklist is in-memory, so two instances do not share it, which
Chapter 9 covers.

## Summary

A token rides in a header, a query string, or a cookie. The header is the default. A query
string is written to logs and browser history. A cookie is attached automatically, which is
why it needs `SameSite`, `HttpOnly` and anti-forgery protection unrelated to JWT.

`ExtractToken`, `FromHeader`, `FromQuery` and `FromCookie` replace the twenty lines every
service writes. `FromHeader` folds the scheme's case and splits on the first space only, the
detail three hand-written parsers disagreed about. Put the verified claims on the request
context under an unexported key type, because a string key is comparable to any other string
with the same text. `Classify` turns a dozen sentinels into five kinds: map them to status
codes if you like, but send the same body every time. `SignPair` issues an access and a
refresh token together and links them through `origin_jti`, so revoking one can find the
other. `TokenPair` is the OAuth2 response shape, with `IDToken` there for OpenID Connect.

## Further Reading

- [RFC 6750: Bearer Token Usage](https://www.rfc-editor.org/rfc/rfc6750): the
  `Authorization: Bearer` form, the query and form-body alternatives, and the
  `WWW-Authenticate` error parameters.
- [RFC 7235 section 2.1](https://www.rfc-editor.org/rfc/rfc7235#section-2.1): the
  authentication scheme is case-insensitive, which is why `FromHeader` folds case.
- [RFC 6749 section 6](https://www.rfc-editor.org/rfc/rfc6749#section-6): refreshing an
  access token, including the fields `TokenPair` mirrors.
- [OpenID Connect Core, token
  response](https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse): where
  `id_token` comes from and what belongs in it.
- [OWASP CSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html): what a cookie-stored token needs on top of a signature.

---

**Next Chapter**: [Encrypting the Payload](11-encrypting-the-payload.md) - AES-GCM over the claims, what it hides, and the several reasons it is usually the wrong answer.
