# Keys, rotation and JWKS

For exact signatures, see the "Multi-key registry", "JWKS" and "AWS Cognito" sections of
`api-map.md`. This document is the task-oriented walkthrough: when you have more than one key, or
need to talk to an external identity provider.

## Single key vs. registry

`jwt.Sign`/`jwt.Verify` take a bare key. That is enough for a single service holding one key pair
(or one shared secret) for its own tokens. Reach for `jwt.Keys` (a `map[string]*Key`, keyed by
`"kid"`) once any of these become true: you need to support more than one active signing key at
once (rotation), you verify tokens whose issuer stamps a `"kid"` you must select by (most external
identity providers), or you want a `/.well-known/jwks.json` endpoint generated for you.

```go
keys := make(jwt.Keys)
keys.Register(jwt.RS256, "api-2024", rsaPublicKey, rsaPrivateKey)
keys.Register(jwt.HS256, "legacy-hmac", nil, hmacSecret) // nil public: reused from privKey for HMAC

token, err := keys.SignToken("api-2024", claims, jwt.MaxAge(15*time.Minute))
// token's header now carries {"kid":"api-2024","alg":"RS256",...}

var got MyClaims
err = keys.VerifyToken(token, &got) // selects "api-2024" from the token's own header
```

`Register` is not safe to call concurrently with reads or other writes (see `security.md`). Build
the whole registry during startup.

## Rotating a key

Register the new key under a new `kid`, alongside the old one, and start signing new tokens with
the new `kid` (change what `SignToken`/`SignPair` is called with). Verification keeps working for
both: `VerifyToken`/`Verify` select the key by whatever `"kid"` the presented token carries, so
already-issued tokens under the old `kid` keep verifying until they naturally expire. Remove the
old entry from the registry only once you are certain no unexpired token still names it, which in
practice means waiting out your longest token lifetime (or forcing reauthentication).

There is no built-in "retire this kid on a timer" mechanism; track that yourself (a `MaxAge` per
`Key`, a scheduled config reload, or an expiry you track alongside the registry).

## Loading keys from configuration

`KeysConfiguration` is the serializable shape (JSON/YAML/TOML/INI struct tags are all present) for
exactly this: a file listing several keys by `id`, `alg` (a name like `"RS256"`, matched
case-insensitively), PEM or raw key text, an optional `max_age`, and an optional hex-encoded
`encryption_key` for payload encryption on that key. `_examples/multiple-kids` loads one from YAML
with `gopkg.in/yaml.v3`:

```go
type Configuration struct {
    WebKeys jwt.KeysConfiguration `yaml:"WebKeys"`
}

var c Configuration
// yaml.Unmarshal(fileBytes, &c)

keys := c.WebKeys.MustLoad() // panics on a bad entry; use .Load() to handle the error yourself
token, err := keys.SignToken("user", claims, jwt.MaxAge(2*time.Hour))
```

`Load` resolves each entry's `Alg` name against the built-in algorithm list (an unrecognized name
is an error, never a silent default), then parses `Private`/`Public` through that algorithm's
`AlgParser`. Errors name the offending `id` and `alg`, which matters once a configuration file
holds more than one key.

Exporting a live registry back to `KeysConfiguration` (for backup, or to persist keys fetched from
a JWKS) goes through `(Keys).Configuration()` / `(*Key).Configuration()`, which PEM-encode the key
material; a key carrying `Encrypt`/`Decrypt` functions cannot round-trip this way, since functions
are not serializable.

## Publishing your own JWKS

`(Keys).JWKS()` builds a `*JWKS` from every registered key's *public* half only; private key
material never appears in it. The output is sorted by `kid`, so serving it repeatedly (with an
`ETag`/`If-None-Match`-aware handler) produces a stable body between calls, not a fresh random
ordering each time:

```go
http.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
    jwks, err := keys.JWKS()
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(jwks)
})
```

## Consuming an external JWKS once

```go
keys, err := jwt.FetchPublicKeys("https://myapp.auth0.com/.well-known/jwks.json")
if err != nil {
    // network error, non-2xx (*jwt.HTTPError), or malformed JSON
}

err = keys.VerifyToken(tokenBytes, &claims) // selects the key by the token's own "kid"
```

This is one fetch, not a client: there is no cache and no background refresh built into
`FetchPublicKeys`/`FetchJWKS` themselves. A provider that rotates its signing key leaves this
in-memory `Keys` stale until you call `FetchPublicKeys` again. Reach for `jwt.KeySet` (next
section) rather than hand-rolling a refresh loop around this.

## Keeping a JWKS current: `KeySet`

`jwt.KeySet` is a self-refreshing `Keys` holder built for exactly the "verify tokens from an
external identity provider, indefinitely, without restarting" case:

```go
keySet, err := jwt.NewRemoteKeySet("https://auth.example.com/.well-known/jwks.json")
if err != nil {
    return err // the first fetch happens before NewRemoteKeySet returns: a bad URL fails at
               // startup, not on the first request that needs it
}
defer keySet.Close() // stop the background refresh goroutine when you are done with keySet

verifiedToken, err := jwt.VerifyWithHeaderValidator(nil, nil, token, keySet.ValidateHeader)
// or: verifiedToken, err := keySet.Verify(token)
```

It refreshes on two triggers: a background timer (`WithRefreshInterval`, default one hour; pass
`0` to disable) and, separately, whenever a token names a `"kid"` the current snapshot does not
hold (rate-limited by `WithMinRefreshInterval`, default one minute, so a stream of tokens naming a
`kid` that will never exist, which costs an attacker nothing to send, does not become a stream of
outbound requests to the provider). Both triggers make key rotation on the provider's side
invisible to your service: the new key typically appears in the provider's published set before
the first token signed with it arrives, and the unknown-`kid` refetch closes any remaining gap
without a restart. A failed refresh (network blip, provider outage) leaves the previous keys in
place rather than breaking verification; `Refresh()` is also available to call by hand, e.g. from
an admin endpoint.

`(*KeySet).Keys()` returns the current snapshot for inspection; reads never take a lock; the
underlying map is swapped atomically on refresh, so a verification already in flight keeps using
the snapshot it started with.

## AWS Cognito

Prefer `jwt.NewCognitoKeySet` over hand-rolling `FetchAWSCognitoPublicKeys` plus
`Keys.VerifyToken`. The manual combination checks only the signature: an ID token issued to a
*different* app client within the *same* user pool would still verify, because nothing about a
bare signature check distinguishes one app client from another in the same pool.
`NewCognitoKeySet` returns a self-refreshing `*KeySet` **and** the matching `jwt.Expected`
validator, pre-populated with the pool as the expected issuer and, when you pass a non-empty
`appClientID`, that client as the expected audience:

```go
keySet, expected, err := jwt.NewCognitoKeySet("us-east-1", "us-east-1_abc123", appClientID)
if err != nil {
    return err
}
defer keySet.Close()

verifiedToken, err := jwt.VerifyWithHeaderValidator(nil, nil, token,
    keySet.ValidateHeader, expected, jwt.Skew(2*time.Minute))
```

`jwt.Skew` belongs in that validator list for Cognito specifically: Cognito tokens omit `"nbf"`
and Cognito's clock can run slightly ahead, so add tolerance rather than hand-tuning `Clock`.

Use the lower-level `jwt.FetchAWSCognitoPublicKeys(region, userPoolID)` directly only when you are
building your own caching/validation layer and understand you must add the issuer/audience checks
yourself; `region`/`userPoolID` are still charset-validated before being interpolated into the
request URL either way (see `security.md`), which is why the function takes them as two separate
parameters instead of a pre-built URL.

`(*JWKS).PublicKeys()` silently drops any `JWK` entry with an algorithm or key type this package
does not recognize, or with malformed key material, rather than failing the whole fetch. If a key
you expect is missing from the resulting `Keys`, check the raw JWKS response before assuming a
bug: an unsupported `kty`/`alg` combination (or a curve name outside P-256/P-384/P-521) is a
common cause.

Common JWKS endpoints, from the README: Auth0
(`https://{domain}/.well-known/jwks.json`), Google (`https://www.googleapis.com/oauth2/v3/certs`),
Microsoft (`https://login.microsoftonline.com/common/discovery/v2.0/keys`), and AWS Cognito
(`https://cognito-idp.{region}.amazonaws.com/{userPoolId}/.well-known/jwks.json`; use
`jwt.NewCognitoKeySet(region, userPoolID, appClientID)` rather than building that URL by hand).

## Token pairs across keys

`(Keys).SignPair(claims, jwt.PairOptions{AccessKID: "access", RefreshKID: "refresh", ...})` signs
an access token and a refresh token from the same registry, each with its own `kid`, and links
them: the refresh token's `"origin_jti"` is set to the access token's `"jti"`, so a `Blocklist`
revocation of the access token can locate the refresh token that would otherwise mint a new one.
Using a separate `RefreshKID` is worth doing: the refresh key is used once per session rather than
once per request, so it can be kept somewhere the more frequently used access key cannot (a
narrower-scoped secret store, for instance).
