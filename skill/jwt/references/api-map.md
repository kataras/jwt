# API Map

Every signature below was read from the current `.go` source (not from `doc.go`'s prose, the
README, pkg.go.dev's rendering of doc comments, or memory). If a call site does not compile
against one of these, the source has moved: re-check it rather than trusting this table. `jwt.`
is `github.com/kataras/jwt`. `PrivateKey` and `PublicKey` are both `= any` (type aliases); the
concrete type required depends on the algorithm, see "Algorithms" below.

## Sign

| Symbol | Signature | Purpose |
| --- | --- | --- |
| `jwt.Sign` | `func Sign(alg Alg, key PrivateKey, claims any, opts ...SignOption) ([]byte, error)` | The common case: encode `claims` as the payload, apply `opts`, sign, return `header.payload.signature` |
| `jwt.SignEncrypted` | `func SignEncrypted(alg Alg, key PrivateKey, encrypt InjectFunc, claims any, opts ...SignOption) ([]byte, error)` | Same, encrypting the marshaled payload with `encrypt` before signing (see `GCM`) |
| `jwt.SignWithHeader` | `func SignWithHeader(alg Alg, key PrivateKey, claims any, customHeader any, opts ...SignOption) ([]byte, error)` | Same, replacing the header with `customHeader` (marshaled as-is; `"alg"` is still forced to `alg.Name()` by the algorithm's own signing, not merged in) |
| `jwt.SignEncryptedWithHeader` | `func SignEncryptedWithHeader(alg Alg, key PrivateKey, encrypt InjectFunc, claims any, customHeader any, opts ...SignOption) ([]byte, error)` | Both of the above combined |

`claims` can be a struct with `json` tags, `jwt.Map` (`= map[string]any`), a raw `[]byte`/`string`
JSON object, or anything `json.Marshal`-able. A raw, non-JSON `claims` value (plain bytes) skips
`opts` merging; pass no `SignOption`s in that case and verify with the `jwt.Plain` validator.

## Verify

| Symbol | Signature | Purpose |
| --- | --- | --- |
| `jwt.Verify` | `func Verify(alg Alg, key PublicKey, token []byte, validators ...TokenValidator) (*VerifiedToken, error)` | Check the token's header against `alg`, verify the signature with `key`, parse and time-validate standard claims, run `validators` in order |
| `jwt.VerifyAs` | `func VerifyAs[T any](alg Alg, key PublicKey, token []byte, validators ...TokenValidator) (T, *VerifiedToken, error)` | `Verify` followed by `ClaimsAs[T]`; returns the decoded claims and the `*VerifiedToken` together |
| `jwt.VerifyEncrypted` | `func VerifyEncrypted(alg Alg, key PublicKey, decrypt InjectFunc, token []byte, validators ...TokenValidator) (*VerifiedToken, error)` | Same, decrypting the payload with `decrypt` after signature verification and before parsing claims |
| `jwt.VerifyWithHeaderValidator` | `func VerifyWithHeaderValidator(alg Alg, key PublicKey, token []byte, headerValidator HeaderValidator, validators ...TokenValidator) (*VerifiedToken, error)` | Same, using `headerValidator` instead of the package-level `CompareHeader`; pass `alg`/`key` as `nil` to let the validator supply both (this is how `Keys.VerifyToken` selects a key by `kid`) |
| `jwt.VerifyEncryptedWithHeaderValidator` | `func VerifyEncryptedWithHeaderValidator(alg Alg, key PublicKey, decrypt InjectFunc, token []byte, headerValidator HeaderValidator, validators ...TokenValidator) (*VerifiedToken, error)` | Both of the above combined |
| `jwt.VerifiedToken` | `struct { Token, Header, Payload, Signature []byte; StandardClaims Claims }` | Returned on success; `Header`/`Payload`/`Signature` are base64url-decoded, `Payload` is post-decryption if applicable |
| `(*VerifiedToken).Claims` | `func (t *VerifiedToken) Claims(dest any) error` | Unmarshal `Payload` into `dest` via the package-level `Unmarshal` var |
| `(*VerifiedToken).ClaimsAs` | `func (t *VerifiedToken) ClaimsAs[T any]() (T, error)` | Generic form of `Claims`; allocates a `T`, decodes into it, returns it by value |
| `jwt.Plain` | `var Plain TokenValidatorFunc` | Pass as a validator to accept a token whose payload is not JSON; `Claims()`/`StandardClaims` are unusable afterward, read `Payload` directly |

`Verify` returns `ErrMissing` for an empty/nil `token` before attempting to parse anything.

## Claims and sign options

| Symbol | Signature | Purpose |
| --- | --- | --- |
| `jwt.Claims` | `struct { NotBefore, IssuedAt, Expiry int64 "json:\"nbf,omitzero\"/\"iat,omitzero\"/\"exp,omitzero\""; ID, OriginID string "jti"/"origin_jti"; Issuer, Subject string "iss"/"sub"; Audience Audience "aud" }` | The registered claims; implements `SignOption` (`ApplyClaims` copies only its non-zero fields into the destination). The three timestamp fields are `omitzero`, not `omitempty`: required once `Marshal` moved to `encoding/json/v2`, since v2's `omitempty` does not consider a numeric zero empty |
| `(Claims).Age` | `func (c Claims) Age() time.Duration` | `Expiry - IssuedAt`, the designed lifetime, not remaining time |
| `(Claims).ExpiresAt` | `func (c Claims) ExpiresAt() time.Time` | `time.Unix(c.Expiry, 0)` |
| `(Claims).Timeleft` | `func (c Claims) Timeleft() time.Duration` | `Expiry - Clock().Unix()`; negative once expired |
| `jwt.Audience` | `type Audience []string` | The `"aud"` claim; unmarshals from either a single JSON string or an array; implements `SignOption` |
| `(Audience).String` | `func (aud Audience) String() string` | Space-joined |
| `(Audience).Contains` | `func (aud Audience) Contains(value string) bool` | Exact, case-sensitive membership check (what `Expected.Audience` uses) |
| `jwt.Map` | `type Map = map[string]any` | Convenience alias for ad hoc claims |
| `jwt.MaxAge` | `func MaxAge(maxAge time.Duration) SignOptionFunc` | Sets `Expiry`/`IssuedAt` from `Clock()+maxAge`/`Clock()`; `maxAge <= time.Second` returns `NoMaxAge` instead |
| `jwt.NoMaxAge` | `var NoMaxAge SignOptionFunc` | Sets both `Expiry` and `IssuedAt` to `0` (no expiration) |
| `jwt.MaxAgeMap` | `func MaxAgeMap(maxAge time.Duration, claims Map)` | Same idea for a `Map` you build by hand; no-op if `claims` is `nil`, `maxAge <= time.Second`, or `claims["exp"]` is already set |
| `jwt.ID` | `func ID(id string) SignOptionFunc` | Sets `"jti"` |
| `jwt.OriginID` | `func OriginID(id string) SignOptionFunc` | Sets the non-standard `"origin_jti"` (links a refresh token to the access token it was issued with; see `SignPair`) |
| `jwt.Issuer` | `func Issuer(issuer string) SignOptionFunc` | Sets `"iss"` |
| `jwt.Subject` | `func Subject(subject string) SignOptionFunc` | Sets `"sub"` |
| `jwt.NotBefore` | `func NotBefore(t time.Time) SignOptionFunc` | Sets `"nbf"` from an absolute time |
| `jwt.IssuedAt` | `func IssuedAt(t time.Time) SignOptionFunc` | Sets `"iat"` from an absolute time, overriding what `MaxAge` would set |
| `jwt.ExpiresAt` | `func ExpiresAt(t time.Time) SignOptionFunc` | Sets `"exp"` from an absolute time; prefer `MaxAge` unless the expiry is dictated by something other than the signing moment |
| `jwt.SignOption` | `interface { ApplyClaims(*Claims) }` | `Claims`, `Audience` and every function above implement it |
| `jwt.SignOptionFunc` | `type SignOptionFunc func(*Claims)` | Function-literal `SignOption`; also what every helper above returns |
| `jwt.Merge` | `func Merge(values ...any) ([]byte, error)` | Splices N JSON objects (struct, map, `[]byte`, `string`, or `json.Marshaler`) into one; later duplicate keys win; what `Sign` uses internally to combine `claims` with the accumulated `SignOption` result |
| `jwt.ErrNotJSONObject` | `var ErrNotJSONObject error` | From `Merge` when a value does not marshal to a JSON object |
| `jwt.Clock` | `var Clock func() time.Time = time.Now` | Every expiry/nbf/iat check and every `MaxAge`/`Leeway`/`Skew` calculation reads this; override for deterministic tests, restore afterward |
| `jwt.Marshal` | `var Marshal func(v any) ([]byte, error)` | Used to encode the payload; default passes `[]byte` through untouched, otherwise `encoding/json/v2` with an option set chosen to reproduce `json.Marshal`'s (v1) byte-for-byte output |
| `jwt.Unmarshal` | `var Unmarshal func(data []byte, v any) error = defaultUnmarshal` | Used by `VerifiedToken.Claims`/`UnverifiedToken.Claims` (and their `ClaimsAs[T]` wrappers); default decodes with `encoding/json/v2` plus a custom unmarshal hook that reproduces `json.Decoder.UseNumber()` for an `any` destination (numbers stay `json.Number`, not `float64`), and tolerates duplicate keys and case-differing standard claim names, matching v1's own behavior |
| `jwt.UnmarshalWithRequired` | `func UnmarshalWithRequired(payload []byte, dest any) error` | Drop-in replacement for `Unmarshal` that also enforces `json:"field,required"` tags on `dest`, recursing into embedded structs |
| `jwt.HasRequiredJSONTag` | `func HasRequiredJSONTag(field reflect.StructField) bool` | True if an exported field's `json` tag contains `,required` |
| `jwt.ErrMissingKey` | `var ErrMissingKey error` | From `UnmarshalWithRequired` when a required field is zero-valued or absent |

## Algorithms

| Symbol | Signature | Purpose |
| --- | --- | --- |
| `jwt.Alg` | `interface { Name() string; Sign(key PrivateKey, headerAndPayload []byte) ([]byte, error); Verify(key PublicKey, headerAndPayload []byte, signature []byte) error }` | What `Sign`/`Verify` dispatch through; implement it yourself for a custom algorithm |
| `jwt.AlgParser` | `interface { Parse(private, public []byte) (PrivateKey, PublicKey, error) }` | Optional; implemented by every built-in `Alg` except `NONE`; used by `KeysConfiguration.Load` |
| `jwt.NONE` | `Alg` (`*algNONE`) | `"none"`; `Sign` returns an empty signature, `Verify` accepts only an empty signature. See `security.md` before using it for anything |
| `jwt.HS256` / `HS384` / `HS512` | `Alg` (`*algHMAC`) | Key type (both directions): `[]byte`. No minimum length is enforced by the type |
| `jwt.RS256` / `RS384` / `RS512` | `Alg` (`*algRSA`), PKCS#1 v1.5 | Sign key: `*rsa.PrivateKey`. Verify key: `*rsa.PublicKey` (a `*rsa.PrivateKey` is also accepted; its public half is extracted) |
| `jwt.PS256` / `PS384` / `PS512` | `Alg` (`*algRSAPSS`), RSASSA-PSS, `PSSSaltLengthAuto` | Same key types as RS256/384/512 |
| `jwt.ES256` / `ES384` / `ES512` | `Alg` (`*algECDSA`), curves P-256/P-384/P-521 | Sign key: `*ecdsa.PrivateKey`. Verify key: `*ecdsa.PublicKey` (or `*ecdsa.PrivateKey`) |
| `jwt.EdDSA` | `Alg` (`*algEdDSA`), Ed25519 | Sign key: `ed25519.PrivateKey` (64 bytes). Verify key: `ed25519.PublicKey` (32 bytes, or an `ed25519.PrivateKey`) |
| `jwt.ErrInvalidKey` | `var ErrInvalidKey error` | Wrong key type, `nil` key, or (ECDSA) a private key whose curve does not match the algorithm |
| `jwt.ErrTokenSignature` | `var ErrTokenSignature error` | Signature did not verify |
| `jwt.MaxTokenSize` | `var MaxTokenSize int = 64 * 1024` | `Decode` and the `Verify` family refuse anything longer with `ErrTokenSize`; read without a lock, set once at startup if you change it |
| `jwt.ErrTokenSize` | `var ErrTokenSize error` | |
| `jwt.ErrTokenForm` | `var ErrTokenForm error` | Token is not three dot-separated base64url segments |
| `jwt.ErrTokenAlg` | `var ErrTokenAlg error` | Header's algorithm does not match what the caller (or a `HeaderValidator`) expected |
| `jwt.ErrMissing` | `var ErrMissing error` | Empty/nil token passed to `Verify`/family |

## Key loading, parsing and generation

| Symbol | Signature | Purpose |
| --- | --- | --- |
| `jwt.MustGenerateRandom` | `func MustGenerateRandom(n int) []byte` | `n` cryptographically random bytes; panics on entropy failure. Use `32`/`48`/`64` for HS256/384/512 |
| `jwt.MustGenerateRandomString` | `func MustGenerateRandomString(length int) string` | Random `[a-zA-Z]` string |
| `jwt.MustGenerateRandomBase64` | `func MustGenerateRandomBase64(length int, padding rune) string` | `length` random bytes, base64-encoded; pass `jwt.NoPadding` or `base64.StdPadding` |
| `jwt.NoPadding` | `const NoPadding = base64.NoPadding` | |
| `jwt.MustLoadHMAC` | `func MustLoadHMAC(filenameOrRaw string) []byte` | Reads a file if `filenameOrRaw` names one that exists on disk, otherwise treats the string itself as the key; panics on read failure |
| `jwt.LoadHMAC` | `func LoadHMAC(filenameOrRaw string) ([]byte, error)` | Same, non-panicking |
| `jwt.MustLoadRSA` / `LoadPrivateKeyRSA` / `LoadPublicKeyRSA` | `func MustLoadRSA(privateKeyFilename, publicKeyFilename string) (*rsa.PrivateKey, *rsa.PublicKey)`; `func LoadPrivateKeyRSA(filename string) (*rsa.PrivateKey, error)`; `func LoadPublicKeyRSA(filename string) (*rsa.PublicKey, error)` | PEM file loaders (also used for PS256/384/512) |
| `jwt.ParsePrivateKeyRSA` / `ParsePublicKeyRSA` | `func ParsePrivateKeyRSA(key []byte) (*rsa.PrivateKey, error)`; `func ParsePublicKeyRSA(key []byte) (*rsa.PublicKey, error)` | Parse already-loaded PEM bytes; private accepts PKCS#1 or PKCS#8, public accepts PKIX or an X.509 certificate |
| `jwt.MustLoadECDSA` / `LoadPrivateKeyECDSA` / `LoadPublicKeyECDSA` | `func MustLoadECDSA(privateKeyFilename, publicKeyFilename string) (*ecdsa.PrivateKey, *ecdsa.PublicKey)`; `func LoadPrivateKeyECDSA(filename string) (*ecdsa.PrivateKey, error)`; `func LoadPublicKeyECDSA(filename string) (*ecdsa.PublicKey, error)` | PEM file loaders |
| `jwt.ParsePrivateKeyECDSA` / `ParsePublicKeyECDSA` | `func ParsePrivateKeyECDSA(key []byte) (*ecdsa.PrivateKey, error)`; `func ParsePublicKeyECDSA(key []byte) (*ecdsa.PublicKey, error)` | Parse PEM bytes; public accepts PKIX or a certificate |
| `jwt.MustLoadEdDSA` / `LoadPrivateKeyEdDSA` / `LoadPublicKeyEdDSA` | `func MustLoadEdDSA(privateKeyFilename, publicKeyFilename string) (ed25519.PrivateKey, ed25519.PublicKey)`; `func LoadPrivateKeyEdDSA(filename string) (ed25519.PrivateKey, error)`; `func LoadPublicKeyEdDSA(filename string) (ed25519.PublicKey, error)` | PEM file loaders |
| `jwt.ParsePrivateKeyEdDSA` / `ParsePublicKeyEdDSA` | `func ParsePrivateKeyEdDSA(key []byte) (ed25519.PrivateKey, error)`; `func ParsePublicKeyEdDSA(key []byte) (ed25519.PublicKey, error)` | Parse PKCS#8/PKIX PEM bytes |
| `jwt.GenerateEdDSA` | `func GenerateEdDSA() (publicPEM []byte, privatePEM []byte, err error)` | Generates a fresh Ed25519 pair as PEM; note the return order is `(public, private)` |
| `jwt.GenerateBase64EdDSA` | `func GenerateBase64EdDSA() (string, string, error)` | Same, as raw-standard-base64 strings, no PEM |
| `jwt.EncodePrivateKeyToPEM` | `func EncodePrivateKeyToPEM(key PrivateKey) (string, error)` | `*rsa.PrivateKey` (PKCS#1), `*ecdsa.PrivateKey` (SEC1) or `ed25519.PrivateKey` (PKCS#8) to PEM text |
| `jwt.EncodePublicKeyToPEM` | `func EncodePublicKeyToPEM(key PublicKey) (string, error)` | `*rsa.PublicKey`, `*ecdsa.PublicKey` or `ed25519.PublicKey` to PKIX PEM text |
| `jwt.ReadFile` | `var ReadFile func(filename string) ([]byte, error) = os.ReadFile` | Every `Load*`/`MustLoad*` above reads through this; point it at `embed.FS.ReadFile` or similar to load keys from something other than the OS filesystem |
| `jwt.HeaderValidator` | `type HeaderValidator func(alg string, headerDecoded []byte) (Alg, PublicKey, InjectFunc, error)` | What `VerifyWithHeaderValidator` calls instead of `CompareHeader`; returning a non-nil `Alg`/`PublicKey` overrides what the caller passed to `Verify` |
| `jwt.CompareHeader` | `var CompareHeader HeaderValidator` | Default header check used by `Verify`/`VerifyEncrypted`; a byte-exact comparison against the fixed literal header for the algorithm name given |

## Multi-key registry (`kid`-based)

See `keys-and-jwks.md` for the full walkthrough; signatures only here.

| Symbol | Signature | Purpose |
| --- | --- | --- |
| `jwt.Key` | `struct { ID string; Alg Alg; Public PublicKey; Private PrivateKey; MaxAge time.Duration; Encrypt, Decrypt InjectFunc }` | One registered key |
| `jwt.Keys` | `type Keys map[string]*Key` | The registry; NOT safe for concurrent writes |
| `(Keys).Register` | `func (keys Keys) Register(alg Alg, kid string, pubKey PublicKey, privKey PrivateKey)` | Adds/overwrites an entry; passing `nil` for `pubKey` on an HMAC `alg` reuses `privKey` as the public key automatically |
| `(Keys).Get` | `func (keys Keys) Get(kid string) (*Key, bool)` | |
| `(Keys).SignToken` | `func (keys Keys) SignToken(kid string, claims any, opts ...SignOption) ([]byte, error)` | Signs with the named key, includes `"kid"`/`"alg"` in the header, applies `Key.MaxAge` first if set |
| `(Keys).VerifyToken` | `func (keys Keys) VerifyToken(token []byte, claimsPtr any, validators ...TokenValidator) error` | Selects the key by the token's `"kid"`, verifies, decodes claims into `claimsPtr` |
| `(Keys).Verify` | `func (keys Keys) Verify(token []byte, validators ...TokenValidator) (*VerifiedToken, error)` | Same, returning the `*VerifiedToken` instead of decoding into a destination |
| `(Keys).ValidateHeader` | `func (keys Keys) ValidateHeader(alg string, headerDecoded []byte) (Alg, PublicKey, InjectFunc, error)` | Implements `HeaderValidator`; requires `"kid"`, requires the header's `"alg"` to equal the registered key's algorithm |
| `(Keys).JWKS` | `func (keys Keys) JWKS() (*JWKS, error)` | Public keys of every registered entry, as a JWKS ready to serve, sorted by `kid` for a stable response body |
| `(Keys).EnrichToken` | `func (keys Keys) EnrichToken(plainToken []byte, extraClaims any) ([]byte, error)` | Verify-then-resign against the registry; see `security.md` |
| `(Keys).SignPair` | `func (keys Keys) SignPair(claims any, opts PairOptions) (SignedPair, error)` | See "Token pair" below |
| `jwt.ErrEmptyKid` | `var ErrEmptyKid error` | Header has no `"kid"` |
| `jwt.ErrUnknownKid` | `var ErrUnknownKid error` | `"kid"` is not registered |
| `jwt.HeaderWithKid` | `struct { Kid, Alg string }` | The `"kid"`/`"alg"` header shape `ValidateHeader` parses |
| `jwt.KeysConfiguration` | `type KeysConfiguration []KeyConfiguration` | Serializable form, for JSON/YAML/TOML/INI files |
| `jwt.KeyConfiguration` | `struct { ID, Alg, Private, Public string; MaxAge time.Duration; EncryptionKey string }` | One entry; `Alg` is a name like `"RS256"` (case-insensitive on load); `EncryptionKey`, if set, is hex-decoded and passed to `GCM` |
| `(KeysConfiguration).Load` | `func (c KeysConfiguration) Load() (Keys, error)` | Parses PEM/raw key material via each algorithm's `AlgParser`; errors name the offending `id`/`alg` |
| `(KeysConfiguration).MustLoad` | `func (c KeysConfiguration) MustLoad() Keys` | Same, panics on error |
| `(KeysConfiguration).Get` | `func (c KeysConfiguration) Get(kid string) (KeyConfiguration, bool)` | |
| `(KeysConfiguration).Clone` / `(KeyConfiguration).Clone` | `func (c KeysConfiguration) Clone() KeysConfiguration`; `func (c KeyConfiguration) Clone() KeyConfiguration` | Deep copy (all fields are value types) |
| `(*Key).Configuration` | `func (key *Key) Configuration() (KeyConfiguration, error)` | PEM-encodes `Private`/`Public` back into a `KeyConfiguration`; errors if the key carries `Encrypt`/`Decrypt` (not serializable) or has no `Alg` |
| `(Keys).Configuration` | `func (keys Keys) Configuration() (KeysConfiguration, error)` | Same, for the whole registry |

## JWKS (RFC 7517)

| Symbol | Signature | Purpose |
| --- | --- | --- |
| `jwt.FetchPublicKeys` | `func FetchPublicKeys(url string) (Keys, error)` | `FetchJWKS(nil, url)` then `.PublicKeys()`; the common case |
| `jwt.FetchJWKS` | `func FetchJWKS(client HTTPClient, rawURL string) (*JWKS, error)` | Lower-level; `client == nil` uses a default client with a 15s timeout, capped redirects, and an https-only URL check (see `security.md`) |
| `jwt.HTTPClient` | `interface { Get(string) (*http.Response, error) }` | What `FetchJWKS` needs; `*http.Client` satisfies it |
| `jwt.MaxJWKSSize` | `const MaxJWKSSize = 1 << 20` | Response body is read through `io.LimitReader` bounded to this many bytes |
| `jwt.HTTPError` | `struct { StatusCode int; Body []byte }` | Returned by `FetchJWKS` for a >=400 response; `Error()` reports only the status code, `Body` is a separate field on purpose |
| `jwt.JWKS` | `struct { Keys []*JWK "json:\"keys\"" }` | A key set |
| `(*JWKS).PublicKeys` | `func (set *JWKS) PublicKeys() Keys` | Converts every recognizable `JWK` into a `Keys` entry; an entry with an unsupported `alg`/`kty` or malformed key material is silently skipped, not an error |
| `jwt.JWK` | `struct { Kty, Kid, Use, Alg, Crv, N, E, Y, X string }` | One key; fields present depend on `Kty` (`"RSA"` uses `N`/`E`, `"EC"` uses `Crv`/`X`/`Y`, `"OKP"` uses `Crv`/`X`) |
| `jwt.GenerateJWK` | `func GenerateJWK(kid string, alg string, publicKey PublicKey) (*JWK, error)` | `*rsa.PublicKey`, `*ecdsa.PublicKey`/`ecdsa.PublicKey`, or `ed25519.PublicKey` to `*JWK` |

## Remote key set (self-refreshing JWKS)

`FetchJWKS`/`FetchPublicKeys` are a single fetch. `KeySet` wraps one to stay current: it fetches
once synchronously (so a bad URL fails at startup, not on the first request), refreshes on a
timer, and additionally refreshes once, rate-limited, whenever a token names a `kid` it does not
currently hold, so a provider's key rotation does not require restarting your process. See
`keys-and-jwks.md` for the walkthrough, including why `NewCognitoKeySet` is the safer entry point
for AWS Cognito specifically.

| Symbol | Signature | Purpose |
| --- | --- | --- |
| `jwt.KeySet` | `struct { ... }` | Self-refreshing `Keys` holder; safe for concurrent use (reads never lock: the key map is swapped atomically). The zero value is not usable; build with `NewRemoteKeySet`/`NewCognitoKeySet` |
| `jwt.NewRemoteKeySet` | `func NewRemoteKeySet(url string, options ...RemoteKeySetOption) (*KeySet, error)` | Fetches `url` once before returning, then refreshes hourly by default (see options) |
| `jwt.NewCognitoKeySet` | `func NewCognitoKeySet(region, userPoolID, appClientID string, options ...RemoteKeySetOption) (*KeySet, Expected, error)` | Builds the Cognito JWKS `*KeySet` and an `Expected{Issuer: ..., Audience: ...}` validator that checks both the pool (issuer) and, if `appClientID != ""`, the app client (audience); pass both to `VerifyWithHeaderValidator` |
| `jwt.RemoteKeySetOption` | `type RemoteKeySetOption func(*KeySet)` | |
| `jwt.WithRefreshInterval` | `func WithRefreshInterval(d time.Duration) RemoteKeySetOption` | Background refresh period; default 1 hour; `0` disables the timer (on-demand refresh via unknown `kid` still applies) |
| `jwt.WithMinRefreshInterval` | `func WithMinRefreshInterval(d time.Duration) RemoteKeySetOption` | Floor between two unknown-`kid`-triggered refreshes; default 1 minute; without this, a stream of tokens naming a nonexistent `kid` (which is free for anyone to send) becomes a stream of outbound requests |
| `jwt.WithHTTPClient` | `func WithHTTPClient(client HTTPClient) RemoteKeySetOption` | Overrides the default 15s/https-only client used for every fetch |
| `(*KeySet).Keys` | `func (ks *KeySet) Keys() Keys` | Current snapshot; do not mutate the returned map |
| `(*KeySet).Refresh` | `func (ks *KeySet) Refresh() error` | Fetches now, regardless of timers; a failed fetch leaves the previous keys in place |
| `(*KeySet).ValidateHeader` | `func (ks *KeySet) ValidateHeader(alg string, headerDecoded []byte) (Alg, PublicKey, InjectFunc, error)` | Implements `HeaderValidator`; drop-in wherever `Keys.ValidateHeader` would go |
| `(*KeySet).Verify` | `func (ks *KeySet) Verify(token []byte, validators ...TokenValidator) (*VerifiedToken, error)` | |
| `(*KeySet).Close` | `func (ks *KeySet) Close() error` | Stops the background refresh goroutine; safe to call more than once |
| `jwt.ErrKeySetEmpty` | `var ErrKeySetEmpty error` | A fetch that succeeded (HTTP-wise) but produced zero usable keys, e.g. every `JWK` had an algorithm/key type this package does not recognize |

## AWS Cognito

| Symbol | Signature | Purpose |
| --- | --- | --- |
| `jwt.FetchAWSCognitoPublicKeys` | `func FetchAWSCognitoPublicKeys(region, userPoolID string) (Keys, error)` | Builds the Cognito JWKS URL from `region`/`userPoolID` (both charset-checked first) and fetches it once, uncached. Verifying against the result with plain `Keys.VerifyToken` checks the signature only, **not** issuer or audience; prefer `jwt.NewCognitoKeySet`, which returns both a self-refreshing key set and the `Expected` validator that checks those |
| `jwt.AWSCognitoError` | `struct { StatusCode int; Message string }` | Returned when Cognito answers >=400 with a body this package can parse; `Error()` prefixes `Message` to mark it as remote-supplied text |

## Token pair (access + refresh)

| Symbol | Signature | Purpose |
| --- | --- | --- |
| `jwt.TokenPair` | `struct { AccessToken, RefreshToken, IDToken string "json:\"...,omitempty\"" }` | JSON response shape |
| `jwt.NewTokenPair` | `func NewTokenPair(accessToken, refreshToken []byte) TokenPair` | Wraps two already-signed tokens; an empty argument is left out of the JSON |
| `jwt.SignedPair` | `struct { AccessToken, RefreshToken []byte; AccessClaims, RefreshClaims Claims }` | Result of signing a linked pair |
| `(SignedPair).TokenPair` | `func (p SignedPair) TokenPair() TokenPair` | Converts to the response shape |
| `jwt.PairOptions` | `struct { AccessKID, RefreshKID string; AccessOptions, RefreshOptions []SignOption; GenerateID func() (string, error); Unlinked bool }` | `RefreshKID` defaults to `AccessKID` when empty (package-level `SignPair` ignores both); `GenerateID` defaults to a version 7 UUID (time-ordered, from the stdlib `uuid` package); `Unlinked` skips setting the refresh token's `"origin_jti"` |
| `jwt.SignPair` | `func SignPair(alg Alg, key PrivateKey, claims any, opts PairOptions) (SignedPair, error)` | Signs both halves with one key; generates and links `"jti"`/`"origin_jti"` unless `Unlinked` |
| `(Keys).SignPair` | `func (keys Keys) SignPair(claims any, opts PairOptions) (SignedPair, error)` | Same, routed through the registry so each half can use its own `kid`; requires `opts.AccessKID` |

## Enrich (add claims to an already-signed token)

| Symbol | Signature | Purpose |
| --- | --- | --- |
| `jwt.Enrich` | `func Enrich(alg Alg, key PrivateKey, accessToken []byte, extraClaims any) ([]byte, error)` | Verifies `accessToken` under `alg`/`key` first, merges `extraClaims` into its payload, re-signs; refuses `nil` and `NONE` for `alg` |
| `(*UnverifiedToken).Enrich` | `func (t *UnverifiedToken) Enrich(alg Alg, key PrivateKey, extraClaims any) ([]byte, error)` | Same idea on the result of `Decode`, which performs **no** verification; only use this when the token's authenticity is already established some other way. The new header is built from `alg`, not copied, so a `"kid"` on the input is dropped |
| `(Keys).EnrichToken` | `func (keys Keys) EnrichToken(plainToken []byte, extraClaims any) ([]byte, error)` | Verify-then-resign through the registry; the key and algorithm come from the token's own `"kid"`, not a parameter, so neither can be chosen by whoever supplied the token |

## Decode (parse without verifying)

| Symbol | Signature | Purpose |
| --- | --- | --- |
| `jwt.Decode` | `func Decode(token []byte) (*UnverifiedToken, error)` | Splits and base64url-decodes the three segments; performs no signature check and no claims validation whatsoever |
| `jwt.UnverifiedToken` | `struct { Header, Payload, Signature []byte }` | |
| `(*UnverifiedToken).Claims` | `func (t *UnverifiedToken) Claims(dest any) error` | Unmarshal the (unverified) payload |
| `(*UnverifiedToken).ClaimsAs` | `func (t *UnverifiedToken) ClaimsAs[T any]() (T, error)` | Generic form of `Claims`; same SECURITY WARNING applies |
| `(*UnverifiedToken).Alg` | `func (t *UnverifiedToken) Alg() (Alg, error)` | Reads `"alg"` from the header and resolves it against the built-in algorithm list; errors for a custom `Alg` not in that list |
| `(*UnverifiedToken).Kid` | `func (t *UnverifiedToken) Kid() (string, error)` | Reads `"kid"` from the header |

## Encryption (payload confidentiality)

| Symbol | Signature | Purpose |
| --- | --- | --- |
| `jwt.GCM` | `func GCM(key, additionalData []byte) (encrypt, decrypt InjectFunc, err error)` | AES-GCM authenticated encryption; `key` must be 16/24/32 bytes for AES-128/192/256; encrypt-then-sign is the intended flow (encrypt the payload, then sign the whole token with a possibly different key) |
| `jwt.InjectFunc` | `type InjectFunc func(plainPayload []byte) ([]byte, error)` | The shape `GCM` returns and what `SignEncrypted`/`VerifyEncrypted` take |
| `jwt.ErrDecrypt` | `var ErrDecrypt error` | Uniform error for any decryption failure: wrong key, corrupted ciphertext, or a failed GCM authentication tag are not distinguished |

There is no JWE support; `token_jwe.go` is a design note, not code (see the README's "Encryption" section). `GCM` plus `SignEncrypted`/`VerifyEncrypted` is the library's answer to payload confidentiality.

## Validators, blocklist, classification

Full signatures and composition rules are in `validators.md`; the essentials:

| Symbol | Signature | Purpose |
| --- | --- | --- |
| `jwt.TokenValidator` | `interface { ValidateToken(token []byte, standardClaims Claims, err error) error }` | |
| `jwt.TokenValidatorFunc` | `type TokenValidatorFunc func(token []byte, standardClaims Claims, err error) error` | |
| `jwt.Expected` | `type Expected Claims` (implements `TokenValidator`) | Exact-match check against non-zero fields |
| `jwt.ErrExpected` | `var ErrExpected error` | |
| `jwt.Leeway` | `func Leeway(leeway time.Duration) TokenValidatorFunc` | Rejects a token expiring within `leeway` |
| `jwt.Future` | `func Future(dur time.Duration) TokenValidatorFunc` | Tolerates `"iat"` up to `dur` in the future |
| `jwt.Skew` | `func Skew(d time.Duration) TokenValidatorFunc` | Tolerates both `"nbf"` and `"iat"` clock skew up to `d` |
| `jwt.RequireExpiry` | `var RequireExpiry TokenValidatorFunc` | Rejects a token with no `"exp"` at all |
| `jwt.Validators` | `func Validators(values ...any) []TokenValidator` | Flattens a mix of `TokenValidator`, `TokenValidatorFunc`, plain matching funcs, and slices of either, dropping nils |
| `jwt.Blocklist` | `struct { GetKey func(token []byte, claims Claims) string; ... }` (implements `TokenValidator`) | In-memory revocation list; the clock is set through `SetClock`, not a field |
| `jwt.NewBlocklist` | `func NewBlocklist(gcEvery time.Duration) *Blocklist` | `gcEvery == 0` disables automatic GC |
| `jwt.NewBlocklistContext` | `func NewBlocklistContext(ctx context.Context, gcEvery time.Duration) *Blocklist` | Same, GC goroutine stops when `ctx` is done |
| `(*Blocklist).Close` | `func (b *Blocklist) Close() error` | Stops the GC goroutine; safe to call more than once; always returns `nil` |
| `(*Blocklist).SetClock` | `func (b *Blocklist) SetClock(fn func() time.Time)` | Per-blocklist clock for GC; safe to call while the GC goroutine runs; `nil` restores the package-level `Clock` |
| `(*Blocklist).InvalidateToken` | `func (b *Blocklist) InvalidateToken(token []byte, c Claims) error` | |
| `(*Blocklist).Has` / `Del` / `Count` / `GC` | `func (b *Blocklist) Has(key string) (bool, error)`; `Del(key string) error`; `Count() (int64, error)`; `GC() int` | |
| `jwt.DefaultBlocklistKey` | `func DefaultBlocklistKey(token []byte, c Claims) string` | `c.ID` if non-empty, else the raw token bytes as a string |
| `jwt.TokenBlocklist` | `interface { TokenValidator; InvalidateToken(...) error; Del(key string) error; Has(key string) (bool, error); Count() (int64, error) }` | Method set of `*Blocklist`; accept this instead of `*Blocklist` if you swap in a Redis-backed implementation |
| `jwt.ErrBlocked` | `var ErrBlocked error` | |
| `jwt.ErrorKind` | `type ErrorKind uint8`, consts `KindNone`, `KindMalformed`, `KindInvalid`, `KindExpired`, `KindRejected` | |
| `jwt.Classify` | `func Classify(err error) ErrorKind` | Collapses this package's sentinel errors (and anything unrecognized, as `KindInvalid`) into one of the five kinds |

## HTTP token extraction

| Symbol | Signature | Purpose |
| --- | --- | --- |
| `jwt.TokenExtractor` | `type TokenExtractor func(r *http.Request) []byte` | Returns `nil` when the request does not carry a token where it looks |
| `jwt.BearerPrefix` | `const BearerPrefix = "Bearer"` | |
| `jwt.FromHeader` | `func FromHeader(names ...string) TokenExtractor` | Default `["Authorization"]`; accepts a bare token or `"Bearer <token>"` (case-insensitive scheme) |
| `jwt.FromQuery` | `func FromQuery(names ...string) TokenExtractor` | Default `["access_token", "token"]`; avoid for anything but cases where a header is impossible |
| `jwt.FromCookie` | `func FromCookie(name string) TokenExtractor` | A token in a cookie needs your own CSRF protection; set `SameSite`/`HttpOnly` when writing it |
| `jwt.ExtractToken` | `func ExtractToken(r *http.Request, extractors ...TokenExtractor) []byte` | Default `[FromHeader()]`; returns the first non-empty result. `Verify` returns `ErrMissing` for a `nil` token, so a missing and a bad credential land in the same place |

## Utilities

| Symbol | Signature | Purpose |
| --- | --- | --- |
| `jwt.Base64Encode` | `func Base64Encode(src []byte) []byte` | Unpadded base64url, the JWT segment encoding |
| `jwt.Base64Decode` | `func Base64Decode(src []byte) ([]byte, error)` | Inverse; tolerates input with or without padding |
| `jwt.BytesToString` | `func BytesToString(b []byte) string` | Zero-copy by default (`unsafe`); build with `-tags safe` for an allocating, fully safe version. Do not mutate the source bytes after calling the default build's version |
