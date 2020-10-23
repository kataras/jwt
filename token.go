package jwt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

var (
	// ErrTokenForm indicates that the extracted token has not the expected form (it's not a JWT).
	ErrTokenForm = errors.New("invalid token form")
	// ErrTokenAlg indicates that the given algorithm does not match the extracted one.
	ErrTokenAlg = errors.New("unexpected token algorithm")
)

type (
	// PrivateKey is a generic type, this key is responsible for signing the token.
	PrivateKey interface{}
	// PublicKey is a generic type, this key is responsible to verify the token.
	PublicKey interface{}
)

// Sign signs and generates a new token based on the algorithm and a secret key.
// The claims is the payload, the actual body of the token, should
// contain information about a specific authorized client.
// Note that the payload part is not encrypted
// therefore, it should NOT contain any private information.
// See the `Verify` function to decode and verify the result token.
//
// Example Code:
//
//  now := time.Now()
//  token, err := jwt.Sign(jwt.HS256, []byte("secret"), map[string]interface{}{
//    "iat": now.Unix(),
//    "exp": now.Add(15 * time.Minute).Unix(),
//    "foo": "bar",
//  })
func Sign(alg Alg, key PrivateKey, claims interface{}) ([]byte, error) {
	return encodeToken(alg, key, claims)
}

// Merge accepts custom and standard claims
// and returns a flattened JSON result of both.
// Usage:
//  Merge(map[string]interface{}{"foo":"bar"}, jwt.Claims{
//    MaxAge: 15 * time.Minute,
//    Issuer: "an-issuer",
//  })
func Merge(custom interface{}, claims Claims) []byte {
	// set the expiration through the MaxAge field helper.
	if maxAge := claims.MaxAge; maxAge > time.Second {
		now := Clock()
		claims.Expiry = now.Add(maxAge).Unix()
		claims.IssuedAt = now.Unix()
	}

	claimsB, err := Marshal(claims)
	if err != nil {
		return nil
	}

	customB, err := Marshal(custom)
	if err != nil {
		return nil
	}

	if len(customB) == 0 {
		return claimsB
	}

	claimsB = claimsB[0 : len(claimsB)-1] // remove last '}'
	customB = customB[1:]                 // remove first '{'

	raw := append(claimsB, ',')
	raw = append(raw, customB...)
	return raw
}

// VerifiedToken holds the information about a verified token.
// Look `Verify` for more.
type VerifiedToken struct {
	// Note:
	// We don't provide information for header and signature parts
	// unless is requested on feature requests.
	Token          []byte
	Payload        []byte
	StandardClaims Claims
}

// Claims decodes the token's payload to the "dest".
// If the application requires custom claims, this is the method to Go.
//
// It calls the `Unmarshal(t.Payload, dest)` package-level function .
// When called, it decodes the token's payload (aka claims)
// to the "dest" pointer of a struct or map value.
// Note that the `StandardClaims` field is always set,
// as it contains the standard JWT claims,
// and validated at the `Verify` function itself,
// therefore NO FURTHER STEP is required
// to validate the "exp", "iat" and "nbf" claims.
func (t *VerifiedToken) Claims(dest interface{}) error {
	return Unmarshal(t.Payload, dest)
}

// TokenValidator provides further token and claims validation.
type TokenValidator interface {
	// ValidateToken accepts the token, the claims extracted from that
	// and any error that may caused by claims validation (e.g. ErrExpired)
	// or the previous validator.
	// A token validator can skip the builtin validation and return a nil error.
	// Usage:
	//  func(v *myValidator) ValidateToken(token []byte, claims Claims, err error) error {
	//    if err!=nil { return err } <- to respect the previous error
	//    // otherwise return nil or any custom error.
	//  }
	ValidateToken(token []byte, claims Claims, err error) error
}

// Verify decodes, verifies and validates the standard JWT claims
// of the given "token" using the algorithm and
// the secret key that this token was generated with.
//
// It returns a VerifiedToken which can be used to
// read the standard claims and some read-only information about the token.
// That VerifiedToken contains a `Claims` method, useful
// to bind the token's payload(claims) to a custom Go struct or a map when necessary.
//
// The last variadic input argument is optional, can be used
// for further claims validations before exit.
// Returns the verified token information.
//
// Example Code:
//
//  verifiedToken, err := jwt.Verify(jwt.HS256, []byte("secret"), token)
//  [handle error...]
//  var claims map[string]interface{}
//  verifiedToken.Claims(&claims)
func Verify(
	alg Alg,
	key PublicKey,
	token []byte,
	validators ...TokenValidator,
) (*VerifiedToken, error) {
	payload, err := decodeToken(alg, key, token)
	if err != nil {
		return nil, err
	}

	var claims Claims
	err = json.Unmarshal(payload, &claims) // use the standard one instead of the custom, no need to support "required" feature here.
	if err != nil {
		return nil, err
	}

	err = validateClaims(Clock(), claims)
	for _, validator := range validators {
		if validator == nil {
			continue
		}
		// A token validator can skip the builtin validation and return a nil error,
		// in that case the previous error is skipped.
		if err = validator.ValidateToken(token, claims, err); err != nil {
			break
		}
	}

	if err != nil {
		return nil, err
	}

	verifiedTok := &VerifiedToken{
		Token:          token,
		Payload:        payload,
		StandardClaims: claims,
	}
	return verifiedTok, nil
}

func encodeToken(alg Alg, key PrivateKey, claims interface{}) ([]byte, error) {
	header := createHeader(alg.Name())

	payload, err := createPayload(claims)
	if err != nil {
		return nil, fmt.Errorf("encodeToken: payload: %w", err)
	}

	headerPayload := joinParts(header, payload)

	signature, err := createSignature(alg, key, headerPayload)
	if err != nil {
		return nil, fmt.Errorf("encodeToken: signature: %v", err)
	}

	// header.payload.signature
	token := joinParts(headerPayload, signature)

	return token, nil
}

// We could omit the "alg" because the token contains it
// BUT, for security reason the algorithm MUST explicitly match
// (even if we perform hash comparison later on).
//
// Decodes and verifies the given "token".
// It returns the payload/body/data part.
func decodeToken(alg Alg, key PublicKey, token []byte) ([]byte, error) {
	parts := bytes.Split(token, sep)
	if len(parts) != 3 {
		return nil, ErrTokenForm
	}

	header := parts[0]
	expectedHeader := createHeader(alg.Name())
	if !bytes.Equal(header, expectedHeader) {
		return nil, ErrTokenAlg
	}

	payload := parts[1]
	signature := parts[2]
	signatureDecoded, err := Base64Decode(signature)
	if err != nil {
		return nil, err
	}
	headerPayload := joinParts(header, payload)
	if err := alg.Verify(key, headerPayload, signatureDecoded); err != nil {
		return nil, err
	}

	return Base64Decode(payload)
}

var (
	sep    = []byte(".")
	pad    = []byte("=")
	padStr = string(pad)
)

func joinParts(parts ...[]byte) []byte {
	return bytes.Join(parts, sep)
}

// A builtin list of fixed headers for builtin algorithms (to boost the performance a bit).
// key = alg, value = the base64encoded full header
// (when kid or any other extra headers are not required to be inside).
var fixedHeaders = map[string][]byte{
	NONE.Name():  nil,
	HS256.Name(): nil,
	HS384.Name(): nil,
	HS512.Name(): nil,
	RS256.Name(): nil,
	RS384.Name(): nil,
	RS512.Name(): nil,
	ES256.Name(): nil,
	ES384.Name(): nil,
	ES512.Name(): nil,
	EdDSA.Name(): nil,
}

func init() {
	for k := range fixedHeaders {
		fixedHeaders[k] = createHeader(k)
	}
}

func createHeader(alg string) []byte {
	if header, ok := fixedHeaders[alg]; ok && len(header) > 0 {
		return header
	}

	header := []byte(`{"alg":"` + alg + `","typ":"JWT"}`)
	return Base64Encode(header)
}

func createPayload(claims interface{}) ([]byte, error) {
	payload, err := Marshal(claims)
	if err != nil {
		return nil, err
	}

	return Base64Encode(payload), nil
}

func createSignature(alg Alg, key PrivateKey, headerAndPayload []byte) ([]byte, error) {
	signature, err := alg.Sign(key, headerAndPayload)
	if err != nil {
		return nil, err
	}
	return Base64Encode(signature), nil
}

// Base64Encode encodes "src" to jwt base64 url format.
// We could use the base64.RawURLEncoding but the below is a bit faster.
func Base64Encode(src []byte) []byte {
	buf := make([]byte, base64.URLEncoding.EncodedLen(len(src)))
	base64.URLEncoding.Encode(buf, src)

	return bytes.TrimRight(buf, padStr) // JWT: no trailing '='.
}

// Base64Decode decodes "src" to jwt base64 url format.
// We could use the base64.RawURLEncoding but the below is a bit faster.
func Base64Decode(src []byte) ([]byte, error) {
	if n := len(src) % 4; n > 0 {
		// JWT: Because of no trailing '=' let's suffix it
		// with the correct number of those '=' before decoding.
		src = append(src, bytes.Repeat(pad, 4-n)...)
	}

	buf := make([]byte, base64.URLEncoding.DecodedLen(len(src)))
	n, err := base64.URLEncoding.Decode(buf, src)
	return buf[:n], err
}

/* Good idea but costs in performance, it's better
to load the original key before it's passed to the public token API.
So instead of the below, it's better to export some helper functions,
e.g. for loading key pairs from PEM files.
Now, the question is to have all those helpers in the main package?
Or:
1) create different subpackages (e.g. jwt/rsa, jwt/ecdsa, jwt/eddsa)
1.1) this introduce another question: maybe it's better to move the alg impl on their packages?
2) have them inside the main package, in the alg's source file (so they're easier to lookup),
and also have common prefix names so their API is easy visible to end-developers, e.g.
LoadPrivateKeyRSA/ECDSA/EdDSA(filename) - ParsePrivateKeyRSA/ECDSA/EdDSA(keyBytes) and
LoadPublicKeyRSA/ECDSA/EdDSA(filename)  - ParsePublicKeyRSA/ECDSA/EdDSA(keyBytes) and
MustLoadRSA/ECDSA/EdDSA(privateFilename, publicFilename string) as a shortcut for the above.

^ The 2nd option was chosen.

func (key PrivateKey) parse(alg string) interface{} {
	switch alg {
	case HS256.Name(), HS384.Name(), HS512.Name(): // expect string or []byte
	case RS256.Name(), RS384.Name(), RS512.Name(), PS256.Name(), PS384.Name(), PS512.Name():
	case ES256.Name(), ES384.Name(), ES512.Name():
	case EdDSA.Name():
	default:
		return key
	}
}
*/
