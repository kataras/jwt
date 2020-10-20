package jwt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

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
}

func init() {
	for k := range fixedHeaders {
		fixedHeaders[k] = createHeader(k)
	}
}

var (
	// ErrTokenForm indicates that the extracted token has not the expected form (it's not a JWT).
	ErrTokenForm = errors.New("invalid token form")
	// ErrTokenAlg indicates that the given algorithm does not match the extracted one.
	ErrTokenAlg = errors.New("unexpected token algorithm")
)

// Token generates a new token based on the algorithm and a secret key.
// The claims is the payload, the actual body of the token, should
// contain information about a specific authorized client.
// Note that the payload part is not encrypted
// therefore, it should NOT contain any private information.
//
// Example Code:
//
//  token, err := jwt.Token(jwt.HS256, []byte("secret"), map[string]interface{}{
//    "iat": now.Unix(),
//    "exp": now.Add(15 * time.Minute).Unix(),
//    "foo": "bar",
//  })
func Token(alg Alg, secret interface{}, claims interface{}) ([]byte, error) {
	return encodeToken(alg, secret, claims)
}

// VerifiedToken holds the information about a verified token.
// Look `VerifyToken` for more.
type VerifiedToken struct {
	// Note:
	// We don't provide information for header and signature parts
	// unless is requested.
	Token   []byte
	Payload []byte
	Claims  Claims
	Dest    interface{}
}

// VerifyToken decodes and verifies the given "token" based
// on the algorithm and the secret key that this token was generated with.
// It binds the payload part to the "dest" if not nil,
// it can be a json.RawMessage to delay unmarshal for multiple destinations
// or use the return VerifiedToken's Payload to unmarshal more custom data.
// The last variadic input argument is optional, can be used
// for further claims validations before exit.
// Returns the verified token information.
//
// Example Code:
//
//  var claims map[string]interface{}
//  verifiedToken, err := jwt.VerifyToken(jwt.HS256, []byte("secret"), time.Now(), token, &claims)
func VerifyToken(
	alg Alg,
	secret interface{},
	t time.Time,
	token []byte,
	dest interface{}, validators ...ClaimsValidator,
) (*VerifiedToken, error) {
	payload, err := decodeToken(alg, secret, token)
	if err != nil {
		return nil, err
	}

	var claims Claims
	err = json.Unmarshal(payload, &claims)
	if err != nil {
		return nil, err
	}

	err = validateClaims(t, claims, validators...)
	if err != nil {
		return nil, err
	}

	if dest != nil {
		err = json.Unmarshal(payload, &dest)
	}

	verifiedTok := &VerifiedToken{
		Token:   token,
		Payload: payload,
		Claims:  claims,
		Dest:    dest,
	}
	return verifiedTok, nil
}

func encodeToken(alg Alg, secret interface{}, claims interface{}) ([]byte, error) {
	header := createHeader(alg.Name())

	payload, err := createPayload(claims)
	if err != nil {
		return nil, fmt.Errorf("encodeToken: payload: %w", err)
	}

	headerPayload := joinParts(header, payload)

	signature, err := createSignature(alg, secret, headerPayload)
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
func decodeToken(alg Alg, secret interface{}, token []byte) ([]byte, error) {
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
	if err := alg.Verify(headerPayload, signatureDecoded, secret); err != nil {
		return nil, err
	}

	return Base64Decode(payload)
}

var (
	sep = []byte(".")
	pad = []byte("=")
)

func joinParts(parts ...[]byte) []byte {
	return bytes.Join(parts, sep)
}

func createHeader(alg string) []byte {
	if header, ok := fixedHeaders[alg]; ok && len(header) > 0 {
		return header
	}

	header := []byte(`{"alg":"` + alg + `","typ":"JWT"}`)
	return Base64Encode(header)
}

func createPayload(claims interface{}) ([]byte, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}

	return Base64Encode(payload), nil
}

func createSignature(alg Alg, secret interface{}, headerAndPayload []byte) ([]byte, error) {
	signature, err := alg.Sign(headerAndPayload, secret)
	if err != nil {
		return nil, err
	}
	return Base64Encode(signature), nil
}

// Base64Encode encodes "src" to jwt base64 url format.
func Base64Encode(src []byte) []byte {
	buf := make([]byte, base64.URLEncoding.EncodedLen(len(src)))
	base64.URLEncoding.Encode(buf, src)

	return bytes.TrimRight(buf, string(pad)) // JWT: no trailing '='.
}

// Base64Decode decodes "src" to jwt base64 url format.
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
