package jwt

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
)

var (
	// ErrMissing indicates that a given token to `Verify` is empty.
	ErrMissing = errors.New("token is empty")
	// ErrTokenForm indicates that the extracted token has not the expected form .
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
// Decodes and verifies the given compact "token".
// It returns the header, payoad and signature parts (decoded).
func decodeToken(alg Alg, key PublicKey, token []byte) ([]byte, []byte, []byte, error) {
	parts := bytes.Split(token, sep)
	if len(parts) != 3 {
		return nil, nil, nil, ErrTokenForm
	}

	header := parts[0]
	payload := parts[1]
	signature := parts[2]

	headerDecoded, err := Base64Decode(header)
	if err != nil {
		return nil, nil, nil, err
	}
	// validate header equality.
	expectedHeader := createHeaderRaw(alg.Name())
	if !bytes.Equal(expectedHeader, headerDecoded) {
		return nil, nil, nil, ErrTokenAlg
	}

	signatureDecoded, err := Base64Decode(signature)
	if err != nil {
		return nil, nil, nil, err
	}
	// validate signature.
	headerPayload := joinParts(header, payload)
	if err := alg.Verify(key, headerPayload, signatureDecoded); err != nil {
		return nil, nil, nil, err
	}

	payload, err = Base64Decode(payload)
	if err != nil {
		return nil, nil, nil, err
	}
	return headerDecoded, payload, signatureDecoded, nil
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
type fixedHeader struct {
	raw     []byte
	encoded []byte
}

var fixedHeaders = map[string]*fixedHeader{
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
		fixedHeaders[k] = &fixedHeader{
			raw:     createHeaderRaw(k),
			encoded: createHeader(k),
		}
	}
}

func createHeader(alg string) []byte {
	if header := fixedHeaders[alg]; header != nil {
		return header.encoded
	}

	return Base64Encode([]byte(`{"alg":"` + alg + `","typ":"JWT"}`))
}

func createHeaderRaw(alg string) []byte {
	if header := fixedHeaders[alg]; header != nil {
		return header.raw
	}

	return []byte(`{"alg":"` + alg + `","typ":"JWT"}`)
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
