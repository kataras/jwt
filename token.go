package jwt

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
)

var algorithms = map[string]func() hash.Hash{
	"HS256": sha256.New,
}

var (
	errAlgorithmUnsporrted = errors.New("algorithm unsupported")
	errTokenForm           = errors.New("invalid token form")
	errTokenAlg            = errors.New("unexpected token algorithm")
	errTokenSignature      = errors.New("invalid token signature")
)

func generateToken(claims interface{}, alg string, secret []byte) ([]byte, error) {
	header := createHeader(alg)

	payload, err := createPayload(claims)
	if err != nil {
		return nil, fmt.Errorf("generateToken: payload: %w", err)
	}

	signature, err := createSignature(alg, secret, header, payload)
	if err != nil {
		return nil, fmt.Errorf("generateToken: signature: %w", err)
	}

	// header.payload.signature
	token := bytes.Join([][]byte{
		header,
		payload,
		signature,
	}, sep)

	return token, nil
}

// We could omit the "alg" because the token contains it
// BUT, for security reason the algorithm MUST explicitly match
// (even if we perform hash comparison later on).
//
// Decodes and verifies the given "token".
// It returns the payload/body/data part.
func verifyToken(token []byte, alg string, secret []byte) ([]byte, error) {
	parts := bytes.Split(token, sep)
	if len(parts) != 3 {
		return nil, errTokenForm
	}

	header := parts[0]
	expectedHeader := createHeader(alg)
	if !bytes.Equal(header, expectedHeader) {
		return nil, errTokenAlg
	}

	payload := parts[1]
	signature := parts[2]
	expectedSignature, err := createSignature(alg, secret, header, payload)
	if err != nil {
		return nil, err
	}

	// The important stuff:
	if !bytes.Equal(signature, expectedSignature) {
		return nil, errTokenSignature
	}

	return base64Decode(payload)
}

var (
	sep = []byte(".")
	eq  = []byte("=")
)

func createHeader(alg string) []byte {
	header := []byte(`{"alg":"` + alg + `","typ":"JWT"}`)
	return base64Encode(header)
}

func createPayload(claims interface{}) ([]byte, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}

	return base64Encode(payload), nil
}

func createSignature(alg string, secret []byte, header, payload []byte) ([]byte, error) {
	hasher, ok := algorithms[alg]
	if !ok {
		return nil, errAlgorithmUnsporrted
	}

	h := hmac.New(hasher, secret)
	// header.payload
	headerPayload := append(header, append(sep, payload...)...)
	_, err := h.Write(headerPayload)
	if err != nil {
		return nil, err // this should never happen according to the internal docs.
	}

	signature := h.Sum(nil)
	return base64Encode(signature), nil
}

func base64Encode(src []byte) []byte {
	buf := make([]byte, base64.URLEncoding.EncodedLen(len(src)))
	base64.URLEncoding.Encode(buf, src)

	return bytes.TrimRight(buf, string(eq)) // JWT: no trailing '='.
}

func base64Decode(src []byte) ([]byte, error) {
	if n := len(src) % 4; n > 0 {
		// JWT: Because of no trailing '=' let's suffix it
		// with the correct number of those '=' before decoding.
		src = append(src, bytes.Repeat(eq, 4-n)...)
	}

	buf := make([]byte, base64.URLEncoding.DecodedLen(len(src)))
	n, err := base64.URLEncoding.Decode(buf, src)
	return buf[:n], err
}
