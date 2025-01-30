package jwt

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
)

// FetchPublicKeys fetches the JSON Web Key Set (JWKS) from the given URL
// and returns the public keys as Keys map.
// It returns an error if the request fails or the JWKS is invalid.
//
// The url is the URL of the JWKS endpoint,
// usually ends with: /.well-known/jwks.json.
//
// It supports all RS256, RS384, RS512, ES256, ES384, ES512 and Ed25519 algorithms.
func FetchPublicKeys(url string) (Keys, error) {
	set, err := FetchJWKS(http.DefaultClient, url)
	if err != nil {
		return nil, err
	}

	return set.PublicKeys(), nil
}

// JWKS represents a JSON Web Key Set.
type JWKS struct {
	Keys []*JWK `json:"keys"`
}

// PublicKeys parse and returns the public keys as Keys map from the JSON Web Key Set (JWKS).
// It supports all RS256, RS384, RS512, ES256, ES384, ES512 and Ed25519 algorithms.
func (set *JWKS) PublicKeys() Keys {
	keys := make(Keys, len(set.Keys))

	for _, key := range set.Keys {
		alg := parseAlg(key.Alg)
		if alg == nil {
			continue
		}

		publicKey, err := convertJWKToPublicKey(key)
		if err != nil {
			continue
		}

		keys[key.Kid] = &Key{
			ID:     key.Kid,
			Alg:    alg,
			Public: publicKey,
		}
	}

	return keys
}

type httpError struct {
	StatusCode int
	Body       []byte
}

func (err httpError) Error() string {
	return fmt.Sprintf("status code: %d: body: %s",
		err.StatusCode, string(err.Body))
}

// FetchJWKS fetches the JSON Web Key Set (JWKS) from the given URL.
// It returns the JWKS object or an error if the request fails.
// If the HTTP client is not set, the default http.Client is used.
//
// The url is the URL of the JWKS endpoint,
// usually ends with: /.well-known/jwks.json.
func FetchJWKS(client HTTPClient, url string) (*JWKS, error) {
	if client == nil {
		client = http.DefaultClient
	}

	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body) // ignore error.
		return nil, httpError{StatusCode: resp.StatusCode, Body: b}
	}

	var jwkSet JWKS
	err = json.NewDecoder(resp.Body).Decode(&jwkSet)
	if err != nil {
		return nil, err
	}

	return &jwkSet, nil
}

//
// convert jwk to public key.
//

type (
	// HTTPClient is an interface that can be used to mock the http.Client.
	// It is used to fetch the JSON Web Key Set (JWKS) from AWS Cognito.
	HTTPClient interface {
		Get(string) (*http.Response, error)
	}

	// JWK represents a JSON Web Key.
	JWK struct {
		Kty string `json:"kty"` // Key type (e.g., "RSA", "OKP" Octet Key Pair)
		Kid string `json:"kid"` // Key ID
		Use string `json:"use"` // Key use (e.g., "sig")
		Alg string `json:"alg"` // Algorithm (e.g., "RS256", "EdDSA")
		Crv string `json:"crv"` // Curve name (e.g., "Ed25519")
		N   string `json:"n"`   // RSA modulus (Base64 URL-encoded)
		E   string `json:"e"`   // RSA exponent (Base64 URL-encoded)
		Y   string `json:"y"`   // Elliptic y-coordinate (Base64 URL-encoded)
		X   string `json:"x"`   // EdDSA public key (Base64 URL-encoded)
	}
)

func convertJWKToPublicKey(jwk *JWK) (PublicKey, error) {
	// Parse the key based on its type
	switch jwk.Kty {
	case "RSA":
		publicKey, err := convertJWKToPublicKeyRSA(jwk)
		if err != nil {
			return nil, fmt.Errorf("parse RSA key: %w", err)
		}

		return publicKey, nil
	case "EC":
		publicKey, err := convertJWKToPublicKeyEC(jwk)
		if err != nil {
			return nil, fmt.Errorf("parse EC key: %w", err)
		}

		return publicKey, nil
	case "OKP":
		publicKey, err := convertJWKToPublicKeyEdDSA(jwk)
		if err != nil {
			return nil, fmt.Errorf("parse EdDSA key: %w", err)
		}

		return publicKey, nil
	default:
		return nil, fmt.Errorf("unsupported key type: %s", jwk.Kty)
	}
}

// convertJWKToPublicKey converts a JWK object to a *rsa.PublicKey object.
func convertJWKToPublicKeyRSA(jwk *JWK) (*rsa.PublicKey, error) {
	// decode the n and e values from base64.
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, err
	}

	// construct a big.Int from the n bytes.
	n := new(big.Int).SetBytes(nBytes)

	// construct an int from the e bytes.
	var e int
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}
	// or: e := int(new(big.Int).SetBytes(eBytes).Int64())

	// construct a *rsa.PublicKey from the n and e values.
	pubKey := &rsa.PublicKey{
		N: n,
		E: e,
	}

	return pubKey, nil
}

func convertJWKToPublicKeyEC(jwk *JWK) (*ecdsa.PublicKey, error) {
	// Check key type
	if jwk.Kty != "EC" {
		return nil, fmt.Errorf("invalid key type: expected EC")
	}

	// Decode x and y coordinates
	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("failed to decode x-coordinate")
	}

	yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return nil, fmt.Errorf("failed to decode y-coordinate")
	}

	// Convert x and y to big.Int
	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	// Determine the elliptic curve
	var curve elliptic.Curve
	switch jwk.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported elliptic curve")
	}

	// Reconstruct the public key
	publicKey := &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}

	return publicKey, nil
}

func convertJWKToPublicKeyEdDSA(jwk *JWK) (ed25519.PublicKey, error) {
	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, err
	}

	publicKey := ed25519.PublicKey(xBytes)
	return publicKey, nil
}

//
// convert public key to JWK.
//

// GenerateJWK generates a JSON Web Key (JWK) from the given public key.
// Supported public key types:
//
//  1. RSA (RS256, RS384, RS512) as *rsa.PublicKey.
//  2. Elliptic Curve (ES256, ES384, ES512) as ecdsa.PublicKey.
//  3. EdDSA as ed25519.PublicKey.
func GenerateJWK(kid string, alg string, publicKey PublicKey) (*JWK, error) {
	switch publicKey := publicKey.(type) {
	case *rsa.PublicKey:
		return generateJWKFromPublicKeyRSA(kid, alg, publicKey), nil
	case ecdsa.PublicKey:
		return generateJWKFromPublicKeyEC(kid, alg, publicKey)
	case ed25519.PublicKey:
		return generateJWKFromPublicKeyEdDSA(kid, publicKey), nil
	default:
		return nil, fmt.Errorf("unsupported public key type: %T", publicKey)
	}
}

func generateJWKFromPublicKeyRSA(kid string, alg string, publicKey *rsa.PublicKey) *JWK {
	// Extract modulus (n) and exponent (e).
	n := base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes())

	// Create JWK
	jwk := JWK{
		Kty: "RSA",
		Kid: kid,
		Use: "sig",
		Alg: alg,
		N:   n,
		E:   e,
	}

	return &jwk
}

func generateJWKFromPublicKeyEC(kid string, alg string, publicKey ecdsa.PublicKey) (*JWK, error) {
	// Get the curve parameters.
	x := base64.RawURLEncoding.EncodeToString(publicKey.X.Bytes())
	y := base64.RawURLEncoding.EncodeToString(publicKey.Y.Bytes())

	// Determine the curve name.
	var crv string
	switch publicKey.Curve {
	case elliptic.P256():
		crv = "P-256"
	case elliptic.P384():
		crv = "P-384"
	case elliptic.P521():
		crv = "P-521"
	default:
		return nil, fmt.Errorf("unsupported elliptic curve: %s", publicKey.Curve.Params().Name)
	}

	jwk := JWK{
		Kty: "EC",
		Kid: kid,
		Use: "sig",
		Alg: alg, // e.g., "ES256", "ES384", "ES512"
		Crv: crv,
		X:   x,
		Y:   y,
	}

	return &jwk, nil
}

func generateJWKFromPublicKeyEdDSA(kid string, publicKey ed25519.PublicKey) *JWK {
	// Base64 URL-encode the public key.
	x := base64.RawURLEncoding.EncodeToString(publicKey)

	// Create JWK
	jwk := JWK{
		Kty: "OKP",
		Kid: kid,
		Use: "sig",
		Alg: "EdDSA",
		Crv: "Ed25519",
		X:   x,
	}

	return &jwk
}

// HMAC is a symmetric algorithm, so it doesn’t use JWKS (which is for public keys).
// Instead, you share the secret key securely between parties.
