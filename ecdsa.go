package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
)

// algECDSA implements the Alg interface for ECDSA signature algorithms.
// It supports ES256, ES384, and ES512 variants using P-256, P-384, and P-521 curves respectively.
type algECDSA struct {
	name      string      // Algorithm name (e.g., "ES256", "ES384", "ES512")
	hasher    crypto.Hash // Hash function to use (SHA256, SHA384, or SHA512)
	keySize   int         // Expected signature size in bytes
	curveBits int         // Curve bit size for validation
}

// Parse implements the AlgParser interface for ECDSA algorithms.
// It parses PEM-encoded private and public keys and returns the corresponding
// *ecdsa.PrivateKey and *ecdsa.PublicKey instances.
//
// Either private or public can be empty, but at least one should be provided.
// Returns an error if the key parsing fails or the key format is invalid.
func (a *algECDSA) Parse(private, public []byte) (privateKey PrivateKey, publicKey PublicKey, err error) {
	if len(private) > 0 {
		privateKey, err = ParsePrivateKeyECDSA(private)
		if err != nil {
			return nil, nil, fmt.Errorf("ECDSA: private key: %v", err)
		}
	}

	if len(public) > 0 {
		publicKey, err = ParsePublicKeyECDSA(public)
		if err != nil {
			return nil, nil, fmt.Errorf("ECDSA: public key: %v", err)
		}
	}

	return
}

// Name returns the algorithm name (e.g., "ES256", "ES384", "ES512").
func (a *algECDSA) Name() string {
	return a.name
}

// Sign implements the Alg interface for ECDSA signature generation.
// It creates an ECDSA signature using the provided private key.
//
// The signature format follows RFC 7515 Section 3.4: the signature is
// the concatenation of the big-endian representations of r and s,
// each padded to the byte length of the curve.
//
// Based on JWT handbook chapter 7.2.2.3.1 Algorithm.
func (a *algECDSA) Sign(key PrivateKey, headerAndPayload []byte) ([]byte, error) {
	privateKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, ErrInvalidKey
	}

	h := a.hasher.New()
	// header.payload
	_, err := h.Write(headerAndPayload)
	if err != nil {
		return nil, err
	}

	hashed := h.Sum(nil)
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hashed)
	if err != nil {
		return nil, err
	}

	curveBits := privateKey.Curve.Params().BitSize
	if a.curveBits != curveBits {
		return nil, ErrInvalidKey
	}

	keyBytes := curveBits / 8
	if curveBits%8 > 0 {
		keyBytes++
	}

	rBytes := r.Bytes()
	rBytesPadded := make([]byte, keyBytes)
	copy(rBytesPadded[keyBytes-len(rBytes):], rBytes)

	sBytes := s.Bytes()
	sBytesPadded := make([]byte, keyBytes)
	copy(sBytesPadded[keyBytes-len(sBytes):], sBytes)

	signature := append(rBytesPadded, sBytesPadded...)
	return signature, nil
}

// Verify implements the Alg interface for ECDSA signature verification.
// It verifies an ECDSA signature against the provided public key.
//
// The method accepts either an *ecdsa.PublicKey or an *ecdsa.PrivateKey
// (from which it extracts the public key). The signature must be in the
// concatenated r||s format as specified by RFC 7515.
func (a *algECDSA) Verify(key PublicKey, headerAndPayload []byte, signature []byte) error {
	publicKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		if privateKey, ok := key.(*ecdsa.PrivateKey); ok {
			publicKey = &privateKey.PublicKey
		} else {
			return ErrInvalidKey
		}
	}

	if len(signature) != 2*a.keySize {
		return ErrTokenSignature
	}

	r := big.NewInt(0).SetBytes(signature[:a.keySize])
	s := big.NewInt(0).SetBytes(signature[a.keySize:])

	h := a.hasher.New()
	// header.payload
	_, err := h.Write(headerAndPayload)
	if err != nil {
		return err
	}

	hashed := h.Sum(nil)
	if !ecdsa.Verify(publicKey, hashed, r, s) {
		return ErrTokenSignature
	}

	return nil
}

// Key Helpers.

// MustLoadECDSA accepts private and public PEM filenames
// and returns a pair of private and public ECDSA keys.
//
// Pass the returned private key to the Sign functions and
// the public key to the Verify functions.
//
// This function panics if either key file cannot be read or parsed.
// Use LoadPrivateKeyECDSA and LoadPublicKeyECDSA for error handling.
//
// Example:
//
//	privateKey, publicKey := jwt.MustLoadECDSA("private.pem", "public.pem")
//	token, err := jwt.Sign(jwt.ES256, privateKey, claims)
//	verifiedToken, err := jwt.Verify(jwt.ES256, publicKey, token)
func MustLoadECDSA(privateKeyFilename, publicKeyFilename string) (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	privateKey, err := LoadPrivateKeyECDSA(privateKeyFilename)
	if err != nil {
		panicHandler(err)
	}

	publicKey, err := LoadPublicKeyECDSA(publicKeyFilename)
	if err != nil {
		panicHandler(err)
	}

	return privateKey, publicKey
}

// LoadPrivateKeyECDSA loads and parses a PEM-encoded ECDSA private key from a file.
//
// The file should contain a PEM-encoded ECDSA private key in PKCS#1 or PKCS#8 format.
// Pass the returned value to Sign functions for token creation.
//
// Returns an error if the file cannot be read or the key cannot be parsed.
//
// Example:
//
//	privateKey, err := jwt.LoadPrivateKeyECDSA("ecdsa_private_key.pem")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	token, err := jwt.Sign(jwt.ES256, privateKey, claims)
func LoadPrivateKeyECDSA(filename string) (*ecdsa.PrivateKey, error) {
	b, err := ReadFile(filename)
	if err != nil {
		return nil, err
	}

	key, err := ParsePrivateKeyECDSA(b)
	if err != nil {
		return nil, err
	}

	return key, nil
}

// LoadPublicKeyECDSA loads and parses a PEM-encoded ECDSA public key from a file.
//
// The file should contain a PEM-encoded ECDSA public key in PKIX format,
// or a certificate containing an ECDSA public key.
// Pass the returned value to Verify functions for token validation.
//
// Returns an error if the file cannot be read or the key cannot be parsed.
//
// Example:
//
//	publicKey, err := jwt.LoadPublicKeyECDSA("ecdsa_public_key.pem")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	verifiedToken, err := jwt.Verify(jwt.ES256, publicKey, token)
func LoadPublicKeyECDSA(filename string) (*ecdsa.PublicKey, error) {
	b, err := ReadFile(filename)
	if err != nil {
		return nil, err
	}

	key, err := ParsePublicKeyECDSA(b)
	if err != nil {
		return nil, err
	}

	return key, nil
}

// ParsePrivateKeyECDSA decodes and parses PEM-encoded ECDSA private key bytes.
//
// The input should be PEM-encoded ECDSA private key data.
// This function handles the low-level parsing after PEM decoding.
//
// Returns an error if the PEM block is missing or the key cannot be parsed.
// Use LoadPrivateKeyECDSA for file-based loading.
//
// Example:
//
//	keyData := []byte("-----BEGIN EC PRIVATE KEY-----\n...")
//	privateKey, err := jwt.ParsePrivateKeyECDSA(keyData)
func ParsePrivateKeyECDSA(key []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(key)
	if block == nil {
		return nil, fmt.Errorf("private key: malformed or missing PEM format (ECDSA)")
	}

	return x509.ParseECPrivateKey(block.Bytes)
}

// ParsePublicKeyECDSA decodes and parses PEM-encoded ECDSA public key bytes.
//
// The input should be PEM-encoded ECDSA public key data in PKIX format,
// or a certificate containing an ECDSA public key.
// This function handles the low-level parsing after PEM decoding.
//
// Returns an error if the PEM block is missing or the key cannot be parsed.
// Use LoadPublicKeyECDSA for file-based loading.
//
// Example:
//
//	keyData := []byte("-----BEGIN PUBLIC KEY-----\n...")
//	publicKey, err := jwt.ParsePublicKeyECDSA(keyData)
func ParsePublicKeyECDSA(key []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(key)
	if block == nil {
		return nil, fmt.Errorf("public key: malformed or missing PEM format (ECDSA)")
	}

	parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			parsedKey = cert.PublicKey
		} else {
			return nil, err
		}
	}

	publicKey, ok := parsedKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key: malformed or missing PEM format (ECDSA)")
	}

	return publicKey, nil
}
