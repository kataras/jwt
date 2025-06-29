package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// algRSA implements the Alg interface for RSA signature algorithms.
// It supports RS256, RS384, and RS512 variants using PKCS#1 v1.5 padding
// with SHA-256, SHA-384, and SHA-512 respectively.
type algRSA struct {
	name   string      // Algorithm name (e.g., "RS256", "RS384", "RS512")
	hasher crypto.Hash // Hash function to use (SHA256, SHA384, or SHA512)
}

// Parse implements the AlgParser interface for RSA algorithms.
// It parses PEM-encoded private and public keys and returns the corresponding
// *rsa.PrivateKey and *rsa.PublicKey instances.
//
// Either private or public can be empty, but at least one should be provided.
// Returns an error if the key parsing fails or the key format is invalid.
func (a *algRSA) Parse(private, public []byte) (privateKey PrivateKey, publicKey PublicKey, err error) {
	if len(private) > 0 {
		privateKey, err = ParsePrivateKeyRSA(private)
		if err != nil {
			return nil, nil, fmt.Errorf("RSA: private key: %v", err)
		}
	}

	if len(public) > 0 {
		publicKey, err = ParsePublicKeyRSA(public)
		if err != nil {
			return nil, nil, fmt.Errorf("RSA: public key: %v", err)
		}
	}

	return
}

// Name returns the algorithm name (e.g., "RS256", "RS384", "RS512").
func (a *algRSA) Name() string {
	return a.name
}

// Sign implements the Alg interface for RSA signature generation.
// It creates an RSA signature using PKCS#1 v1.5 padding with the provided private key.
//
// The key must be an *rsa.PrivateKey. For security, RSA keys should be at least
// 2048 bits in length (3072+ bits recommended for new applications).
//
// Returns an error if the key is invalid or signing fails.
func (a *algRSA) Sign(key PrivateKey, headerAndPayload []byte) ([]byte, error) {
	privateKey, ok := key.(*rsa.PrivateKey)
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
	return rsa.SignPKCS1v15(rand.Reader, privateKey, a.hasher, hashed)
}

// Verify implements the Alg interface for RSA signature verification.
// It verifies an RSA signature using PKCS#1 v1.5 padding against the provided public key.
//
// The method accepts either an *rsa.PublicKey or an *rsa.PrivateKey
// (from which it extracts the public key).
func (a *algRSA) Verify(key PublicKey, headerAndPayload []byte, signature []byte) error {
	publicKey, ok := key.(*rsa.PublicKey)
	if !ok {
		if privateKey, ok := key.(*rsa.PrivateKey); ok {
			publicKey = &privateKey.PublicKey
		} else {
			return ErrInvalidKey
		}
	}

	h := a.hasher.New()
	// header.payload
	_, err := h.Write(headerAndPayload)
	if err != nil {
		return err
	}

	hashed := h.Sum(nil)
	if err = rsa.VerifyPKCS1v15(publicKey, a.hasher, hashed, signature); err != nil {
		return fmt.Errorf("%w: %v", ErrTokenSignature, err)
	}

	return nil
}

// Key Helpers.

// MustLoadRSA accepts private and public PEM file paths
// and returns a pair of private and public RSA keys.
//
// Pass the returned private key to Sign functions and
// the public key to Verify functions.
//
// This function panics if either key file cannot be read or parsed.
// Use LoadPrivateKeyRSA and LoadPublicKeyRSA for error handling.
//
// Example:
//
//	privateKey, publicKey := jwt.MustLoadRSA("rsa_private.pem", "rsa_public.pem")
//	token, err := jwt.Sign(jwt.RS256, privateKey, claims)
//	verifiedToken, err := jwt.Verify(jwt.RS256, publicKey, token)
func MustLoadRSA(privateKeyFilename, publicKeyFilename string) (*rsa.PrivateKey, *rsa.PublicKey) {
	privateKey, err := LoadPrivateKeyRSA(privateKeyFilename)
	if err != nil {
		panicHandler(err)
	}

	publicKey, err := LoadPublicKeyRSA(publicKeyFilename)
	if err != nil {
		panicHandler(err)
	}

	return privateKey, publicKey
}

// LoadPrivateKeyRSA loads and parses a PEM-encoded RSA private key from a file.
//
// The file should contain a PEM-encoded RSA private key in PKCS#1 or PKCS#8 format.
// Pass the returned value to Sign functions for token creation.
//
// Returns an error if the file cannot be read or the key cannot be parsed.
//
// Example:
//
//	privateKey, err := jwt.LoadPrivateKeyRSA("rsa_private_key.pem")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	token, err := jwt.Sign(jwt.RS256, privateKey, claims)
func LoadPrivateKeyRSA(filename string) (*rsa.PrivateKey, error) {
	b, err := ReadFile(filename)
	if err != nil {
		return nil, err
	}

	key, err := ParsePrivateKeyRSA(b)
	if err != nil {
		return nil, err
	}

	return key, nil
}

// LoadPublicKeyRSA loads and parses a PEM-encoded RSA public key from a file.
//
// The file should contain a PEM-encoded RSA public key in PKIX format,
// or a certificate containing an RSA public key.
// Pass the returned value to Verify functions for token validation.
//
// Returns an error if the file cannot be read or the key cannot be parsed.
//
// Example:
//
//	publicKey, err := jwt.LoadPublicKeyRSA("rsa_public_key.pem")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	verifiedToken, err := jwt.Verify(jwt.RS256, publicKey, token)
func LoadPublicKeyRSA(filename string) (*rsa.PublicKey, error) {
	b, err := ReadFile(filename)
	if err != nil {
		return nil, err
	}

	key, err := ParsePublicKeyRSA(b)
	if err != nil {
		return nil, err
	}

	return key, nil
}

// ParsePrivateKeyRSA decodes and parses PEM-encoded RSA private key bytes.
//
// The input should be PEM-encoded RSA private key data in PKCS#1 or PKCS#8 format.
// This function handles both formats automatically.
//
// Returns an error if the PEM block is missing or the key cannot be parsed.
// Use LoadPrivateKeyRSA for file-based loading.
//
// Example:
//
//	keyData := []byte("-----BEGIN RSA PRIVATE KEY-----\n...")
//	privateKey, err := jwt.ParsePrivateKeyRSA(keyData)
func ParsePrivateKeyRSA(key []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(key)
	if block == nil {
		return nil, fmt.Errorf("private key: malformed or missing PEM format (RSA)")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
			pKey, ok := key.(*rsa.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("private key: expected a type of *rsa.PrivateKey")
			}

			privateKey = pKey
		} else {
			return nil, err
		}
	}

	return privateKey, nil
}

// ParsePublicKeyRSA decodes and parses PEM-encoded RSA public key bytes.
//
// The input should be PEM-encoded RSA public key data in PKIX format,
// or a certificate containing an RSA public key.
// This function handles both formats automatically.
//
// Returns an error if the PEM block is missing or the key cannot be parsed.
// Use LoadPublicKeyRSA for file-based loading.
//
// Example:
//
//	keyData := []byte("-----BEGIN PUBLIC KEY-----\n...")
//	publicKey, err := jwt.ParsePublicKeyRSA(keyData)
func ParsePublicKeyRSA(key []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(key)
	if block == nil {
		return nil, fmt.Errorf("public key: malformed or missing PEM format (RSA)")
	}

	parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			parsedKey = cert.PublicKey
		} else {
			return nil, err
		}
	}

	publicKey, ok := parsedKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key: expected a type of *rsa.PublicKey")
	}

	return publicKey, nil
}
