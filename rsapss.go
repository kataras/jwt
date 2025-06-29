package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

// algRSAPSS implements the Alg interface for RSA-PSS signature algorithms.
// It supports PS256, PS384, and PS512 variants using RSASSA-PSS padding
// with SHA-256, SHA-384, and SHA-512 respectively.
//
// RSASSA-PSS is a probabilistic signature scheme that provides enhanced
// security compared to PKCS#1 v1.5 padding used by standard RSA algorithms.
type algRSAPSS struct {
	name string          // Algorithm name (e.g., "PS256", "PS384", "PS512")
	opts *rsa.PSSOptions // PSS options including hash function and salt length
}

// Parse implements the AlgParser interface for RSA-PSS algorithms.
// It parses PEM-encoded private and public keys and returns the corresponding
// *rsa.PrivateKey and *rsa.PublicKey instances.
//
// Note: RSA-PSS uses the same key format as standard RSA keys.
// Either private or public can be empty, but at least one should be provided.
// Returns an error if the key parsing fails or the key format is invalid.
func (a *algRSAPSS) Parse(private, public []byte) (privateKey PrivateKey, publicKey PublicKey, err error) {
	if len(private) > 0 {
		privateKey, err = ParsePrivateKeyRSA(private)
		if err != nil {
			return nil, nil, fmt.Errorf("RSA-PSS: private key: %v", err)
		}
	}

	if len(public) > 0 {
		publicKey, err = ParsePublicKeyRSA(public)
		if err != nil {
			return nil, nil, fmt.Errorf("RSA-PSS: public key: %v", err)
		}
	}

	return
}

// Name returns the algorithm name (e.g., "PS256", "PS384", "PS512").
func (a *algRSAPSS) Name() string {
	return a.name
}

// Sign implements the Alg interface for RSA-PSS signature generation.
// It creates an RSA-PSS signature using the provided private key.
//
// RSA-PSS uses probabilistic padding with random salt, making each signature
// unique even for the same message. The key must be an *rsa.PrivateKey.
// For security, RSA keys should be at least 2048 bits in length.
//
// Returns an error if the key is invalid or signing fails.
func (a *algRSAPSS) Sign(key PrivateKey, headerAndPayload []byte) ([]byte, error) {
	privateKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, ErrInvalidKey
	}

	h := a.opts.Hash.New()
	// header.payload
	_, err := h.Write(headerAndPayload)
	if err != nil {
		return nil, err
	}

	hashed := h.Sum(nil)
	return rsa.SignPSS(rand.Reader, privateKey, a.opts.Hash, hashed, a.opts)
}

// Verify implements the Alg interface for RSA-PSS signature verification.
// It verifies an RSA-PSS signature against the provided public key.
//
// The method accepts either an *rsa.PublicKey or an *rsa.PrivateKey
// (from which it extracts the public key). RSA-PSS verification handles
// the probabilistic nature of the padding automatically.
func (a *algRSAPSS) Verify(key PublicKey, headerAndPayload []byte, signature []byte) error {
	publicKey, ok := key.(*rsa.PublicKey)
	if !ok {
		if privateKey, ok := key.(*rsa.PrivateKey); ok {
			publicKey = &privateKey.PublicKey
		} else {
			return ErrInvalidKey
		}
	}

	h := a.opts.Hash.New()
	// header.payload
	_, err := h.Write(headerAndPayload)
	if err != nil {
		return err
	}

	hashed := h.Sum(nil)

	if err = rsa.VerifyPSS(publicKey, a.opts.Hash, hashed, signature, a.opts); err != nil {
		return fmt.Errorf("%w: %v", ErrTokenSignature, err)
	}

	return nil
}
