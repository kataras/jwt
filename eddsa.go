package jwt

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
)

// algEdDSA implements the Alg interface for EdDSA signature algorithms.
// It supports Ed25519 signatures as specified in RFC 8037.
type algEdDSA struct {
	name string // Algorithm name ("EdDSA")
}

// Parse implements the AlgParser interface for EdDSA algorithms.
// It parses PEM-encoded or raw Ed25519 keys and returns the corresponding
// ed25519.PrivateKey and ed25519.PublicKey instances.
//
// This method supports both PEM-encoded keys and raw key bytes.
// If PEM parsing fails, it falls back to treating the input as raw key material.
// Either private or public can be empty, but at least one should be provided.
func (a *algEdDSA) Parse(private, public []byte) (privateKey PrivateKey, publicKey PublicKey, err error) {
	if len(public) > 0 {
		publicKey, err = ParsePublicKeyEdDSA(public)
		if err != nil {
			if errors.Is(err, errPEMMalformed) {
				err = nil
				publicKey = ed25519.PublicKey(public)
			} else {
				return nil, nil, fmt.Errorf("EdDSA: public key: %v", err)
			}
		}
	}

	if len(private) > 0 {
		privateKey, err = ParsePrivateKeyEdDSA(private)
		if err != nil {
			if errors.Is(err, errPEMMalformed) {
				err = nil
				privateKey = ed25519.PrivateKey(private)
			} else {
				return nil, nil, fmt.Errorf("EdDSA: private key: %v", err)
			}
		}
	}

	return
}

// Name returns the algorithm name ("EdDSA").
func (a *algEdDSA) Name() string {
	return a.name
}

// Sign implements the Alg interface for EdDSA signature generation.
// It creates an Ed25519 signature using the provided private key.
//
// The key must be an ed25519.PrivateKey of exactly ed25519.PrivateKeySize bytes.
// Returns an error if the key is invalid or of wrong type/size.
func (a *algEdDSA) Sign(key PrivateKey, headerAndPayload []byte) ([]byte, error) {
	privateKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, ErrInvalidKey
	}

	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, ErrInvalidKey
	}

	return ed25519.Sign(privateKey, []byte(headerAndPayload)), nil
}

// Verify implements the Alg interface for EdDSA signature verification.
// It verifies an Ed25519 signature against the provided public key.
//
// The method accepts either an ed25519.PublicKey or an ed25519.PrivateKey
// (from which it extracts the public key). The key must be exactly
// ed25519.PublicKeySize bytes.
func (a *algEdDSA) Verify(key PublicKey, headerAndPayload []byte, signature []byte) error {
	publicKey, ok := key.(ed25519.PublicKey)
	if !ok {
		if privateKey, ok := key.(ed25519.PrivateKey); ok {
			publicKey = privateKey.Public().(ed25519.PublicKey)
		} else {
			return ErrInvalidKey
		}
	}

	if len(publicKey) != ed25519.PublicKeySize {
		return ErrInvalidKey
	}

	if !ed25519.Verify(publicKey, headerAndPayload, signature) {
		return ErrTokenSignature
	}

	return nil
}

// Key Helpers.

// MustLoadEdDSA accepts private and public PEM filenames
// and returns a pair of private and public Ed25519 keys.
//
// Pass the returned private key to Sign functions and
// the public key to Verify functions.
//
// This function panics if either key file cannot be read or parsed.
// Use LoadPrivateKeyEdDSA and LoadPublicKeyEdDSA for error handling.
//
// Example:
//
//	privateKey, publicKey := jwt.MustLoadEdDSA("ed25519_private.pem", "ed25519_public.pem")
//	token, err := jwt.Sign(jwt.EdDSA, privateKey, claims)
//	verifiedToken, err := jwt.Verify(jwt.EdDSA, publicKey, token)
func MustLoadEdDSA(privateKeyFilename, publicKeyFilename string) (ed25519.PrivateKey, ed25519.PublicKey) {
	privateKey, err := LoadPrivateKeyEdDSA(privateKeyFilename)
	if err != nil {
		panicHandler(err)
	}

	publicKey, err := LoadPublicKeyEdDSA(publicKeyFilename)
	if err != nil {
		panicHandler(err)
	}

	return privateKey, publicKey
}

// LoadPrivateKeyEdDSA loads and parses a PEM-encoded Ed25519 private key from a file.
//
// The file should contain a PEM-encoded Ed25519 private key in PKCS#8 format.
// Pass the returned value to Sign functions for token creation.
//
// Returns an error if the file cannot be read or the key cannot be parsed.
//
// Example:
//
//	privateKey, err := jwt.LoadPrivateKeyEdDSA("ed25519_private_key.pem")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	token, err := jwt.Sign(jwt.EdDSA, privateKey, claims)
func LoadPrivateKeyEdDSA(filename string) (ed25519.PrivateKey, error) {
	b, err := ReadFile(filename)
	if err != nil {
		return nil, err
	}

	key, err := ParsePrivateKeyEdDSA(b)
	if err != nil {
		return nil, err
	}

	return key, nil
}

// LoadPublicKeyEdDSA loads and parses a PEM-encoded Ed25519 public key from a file.
//
// The file should contain a PEM-encoded Ed25519 public key in PKIX format.
// Pass the returned value to Verify functions for token validation.
//
// Returns an error if the file cannot be read or the key cannot be parsed.
//
// Example:
//
//	publicKey, err := jwt.LoadPublicKeyEdDSA("ed25519_public_key.pem")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	verifiedToken, err := jwt.Verify(jwt.EdDSA, publicKey, token)
func LoadPublicKeyEdDSA(filename string) (ed25519.PublicKey, error) {
	b, err := ReadFile(filename)
	if err != nil {
		return nil, err
	}

	key, err := ParsePublicKeyEdDSA(b)
	if err != nil {
		return nil, err
	}

	return key, nil
}

// ParsePrivateKeyEdDSA decodes and parses PEM-encoded Ed25519 private key bytes.
//
// The input should be PEM-encoded Ed25519 private key data in PKCS#8 format.
// This function handles the ASN.1 parsing to extract the seed and generate
// the full Ed25519 private key.
//
// Returns an error if the PEM block is missing or the key cannot be parsed.
// Use LoadPrivateKeyEdDSA for file-based loading.
//
// Example:
//
//	keyData := []byte("-----BEGIN PRIVATE KEY-----\n...")
//	privateKey, err := jwt.ParsePrivateKeyEdDSA(keyData)
func ParsePrivateKeyEdDSA(key []byte) (ed25519.PrivateKey, error) {
	asn1PrivKey := struct {
		Version          int
		ObjectIdentifier struct {
			ObjectIdentifier asn1.ObjectIdentifier
		}
		PrivateKey []byte
	}{}

	block, _ := pem.Decode(key)
	if block == nil {
		return nil, fmt.Errorf("private key: %w (EdDSA)", errPEMMalformed)
	}

	if _, err := asn1.Unmarshal(block.Bytes, &asn1PrivKey); err != nil {
		return nil, err
	}

	seed := asn1PrivKey.PrivateKey[2:]
	if l := len(seed); l != ed25519.SeedSize {
		return nil, fmt.Errorf("private key: bad seed length: %d", l)
	}

	privateKey := ed25519.NewKeyFromSeed(seed)
	return privateKey, nil
}

// errPEMMalformed indicates that the PEM data is malformed or missing.
var errPEMMalformed = errors.New("pem malformed")

// ParsePublicKeyEdDSA decodes and parses PEM-encoded Ed25519 public key bytes.
//
// The input should be PEM-encoded Ed25519 public key data in PKIX format.
// This function handles the ASN.1 parsing to extract the public key bytes.
//
// Returns an error if the PEM block is missing or the key cannot be parsed.
// Use LoadPublicKeyEdDSA for file-based loading.
//
// Example:
//
//	keyData := []byte("-----BEGIN PUBLIC KEY-----\n...")
//	publicKey, err := jwt.ParsePublicKeyEdDSA(keyData)
func ParsePublicKeyEdDSA(key []byte) (ed25519.PublicKey, error) {
	asn1PubKey := struct {
		OBjectIdentifier struct {
			ObjectIdentifier asn1.ObjectIdentifier
		}
		PublicKey asn1.BitString
	}{}

	block, _ := pem.Decode(key)
	if block == nil {
		return nil, fmt.Errorf("public key: %w (EdDSA)", errPEMMalformed)
	}

	if _, err := asn1.Unmarshal(block.Bytes, &asn1PubKey); err != nil {
		return nil, err
	}

	publicKey := ed25519.PublicKey(asn1PubKey.PublicKey.Bytes)
	return publicKey, nil
}

// GenerateEdDSA generates a random Ed25519 key pair and returns them as PEM-encoded data.
//
// This function generates a new Ed25519 key pair and encodes both keys
// in PEM format (PKCS#8 for private key, PKIX for public key).
//
// Returns the public key PEM, private key PEM, and any error that occurred.
// Note: The returned order is (publicPEM, privatePEM), which differs from
// the conventional (private, public) order.
//
// Example:
//
//	publicPEM, privatePEM, err := jwt.GenerateEdDSA()
//	if err != nil {
//	    log.Fatal(err)
//	}
//	// Save to files or use directly
func GenerateEdDSA() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv) // Convert a generated ed25519 key into a PEM block so that the ssh library can ingest it, bit round about tbh
	if err != nil {
		return nil, nil, err
	}
	privatePEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: privBytes,
		},
	)

	pubBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, nil, err
	}

	publicPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubBytes,
		})

	return publicPEM, privatePEM, nil
}

// GenerateBase64EdDSA generates a random Ed25519 key pair as base64-encoded strings.
//
// This function generates a new Ed25519 key pair and returns the keys
// as base64-encoded strings using raw standard encoding (no padding).
// This format is convenient for configuration files or environment variables.
//
// Returns the public key string, private key string, and any error that occurred.
//
// Example:
//
//	publicKey, privateKey, err := jwt.GenerateBase64EdDSA()
//	if err != nil {
//	    log.Fatal(err)
//	}
//	// Use keys directly or store in config
//	fmt.Printf("Public Key: %s\n", publicKey)
//	fmt.Printf("Private Key: %s\n", privateKey)
func GenerateBase64EdDSA() (string, string, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	pub := ed25519.PrivateKey(priv).Public().(ed25519.PublicKey)

	publicKey := base64.RawStdEncoding.EncodeToString(pub)
	privateKey := base64.RawStdEncoding.EncodeToString(priv)

	return publicKey, privateKey, nil
}
