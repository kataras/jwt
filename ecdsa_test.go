package jwt

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"testing"
)

func TestEncodeDecodeTokenECDSA(t *testing.T) {
	privateKey, err := loadPrivateKeyECDSA("./_testfiles/ecdsa_private_key.pem")
	if err != nil {
		t.Fatalf("ecdsa: private key: %v", err)
	}

	publicKey, err := loadPublicKeyECDSA("./_testfiles/ecdsa_public_key.pem")
	if err != nil {
		t.Fatalf("ecdsa: public key: %v", err)
	}

	// eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImthdGFyYXMifQ.oW8ic_m78NAzBPcl9TSX0qjqsyFUkyZQfvIHCJYC-DeVMLbbOjR78UGk-3XQ3o1nfyI2tQBXsYDc5OK80DR3yA
	testEncodeDecodeToken(t, ES256, privateKey, publicKey, nil)
}

func loadPrivateKeyECDSA(filename string) (*ecdsa.PrivateKey, error) {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	key, err := parsePrivateKeyECDSA(b)
	if err != nil {
		return nil, err
	}

	return key, nil
}

func loadPublicKeyECDSA(filename string) (*ecdsa.PublicKey, error) {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	key, err := parsePublicKeyECDSA(b)
	if err != nil {
		return nil, err
	}

	return key, nil
}

// Parse PEM encoded Elliptic Curve Private Key Structure
func parsePrivateKeyECDSA(key []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(key)
	if block == nil {
		return nil, fmt.Errorf("pem format missing")
	}

	return x509.ParseECPrivateKey(block.Bytes)
}

// Parse PEM encoded PKCS1 or PKCS8 public key
func parsePublicKeyECDSA(key []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(key)

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
		return nil, fmt.Errorf("not a type of ecdsa private key")
	}

	return publicKey, nil
}
