package jwt

import (
	"testing"
)

func TestEncodeDecodeTokenECDSA(t *testing.T) {
	privateKey, err := LoadPrivateKeyECDSA("./_testfiles/ecdsa_private_key.pem")
	if err != nil {
		t.Fatalf("ecdsa: private key: %v", err)
	}

	publicKey, err := LoadPublicKeyECDSA("./_testfiles/ecdsa_public_key.pem")
	if err != nil {
		t.Fatalf("ecdsa: public key: %v", err)
	}

	// eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImthdGFyYXMifQ.oW8ic_m78NAzBPcl9TSX0qjqsyFUkyZQfvIHCJYC-DeVMLbbOjR78UGk-3XQ3o1nfyI2tQBXsYDc5OK80DR3yA
	testEncodeDecodeToken(t, ES256, privateKey, publicKey, nil)
	// test the automatic extract of public key from private key.
	testEncodeDecodeToken(t, ES256, privateKey, privateKey, nil)
}
