package jwt

import (
	"testing"
)

func TestEncodeDecodeTokenEdDSA(t *testing.T) {
	privateKey, err := LoadPrivateKeyEdDSA("./_testfiles/ed25519_private_key.pem")
	if err != nil {
		t.Fatalf("EdDSA: private key: %v", err)
	}

	publicKey, err := LoadPublicKeyEdDSA("./_testfiles/ed25519_public_key.pem")
	if err != nil {
		t.Fatalf("EdDSA: public key: %v", err)
	}

	// eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImthdGFyYXMifQ.U3ChCsJwStNnEdE_wgkh5elQHIKPYfdi4BZoy8CWQNAaFymND_-6fwghDC4bQRrcotXjD6WZDaSrJ_W7uVoBBQ
	testEncodeDecodeToken(t, EdDSA, privateKey, publicKey, nil)
}
