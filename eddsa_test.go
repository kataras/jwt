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
	// test the automatic extract of public key from private key.
	testEncodeDecodeToken(t, EdDSA, privateKey, privateKey, nil)
}

func TestMustLoadEdDSA(t *testing.T) {
	catchPanic(t, false, func() {
		MustLoadEdDSA("./_testfiles/ed25519_private_key.pem", "./_testfiles/ed25519_public_key.pem")
	})
	catchPanic(t, true, func() {
		// test invalid keys.
		MustLoadEdDSA("./_testfiles/rsa_private_key.pem", "./_testfiles/rsa_public_key.pem")
		MustLoadEdDSA("./_testfiles/ecdsa_private_key.pem", "./_testfiles/ecdsa_public_key.pem")
		// test malformed pem file.
		MustLoadEdDSA("./_testfiles/invalid_pem.pem", "./_testfiles/invalid_pem.pem")
		// test not found file.
		MustLoadEdDSA("./invalid.pem", "./invalid.pem")
	})
}
