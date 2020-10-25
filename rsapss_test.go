package jwt

import "testing"

func TestEncodeDecodeTokenRSAPSS(t *testing.T) {
	privateKey, err := LoadPrivateKeyRSA("./_testfiles/rsapss_private_key.pem")
	if err != nil {
		t.Fatalf("rsa-pss: private key: %v", err)
	}

	publicKey, err := LoadPublicKeyRSA("./_testfiles/rsapss_public_key.pem")
	if err != nil {
		t.Fatalf("rsa-pss: public key: %v", err)
	}

	testEncodeDecodeToken(t, PS256, privateKey, publicKey, nil)
	// test the automatic extract of public key from private key.
	testEncodeDecodeToken(t, PS256, privateKey, privateKey, nil)
}
