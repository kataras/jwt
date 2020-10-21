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

	expectedToken := []byte("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImthdGFyYXMifQ.UixieI36CqZGP0SNQmB5drz1ctFPPxKJGYx70iUvFM0bjziwSALZa0IQ9IZM6B5HndXVRYyTVWms_ONDozFP9j6eljGv7fLfl6_zY-kBWQhG3oqB7QuqsRZFfiUf-o9uuRYfAWZkpTVZieqA7kOL7mkvJiTfaZ2_Z3c3bUL7feY4JoVHvl6cI2ws1H-f9paiGourwXO4yE47Vr499vN0vIRSLqrOx3Q1AQkdru-3yFrjvo8Bgc8KXcU_rYS7FyDwFCDVeHLdtHpI1HVIQ625_TTZ7esjYdcbjLaHBq3Aj4nkJEoz-CszCD7RAQpB_hh7zMZUtDX3Yb1MGm8EL1GHmA")
	testEncodeDecodeToken(t, RS256, privateKey, publicKey, expectedToken)
}
