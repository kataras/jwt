package main

import (
	"log"
	"os"

	"github.com/kataras/jwt"
)

func main() {
	// GenerateEdDSA returns PEM text, which is why both halves are []byte and not
	// ed25519.PublicKey and ed25519.PrivateKey. Those were the declared return types
	// until v1.0.0, and they compiled only because both are defined over []byte: feeding
	// the result straight to jwt.Sign failed the key-length check.
	publicPEM, privatePEM, err := jwt.GenerateEdDSA()
	if err != nil {
		log.Fatal(err)
	}

	if err = os.WriteFile("ed25519_private.pem", privatePEM, 0o600); err != nil {
		log.Fatalf("ed25519: private: write file: %v", err)
	}

	if err = os.WriteFile("ed25519_public.pem", publicPEM, 0o600); err != nil {
		log.Fatalf("ed25519: public: write file: %v", err)
	}

	// Load them back to sign and verify with.
	privateKey, publicKey := jwt.MustLoadEdDSA("ed25519_private.pem", "ed25519_public.pem")

	token, err := jwt.Sign(jwt.EdDSA, privateKey, jwt.Map{"sub": "kataras"})
	if err != nil {
		log.Fatal(err)
	}

	if _, err = jwt.Verify(jwt.EdDSA, publicKey, token); err != nil {
		log.Fatal(err)
	}

	log.Printf("wrote ed25519_private.pem and ed25519_public.pem, and verified a token signed with them")
}
