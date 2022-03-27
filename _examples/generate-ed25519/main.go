package main

import (
	"crypto/ed25519"
	"io/ioutil"
	"log"

	"github.com/kataras/jwt"
)

func main() {
	pub, priv, err := generateEdDSA()
	if err != nil {
		log.Fatal(err)
	}

	err = ioutil.WriteFile("ed25519_private.pem", priv, 0600)
	if err != nil {
		log.Fatalf("ed25519: private: write file: %w", err)
	}

	err = ioutil.WriteFile("ed25519_public.pem", pub, 0600)
	if err != nil {
		log.Fatalf("ed25519: public: write file: %w", err)
	}
}

func generateEdDSA() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return jwt.GenerateEdDSA()
}
