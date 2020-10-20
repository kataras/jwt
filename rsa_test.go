package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"testing"
)

func TestEncodeDecodeTokenRSA(t *testing.T) {
	privateKey, err := loadPrivateKeyRSA("./_testfiles/rsa_private.key")
	if err != nil {
		t.Fatalf("rsa: private key: %v", err)
	}

	publicKey, err := loadPublicKeyRSA("./_testfiles/rsa_public.key")
	if err != nil {
		t.Fatalf("rsa: public key: %v", err)
	}

	expectedToken := []byte("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImthdGFyYXMifQ.NLM2chv-PdawOXushzNaN2vn5qS5gi34-5ZRTzqnzdx-YRT_oQOU6qyQJ7rKxYFxSzo1OPUFZYM4EigUC6JoMqxaD5HzVYJ0s5DMyqiOhQP9JcE4HbQxdGjN9559aKipIjkN_tJZLRU_59sS2qObArsZuK6tk-vcju8VNs1-hvzrEWlNth5mpjxjfjf89sNAvXh1-N8ju8nODtUXqVzP5TOTsTHUwDaUxsSTSi2YcJXphtCI8MeBXrDzHSvtnlWavgBcAAXsnIKz3U74N4ryv2HTeUZkazt1_azpRgYPfBptOLAJZbtw3q1FDqeitQ-vBEsD9lAl4NDJ7YN71OWKhA")
	testEncodeDecodeToken(t, RS256, privateKey, publicKey, expectedToken)
}

func generateTestFilesRSA() error {
	reader := rand.Reader
	bitSize := 2048

	privateKey, err := rsa.GenerateKey(reader, bitSize)
	if err != nil {
		return err
	}

	privateKeyDer := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyBlock := &pem.Block{
		Type:    "PRIVATE KEY",
		Headers: nil,
		Bytes:   privateKeyDer,
	}
	privKeyPem := pem.EncodeToMemory(privateKeyBlock)

	publicKeyDer, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return err
	}

	pubKeyBlock := &pem.Block{
		Type:    "PUBLIC KEY",
		Headers: nil,
		Bytes:   publicKeyDer,
	}
	pubKeyPem := pem.EncodeToMemory(pubKeyBlock)

	if err = ioutil.WriteFile("./_testfiles/rsa_private.key", privKeyPem, 0666); err != nil {
		return err
	}
	return ioutil.WriteFile("./_testfiles/rsa_public.key", pubKeyPem, 0666)
}

func loadPrivateKeyRSA(filename string) (*rsa.PrivateKey, error) {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	key, err := parsePrivateKeyRSA(b)
	if err != nil {
		return nil, err
	}

	return key, nil
}

func loadPublicKeyRSA(filename string) (*rsa.PublicKey, error) {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	key, err := parsePublicKeyRSA(b)
	if err != nil {
		return nil, err
	}

	return key, nil
}

func parsePrivateKeyRSA(key []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(key)
	if block == nil {
		return nil, fmt.Errorf("pem format missing")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
			pKey, ok := key.(*rsa.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("not a type of rsa private key")
			}

			privateKey = pKey
		} else {
			return nil, err
		}
	}

	return privateKey, nil
}

func parsePublicKeyRSA(key []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(key)
	if block == nil {
		return nil, fmt.Errorf("pem format missing")
	}

	parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			parsedKey = cert.PublicKey
		} else {
			return nil, err
		}
	}

	pkey, ok := parsedKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not a type of rsa public key")
	}

	return pkey, nil
}
