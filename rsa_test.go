package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"testing"
)

// Test keys generated through OpenSSL CLI.
func TestEncodeDecodeTokenRSA(t *testing.T) {
	privateKey, err := LoadPrivateKeyRSA("./_testfiles/rsa_private_key.pem")
	if err != nil {
		t.Fatalf("rsa: private key: %v", err)
	}

	publicKey, err := LoadPublicKeyRSA("./_testfiles/rsa_public_key.pem")
	if err != nil {
		t.Fatalf("rsa: public key: %v", err)
	}

	expectedToken := []byte("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImthdGFyYXMifQ.g0cp5TqTxVA0w-xtt_tnR0LbyGbIiGqS_Kjbdh1HYu90gfcvFt5svZN4TA-TvO5wdFxflkeoGtX6iYMmIFnvaswPvxzHNso0nDWVStwkX5B0hu1CVqNvy_YGYO-RqMtVWbj5wjtbBnGdqDroWWAM2ynCnkRkl2kXHxlpNhZqkLNjz9yfLsYyzqj3h58hTo6BYCuh0jxtq7ihyxZfJQhFF41Wlmt0GqoYCKJ8vD2J8GjqhyDRanMEnz9KfYmhcLEoz1vNlo6ZYUqupRBRvAmJlujGuJntne-EJz7xkeH4dIpMSmlJeMSiZHEAKa-Q3YFvvK08Mi3DEEFGR9xgn0vOrQ")
	testEncodeDecodeToken(t, RS256, privateKey, publicKey, expectedToken)
}

// Test generated RSA keys from Go.
func TestEncodeDecodeTokenRSAGo(t *testing.T) {
	privateKey, err := LoadPrivateKeyRSA("./_testfiles/rsa_private_key_go.pem")
	if err != nil {
		t.Fatalf("rsa: private key: %v", err)
	}

	publicKey, err := LoadPublicKeyRSA("./_testfiles/rsa_public_key_go.pem")
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

	if err = ioutil.WriteFile("./_testfiles/rsa_private_key.pem", privKeyPem, 0666); err != nil {
		return err
	}
	return ioutil.WriteFile("./_testfiles/rsa_public_key.pem", pubKeyPem, 0666)
}
