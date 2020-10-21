package jwt

import (
	"crypto/ed25519"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"testing"
)

func TestEncodeDecodeTokenEdDSA(t *testing.T) {
	privateKey, err := loadPrivateKeyEdDSA("./_testfiles/ed25519_private_key.pem")
	if err != nil {
		t.Fatalf("EdDSA: private key: %v", err)
	}

	publicKey, err := loadPublicKeyEdDSA("./_testfiles/ed25519_public_key.pem")
	if err != nil {
		t.Fatalf("EdDSA: public key: %v", err)
	}

	// eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImthdGFyYXMifQ.U3ChCsJwStNnEdE_wgkh5elQHIKPYfdi4BZoy8CWQNAaFymND_-6fwghDC4bQRrcotXjD6WZDaSrJ_W7uVoBBQ
	testEncodeDecodeToken(t, EdDSA, privateKey, publicKey, nil)
}

func loadPrivateKeyEdDSA(filename string) (ed25519.PrivateKey, error) {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	key, err := parsePrivateKeyEdDSA(b)
	if err != nil {
		return nil, err
	}

	return key, nil
}

func loadPublicKeyEdDSA(filename string) (ed25519.PublicKey, error) {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	key, err := parsePublicKeyEdDSA(b)
	if err != nil {
		return nil, err
	}

	return key, nil
}

func parsePrivateKeyEdDSA(key []byte) (ed25519.PrivateKey, error) {
	asn1PrivKey := struct {
		Version          int
		ObjectIdentifier struct {
			ObjectIdentifier asn1.ObjectIdentifier
		}
		PrivateKey []byte
	}{}

	block, _ := pem.Decode(key)
	if block == nil {
		return nil, fmt.Errorf("pem format missing")
	}

	if _, err := asn1.Unmarshal(block.Bytes, &asn1PrivKey); err != nil {
		return nil, err
	}

	privateKey := ed25519.NewKeyFromSeed(asn1PrivKey.PrivateKey[2:])
	return privateKey, nil
}

func parsePublicKeyEdDSA(key []byte) (ed25519.PublicKey, error) {
	asn1PubKey := struct {
		OBjectIdentifier struct {
			ObjectIdentifier asn1.ObjectIdentifier
		}
		PublicKey asn1.BitString
	}{}

	block, _ := pem.Decode(key)
	if block == nil {
		return nil, fmt.Errorf("pem format missing")
	}

	if _, err := asn1.Unmarshal(block.Bytes, &asn1PubKey); err != nil {
		return nil, err
	}

	publicKey := ed25519.PublicKey(asn1PubKey.PublicKey.Bytes)
	return publicKey, nil
}
