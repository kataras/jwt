package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha256" // ignore:lint
	_ "crypto/sha512"
)

type algRSA struct {
	name   string
	hasher crypto.Hash
}

func (a *algRSA) Name() string {
	return a.name
}

func (a *algRSA) Sign(headerAndPayload []byte, key interface{}) ([]byte, error) {
	privateKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, ErrInvalidKey
	}

	h := a.hasher.New()
	// header.payload
	_, err := h.Write(headerAndPayload)
	if err != nil {
		return nil, err
	}

	hashed := h.Sum(nil)
	return rsa.SignPKCS1v15(rand.Reader, privateKey, a.hasher, hashed)
}

func (a *algRSA) Verify(headerAndPayload []byte, signature []byte, key interface{}) error {
	publicKey, ok := key.(*rsa.PublicKey)
	if !ok {
		if privateKey, ok := key.(*rsa.PrivateKey); ok {
			publicKey = &privateKey.PublicKey
		} else {
			return ErrInvalidKey
		}
	}

	h := a.hasher.New()
	// header.payload
	_, err := h.Write(headerAndPayload)
	if err != nil {
		return err
	}

	hashed := h.Sum(nil)
	return rsa.VerifyPKCS1v15(publicKey, a.hasher, hashed, signature)
}
