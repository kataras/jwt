package jwt

import (
	"crypto/ed25519"
)

type algEdDSA struct {
	name string
}

func (a *algEdDSA) Name() string {
	return a.name
}

func (a *algEdDSA) Sign(headerAndPayload []byte, key interface{}) ([]byte, error) {
	privateKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, ErrInvalidKey
	}

	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, ErrInvalidKey
	}

	return ed25519.Sign(privateKey, []byte(headerAndPayload)), nil
}

func (a *algEdDSA) Verify(headerAndPayload []byte, signature []byte, key interface{}) error {
	publicKey, ok := key.(ed25519.PublicKey)
	if !ok {
		if privateKey, ok := key.(ed25519.PrivateKey); ok {
			publicKey = privateKey.Public().(ed25519.PublicKey)
		} else {
			return ErrInvalidKey
		}
	}

	if len(publicKey) != ed25519.PublicKeySize {
		return ErrInvalidKey
	}

	if !ed25519.Verify(publicKey, headerAndPayload, signature) {
		return ErrTokenSignature
	}

	return nil
}
