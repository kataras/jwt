package jwt

import (
	"crypto"
	"crypto/hmac"
	_ "crypto/sha256" // ignore:lint
	_ "crypto/sha512"
)

type algHMAC struct {
	name   string
	hasher crypto.Hash
}

func (a *algHMAC) Name() string {
	return a.name
}

func (a *algHMAC) Sign(headerAndPayload []byte, key interface{}) ([]byte, error) {
	secret, ok := key.([]byte)
	if !ok {
		return nil, ErrInvalidKey
	}

	// We can improve its performance (if we store the secret on the same structure)
	// by using a pool and its Reset method.
	h := hmac.New(a.hasher.New, secret)
	// header.payload
	_, err := h.Write(headerAndPayload)
	if err != nil {
		return nil, err // this should never happen according to the internal docs.
	}

	return h.Sum(nil), nil
}

func (a *algHMAC) Verify(headerAndPayload []byte, signature []byte, key interface{}) error {
	expectedSignature, err := a.Sign(headerAndPayload, key)
	if err != nil {
		return err
	}

	if !hmac.Equal(expectedSignature, signature) {
		return ErrTokenSignature
	}

	return nil
}
