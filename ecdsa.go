package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"math/big"
)

type algECDSA struct {
	name      string
	hasher    crypto.Hash
	keySize   int
	curveBits int
}

func (a *algECDSA) Name() string {
	return a.name
}

func (a *algECDSA) Sign(headerAndPayload []byte, key interface{}) ([]byte, error) {
	privateKey, ok := key.(*ecdsa.PrivateKey)
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
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hashed)
	if err != nil {
		return nil, err
	}

	curveBits := privateKey.Curve.Params().BitSize
	if a.curveBits != curveBits {
		return nil, ErrInvalidKey
	}

	keyBytes := curveBits / 8
	if curveBits%8 > 0 {
		keyBytes++
	}

	rBytes := r.Bytes()
	rBytesPadded := make([]byte, keyBytes)
	copy(rBytesPadded[keyBytes-len(rBytes):], rBytes)

	sBytes := s.Bytes()
	sBytesPadded := make([]byte, keyBytes)
	copy(sBytesPadded[keyBytes-len(sBytes):], sBytes)

	signature := append(rBytesPadded, sBytesPadded...)
	return signature, nil
}

func (a *algECDSA) Verify(headerAndPayload []byte, signature []byte, key interface{}) error {
	publicKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		if privateKey, ok := key.(*ecdsa.PrivateKey); ok {
			publicKey = &privateKey.PublicKey
		} else {
			return ErrInvalidKey
		}
	}

	if len(signature) != 2*a.keySize {
		return ErrTokenSignature
	}

	r := big.NewInt(0).SetBytes(signature[:a.keySize])
	s := big.NewInt(0).SetBytes(signature[a.keySize:])

	h := a.hasher.New()
	// header.payload
	_, err := h.Write(headerAndPayload)
	if err != nil {
		return err
	}

	hashed := h.Sum(nil)
	if !ecdsa.Verify(publicKey, hashed, r, s) {
		return ErrTokenSignature
	}

	return nil
}
