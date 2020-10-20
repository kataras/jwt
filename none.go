package jwt

import "bytes"

type algNONE struct{}

func (a *algNONE) Name() string {
	return "NONE"
}

func (a *algNONE) Sign(headerAndPayload []byte, key interface{}) ([]byte, error) {
	return nil, nil
}

func (a *algNONE) Verify(headerAndPayload []byte, signature []byte, key interface{}) error {
	if !bytes.Equal(signature, []byte{}) {
		return ErrTokenSignature
	}

	return nil
}
