package jwt

import "bytes"

// algNONE implements the Alg interface for unsecured JWTs.
// This algorithm provides no cryptographic security and should only be used
// when security is not a concern, such as for debugging or client-side data.
//
// WARNING: Tokens signed with "none" algorithm can be forged by anyone.
// Never use this algorithm for security-sensitive applications.
type algNONE struct{}

// Name returns "NONE" as the algorithm identifier.
func (a *algNONE) Name() string {
	return "NONE"
}

// Sign implements the Alg interface for the "none" algorithm.
// It returns an empty signature since no cryptographic signing is performed.
// The key parameter is ignored and can be nil.
func (a *algNONE) Sign(key PrivateKey, headerAndPayload []byte) ([]byte, error) {
	return nil, nil
}

// Verify implements the Alg interface for the "none" algorithm.
// It verifies that the signature is empty, as required by RFC 7515.
// Returns ErrTokenSignature if the signature is not empty.
func (a *algNONE) Verify(key PublicKey, headerAndPayload []byte, signature []byte) error {
	if !bytes.Equal(signature, []byte{}) {
		return ErrTokenSignature
	}

	return nil
}
