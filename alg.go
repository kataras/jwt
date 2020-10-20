package jwt

import (
	"crypto"
	"errors"
)

// The builtin signing available algorithms.
var (
	// HMAC-SHA signing algorithms.
	// Keys should be type of []byte.
	HS256 Alg = &algHMAC{"HS256", crypto.SHA256}
	HS384 Alg = &algHMAC{"HS384", crypto.SHA384}
	HS512 Alg = &algHMAC{"HS512", crypto.SHA512}
	// RSA signing algorithms.
	// Sign   key: *rsa.PublicKey (or *rsa.PrivateKey with its PublicKey filled)
	// Verify key: *rsa.PrivateKey
	RS256 Alg = &algRSA{"RS256", crypto.SHA256}
	RS384 Alg = &algRSA{"RS384", crypto.SHA384}
	RS512 Alg = &algRSA{"RS512", crypto.SHA512}
)

var (
	// ErrTokenSignature indicates that the verification failed.
	ErrTokenSignature = errors.New("invalid token signature")
	// ErrInvalidKey indicates that an algorithm required secret key is not a valid type.
	ErrInvalidKey = errors.New("invalid key")
)

// Alg represents a signing and verifying algorithm.
type Alg interface {
	// Name should return the "alg" JWT field.
	Name() string
	// Sign should return the signed data based on the given
	// full header and payload data and a secret key.
	Sign(headerAndPayload []byte, key interface{}) ([]byte, error)
	// Verify should verify the JWT "signature" (base64-decoded) against
	// the header and payload data's one based on the given secret key.
	Verify(headerAndPayload []byte, signature []byte, key interface{}) error
	// Note:
	// some signing algorithms may be asymmetric,
	// so we accept the headerAndPayload as it's, instead of a Sign's result.
}
