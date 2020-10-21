package jwt

import (
	"crypto"
	"crypto/rsa"
	_ "crypto/sha256" // ignore:lint
	_ "crypto/sha512"
	"errors"
)

// The builtin signing available algorithms.
// Author's recommendation of choosing the best algorithm for your application:
// If you already work with RSA keys, choose RSA (length of produced token characters is bigger) - assymetric.
// If you need the separation between public and private key, Choose ECDSA or EdDSA(faster) - assymetric.
// ECDSA and EdDSA produces a smaller token than RSA.
// If you need performance and well-tested algorithm, choose HMAC - symmetric.
// The basic difference between symmetric and an asymmetric encryption algorithm
// is that symmetric encryption uses one key for both encryption and decryption,
// and the asymmetric encryption uses public key for encryption and a private key for decryption.
// In general, asymmetric data is more secure because it uses different keys
// for the encryption and decryption process but it's slower than symmetric ones.
var (
	// None for unsecured JWTs.
	// An unsecured JWT may be fit for client-side use.
	// For instance, if the session ID is a hard-to-guess number, and
	// the rest of the data is only used by the client for constructing a
	// view, the use of a signature is superfluous.
	// This data can be used by a single-page web application
	// to construct a view with the "pretty" name for the user
	// without hitting the backend while he gets
	// redirected to his last visited page. Even if a malicious user
	// were to modify this data he or she would gain nothing.
	// Example payload:
	//  {
	//    "sub": "user123",
	//    "session": "ch72gsb320000udocl363eofy",
	//    "name": "Pretty Name",
	//    "lastpage": "/views/settings"
	//  }
	NONE Alg = &algNONE{}
	// HMAC-SHA signing algorithms.
	// Keys should be type of []byte.
	HS256 Alg = &algHMAC{"HS256", crypto.SHA256}
	HS384 Alg = &algHMAC{"HS384", crypto.SHA384}
	HS512 Alg = &algHMAC{"HS512", crypto.SHA512}
	// RSA signing algorithms.
	// Sign   key: *rsa.PrivateKey
	// Verify key: *rsa.PublicKey (or *rsa.PrivateKey with its PublicKey filled)
	//
	// Signing and verifying RS256 signed tokens is just as easy.
	// The only difference lies in the use of a private/public key pair rather than a shared secret.
	// There are many ways to create RSA keys.
	// OpenSSL is one of the most popular libraries for key creation and management.
	// Generate a private key:
	// $ openssl genpkey -algorithm rsa -out private_key.pem -pkeyopt rsa_keygen_bits:2048
	// Derive the public key from the private key:
	// $ openssl rsa -pubout -in private_key.pem -out public_key.pem
	RS256 Alg = &algRSA{"RS256", crypto.SHA256}
	RS384 Alg = &algRSA{"RS384", crypto.SHA384}
	RS512 Alg = &algRSA{"RS512", crypto.SHA512}
	// RSASSA-PSS signing algorithms.
	// Sign   key: *rsa.PrivateKey
	// Verify key: *rsa.PublicKey (or *rsa.PrivateKey with its PublicKey filled)
	//
	// RSASSA-PSS is another signature scheme with appendix based on RSA.
	// PSS stands for Probabilistic Signature Scheme, in contrast with the usual deterministic approach.
	// This scheme makes use of a cryptographically secure random number generator.
	// If a secure RNG is not available, the resulting signature and verification operations
	// provide a level of security comparable to deterministic approaches.
	// This way RSASSA-PSS results in a net improvement over PKCS v1.5 signatures
	//
	// Note that the OpenSSL generates different OIDs to protect
	// reusing the same key material for different cryptosystems.
	PS256 Alg = &algRSAPSS{"PS256", &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: crypto.SHA256}}
	PS384 Alg = &algRSAPSS{"PS384", &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: crypto.SHA384}}
	PS512 Alg = &algRSAPSS{"PS512", &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: crypto.SHA512}}
	// ECDSA signing algorithms.
	// Sign   key: *ecdsa.PrivateKey
	// Verify key: *ecdsa.PublicKey (or *ecdsa.PrivateKey with its PublicKey filled)
	//
	// 4.2.3 ES256: ECDSA using P-256 and SHA-256
	// ECDSA algorithms also make use of public keys. The math behind the algorithm is different,
	// though, so the steps to generate the keys are different as well. The "P-256" in the name of this
	// algorithm tells us exactly which version of the algorithm to use.
	//
	// Generate a private key:
	// $ openssl ecparam -name prime256v1 -genkey -noout -out ecdsa_private_key.pem
	// Derive the public key from the private key:
	// $ openssl ec -in ecdsa_private_key.pem -pubout -out ecdsa_public_key.pem
	//
	// If you open these files you will note that there is much less data in them.
	// This is one of the benefits of ECDSA over RSA.
	// The generated files are in PEM format as well,
	// so simply pasting them in your source will suffice.
	// Higher performance than RSA and it generates a smaller token (almost 3 times less).
	ES256 Alg = &algECDSA{"ES256", crypto.SHA256, 32, 256}
	ES384 Alg = &algECDSA{"ES384", crypto.SHA384, 48, 384}
	ES512 Alg = &algECDSA{"ES512", crypto.SHA512, 66, 521}
	// Ed25519 Edwards-curve Digital Signature Algorithm.
	// The algorithm's name is: "EdDSA".
	// Sign   key: ed25519.PrivateKey
	// Verify key: ed25519.PublicKey
	// EdDSA uses small public keys (32 or 57 bytes)
	// and signatures (64 or 114 bytes) for Ed25519 and Ed448, respectively.
	// EdDSA provides HIGHER PERFORMANCE than RSA and ECDSA, HMAC is still the fastest one.
	// It is fairly new algorithm, this has its benefits and its downsides.
	// Personally, I recommend using this algorithm whenever you can.
	// Its standard library, which this jwt package use, added on go1.13.
	EdDSA Alg = &algEdDSA{"EdDSA"}
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
