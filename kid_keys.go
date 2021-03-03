package jwt

import "errors"

var (
	// ErrEmptyKid fires when the header is missing a "kid" field.
	ErrEmptyKid = errors.New("jwt: kid is empty")
	// ErrUnknownKid fires when the header has a "kid" field
	// but does not match with any of the registered ones.
	ErrUnknownKid = errors.New("jwt: unknown kid")
)

type (
	// HeaderWithKid represents a simple header part which
	// holds the "kid" and "alg" fields.
	HeaderWithKid struct {
		Kid string `json:"kid"`
		Alg string `json:"alg"`
	}

	// Key holds the Go parsed key pairs.
	// This package has all the helpers you need to parse
	// a file or a string to go crypto keys,
	// e.g. `ParsePublicKeyRSA` and `ParsePrivateKeyRSA` package-level functions.
	Key struct {
		ID      string
		Alg     Alg
		Public  PublicKey
		Private PrivateKey
	}

	// Keys is a map which holds the key id and a key pair.
	// User should initialize the keys once, not safe for concurrent writes.
	// See its `SignToken`, `VerifyToken` and `ValidateHeader` methods.
	// Usage:
	//  var keys jwt.Keys
	//  keys.Register("api", jwt.RS256, apiPubKey, apiPrivKey)
	//  keys.Register("cognito", jwt.RS256, cognitoPubKey, nil)
	//  ...
	//  token, err := keys.SignToken("api", myClaims{...}, jwt.MaxAge(15*time.Minute))
	//  ...
	//  var c myClaims
	//  err := keys.VerifyToken("api", token, &myClaims)
	//  }
	Keys map[string]*Key
)

// Get returns the key based on its id.
func (keys Keys) Get(kid string) (*Key, bool) {
	k, ok := keys[kid]
	return k, ok
}

// Register registers a keypair to a unique identifier per key.
func (keys Keys) Register(alg Alg, kid string, pubKey PublicKey, privKey PrivateKey) {
	keys[kid] = &Key{
		ID:      kid,
		Alg:     alg,
		Public:  pubKey,
		Private: privKey,
	}
}

// ValidateHeader validates the given json header value (base64 decoded) based on the "keys".
// Keys structure completes the `HeaderValidator` interface.
func (keys Keys) ValidateHeader(alg string, headerDecoded []byte) (Alg, PublicKey, error) {
	var h HeaderWithKid

	err := Unmarshal(headerDecoded, &h)
	if err != nil {
		return nil, nil, err
	}

	if h.Kid == "" {
		return nil, nil, ErrEmptyKid
	}

	key, ok := keys.Get(h.Kid)
	if !ok {
		return nil, nil, ErrUnknownKid
	}

	if h.Alg != key.Alg.Name() {
		return nil, nil, ErrTokenAlg
	}

	// If for some reason a specific alg was given by the caller then check that as well.
	if alg != "" && alg != h.Alg {
		return nil, nil, ErrTokenAlg
	}

	return key.Alg, key.Public, nil
}

// SignToken signs the "claims" using the given "alg" based a specific key.
func (keys Keys) SignToken(kid string, claims interface{}, opts ...SignOption) ([]byte, error) {
	k, ok := keys.Get(kid)
	if !ok {
		return nil, ErrUnknownKid
	}

	return SignWithHeader(k.Alg, k.Private, claims, HeaderWithKid{
		Kid: kid,
		Alg: k.Alg.Name(),
	}, opts...)
}

// VerifyToken verifies the "token" using the given "alg" based on the registered public key(s)
// and sets the custom claims to the destination "claimsPtr".
func (keys Keys) VerifyToken(token []byte, claimsPtr interface{}, validators ...TokenValidator) error {
	verifiedToken, err := VerifyWithHeaderValidator(nil, nil, token, keys.ValidateHeader, validators...)
	if err != nil {
		return err
	}

	return verifiedToken.Claims(&claimsPtr)
}
