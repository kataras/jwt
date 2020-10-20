package jwt

import (
	"encoding/json"
	"time"
)

// Clock is used to validate tokens expiration if the "exp" (expiration) exists in the payload.
// It can be overridden to use any other time value, useful for testing.
//
// Usage: now := Clock()
var Clock = time.Now

// Token generates a new token based on the algorithm and a secret key.
// The claims is the payload, the actual body of the token, should
// contain information about a specific authorized client.
// Note that the payload part is not encrypted
// therefore, it should NOT contain any private information.
func Token(alg string, secret []byte, claims interface{}) ([]byte, error) {
	return encodeToken(alg, secret, claims)
}

// VerifiedToken holds the information about a verified token.
// Look `VerifyToken` for more.
type VerifiedToken struct {
	// Note:
	// We don't provide information for header and signature parts
	// unless is requested.
	Token   []byte
	Payload []byte
	Claims  Claims
	Dest    interface{}
}

// VerifyToken decodes and verifies the given "token" based
// on the algorithm and the secret key that this token was generated with.
// It binds the payload part to the "dest" if not nil,
// it can be a json.RawMessage to delay unmarshal for multiple destinations
// or use the return VerifiedToken's Payload to unmarshal more custom data.
// The last variadic input argument is optional, can be used
// for further claims validations before exit.
// Returns the verified token information.
func VerifyToken(alg string, secret []byte, token []byte, dest interface{}, validators ...ClaimsValidator) (*VerifiedToken, error) {
	payload, err := decodeToken(alg, secret, token)
	if err != nil {
		return nil, err
	}

	var claims Claims
	err = json.Unmarshal(payload, &claims)
	if err != nil {
		return nil, err
	}

	err = validateClaims(Clock(), claims, validators...)
	if err != nil {
		return nil, err
	}

	if dest != nil {
		err = json.Unmarshal(payload, &dest)
	}

	verifiedTok := &VerifiedToken{
		Token:   token,
		Payload: payload,
		Claims:  claims,
		Dest:    dest,
	}
	return verifiedTok, nil
}
