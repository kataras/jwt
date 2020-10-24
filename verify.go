package jwt

import "encoding/json"

// Verify decodes, verifies and validates the standard JWT claims
// of the given "token" using the algorithm and
// the secret key that this token was generated with.
//
// It returns a VerifiedToken which can be used to
// read the standard claims and some read-only information about the token.
// That VerifiedToken contains a `Claims` method, useful
// to bind the token's payload(claims) to a custom Go struct or a map when necessary.
//
// The last variadic input argument is optional, can be used
// for further claims validations before exit.
// Returns the verified token information.
//
// Example Code:
//
//  verifiedToken, err := jwt.Verify(jwt.HS256, []byte("secret"), token)
//  [handle error...]
//  var claims map[string]interface{}
//  verifiedToken.Claims(&claims)
func Verify(
	alg Alg,
	key PublicKey,
	token []byte,
	validators ...TokenValidator,
) (*VerifiedToken, error) {
	if len(token) == 0 {
		return nil, ErrMissing
	}

	header, payload, signature, err := decodeToken(alg, key, token)
	if err != nil {
		return nil, err
	}

	var claims Claims
	err = json.Unmarshal(payload, &claims) // use the standard one instead of the custom, no need to support "required" feature here.
	if err != nil {
		return nil, err
	}

	err = validateClaims(Clock(), claims)
	for _, validator := range validators {
		if validator == nil {
			continue
		}
		// A token validator can skip the builtin validation and return a nil error,
		// in that case the previous error is skipped.
		if err = validator.ValidateToken(token, claims, err); err != nil {
			break
		}
	}

	if err != nil {
		return nil, err
	}

	verifiedTok := &VerifiedToken{
		Token:          token,
		Header:         header,
		Payload:        payload,
		Signature:      signature,
		StandardClaims: claims,
	}
	return verifiedTok, nil
}

// TokenValidator provides further token and claims validation.
type TokenValidator interface {
	// ValidateToken accepts the token, the claims extracted from that
	// and any error that may caused by claims validation (e.g. ErrExpired)
	// or the previous validator.
	// A token validator can skip the builtin validation and return a nil error.
	// Usage:
	//  func(v *myValidator) ValidateToken(token []byte, claims Claims, err error) error {
	//    if err!=nil { return err } <- to respect the previous error
	//    // otherwise return nil or any custom error.
	//  }
	ValidateToken(token []byte, claims Claims, err error) error
}

// VerifiedToken holds the information about a verified token.
// Look `Verify` for more.
type VerifiedToken struct {
	Token          []byte // The original token.
	Header         []byte // The header (decoded) part.
	Payload        []byte // The payload (decoded) part.
	Signature      []byte // The signature (decoded) part.
	StandardClaims Claims // Any standard claims that are extracted from the payload.
}

// Claims decodes the token's payload to the "dest".
// If the application requires custom claims, this is the method to Go.
//
// It calls the `Unmarshal(t.Payload, dest)` package-level function .
// When called, it decodes the token's payload (aka claims)
// to the "dest" pointer of a struct or map value.
// Note that the `StandardClaims` field is always set,
// as it contains the standard JWT claims,
// and validated at the `Verify` function itself,
// therefore NO FURTHER STEP is required
// to validate the "exp", "iat" and "nbf" claims.
func (t *VerifiedToken) Claims(dest interface{}) error {
	return Unmarshal(t.Payload, dest)
}
