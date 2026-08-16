package jwt

// TokenPair represents a standard OAuth2/JWT token response containing
// both access and refresh tokens.
//
// This structure is designed to be JSON-serialized and sent to clients
// as part of authentication responses. The tokens are stored as json.RawMessage
// to preserve their exact byte representation and avoid unnecessary parsing.
//
// The structure follows OAuth2 conventions with "access_token" and "refresh_token"
// field names, making it compatible with standard OAuth2 clients and libraries.
//
// Example JSON output:
//
//	{
//	  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
//	  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
//	}
type TokenPair struct {
	// AccessToken is the short-lived credential the client sends on each request.
	AccessToken string `json:"access_token,omitempty"`
	// RefreshToken is the long-lived credential the client exchanges for a new access
	// token. Leave it empty for a response that does not issue one.
	RefreshToken string `json:"refresh_token,omitempty"`
	// IDToken carries identity claims about the user, as OpenID Connect defines it.
	// Optional, and empty for plain OAuth2 responses.
	//
	// Providers that issue one return all three together, and a two-field struct did not
	// match any real response, so callers declared their own type instead of using this
	// one.
	IDToken string `json:"id_token,omitempty"`
}

// NewTokenPair creates a TokenPair from raw access and refresh token bytes.
//
// The function automatically quotes the token bytes to create valid JSON string values.
// This is useful when you have raw JWT tokens that need to be included in a JSON response.
//
// Either token may be empty, and an empty one is left out of the JSON.
//
// That last part is new. The fields were json.RawMessage filled by BytesQuote, which
// returns two quote characters for no input, so an empty token was never empty as far as
// omitempty was concerned and the response carried "access_token":"" instead.
//
// Example:
//
//	accessToken, _ := jwt.Sign(jwt.HS256, key, accessClaims, jwt.MaxAge(15*time.Minute))
//	refreshToken, _ := jwt.Sign(jwt.HS256, key, refreshClaims, jwt.MaxAge(7*24*time.Hour))
//
//	pair := jwt.NewTokenPair(accessToken, refreshToken)
//
//	// Send as JSON response
//	w.Header().Set("Content-Type", "application/json")
//	json.NewEncoder(w).Encode(pair)
func NewTokenPair(accessToken, refreshToken []byte) TokenPair {
	return TokenPair{
		AccessToken:  string(accessToken),
		RefreshToken: string(refreshToken),
	}
}
