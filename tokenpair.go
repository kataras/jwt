package jwt

import "encoding/json"

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
	AccessToken  json.RawMessage `json:"access_token,omitempty"`
	RefreshToken json.RawMessage `json:"refresh_token,omitempty"`
}

// NewTokenPair creates a TokenPair from raw access and refresh token bytes.
//
// The function automatically quotes the token bytes to create valid JSON string values.
// This is useful when you have raw JWT tokens that need to be included in a JSON response.
//
// Either token can be nil/empty if you only want to include one token in the response.
// The omitempty tags will exclude empty tokens from the JSON output.
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
		AccessToken:  BytesQuote(accessToken),
		RefreshToken: BytesQuote(refreshToken),
	}
}

// BytesQuote wraps a byte slice in double quotes to create a JSON string value.
//
// This function creates a new byte slice with the input data surrounded by
// double quotes, making it suitable for use as a JSON string value.
//
// The function allocates a new slice that is exactly len(b)+2 bytes long
// and copies the input data between the quotes.
//
// Example:
//
//	token := []byte("eyJhbGciOiJIUzI1NiJ9...")
//	quoted := jwt.BytesQuote(token)
//	// quoted = []byte("\"eyJhbGciOiJIUzI1NiJ9...\"")
//
// This is primarily used internally by NewTokenPair but can be useful
// for other JSON formatting scenarios.
func BytesQuote(b []byte) []byte {
	dst := make([]byte, len(b)+2)
	dst[0] = '"'
	copy(dst[1:], b)
	dst[len(dst)-1] = '"'
	return dst
}
