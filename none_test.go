package jwt

import "testing"

func TestEncodeDecodeTokenNONE(t *testing.T) {
	// The header decodes to {"alg":"none","typ":"JWT"}. It read "NONE" until v1.0.0,
	// which is not the name RFC 7518 section 3.6 gives the unsecured algorithm and which
	// no other implementation accepts.
	expectedToken := []byte("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VybmFtZSI6ImthdGFyYXMifQ.")
	testEncodeDecodeToken(t, NONE, nil, nil, expectedToken)
}
