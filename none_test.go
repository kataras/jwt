package jwt

import "testing"

func TestEncodeDecodeTokenNONE(t *testing.T) {
	expectedToken := []byte("eyJhbGciOiJOT05FIiwidHlwIjoiSldUIn0.eyJ1c2VybmFtZSI6ImthdGFyYXMifQ.")
	testEncodeDecodeToken(t, NONE, nil, nil, expectedToken)
}
