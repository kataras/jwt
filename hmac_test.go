package jwt

import "testing"

func TestEncodeDecodeTokenHMAC(t *testing.T) {
	key := []byte("sercrethatmaycontainch@r$")
	expectedToken := []byte("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImthdGFyYXMifQ.HX22uANEy1qEG0m0utORW4YYfyNeuG9FzvRPMxpSaTc")
	testEncodeDecodeToken(t, HS256, key, key, expectedToken)
}
