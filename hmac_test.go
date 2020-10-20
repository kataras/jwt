package jwt

import "testing"

func TestEncodeDecodeTokenHMAC(t *testing.T) {
	key := []byte("secret")
	expectedToken := []byte("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImthdGFyYXMifQ.3VOM5969RLbycM0p8SrQLpugfExEWk-TAv6Du7BWUXg")
	testEncodeDecodeToken(t, HS256, key, key, expectedToken)
}
