package jwt

import (
	"bytes"
	"encoding/json"
	"testing"
)

var testAlg, testSecret = "HS256", []byte("secret")

func TestEncodeDecodeToken(t *testing.T) {
	var (
		claims = map[string]interface{}{
			"username": "kataras",
		}

		expectedToken = []byte("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImthdGFyYXMifQ.3VOM5969RLbycM0p8SrQLpugfExEWk-TAv6Du7BWUXg")
	)

	token, err := encodeToken(testAlg, testSecret, claims)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(token, expectedToken) {
		t.Fatalf("expected token not match, got: %s", string(token))
	}

	payload, err := decodeToken(testAlg, testSecret, token)
	if err != nil {
		t.Fatal(err)
	}

	var got map[string]interface{}
	if err = json.Unmarshal(payload, &got); err != nil {
		t.Fatal(err)
	}

	if !compareMap(claims, got) {
		t.Fatalf("payload didn't match, expected: %#+v but got: %#+v", claims, got)
	}
}

func BenchmarkEncodeToken(b *testing.B) {
	var claims = map[string]interface{}{
		"username": "kataras",
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := encodeToken(testAlg, testSecret, claims)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func compareMap(m1, m2 map[string]interface{}) bool {
	if len(m1) != len(m2) {
		return false
	}

	for k, v := range m1 {
		val, ok := m2[k]
		if !ok {
			return false
		}

		if v != val {
			return false
		}
	}

	return true
}
