package jwt

import (
	"encoding/json"
	"testing"
)

var testAlg, testSecret = "HS256", []byte("secret")

func TestGenerateAndVerifyToken(t *testing.T) {
	var claims = map[string]interface{}{
		"username": "kataras",
	}

	token, err := generateToken(claims, testAlg, testSecret)
	if err != nil {
		t.Fatal(err)
	}

	t.Log(string(token))

	payload, err := verifyToken(token, testAlg, testSecret)
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
