package jwt

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

var testAlg, testSecret = HS256, []byte("secret")
var invalidKey = "inv"

func testEncodeDecodeToken(t *testing.T, alg Alg, signKey PrivateKey, verKey PublicKey, expectedToken []byte) {
	t.Helper()

	claims := map[string]interface{}{
		"username": "kataras",
	}

	if alg != NONE { // test invalid key error for all algorithms.
		if _, err := encodeToken(alg, invalidKey, claims); !errors.Is(err, ErrInvalidKey) {
			t.Fatalf("[%s] encode token: expected error: ErrInvalidKey but got: %v", alg.Name(), err)
		}
	}

	token, err := encodeToken(alg, signKey, claims)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Alg: %s\n\t\t Token: %s", alg.Name(), string(token))

	if len(expectedToken) > 0 {
		// ECDSA and EdDSA elliptics cannot produce the same token everytime.
		if !bytes.Equal(token, expectedToken) {
			t.Fatalf("expected token:\n%s\n\nbut got:\n%s", string(expectedToken), string(token))
		}
	}

	if alg != NONE { // test invalid key error for all algorithms.
		if _, _, _, err := decodeToken(alg, invalidKey, token); !errors.Is(err, ErrInvalidKey) {
			t.Fatalf("[%s] decode token: expected error: ErrInvalidKey but got: %v", alg.Name(), err)
		}
	}

	header, payload, _, err := decodeToken(alg, verKey, token)
	if err != nil {
		t.Fatal(err)
	}
	// test header.
	if expected, got := createHeaderRaw(alg.Name()), header; !bytes.Equal(expected, got) {
		t.Fatalf("expected header: %q but got: %q", expected, got)
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
