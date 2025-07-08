package jwt

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

var testAlg, testSecret = HS256, []byte("sercrethatmaycontainch@r$")
var invalidKey = "inv"

func testEncodeDecodeToken(t *testing.T, alg Alg, signKey PrivateKey, verKey PublicKey, expectedToken []byte) {
	t.Helper()

	claims := map[string]any{
		"username": "kataras",
	}

	payload, err := Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}

	if alg != NONE { // test invalid key error for all algorithms.
		if _, err := encodeToken(alg, invalidKey, payload, nil); !errors.Is(err, ErrInvalidKey) {
			t.Fatalf("[%s] encode token: expected error: ErrInvalidKey but got: %v", alg.Name(), err)
		}
	}

	token, err := encodeToken(alg, signKey, payload, nil)
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

	// Test invalid signature.
	lastPartIdx := bytes.LastIndexByte(token, '.') + 1
	unexpectedSignature := []byte("DX22uANEy1qEG0m0utEW4YYfyNeuG9FzvRPMxpSaTc")
	unexpectedSignatureToken := make([]byte, len(token[0:lastPartIdx])+len(unexpectedSignature))
	copy(unexpectedSignatureToken, token[0:lastPartIdx])
	copy(unexpectedSignatureToken[len(token[0:lastPartIdx]):], unexpectedSignature)
	if _, _, _, err := decodeToken(alg, verKey, unexpectedSignatureToken, nil); !errors.Is(err, ErrTokenSignature) {
		t.Fatalf("[%s] decode token: expected error: ErrTokenSignature but got: %v", alg.Name(), err)
	}

	if alg != NONE { // test invalid key error for all algorithms.
		if _, _, _, err := decodeToken(alg, invalidKey, token, nil); !errors.Is(err, ErrInvalidKey) {
			t.Fatalf("[%s] decode token: expected error: ErrInvalidKey but got: %v: %q", alg.Name(), err, token)
		}
	}

	header, payload, _, err := decodeToken(alg, verKey, token, nil)
	if err != nil {
		t.Fatal(err)
	}
	// test header.
	if expected, got := createHeaderRaw(alg.Name()), header; !bytes.Equal(expected, got) {
		t.Fatalf("expected header: %q but got: %q", expected, got)
	}

	var got map[string]any
	if err = json.Unmarshal(payload, &got); err != nil {
		t.Fatal(err)
	}

	if !compareMap(claims, got) {
		t.Fatalf("payload didn't match, expected: %#+v but got: %#+v", claims, got)
	}
}

func TestCompareHeader(t *testing.T) {
	var tests = []struct {
		alg    string
		header string
		ok     bool
	}{
		{HS256.Name(), `{"alg":"HS256","typ":"JWT"}`, true},
		{HS256.Name(), `{"typ":"JWT","alg":"HS256"}`, true},
		{RS256.Name(), `{"alg":"HS256","typ":"JWT"}`, false},
		{"", `{"alg":"HS256","typ":"JWT"`, false},
		{HS256.Name(), "", false},
		{HS256.Name(), `{"alg":"HS256","typ":"JWT`, false},
		{HS256.Name(), `{"typ":"JWT","ALG":"HS256"}`, false},
	}

	for i, tt := range tests {
		_, _, _, err := compareHeader(tt.alg, []byte(tt.header))
		if tt.ok && err != nil {
			t.Fatalf("[%d] expected to pass but got error: %v", i, err)
		}

		if !tt.ok && err == nil {
			t.Fatalf("[%d] expected to fail", i)
		}
	}
}

func TestDecodeWithoutVerify(t *testing.T) {
	input := testToken
	tok, err := Decode(input)
	if err != nil {
		t.Fatal(err)
	}
	expectedPayload := []byte(`{"username":"kataras"}`)

	if !bytes.Equal(tok.Payload, expectedPayload) {
		t.Fatalf("expected payload part to be:\n%q\\nnbut got:\n %q", expectedPayload, tok.Payload)
	}
}

func BenchmarkEncodeToken(b *testing.B) {
	var claims = map[string]any{
		"username": "kataras",
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		payload, err := Marshal(claims)
		if err != nil {
			b.Fatal(err)
		}

		_, err = encodeToken(testAlg, testSecret, payload, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func compareMap(m1, m2 map[string]any) bool {
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

// This test verifies the fix for GitHub issue #13
func TestHeaderValidationWithAdditionalFields(t *testing.T) {
	tests := []struct {
		name   string
		header string
		alg    string
		valid  bool
	}{
		{
			name:   "Header with kid field and no typ (Cloudflare Zero Trust case)",
			header: `{"kid":"test-key-id","alg":"ES384"}`,
			alg:    "ES384",
			valid:  true,
		},
		{
			name:   "Header with kid field and typ=JWT",
			header: `{"kid":"test-key-id","alg":"ES384","typ":"JWT"}`,
			alg:    "ES384",
			valid:  true,
		},
		{
			name:   "Header with multiple additional fields",
			header: `{"kid":"key1","iss":"example.com","alg":"RS256","jku":"https://example.com/jwks"}`,
			alg:    "RS256",
			valid:  true,
		},
		{
			name:   "Header with wrong algorithm",
			header: `{"kid":"test-key","alg":"HS256"}`,
			alg:    "ES384",
			valid:  false,
		},
		{
			name:   "Header with invalid typ field",
			header: `{"kid":"test-key","alg":"ES384","typ":"INVALID"}`,
			alg:    "ES384",
			valid:  false,
		},
		{
			name:   "Standard header (should still work)",
			header: `{"alg":"ES384","typ":"JWT"}`,
			alg:    "ES384",
			valid:  true,
		},
		{
			name:   "Minimal header without typ (should still work)",
			header: `{"alg":"ES384"}`,
			alg:    "ES384",
			valid:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headerBytes := []byte(tt.header)
			_, _, _, err := compareHeader(tt.alg, headerBytes)

			if tt.valid && err != nil {
				t.Errorf("Expected header to be valid, but got error: %v", err)
			}
			if !tt.valid && err == nil {
				t.Errorf("Expected header to be invalid, but validation passed")
			}
		})
	}
}

func TestDecodeTokenWithKidField(t *testing.T) {
	// Create a token with kid field in header (base64url encoded)
	// Header: {"kid":"test-key-id","alg":"ES384"}
	// Payload: {"sub":"123456","name":"John Doe","admin":true}
	token := "eyJhbGciOiJFUzM4NCIsImtpZCI6InRlc3Qta2V5LWlkIn0.eyJzdWIiOiIxMjM0NTYiLCJuYW1lIjoiSm9obiBEb2UiLCJhZG1pbiI6dHJ1ZSwiaWF0IjoxNzUwMjA0MTEzfQ.QAfDHhbQgrejIol0fd4mmBMLU3i1Zn0yqN7ar41wRkuod7K5MbB0BjLxQHxB9PhuER9n7QuGSg8p45GDph4bjz17Z91MLwqlgMt0ws38O1MqxJ-gN9g0AyYzR86hTab5"

	// This should not fail with "unexpected token algorithm" error
	unverifiedToken, err := Decode([]byte(token))
	if err != nil {
		t.Fatalf("Should be able to decode token with kid field: %v", err)
	}

	if unverifiedToken == nil {
		t.Fatal("Decoded token should not be nil")
	}

	// Verify we can extract claims
	var claims map[string]interface{}
	err = unverifiedToken.Claims(&claims)
	if err != nil {
		t.Fatalf("Should be able to extract claims: %v", err)
	}

	if claims["sub"] != "123456" {
		t.Errorf("Expected sub claim to be '123456', got %v", claims["sub"])
	}
}
