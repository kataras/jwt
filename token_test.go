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

// TestTokenFormRejectsWrongPartCount pins decodeToken and Decode's replacement of
// bytes.Split(token, sep); len(parts) != 3 with bytes.CutLast+bytes.Cut. The two must
// reject exactly the same malformed shapes: too few dots, and too many.
func TestTokenFormRejectsWrongPartCount(t *testing.T) {
	tests := []struct {
		name  string
		token string
	}{
		{"no dots", "abc"},
		{"one dot", "a.b"},
		{"three dots", "a.b.c.d"},
		{"four dots", "a.b.c.d.e"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := []byte(tt.token)

			if _, err := Verify(testAlg, testSecret, token); !errors.Is(err, ErrTokenForm) {
				t.Fatalf("Verify(%q): expected ErrTokenForm but got: %v", tt.token, err)
			}

			if _, err := Decode(token); !errors.Is(err, ErrTokenForm) {
				t.Fatalf("Decode(%q): expected ErrTokenForm but got: %v", tt.token, err)
			}
		})
	}

	// An empty token is rejected earlier, by Verify's own ErrMissing check, before it
	// ever reaches the CutLast/Cut parsing this test otherwise pins. Decode has no such
	// upfront check, so an empty token reaches CutLast directly and is rejected there.
	if _, err := Verify(testAlg, testSecret, []byte("")); !errors.Is(err, ErrMissing) {
		t.Fatalf("Verify(\"\"): expected ErrMissing but got: %v", err)
	}
	if _, err := Decode([]byte("")); !errors.Is(err, ErrTokenForm) {
		t.Fatalf("Decode(\"\"): expected ErrTokenForm but got: %v", err)
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
