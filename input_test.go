package jwt

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestBase64DecodeDoesNotWriteIntoTheCallerBuffer(t *testing.T) {
	// bytes.Split caps every part it returns except the last, so the signature segment of
	// a token keeps the token's full capacity. Base64Decode used to append '=' bytes to
	// reach a multiple of four, and that append landed in the caller's buffer past the
	// end of the token. A pooled HTTP read buffer, which is how most servers hand a token
	// to this package, is exactly the case where that memory belongs to something else.
	token, err := Sign(HS256, testSecret, map[string]any{"sub": "user"})
	if err != nil {
		t.Fatal(err)
	}

	// A buffer with room to spare after the token, standing in for a pooled one. The
	// tail is filled with a sentinel that nothing should touch.
	const tail = 64
	buffer := make([]byte, len(token)+tail)
	copy(buffer, token)
	for i := len(token); i < len(buffer); i++ {
		buffer[i] = 0xAA
	}

	// Hand over a slice whose length stops at the token but whose capacity does not.
	view := buffer[:len(token)]

	if _, err = Verify(HS256, testSecret, view); err != nil {
		t.Fatal(err)
	}

	for i := len(token); i < len(buffer); i++ {
		if buffer[i] != 0xAA {
			t.Fatalf("byte %d past the end of the token was overwritten with %#x", i-len(token), buffer[i])
		}
	}
}

func TestBase64DecodeAcceptsPaddedAndUnpaddedInput(t *testing.T) {
	// JWT segments carry no padding, but Base64Decode is exported and has always taken
	// either form. Trimming instead of appending must not change that.
	for _, tt := range []struct{ in, want string }{
		{"eyJ1c2VybmFtZSI6ImthdGFyYXMifQ", `{"username":"kataras"}`},
		{"eyJ1c2VybmFtZSI6ImthdGFyYXMifQ==", `{"username":"kataras"}`},
		{"YQ", "a"},
		{"YQ==", "a"},
		{"YWI", "ab"},
		{"YWI=", "ab"},
		{"YWJj", "abc"},
		{"", ""},
	} {
		got, err := Base64Decode([]byte(tt.in))
		if err != nil {
			t.Fatalf("%q: %v", tt.in, err)
		}
		if string(got) != tt.want {
			t.Fatalf("%q: expected %q but got %q", tt.in, tt.want, got)
		}
	}

	// A round trip through both helpers still works.
	original := []byte(`{"a":1,"b":"two","c":[3]}`)
	decoded, err := Base64Decode(Base64Encode(original))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded, original) {
		t.Fatalf("round trip changed the bytes: %q", decoded)
	}
}

func TestTokenSizeLimit(t *testing.T) {
	// Verification allocates in proportion to the token it is given, and the token comes
	// from whoever is calling. Without a ceiling a single unauthenticated request could
	// ask the process for as much memory as it could send.
	oversized := make([]byte, MaxTokenSize+1)
	for i := range oversized {
		oversized[i] = 'a'
	}
	oversized[10] = '.'
	oversized[20] = '.'

	if _, err := Verify(HS256, testSecret, oversized); !errors.Is(err, ErrTokenSize) {
		t.Fatalf("Verify: expected ErrTokenSize but got: %v", err)
	}

	if _, err := Decode(oversized); !errors.Is(err, ErrTokenSize) {
		t.Fatalf("Decode: expected ErrTokenSize but got: %v", err)
	}

	// A token of a normal size is unaffected.
	token, err := Sign(HS256, testSecret, map[string]any{"sub": "user"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Verify(HS256, testSecret, token); err != nil {
		t.Fatal(err)
	}
}

// quotedNameAlg is a third-party Alg whose name would break out of the header JSON.
type quotedNameAlg struct{ name string }

func (a quotedNameAlg) Name() string { return a.name }

func (a quotedNameAlg) Sign(key PrivateKey, headerAndPayload []byte) ([]byte, error) {
	return nil, nil
}

func (a quotedNameAlg) Verify(key PublicKey, headerAndPayload []byte, signature []byte) error {
	return nil
}

func TestAlgorithmNameCannotInjectHeaderFields(t *testing.T) {
	// Alg is an exported interface and the header is built by concatenating Name() into a
	// JSON literal, so a third-party implementation could add header fields of its own
	// choosing to a token signed with somebody else's key.
	for _, name := range []string{
		`HS256","kid":"injected`,
		`HS256"}`,
		"HS256\\",
		"HS256\n",
		"",
		strings.Repeat("A", 200),
	} {
		alg := quotedNameAlg{name: name}

		if _, err := Sign(alg, testSecret, map[string]any{"sub": "user"}); !errors.Is(err, ErrTokenAlg) {
			t.Fatalf("name %q: expected ErrTokenAlg but got: %v", name, err)
		}
	}

	// A well-formed custom name still works, so this does not amount to an allowlist of
	// the built-in algorithms.
	alg := quotedNameAlg{name: "CUSTOM256"}
	token, err := Sign(alg, testSecret, map[string]any{"sub": "user"})
	if err != nil {
		t.Fatalf("a well-formed custom algorithm name must be accepted: %v", err)
	}
	if !bytes.Contains(token, Base64Encode([]byte(`{"alg":"CUSTOM256","typ":"JWT"}`))) {
		decoded, _ := Decode(token)
		t.Fatalf("unexpected header: %s", decoded.Header)
	}
}

func TestMergeRejectsFragmentsThatAreNotValidJSON(t *testing.T) {
	// Merge splices raw JSON rather than reparsing it, which is deliberate and is why it
	// is fast. It checked only the first and last byte, so a string or []byte value that
	// merely started with '{' and ended with '}' was spliced in as-is, and the result was
	// a signed token whose payload is not JSON at all.
	for _, bad := range []any{
		`{"broken"}`,
		`{"a":}`,
		`{"a":1,}`,
		[]byte(`{"unterminated":"`),
		`{]}`,
	} {
		if _, err := Merge(map[string]any{"sub": "user"}, bad); err == nil {
			t.Fatalf("%v: expected the fragment to be refused", bad)
		}
	}

	// Valid fragments still merge, in either form.
	got, err := Merge(map[string]any{"sub": "user"}, `{"role":"admin"}`)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"sub":"user","role":"admin"}` {
		t.Fatalf("unexpected merge result: %s", got)
	}
}

func TestMergeErrorDoesNotEchoTheClaims(t *testing.T) {
	// The error used to format the whole value with %v, so a payload full of personal
	// data or secrets landed in whatever the caller logged.
	_, err := Merge(map[string]any{"sub": "user"}, `{"password":"hunter2","ssn":"123-45-6789"}xx`)
	if err == nil {
		t.Fatal("expected an error")
	}

	for _, secret := range []string{"hunter2", "123-45-6789"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("the claims leaked into the error: %v", err)
		}
	}
}
