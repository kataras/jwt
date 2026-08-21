package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

// TestGenerateJWKECFixedWidthCoordinates checks that an EC JWK carries the full
// fixed-size coordinate RFC 7518 section 6.2.1.2 requires, on every curve this
// package supports.
func TestGenerateJWKECFixedWidthCoordinates(t *testing.T) {
	tests := []struct {
		alg   string
		crv   string
		curve elliptic.Curve
		size  int
	}{
		{"ES256", "P-256", elliptic.P256(), 32},
		{"ES384", "P-384", elliptic.P384(), 48},
		{"ES512", "P-521", elliptic.P521(), 66},
	}

	for _, tt := range tests {
		t.Run(tt.crv, func(t *testing.T) {
			// A handful of keys per curve. One in 256 P-256 keys has a leading zero
			// byte in a coordinate, so a run this short will not reliably hit the
			// short-encoding case on its own. TestGenerateJWKECLeadingZeroCoordinate
			// below covers that deterministically.
			for range 32 {
				privateKey, err := ecdsa.GenerateKey(tt.curve, rand.Reader)
				if err != nil {
					t.Fatalf("generate %s key: %v", tt.crv, err)
				}

				jwk, err := GenerateJWK("k", tt.alg, &privateKey.PublicKey)
				if err != nil {
					t.Fatalf("GenerateJWK: %v", err)
				}

				if jwk.Crv != tt.crv {
					t.Fatalf("crv = %q, want %q", jwk.Crv, tt.crv)
				}

				assertCoordinate(t, "x", jwk.X, tt.size)
				assertCoordinate(t, "y", jwk.Y, tt.size)
			}
		})
	}
}

// TestGenerateJWKECLeadingZeroCoordinate pins the case big.Int.Bytes() gets wrong:
// a P-256 key whose x coordinate begins with a zero byte. The old code encoded
// X.Bytes(), which strips that byte and emits 42 base64 characters instead of 43,
// producing a JWK other implementations reject.
func TestGenerateJWKECLeadingZeroCoordinate(t *testing.T) {
	// A real P-256 point, SEC 1 uncompressed: 0x04 || X || Y. Its X starts 0x00.
	const uncompressed = "04" +
		"000c34640140796806b4aca20b4605a149f658c3ffbb7e1c0c0f7799c5143cb6" +
		"33fa2119479f4ccb0c202c419d5c2166f535e5d1d56f1d68d0fb4d9eb93b04bd"

	point, err := hex.DecodeString(uncompressed)
	if err != nil {
		t.Fatal(err)
	}

	// point[0] is the 0x04 tag, so point[1] is the first byte of x. It being zero
	// is what made the minimal big.Int encoding one byte short.
	if point[1] != 0x00 {
		t.Fatal("the fixture no longer has a leading zero byte in x")
	}

	publicKey, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
	if err != nil {
		t.Fatalf("the fixture is not a valid P-256 point: %v", err)
	}

	jwk, err := GenerateJWK("k", "ES256", publicKey)
	if err != nil {
		t.Fatalf("GenerateJWK: %v", err)
	}

	x := assertCoordinate(t, "x", jwk.X, 32)
	if x[0] != 0x00 {
		t.Fatalf("x[0] = %#02x, want the leading zero byte to be kept", x[0])
	}

	assertCoordinate(t, "y", jwk.Y, 32)

	// The JWK must still parse back to the same key.
	back, err := convertJWKToPublicKeyEC(jwk)
	if err != nil {
		t.Fatalf("convertJWKToPublicKeyEC: %v", err)
	}

	if !publicKey.Equal(back) {
		t.Fatal("round trip through the JWK changed the key")
	}
}

// assertCoordinate decodes a base64url JWK coordinate and reports it unless its
// length differs from want.
func assertCoordinate(t *testing.T, name, encoded string, want int) []byte {
	t.Helper()

	// base64url of a fixed-width coordinate has a fixed length too.
	if wantLen := base64.RawURLEncoding.EncodedLen(want); len(encoded) != wantLen {
		t.Fatalf("%q is %d base64 characters, want %d: %q", name, len(encoded), wantLen, encoded)
	}

	b, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode %q: %v", name, err)
	}

	if len(b) != want {
		t.Fatalf("%q decodes to %d bytes, want %d", name, len(b), want)
	}

	return b
}
