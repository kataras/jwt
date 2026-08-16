package jwt

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"testing"
)

// Enrich used to take both its algorithm and its entire header from the token it was
// handed, and it verified nothing. A caller that enriched a token it had received was
// therefore signing an attacker's header with its own private key, and could be steered
// to the unsecured algorithm and emit a token with no signature at all.
//
// These tests describe that attack from the attacker's side. Each one fails loudly if the
// oracle is ever reopened.

// craftToken assembles a token from a raw header and payload with an arbitrary signature,
// the way an attacker would, without going through Sign.
func craftToken(header, payload, signature string) []byte {
	var b bytes.Buffer
	b.Write(Base64Encode([]byte(header)))
	b.WriteByte('.')
	b.Write(Base64Encode([]byte(payload)))
	b.WriteByte('.')
	b.WriteString(signature)
	return b.Bytes()
}

func TestEnrichRefusesUnsignedToken(t *testing.T) {
	// The attacker presents a token claiming the unsecured algorithm and no signature.
	forged := craftToken(`{"alg":"NONE","typ":"JWT"}`, `{"sub":"attacker"}`, "")

	enriched, err := Enrich(HS256, testSecret, forged, map[string]any{"role": "admin"})
	if err == nil {
		t.Fatalf("expected the unsigned token to be refused, but got an enriched token: %s", enriched)
	}
	if !errors.Is(err, ErrTokenAlg) {
		t.Fatalf("expected ErrTokenAlg but got: %v", err)
	}
}

func TestEnrichRefusesTheUnsecuredAlgorithm(t *testing.T) {
	// Even when the caller asks for it directly, enriching under NONE is refused: the
	// result would be a token anyone can rewrite.
	token, err := Sign(NONE, nil, map[string]any{"sub": "user"})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := Enrich(NONE, nil, token, map[string]any{"role": "admin"}); !errors.Is(err, ErrTokenAlg) {
		t.Fatalf("expected ErrTokenAlg but got: %v", err)
	}

	// The same refusal applies on the lower-level path.
	unverified, err := Decode(token)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unverified.Enrich(NONE, nil, map[string]any{"role": "admin"}); !errors.Is(err, ErrTokenAlg) {
		t.Fatalf("UnverifiedToken.Enrich: expected ErrTokenAlg but got: %v", err)
	}
}

func TestEnrichRefusesAForeignSignature(t *testing.T) {
	// A token signed by somebody else must not be re-signed with our key.
	foreign, err := Sign(HS256, []byte("a-completely-different-shared-key"), map[string]any{"sub": "attacker"})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := Enrich(HS256, testSecret, foreign, map[string]any{"role": "admin"}); !errors.Is(err, ErrTokenSignature) {
		t.Fatalf("expected ErrTokenSignature but got: %v", err)
	}
}

func TestUnverifiedEnrichDoesNotCarryTheOriginalHeaderThrough(t *testing.T) {
	// UnverifiedToken.Enrich signs whatever it is handed without checking it, so it must
	// build a fresh header. Anything else means header fields chosen by whoever supplied
	// the token end up inside our signature.
	forged := craftToken(`{"alg":"HS256","typ":"JWT","kid":"chosen-by-the-attacker"}`,
		`{"sub":"attacker"}`, "not-a-real-signature")

	unverified, err := Decode(forged)
	if err != nil {
		t.Fatal(err)
	}

	enriched, err := unverified.Enrich(HS256, testSecret, map[string]any{"role": "admin"})
	if err != nil {
		t.Fatal(err)
	}

	decoded, err := Decode(enriched)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Contains(decoded.Header, []byte("chosen-by-the-attacker")) {
		t.Fatalf("the unverified header survived into the enriched token: %s", decoded.Header)
	}

	if expected := createHeaderRaw(HS256.Name()); !bytes.Equal(decoded.Header, expected) {
		t.Fatalf("expected the header %q but got %q", expected, decoded.Header)
	}
}

func TestEnrichKeepsAVerifiedHeader(t *testing.T) {
	// This is not a security assertion; the old code carried the header through as well.
	// It guards against the fix over-correcting. A header that survived verification was
	// covered by a signature made with our own key, so carrying it forward is safe, and
	// regenerating it here would silently strip a "kid" that the next verifier needs.
	original, err := SignWithHeader(HS256, testSecret, map[string]any{"sub": "user"},
		map[string]any{"alg": "HS256", "typ": "JWT", "kid": "our-own-key"})
	if err != nil {
		t.Fatal(err)
	}

	enriched, err := Enrich(HS256, testSecret, original, map[string]any{"role": "admin"})
	if err != nil {
		t.Fatal(err)
	}

	decoded, err := Decode(enriched)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Contains(decoded.Header, []byte("our-own-key")) {
		t.Fatalf("the verified header lost its kid: %s", decoded.Header)
	}
}

func TestEnrichDerivesTheVerificationKeyForEveryAlgorithm(t *testing.T) {
	// publicKeyOf works out the verification key from the signing key. For the asymmetric
	// algorithms that means crypto.Signer.Public().
	//
	// ed25519.PrivateKey is the case worth pinning: it is a defined type whose underlying
	// type is []byte, and it also implements crypto.Signer. A type switch matches defined
	// types only on the nose, so "case []byte" does not catch it and it reaches
	// "case crypto.Signer" as intended. If that ever inverted, the verification key would
	// be the private key and this test would fail rather than quietly doing the wrong
	// thing.
	rsaPrivate, _ := MustLoadRSA("./_testfiles/rsa_private_key.pem", "./_testfiles/rsa_public_key.pem")
	ecdsaPrivate, _ := MustLoadECDSA("./_testfiles/ecdsa_private_key.pem", "./_testfiles/ecdsa_public_key.pem")
	eddsaPrivate, eddsaPublic := MustLoadEdDSA("./_testfiles/ed25519_private_key.pem", "./_testfiles/ed25519_public_key.pem")

	tests := []struct {
		name    string
		alg     Alg
		private PrivateKey
		public  PublicKey
	}{
		{"HS256", HS256, testSecret, testSecret},
		{"RS256", RS256, rsaPrivate, &rsaPrivate.PublicKey},
		{"PS256", PS256, rsaPrivate, &rsaPrivate.PublicKey},
		{"ES256", ES256, ecdsaPrivate, &ecdsaPrivate.PublicKey},
		{"EdDSA", EdDSA, eddsaPrivate, eddsaPublic},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original, err := Sign(tt.alg, tt.private, map[string]any{"sub": "user"})
			if err != nil {
				t.Fatal(err)
			}

			enriched, err := Enrich(tt.alg, tt.private, original, map[string]any{"role": "admin"})
			if err != nil {
				t.Fatalf("enrich: %v", err)
			}

			verified, err := Verify(tt.alg, tt.public, enriched)
			if err != nil {
				t.Fatalf("the enriched token does not verify: %v", err)
			}

			var claims map[string]any
			if err = verified.Claims(&claims); err != nil {
				t.Fatal(err)
			}
			if claims["sub"] != "user" || claims["role"] != "admin" {
				t.Fatalf("expected both claims, got: %v", claims)
			}
		})
	}
}

func TestEnrichTokenBindsKidToItsRegisteredAlgorithm(t *testing.T) {
	keys := make(Keys)
	keys.Register(HS256, "signing-key", testSecret, testSecret)

	token, err := keys.SignToken("signing-key", map[string]any{"sub": "user"})
	if err != nil {
		t.Fatal(err)
	}

	enriched, err := keys.EnrichToken(token, map[string]any{"role": "admin"})
	if err != nil {
		t.Fatal(err)
	}

	// The enriched token still selects the same key on the way back in.
	var claims map[string]any
	if err = keys.VerifyToken(enriched, &claims); err != nil {
		t.Fatalf("the enriched token no longer verifies: %v", err)
	}
	if claims["role"] != "admin" {
		t.Fatalf("expected the extra claim to be merged, got: %v", claims)
	}
	if claims["sub"] != "user" {
		t.Fatalf("expected the original claim to survive, got: %v", claims)
	}

	// A token naming a registered kid but a different algorithm is refused rather than
	// enriched.
	forged := craftToken(`{"kid":"signing-key","alg":"NONE"}`, `{"sub":"attacker"}`, "")
	if _, err := keys.EnrichToken(forged, map[string]any{"role": "admin"}); err == nil {
		t.Fatal("expected the algorithm swap to be refused")
	}

	// So is one that names a registered kid but was signed with another key. The token
	// has to carry the right kid for this to be a test of the signature check at all: a
	// token with no kid is turned away earlier, by ErrEmptyKid, and would pass this test
	// against the old code that never checked a signature.
	foreignKeys := make(Keys)
	foreignKeys.Register(HS256, "signing-key", []byte("a-completely-different-shared-key"),
		[]byte("a-completely-different-shared-key"))

	foreign, err := foreignKeys.SignToken("signing-key", map[string]any{"sub": "attacker"})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := keys.EnrichToken(foreign, map[string]any{"role": "admin"}); !errors.Is(err, ErrTokenSignature) {
		t.Fatalf("expected ErrTokenSignature but got: %v", err)
	}

	// And one with no kid at all is turned away before any of that.
	noKid, err := Sign(HS256, testSecret, map[string]any{"sub": "attacker"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keys.EnrichToken(noKid, map[string]any{"role": "admin"}); !errors.Is(err, ErrEmptyKid) {
		t.Fatalf("expected ErrEmptyKid but got: %v", err)
	}
}

func TestKeysHMACRegistrationWithNilPublicKey(t *testing.T) {
	// The package's own documented example registers an HMAC key with a nil public key,
	// because HMAC verifies with the same secret it signs with. That produced a registry
	// entry which failed every verification with ErrInvalidKey.
	keys := make(Keys)
	keys.Register(HS256, "hmac-key", nil, testSecret)

	token, err := keys.SignToken("hmac-key", map[string]any{"sub": "user"})
	if err != nil {
		t.Fatal(err)
	}

	var claims map[string]any
	if err = keys.VerifyToken(token, &claims); err != nil {
		t.Fatalf("verifying an HMAC key registered with a nil public key: %v", err)
	}
	if claims["sub"] != "user" {
		t.Fatalf("expected the subject to survive, got: %v", claims)
	}

	if _, err = keys.EnrichToken(token, map[string]any{"role": "admin"}); err != nil {
		t.Fatalf("enriching the same token: %v", err)
	}
}

func TestTypedNilPublicKeyDoesNotPanic(t *testing.T) {
	// A nil pointer stored in an interface makes the interface non-nil, so a
	// *rsa.PublicKey(nil) passed every "is it nil" check in the verification path,
	// asserted successfully, and crashed inside crypto/rsa. Any token naming that kid
	// took the process down.
	rsaPrivate, _ := MustLoadRSA("./_testfiles/rsa_private_key.pem", "./_testfiles/rsa_public_key.pem")
	ecdsaPrivate, _ := MustLoadECDSA("./_testfiles/ecdsa_private_key.pem", "./_testfiles/ecdsa_public_key.pem")

	var nilRSA *rsa.PublicKey
	var nilECDSA *ecdsa.PublicKey

	tests := []struct {
		name   string
		alg    Alg
		public PublicKey
		token  []byte
	}{
		{"RS256", RS256, nilRSA, craftToken(`{"kid":"k","alg":"RS256"}`, `{"sub":"attacker"}`, "sig")},
		{"PS256", PS256, nilRSA, craftToken(`{"kid":"k","alg":"PS256"}`, `{"sub":"attacker"}`, "sig")},
		{"ES256", ES256, nilECDSA, craftToken(`{"kid":"k","alg":"ES256"}`, `{"sub":"attacker"}`, "sig")},
		{"EdDSA", EdDSA, ed25519.PrivateKey(nil), craftToken(`{"kid":"k","alg":"EdDSA"}`, `{"sub":"attacker"}`, "sig")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keys := make(Keys)
			keys.Register(tt.alg, "k", tt.public, nil)

			var claims map[string]any
			if err := keys.VerifyToken(tt.token, &claims); err == nil {
				t.Fatal("expected an error rather than a verified token")
			}
		})
	}

	// Signing with a typed-nil private key is rejected too, rather than panicking.
	for _, tt := range []struct {
		name    string
		alg     Alg
		private PrivateKey
	}{
		{"RS256", RS256, (*rsa.PrivateKey)(nil)},
		{"PS256", PS256, (*rsa.PrivateKey)(nil)},
		{"ES256", ES256, (*ecdsa.PrivateKey)(nil)},
	} {
		t.Run("sign/"+tt.name, func(t *testing.T) {
			if _, err := Sign(tt.alg, tt.private, map[string]any{"sub": "user"}); !errors.Is(err, ErrInvalidKey) {
				t.Fatalf("expected ErrInvalidKey but got: %v", err)
			}
		})
	}

	// The real keys still work, so the guards did not turn into a blanket rejection.
	for _, tt := range []struct {
		name    string
		alg     Alg
		private PrivateKey
		public  PublicKey
	}{
		{"RS256", RS256, rsaPrivate, &rsaPrivate.PublicKey},
		{"ES256", ES256, ecdsaPrivate, &ecdsaPrivate.PublicKey},
	} {
		t.Run("valid/"+tt.name, func(t *testing.T) {
			token, err := Sign(tt.alg, tt.private, map[string]any{"sub": "user"})
			if err != nil {
				t.Fatal(err)
			}
			if _, err = Verify(tt.alg, tt.public, token); err != nil {
				t.Fatal(err)
			}
		})
	}
}
