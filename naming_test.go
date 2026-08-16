package jwt

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// Names and types that contradict what the code does. Each of these compiled and ran for
// a long time while meaning something other than it said.

func TestNoneAlgorithmUsesTheNameFromTheRFC(t *testing.T) {
	if got := NONE.Name(); got != "none" {
		t.Fatalf(`RFC 7518 section 3.6 names the unsecured algorithm "none", got %q`, got)
	}

	token, err := Sign(NONE, nil, map[string]any{"sub": "user"})
	if err != nil {
		t.Fatal(err)
	}

	decoded, err := Decode(token)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(string(decoded.Header), `"alg":"none"`) {
		t.Fatalf("expected the header to name the RFC algorithm, got %s", decoded.Header)
	}

	if _, err = Verify(NONE, nil, token); err != nil {
		t.Fatalf("a token this package produced must verify here: %v", err)
	}
}

func TestGenerateJWKAcceptsPointerECDSAKeys(t *testing.T) {
	// Every ECDSA key this package produces is a *ecdsa.PublicKey. GenerateJWK matched
	// the value type only, so Keys.JWKS failed for every ES256, ES384 and ES512 key with
	// "unsupported public key type".
	_, ecdsaPublic := MustLoadECDSA("./_testfiles/ecdsa_private_key.pem", "./_testfiles/ecdsa_public_key.pem")

	jwk, err := GenerateJWK("ec-kid", "ES256", ecdsaPublic)
	if err != nil {
		t.Fatalf("a pointer ECDSA public key must be accepted: %v", err)
	}

	if jwk.Kty != "EC" || jwk.Crv != "P-256" || jwk.X == "" || jwk.Y == "" {
		t.Fatalf("incomplete EC JWK: %+v", jwk)
	}

	// The value type still works, so nothing that used to compile has stopped.
	if _, err = GenerateJWK("ec-kid", "ES256", *ecdsaPublic); err != nil {
		t.Fatalf("a value ECDSA public key must still be accepted: %v", err)
	}

	// And through the registry, which is where it mattered.
	keys := make(Keys)
	keys.Register(ES256, "ec-kid", ecdsaPublic, nil)
	if _, err = keys.JWKS(); err != nil {
		t.Fatalf("Keys.JWKS with an ECDSA key: %v", err)
	}
}

func TestJWKOmitsMembersThatDoNotApply(t *testing.T) {
	// RFC 7517 does not allow an RSA key to carry an empty "crv", or an EC key to carry
	// an empty "n" and "e". Some consumers reject them.
	_, rsaPublic := MustLoadRSA("./_testfiles/rsa_private_key.pem", "./_testfiles/rsa_public_key.pem")
	_, ecdsaPublic := MustLoadECDSA("./_testfiles/ecdsa_private_key.pem", "./_testfiles/ecdsa_public_key.pem")
	_, eddsaPublic := MustLoadEdDSA("./_testfiles/ed25519_private_key.pem", "./_testfiles/ed25519_public_key.pem")

	for _, tt := range []struct {
		name    string
		key     PublicKey
		alg     string
		absent  []string
		present []string
	}{
		{"rsa", rsaPublic, "RS256", []string{"crv", "x", "y"}, []string{"n", "e"}},
		{"ecdsa", ecdsaPublic, "ES256", []string{"n", "e"}, []string{"crv", "x", "y"}},
		{"ed25519", eddsaPublic, "EdDSA", []string{"n", "e", "y"}, []string{"crv", "x"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			jwk, err := GenerateJWK("kid", tt.alg, tt.key)
			if err != nil {
				t.Fatal(err)
			}

			b, err := json.Marshal(jwk)
			if err != nil {
				t.Fatal(err)
			}

			var members map[string]any
			if err = json.Unmarshal(b, &members); err != nil {
				t.Fatal(err)
			}

			for _, member := range tt.absent {
				if _, ok := members[member]; ok {
					t.Errorf("%q must be absent for this key type: %s", member, b)
				}
			}
			for _, member := range tt.present {
				if v, ok := members[member]; !ok || v == "" {
					t.Errorf("%q must be present and non-empty: %s", member, b)
				}
			}
		})
	}
}

func TestKeysJWKSIsOrderedByKeyID(t *testing.T) {
	// Keys is a map, so without an explicit order a handler serving
	// /.well-known/jwks.json returned a different body on every request.
	_, rsaPublic := MustLoadRSA("./_testfiles/rsa_private_key.pem", "./_testfiles/rsa_public_key.pem")

	keys := make(Keys)
	for _, kid := range []string{"delta", "alpha", "charlie", "bravo"} {
		keys.Register(RS256, kid, rsaPublic, nil)
	}

	var first string
	for range 10 {
		set, err := keys.JWKS()
		if err != nil {
			t.Fatal(err)
		}

		b, err := json.Marshal(set)
		if err != nil {
			t.Fatal(err)
		}

		if first == "" {
			first = string(b)
			continue
		}
		if string(b) != first {
			t.Fatal("the same registry produced two different key sets")
		}
	}

	set, err := keys.JWKS()
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range []string{"alpha", "bravo", "charlie", "delta"} {
		if set.Keys[i].Kid != want {
			t.Fatalf("expected %q at position %d but got %q", want, i, set.Keys[i].Kid)
		}
	}
}

func TestGenerateEdDSAReturnsPEM(t *testing.T) {
	// The declared return types said ed25519.PublicKey and ed25519.PrivateKey and the
	// body returned PEM text. It compiled because both are defined over []byte, and the
	// result could not be used for signing.
	publicPEM, privatePEM, err := GenerateEdDSA()
	if err != nil {
		t.Fatal(err)
	}

	if !strings.HasPrefix(string(privatePEM), "-----BEGIN PRIVATE KEY-----") {
		t.Fatalf("expected PEM, got %q", firstLine(privatePEM))
	}
	if !strings.HasPrefix(string(publicPEM), "-----BEGIN PUBLIC KEY-----") {
		t.Fatalf("expected PEM, got %q", firstLine(publicPEM))
	}

	// Parsed back, the keys sign and verify.
	privateKey, err := ParsePrivateKeyEdDSA(privatePEM)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := ParsePublicKeyEdDSA(publicPEM)
	if err != nil {
		t.Fatal(err)
	}

	if len(privateKey) != ed25519.PrivateKeySize {
		t.Fatalf("expected a %d byte private key, got %d", ed25519.PrivateKeySize, len(privateKey))
	}

	token, err := Sign(EdDSA, privateKey, map[string]any{"sub": "user"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Verify(EdDSA, publicKey, token); err != nil {
		t.Fatal(err)
	}
}

func firstLine(b []byte) string {
	if i := strings.IndexByte(string(b), '\n'); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

func TestKeysConfigurationLoadRejectsUnknownAlgorithms(t *testing.T) {
	// An unrecognised name used to leave the algorithm at its RS256 starting value, so a
	// typo produced a silently mis-configured key and confusing failures much later.
	for _, alg := range []string{"HS256 ", "hs2566", "", "RSA256", "nope"} {
		config := KeysConfiguration{{ID: "my-key", Alg: alg, Private: "x", Public: "y"}}

		if _, err := config.Load(); err == nil {
			t.Fatalf("alg %q: expected an error rather than a silent RS256 key", alg)
		} else if !strings.Contains(err.Error(), "my-key") {
			t.Fatalf("alg %q: the error must name the offending key, got: %v", alg, err)
		}
	}

	// A name that differs only in case is still accepted, as it was before.
	privatePEM, publicPEM, err := generateRSAPEM()
	if err != nil {
		t.Fatal(err)
	}

	config := KeysConfiguration{{ID: "my-key", Alg: "rs256", Private: privatePEM, Public: publicPEM}}
	keys, err := config.Load()
	if err != nil {
		t.Fatalf("a lowercase algorithm name must still load: %v", err)
	}
	if key, ok := keys.Get("my-key"); !ok || key.Alg != RS256 {
		t.Fatal("expected the RS256 key to be registered")
	}
}

func TestKeysConfigurationLoadNamesTheFailingKey(t *testing.T) {
	config := KeysConfiguration{
		{ID: "good-key", Alg: "HS256", Private: "secret", Public: "secret"},
		{ID: "broken-key", Alg: "RS256", Private: "not a pem block", Public: "nor is this"},
	}

	_, err := config.Load()
	if err == nil {
		t.Fatal("expected the malformed key to fail")
	}
	if !strings.Contains(err.Error(), "broken-key") {
		t.Fatalf("the error must name the key that failed, got: %v", err)
	}
}

func generateRSAPEM() (privatePEM, publicPEM string, err error) {
	private, public := MustLoadRSA("./_testfiles/rsa_private_key.pem", "./_testfiles/rsa_public_key.pem")

	if privatePEM, err = EncodePrivateKeyToPEM(private); err != nil {
		return "", "", err
	}

	publicPEM, err = EncodePublicKeyToPEM(public)
	return privatePEM, publicPEM, err
}

func TestMustGenerateRandomStringUsesTheWholeBuffer(t *testing.T) {
	// The buffer was indexed with j%length while it was refilled on j%bufferSize, and
	// bufferSize is larger for any length of four or more, so the tail of each buffer was
	// never read and its head was read repeatedly.
	//
	// This cannot assert randomness, but it can assert that the output is the right
	// length, uses the documented alphabet, and does not repeat across calls.
	seen := make(map[string]struct{})

	for _, length := range []int{1, 2, 4, 8, 16, 32, 64} {
		for range 50 {
			got := MustGenerateRandomString(length)
			if len(got) != length {
				t.Fatalf("length %d: got a string of %d", length, len(got))
			}

			for _, c := range got {
				if !strings.ContainsRune(letterBytes, c) {
					t.Fatalf("length %d: unexpected character %q", length, c)
				}
			}

			if length >= 16 {
				if _, repeat := seen[got]; repeat {
					t.Fatalf("length %d: the same string came back twice: %q", length, got)
				}
				seen[got] = struct{}{}
			}
		}
	}

	if got := MustGenerateRandomString(0); got != "" {
		t.Fatalf("expected an empty string for length 0, got %q", got)
	}
	if got := MustGenerateRandomString(-1); got != "" {
		t.Fatalf("expected an empty string for a negative length, got %q", got)
	}
}

func TestMixedRegistryPublishesAndExports(t *testing.T) {
	// A registry holding an HMAC key alongside asymmetric ones used to be unpublishable:
	// Keys.JWKS returned "unsupported public key type: []uint8" and refused the whole set,
	// and Keys.Configuration did the same. Both are ordinary things to want.
	_, rsaPublic := MustLoadRSA("./_testfiles/rsa_private_key.pem", "./_testfiles/rsa_public_key.pem")

	keys := make(Keys)
	keys.Register(RS256, "rsa", rsaPublic, nil)
	keys.Register(HS256, "hmac", testSecret, testSecret)

	set, err := keys.JWKS()
	if err != nil {
		t.Fatalf("a mixed registry must still publish: %v", err)
	}

	// The HMAC secret must never appear in a key set. Publishing it would hand out the
	// ability to mint tokens, which is the whole reason this skips rather than fails.
	if len(set.Keys) != 1 || set.Keys[0].Kid != "rsa" {
		t.Fatalf("expected only the RSA key to be published, got %d: %+v", len(set.Keys), set.Keys)
	}

	// Exporting does include it, because a configuration file is where a shared secret
	// legitimately lives, and it round trips.
	config, err := keys.Configuration()
	if err != nil {
		t.Fatalf("Configuration on a mixed registry: %v", err)
	}
	if len(config) != 2 {
		t.Fatalf("expected both keys to be exported, got %d", len(config))
	}

	back, err := config.Load()
	if err != nil {
		t.Fatalf("the exported configuration must load back: %v", err)
	}

	key, ok := back.Get("hmac")
	if !ok {
		t.Fatal("the HMAC key did not survive the round trip")
	}
	if secret, ok := key.Private.(string); !ok || secret != string(testSecret) {
		t.Fatalf("the HMAC secret changed in the round trip: %#v", key.Private)
	}
}

func TestSignTokenCallerOptionWins(t *testing.T) {
	// The key's MaxAge is prepended, so a caller-supplied one applies afterwards and wins.
	// The doc comment claimed the opposite until v0.2.0.
	keys := make(Keys)
	keys["k"] = &Key{ID: "k", Alg: HS256, Public: testSecret, Private: testSecret, MaxAge: 10 * time.Hour}

	token, err := keys.SignToken("k", map[string]any{"sub": "user"}, MaxAge(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}

	verified, err := keys.Verify(token)
	if err != nil {
		t.Fatal(err)
	}

	left := verified.StandardClaims.Timeleft()
	if left > 5*time.Minute {
		t.Fatalf("expected the caller's 2 minute MaxAge to win, but %v is left", left)
	}
}
