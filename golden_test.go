package jwt

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

// Golden tests pin the exact bytes this package emits today, so that a refactor which
// changes generated output cannot pass unnoticed. They are deliberately dumb: they record
// current behaviour, including behaviour that is wrong and scheduled to be fixed. When an
// entry legitimately changes, regenerate with:
//
//	go test -run TestGolden -update
//
// and record the before and after in PASS-LEDGER.md. A golden whose expectation was edited
// to match new output without that record proves nothing.

var updateGolden = flag.Bool("update", false, "rewrite testdata/golden.json from current output")

const goldenPath = "testdata/golden.json"

// goldenEntry is one recorded output, kept in a slice rather than a map so the file has a
// stable order and its diffs stay readable.
type goldenEntry struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func collectGolden(t *testing.T) []goldenEntry {
	t.Helper()

	rsaPrivate, rsaPublic := MustLoadRSA("./_testfiles/rsa_private_key.pem", "./_testfiles/rsa_public_key.pem")
	ecdsaPrivate, ecdsaPublic := MustLoadECDSA("./_testfiles/ecdsa_private_key.pem", "./_testfiles/ecdsa_public_key.pem")
	eddsaPrivate, eddsaPublic := MustLoadEdDSA("./_testfiles/ed25519_private_key.pem", "./_testfiles/ed25519_public_key.pem")

	claims := map[string]any{"username": "kataras"}

	var entries []goldenEntry
	add := func(name, value string) {
		entries = append(entries, goldenEntry{Name: name, Value: value})
	}
	addErr := func(name string, err error) {
		if err == nil {
			add(name, "<nil>")
			return
		}
		add(name, err.Error())
	}

	// Headers, one per algorithm. This is where the "NONE" versus RFC 7518 "none"
	// difference shows up.
	for _, alg := range allAlgs {
		add("header/"+alg.Name(), string(createHeaderRaw(alg.Name())))
	}

	// Whole tokens, for the algorithms whose signatures are deterministic.
	deterministic := []struct {
		alg Alg
		key PrivateKey
	}{
		{NONE, nil},
		{HS256, testSecret},
		{HS384, testSecret},
		{HS512, testSecret},
		{RS256, rsaPrivate},
		{RS384, rsaPrivate},
		{RS512, rsaPrivate},
		{EdDSA, eddsaPrivate},
	}
	for _, d := range deterministic {
		token, err := Sign(d.alg, d.key, claims)
		if err != nil {
			t.Fatalf("sign %s: %v", d.alg.Name(), err)
		}
		add("token/"+d.alg.Name(), string(token))
	}

	// ECDSA and RSA-PSS randomise the signature, so only the signed input is stable.
	for _, d := range []struct {
		alg Alg
		key PrivateKey
	}{
		{PS256, rsaPrivate},
		{PS384, rsaPrivate},
		{PS512, rsaPrivate},
		{ES256, ecdsaPrivate},
	} {
		token, err := Sign(d.alg, d.key, claims)
		if err != nil {
			t.Fatalf("sign %s: %v", d.alg.Name(), err)
		}
		add("signedinput/"+d.alg.Name(), string(token[:bytes.LastIndexByte(token, '.')]))
	}

	// A custom header replaces the whole header, so the emitted token carries no "alg"
	// at all. Recorded because the doc comment claims the opposite.
	customHeaderToken, err := SignWithHeader(HS256, testSecret, claims, map[string]any{"kid": "k1"})
	if err != nil {
		t.Fatalf("sign with header: %v", err)
	}
	add("token/customheader", string(customHeaderToken))

	// Base64.
	add("base64/encode", string(Base64Encode([]byte(`{"username":"kataras"}`))))
	decoded, err := Base64Decode([]byte("eyJ1c2VybmFtZSI6ImthdGFyYXMifQ"))
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	add("base64/decode", string(decoded))

	// JWK generation, per public key type. ECDSA currently fails, and that failure is
	// recorded so the fix is visible as a golden change.
	for _, c := range []struct {
		name string
		alg  string
		key  PublicKey
	}{
		{"rsa", "RS256", rsaPublic},
		{"ed25519", "EdDSA", eddsaPublic},
		{"ecdsa-pointer", "ES256", ecdsaPublic},
		{"ecdsa-value", "ES256", *ecdsaPublic},
	} {
		jwk, err := GenerateJWK("test-kid", c.alg, c.key)
		if err != nil {
			addErr("jwk/"+c.name, err)
			continue
		}
		b, err := json.Marshal(jwk)
		if err != nil {
			t.Fatalf("marshal jwk %s: %v", c.name, err)
		}
		add("jwk/"+c.name, string(b))
	}

	// A key set built from the registry.
	keys := make(Keys)
	keys.Register(RS256, "rsa-kid", rsaPublic, rsaPrivate)
	keys.Register(EdDSA, "eddsa-kid", eddsaPublic, eddsaPrivate)
	set, err := keys.JWKS()
	if err != nil {
		addErr("jwks/rsa+eddsa", err)
	} else {
		// No sorting here on purpose. Keys.JWKS orders by key id itself, and this
		// golden failing at random is how that was noticed in the first place.
		b, err := json.Marshal(set)
		if err != nil {
			t.Fatalf("marshal jwks: %v", err)
		}
		add("jwks/rsa+eddsa", string(b))
	}

	withECDSA := make(Keys)
	withECDSA.Register(ES256, "ecdsa-kid", ecdsaPublic, ecdsaPrivate)
	if _, err := withECDSA.JWKS(); err != nil {
		addErr("jwks/ecdsa", err)
	} else {
		add("jwks/ecdsa", "<no error>")
	}

	// PEM round trips.
	for _, c := range []struct {
		name    string
		private PrivateKey
		public  PublicKey
	}{
		{"rsa", rsaPrivate, rsaPublic},
		{"ecdsa", ecdsaPrivate, ecdsaPublic},
		{"ed25519", eddsaPrivate, eddsaPublic},
	} {
		// The PEM output is recorded as a digest rather than verbatim. It is only the
		// test fixtures from _testfiles, so nothing secret is at stake, but a golden file
		// full of "BEGIN PRIVATE KEY" is alarming to anyone scanning the repository and
		// puts a second copy of key material in the tree for no benefit. A digest fails
		// on any change to the encoder just as well.
		privatePEM, err := EncodePrivateKeyToPEM(c.private)
		if err != nil {
			addErr("pem/private/"+c.name, err)
		} else {
			add("pem/private/"+c.name, digest(privatePEM))
		}

		publicPEM, err := EncodePublicKeyToPEM(c.public)
		if err != nil {
			addErr("pem/public/"+c.name, err)
		} else {
			add("pem/public/"+c.name, digest(publicPEM))
		}
	}

	// Merge, including the duplicate-key case that other JSON readers resolve differently
	// from Go.
	for _, c := range []struct {
		name   string
		values []any
	}{
		{"two-objects", []any{[]byte(`{"a":1}`), []byte(`{"b":2}`)}},
		{"duplicate-key", []any{[]byte(`{"role":"admin"}`), []byte(`{"role":"user"}`)}},
		{"empty-object", []any{[]byte(`{}`), []byte(`{"a":1}`)}},
		{"struct-and-map", []any{struct {
			A int `json:"a"`
		}{A: 1}, map[string]any{"b": 2}}},
	} {
		merged, err := Merge(c.values...)
		if err != nil {
			addErr("merge/"+c.name, err)
			continue
		}
		add("merge/"+c.name, string(merged))
	}

	// TokenPair never omits an empty token, because BytesQuote returns two quote bytes
	// rather than nothing.
	for _, c := range []struct {
		name           string
		access, refres []byte
	}{
		{"both-empty", nil, nil},
		{"both-set", []byte("access"), []byte("refresh")},
	} {
		b, err := json.Marshal(NewTokenPair(c.access, c.refres))
		if err != nil {
			t.Fatalf("marshal token pair %s: %v", c.name, err)
		}
		add("tokenpair/"+c.name, string(b))
	}

	// Confirm the loaded key types are what the rest of the package assumes, so a golden
	// mismatch elsewhere is never traced back to a surprise here.
	add("keytype/rsa", typeName(rsaPublic))
	add("keytype/ecdsa", typeName(ecdsaPublic))
	add("keytype/ed25519", typeName(eddsaPublic))

	return entries
}

// digest records a value by its SHA-256 rather than in full. Used where the value is long,
// or is key material that does not belong in a second file.
func digest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func typeName(key PublicKey) string {
	switch key.(type) {
	case *rsa.PublicKey:
		return "*rsa.PublicKey"
	case *ecdsa.PublicKey:
		return "*ecdsa.PublicKey"
	case ecdsa.PublicKey:
		return "ecdsa.PublicKey"
	case ed25519.PublicKey:
		return "ed25519.PublicKey"
	default:
		return "unknown"
	}
}

func TestGolden(t *testing.T) {
	got := collectGolden(t)

	if *updateGolden {
		if err := os.MkdirAll(filepath.Dir(goldenPath), 0o755); err != nil {
			t.Fatal(err)
		}

		b, err := json.MarshalIndent(got, "", "  ")
		if err != nil {
			t.Fatal(err)
		}

		if err = os.WriteFile(goldenPath, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}

		t.Logf("wrote %d entries to %s", len(got), goldenPath)
		return
	}

	b, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("%v (run: go test -run TestGolden -update)", err)
	}

	var want []goldenEntry
	if err = json.Unmarshal(b, &want); err != nil {
		t.Fatal(err)
	}

	wantByName := make(map[string]string, len(want))
	for _, entry := range want {
		wantByName[entry.Name] = entry.Value
	}

	gotByName := make(map[string]string, len(got))
	for _, entry := range got {
		gotByName[entry.Name] = entry.Value

		expected, ok := wantByName[entry.Name]
		if !ok {
			t.Errorf("new golden entry %q with value:\n%s", entry.Name, entry.Value)
			continue
		}

		if expected != entry.Value {
			t.Errorf("golden %q changed.\nwant:\n%s\ngot:\n%s", entry.Name, expected, entry.Value)
		}
	}

	for _, entry := range want {
		if _, ok := gotByName[entry.Name]; !ok {
			t.Errorf("golden entry %q disappeared", entry.Name)
		}
	}
}
