package jwt

import (
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// These tests cover inputs that used to reach a slice expression or a nil interface
// without a preceding check. Every one of them panicked before the guards were added, so
// a regression shows up as a panic rather than a failed assertion.

func TestGCMDecryptShortCiphertext(t *testing.T) {
	_, decrypt, err := GCM(MustGenerateRandom(32), nil)
	if err != nil {
		t.Fatal(err)
	}

	// The GCM nonce is 12 bytes. Anything shorter cannot carry one.
	for n := range 12 {
		got, err := decrypt(make([]byte, n))
		if !errors.Is(err, ErrDecrypt) {
			t.Fatalf("ciphertext of %d bytes: expected ErrDecrypt but got: %v", n, err)
		}
		if got != nil {
			t.Fatalf("ciphertext of %d bytes: expected nil payload but got: %q", n, got)
		}
	}

	// A ciphertext exactly the nonce length is long enough to slice, and fails
	// authentication instead.
	if _, err := decrypt(make([]byte, 12)); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("ciphertext of 12 bytes: expected ErrDecrypt but got: %v", err)
	}
}

func TestParsePrivateKeyEdDSAShortSeed(t *testing.T) {
	// Build a PEM whose ASN.1 structure is valid but whose inner private key octet
	// string is too short to hold the two-byte header, let alone a seed.
	for _, size := range []int{0, 1, 2, 5} {
		asn1Key := struct {
			Version          int
			ObjectIdentifier struct {
				ObjectIdentifier asn1.ObjectIdentifier
			}
			PrivateKey []byte
		}{
			Version:    0,
			PrivateKey: make([]byte, size),
		}
		asn1Key.ObjectIdentifier.ObjectIdentifier = asn1.ObjectIdentifier{1, 3, 101, 112}

		der, err := asn1.Marshal(asn1Key)
		if err != nil {
			t.Fatal(err)
		}

		block := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

		key, err := ParsePrivateKeyEdDSA(block)
		if err == nil {
			t.Fatalf("private key of %d bytes: expected an error but got a key of %d bytes", size, len(key))
		}
	}
}

func TestDecodeTokenWithoutAnyAlgorithm(t *testing.T) {
	token, err := Sign(HS256, testSecret, map[string]any{"username": "kataras"})
	if err != nil {
		t.Fatal(err)
	}

	// A HeaderValidator may return a nil Alg to mean "use the one the caller passed".
	// When the caller passed nil as well, nothing names an algorithm.
	noAlg := func(alg string, headerDecoded []byte) (Alg, PublicKey, InjectFunc, error) {
		return nil, testSecret, nil, nil
	}

	if _, err := VerifyWithHeaderValidator(nil, nil, token, noAlg); !errors.Is(err, ErrTokenAlg) {
		t.Fatalf("expected ErrTokenAlg but got: %v", err)
	}
}

func TestKeysWithNilAlg(t *testing.T) {
	keys := make(Keys)
	keys["broken"] = &Key{ID: "broken", Public: testSecret, Private: testSecret}

	header := Base64Encode([]byte(`{"alg":"HS256","typ":"JWT","kid":"broken"}`))
	decoded, err := Base64Decode(header)
	if err != nil {
		t.Fatal(err)
	}

	if _, _, _, err := keys.ValidateHeader("", decoded); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("ValidateHeader: expected ErrInvalidKey but got: %v", err)
	}

	if _, err := keys["broken"].Configuration(); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("Configuration: expected ErrInvalidKey but got: %v", err)
	}
}

func TestLoadHMACDirectory(t *testing.T) {
	// A directory is not key material. LoadHMAC must surface the read error rather than
	// quietly turning the directory's own path into the secret.
	dir := t.TempDir()

	if _, err := LoadHMAC(dir); err == nil {
		t.Fatalf("expected a read error for the directory %q", dir)
	}

	// A real file still loads its contents.
	path := filepath.Join(dir, "hmac.key")
	want := []byte("sercrethatmaycontainch@r$32chars")
	if err := os.WriteFile(path, want, 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := LoadHMAC(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("expected the file contents %q but got %q", want, got)
	}
}
