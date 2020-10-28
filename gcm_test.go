package jwt

import (
	"bytes"
	"reflect"
	"testing"
)

func TestGCM(t *testing.T) {
	// Get a plain, we will compare it later on.
	plainToken, err := Sign(testAlg, testSecret, Map{"foo": "bar", "age": 27}, Claims{Issuer: "issuer"})
	if err != nil {
		t.Fatal(err)
	}

	var (
		key           = MustGenerateRandom(32)
		addtionalData = []byte("adata")
		// constant-time because of AES.
		expectedToken = []byte("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.QmT4pOOamAy7TwdqeF6RpHplP21yMNulO5fVQqva2arIZExIerYfVtLwihoKShSTMtCXeKFlLRNlrRa7hav3DZg.en_w-8wf5nL_s7J1qiG3l0HasomYCe7qme4UfhDYOiw")
	)

	encrypt, decrypt, err := GCM(key, addtionalData)
	if err != nil {
		t.Fatal(err)
	}

	encryptedToken, err := SignEncrypted(testAlg, testSecret, encrypt, Map{"foo": "bar", "age": 27}, Claims{Issuer: "issuer"})
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Encrypted Token: %s", string(encryptedToken))

	if bytes.Equal(expectedToken, encryptedToken) {
		t.Fatalf("expected token to be: %q but got: %q", expectedToken, encryptedToken)
	}

	if bytes.Equal(plainToken, encryptedToken) {
		t.Fatalf("expected plain and encrypted token to be different: %s", string(plainToken))
	}

	// Test if encryption & decryption work as expected.
	verifiedToken, err := VerifyEncrypted(testAlg, testSecret, decrypt, encryptedToken)
	if err != nil {
		t.Fatal(err)
	}

	type claims struct {
		Foo    string `json:"foo"`
		Age    int    `json:"age"`
		Issuer string `json:"iss"`
	}
	expectedClaims := claims{"bar", 27, "issuer"}
	var gotClaims claims
	err = verifiedToken.Claims(&gotClaims)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(expectedClaims, gotClaims) {
		t.Fatalf("expected claims to be:\n%#+v\n\nbut got:\n%#+v", expectedClaims, gotClaims)
	}

	// Test try to decrypt unencrypted (failure).
	verifiedToken, err = VerifyEncrypted(testAlg, testSecret, decrypt, plainToken)
	if err != ErrDecrypt {
		t.Fatalf("expected error: %v but got: %v", ErrDecrypt, err)
	}

	// Test encrypted but different key (same additionalData).
	encrypt, decrypt, err = GCM(MustGenerateRandom(32), []byte("data"))
	if err != nil {
		t.Fatal(err)
	}
	verifiedToken, err = VerifyEncrypted(testAlg, testSecret, decrypt, encryptedToken)
	if err != ErrDecrypt {
		t.Fatalf("expected error: %v but got: %v", ErrDecrypt, err)
	}

	// Test fail because of different additionalData.
	encrypt, decrypt, err = GCM(key, []byte("a_data"))
	if err != nil {
		t.Fatal(err)
	}
	verifiedToken, err = VerifyEncrypted(testAlg, testSecret, decrypt, encryptedToken)
	if err != ErrDecrypt {
		t.Fatalf("expected error: %v but got: %v", ErrDecrypt, err)
	}
}
