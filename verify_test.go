package jwt

import (
	"bytes"
	"errors"
	"testing"
)

// The actual implementation tests live inside token_test.go and each algorithm's test file.

type tokenValidatorTest struct {
}

var errTestvalidateToken = errors.New("test token validator error")

func (v tokenValidatorTest) ValidateToken(token []byte, claims Claims, err error) error {
	if err != nil {
		return err
	}

	return errTestvalidateToken
}
func TestVerify(t *testing.T) {
	if _, err := Verify(testAlg, testSecret, nil); err == nil {
		t.Fatalf("expected error to be: %v", ErrMissing)
	}

	_, err := Verify(testAlg, testSecret, testToken, tokenValidatorTest{})
	if err != errTestvalidateToken {
		t.Fatalf("expected verify token validator error: %v but got: %v", errTestvalidateToken, err)
	}

	_, err = Verify(testAlg, []byte("othersecret"), testToken, tokenValidatorTest{})
	if err != ErrTokenSignature {
		t.Fatalf("expected verify error: %v but got: %v", ErrTokenSignature, err)
	}
}

func TestPlainTokenValidator(t *testing.T) {
	payload := []byte("test raw\ncontents")
	token, err := Sign(testAlg, testSecret, payload)
	if err != nil {
		t.Fatal(err)
	}

	verifiedToken, err := Verify(testAlg, testSecret, token, Plain) // The user MUST enforce this option to allow raw payloads, it's a security feature.
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(verifiedToken.Payload, payload) {
		t.Fatalf("expected raw payload to match: %q but got: %q", payload, verifiedToken.Payload)
	}
}
