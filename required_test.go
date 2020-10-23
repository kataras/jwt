package jwt

import (
	"errors"
	"testing"
)

func TestUnmarshalWithRequired(t *testing.T) {
	token, err := Sign(testAlg, testSecret, Map{"username": "kataras"})
	if err != nil {
		t.Fatal(err)
	}

	verifiedToken, err := Verify(testAlg, testSecret, token)
	if err != nil {
		t.Fatal(err)
	}

	var claims = struct {
		Username string `json:"username,required"`
	}{}
	err = verifiedToken.Claims(&claims)
	if err != nil {
		t.Fatal(err)
	}

	if expected, got := "kataras", claims.Username; expected != got {
		t.Fatalf("expected claims{username} to be: %s but got: %s", expected, got)
	}

	var claimsShouldFail = struct {
		Username string `json:"username,required"`
		Age      int    `json:"age,required"`
	}{}
	err = verifiedToken.Claims(&claimsShouldFail)
	// this should pass as we don't set the Unmarshal func yet.
	if err != nil {
		t.Fatal(err)
	}
	Unmarshal = UnmarshalWithRequired
	// this should fail now.
	err = verifiedToken.Claims(&claimsShouldFail)
	if !errors.Is(err, ErrMissingKey) {
		t.Fatalf("expected error: ErrMissingKey but got: %v", err)
	}
}
