package jwt

import (
	"reflect"
	"testing"
	"time"
)

// The actual implementation tests live inside token_test.go and each algorithm's test file.

func TestSignOption(t *testing.T) {
	now := time.Date(2020, 10, 26, 1, 1, 1, 1, time.Local)
	exp := now.Add(time.Second).Unix()
	iat := now.Unix()
	type claims struct {
		Foo      string `json:"foo"`
		Issuer   string `json:"iss"`
		Expiry   int64  `json:"exp"`
		IssuedAt int64  `json:"iat"`
	}
	expectedCustomClaims := claims{
		"bar",
		"issuer",
		exp,
		iat,
	}
	expectedStdClaims := Claims{Issuer: "issuer", Expiry: exp, IssuedAt: iat}

	prevClock := Clock
	t.Cleanup(func() {
		Clock = prevClock
	})

	Clock = func() time.Time {
		return now
	}

	token, err := Sign(testAlg, testSecret, Map{"foo": "bar"}, expectedStdClaims, MaxAge(time.Second))

	if err != nil {
		t.Fatal(err)
	}

	verifiedToken, err := Verify(testAlg, testSecret, token)
	if err != nil {
		t.Fatal(err)
	}

	if got := verifiedToken.StandardClaims; !reflect.DeepEqual(got, expectedStdClaims) {
		t.Fatalf("expected standard claims:\n%#+v\n\nbut got:\n%#+v", expectedStdClaims, got)
	}

	var got claims
	if err = verifiedToken.Claims(&got); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(expectedCustomClaims, got) {
		t.Fatalf("expected custom claims:\n%#+v\n\nbut got:\n%#+v", expectedCustomClaims, got)
	}
}
