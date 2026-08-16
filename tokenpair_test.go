package jwt

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestTokenPair(t *testing.T) {
	accessToken, err := Sign(testAlg, testSecret, Map{"foo": "bar"}, MaxAge(10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	refreshToken, err := Sign(testAlg, testSecret, Claims{Subject: "foobar"}, MaxAge(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	tokenPair := NewTokenPair(accessToken, refreshToken)

	b, err := json.Marshal(tokenPair)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var tokPair TokenPair
	if err = json.Unmarshal(b, &tokPair); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if !reflect.DeepEqual(tokenPair, tokPair) {
		t.Fatalf("expected token pairs to be matched, expected:\n%#+v\n\nbut got:\n%#+v", tokenPair, tokPair)
	}
}

func TestTokenPairOmitsEmptyTokens(t *testing.T) {
	// The fields were json.RawMessage filled by a helper that wrapped the bytes in
	// quotes, so an empty token became the two-byte value `""`. omitempty never fired and
	// every response carried "access_token":"" whether or not a token was issued.
	b, err := json.Marshal(NewTokenPair(nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "{}" {
		t.Fatalf("expected an empty object but got %s", b)
	}

	accessToken, err := Sign(testAlg, testSecret, Map{"foo": "bar"})
	if err != nil {
		t.Fatal(err)
	}

	b, err = json.Marshal(NewTokenPair(accessToken, nil))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "refresh_token") {
		t.Fatalf("an absent refresh token must be left out: %s", b)
	}
	if !strings.Contains(string(b), string(accessToken)) {
		t.Fatalf("the access token is missing from %s", b)
	}

	// An OpenID Connect response carries a third token, and a two-field struct matched no
	// real provider.
	pair := NewTokenPair(accessToken, nil)
	pair.IDToken = "an-id-token"
	b, err = json.Marshal(pair)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"id_token":"an-id-token"`) {
		t.Fatalf("expected the id token in %s", b)
	}
}
