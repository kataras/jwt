package jwt

import (
	"encoding/json"
	"reflect"
	"strconv"
	"testing"
	"time"
)

func TestBytesQuote(t *testing.T) {
	b := []byte("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiNTNhZmNmMDUtMzhhMy00M2Mz")
	bQuoted := BytesQuote(b)

	if expected, got := strconv.Quote(string(b)), string(bQuoted); expected != got {
		t.Fatalf("expected %s but got %s", expected, got)
	}
}

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
