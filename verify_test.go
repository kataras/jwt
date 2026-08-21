package jwt

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"
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

// TestVerifyCaseInsensitiveClaimNames pins decodeOptions' MatchCaseInsensitiveNames(true)
// (jwt.go). This is not new behavior under json/v2 — encoding/json (v1) has always
// case-folded struct field matching — but it must not regress: a token whose issuer
// capitalized a standard claim name differently verified under Go 1.26 and must keep
// verifying under encoding/json/v2. Covers both decode call sites in verifyToken.
func TestVerifyCaseInsensitiveClaimNames(t *testing.T) {
	past := time.Now().Add(-time.Hour).Unix()

	t.Run("standardClaims decode path", func(t *testing.T) {
		// A bare (unquoted) number in "EXP" decodes directly into Claims.Expiry on the
		// first attempt.
		payload := []byte(fmt.Sprintf(`{"EXP":%d}`, past))
		token, err := encodeToken(testAlg, testSecret, payload, nil)
		if err != nil {
			t.Fatalf("encodeToken: %v", err)
		}

		if _, err := Verify(testAlg, testSecret, token); !errors.Is(err, ErrExpired) {
			t.Fatalf("expected ErrExpired (proves \"EXP\" matched the exp field) but got: %v", err)
		}
	})

	t.Run("claimsSecondChance decode path", func(t *testing.T) {
		// A quoted numeric string in "EXP" fails to decode into Claims.Expiry (an int64
		// field can't take a JSON string), which is exactly what forces the fallback to
		// claimsSecondChance, whose Expiry field is json.Number and does accept it.
		payload := []byte(fmt.Sprintf(`{"EXP":"%d"}`, past))
		token, err := encodeToken(testAlg, testSecret, payload, nil)
		if err != nil {
			t.Fatalf("encodeToken: %v", err)
		}

		if _, err := Verify(testAlg, testSecret, token); !errors.Is(err, ErrExpired) {
			t.Fatalf("expected ErrExpired (proves \"EXP\" matched via claimsSecondChance) but got: %v", err)
		}
	})
}

// TestSignInvalidUTF8Claim and TestVerifyInvalidUTF8Claim pin marshalOptions' and
// decodeOptions' AllowInvalidUTF8(true) (jwt.go). encoding/json (v1) replaces invalid
// UTF-8 with U+FFFD rather than erroring; a migration to encoding/json/v2 must keep that
// leniency, or a claim value that signed and verified successfully under Go 1.26 would
// start failing Sign or Verify under 1.27 for exactly the same bytes.
func TestSignInvalidUTF8Claim(t *testing.T) {
	claims := map[string]any{"note": "hello \xff\xfe world"}

	if _, err := Sign(testAlg, testSecret, claims); err != nil {
		t.Fatalf("Sign with invalid UTF-8 claim: expected no error but got: %v", err)
	}
}

func TestVerifyInvalidUTF8Claim(t *testing.T) {
	claims := map[string]any{"note": "hello \xff\xfe world"}

	token, err := Sign(testAlg, testSecret, claims)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	verifiedToken, err := Verify(testAlg, testSecret, token)
	if err != nil {
		t.Fatalf("Verify with invalid UTF-8 claim: expected no error but got: %v", err)
	}

	var got map[string]any
	if err := verifiedToken.Claims(&got); err != nil {
		t.Fatalf("Claims: %v", err)
	}

	// Invalid bytes are replaced with U+FFFD on the way out, matching what
	// encoding/json (v1) has always done — not preserved byte-for-byte.
	if want := "hello �� world"; got["note"] != want {
		t.Fatalf("claims[\"note\"] = %q, want %q", got["note"], want)
	}
}

func TestVerifiedTokenClaimsAs(t *testing.T) {
	type customClaims struct {
		Key      string `json:"key"`
		Audience string `json:"aud"`
	}

	tok := customClaims{"test key", "api"}
	token, err := Sign(testAlg, testSecret, tok)
	if err != nil {
		t.Fatal(err)
	}

	verifiedToken, err := Verify(testAlg, testSecret, token)
	if err != nil {
		t.Fatal(err)
	}

	got, err := verifiedToken.ClaimsAs[customClaims]()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, tok) {
		t.Fatalf("expected:\n%#+v\n\nbut got:\n%#+v", tok, got)
	}

	// Map destination: numbers must still come back as json.Number, exactly as they do
	// through Claims/Unmarshal, since ClaimsAs is a thin wrapper around Claims.
	mapClaims, err := verifiedToken.ClaimsAs[map[string]any]()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := mapClaims["key"]; !ok {
		t.Fatalf("expected \"key\" in map claims, got: %#+v", mapClaims)
	}

	// Error propagation: an incompatible destination type must surface the same error
	// Claims itself would return, not a distinct one.
	claimsErr := verifiedToken.Claims(&[]int{})
	_, claimsAsErr := verifiedToken.ClaimsAs[[]int]()
	if (claimsErr == nil) != (claimsAsErr == nil) {
		t.Fatalf("expected Claims and ClaimsAs to agree on error presence, got %v and %v", claimsErr, claimsAsErr)
	}
}

func TestUnverifiedTokenClaimsAs(t *testing.T) {
	token, err := Sign(testAlg, testSecret, map[string]any{"sub": "user-1"})
	if err != nil {
		t.Fatal(err)
	}

	unverified, err := Decode(token)
	if err != nil {
		t.Fatal(err)
	}

	claims, err := unverified.ClaimsAs[Map]()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := claims["sub"], "user-1"; got != want {
		t.Fatalf("claims[\"sub\"] = %v, want %v", got, want)
	}
}

func TestVerifyAs(t *testing.T) {
	type customClaims struct {
		Key string `json:"key"`
	}

	tok := customClaims{"test key"}
	token, err := Sign(testAlg, testSecret, tok)
	if err != nil {
		t.Fatal(err)
	}

	got, verifiedToken, err := VerifyAs[customClaims](testAlg, testSecret, token)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, tok) {
		t.Fatalf("expected:\n%#+v\n\nbut got:\n%#+v", tok, got)
	}
	if verifiedToken == nil {
		t.Fatal("expected a non-nil *VerifiedToken alongside the decoded claims")
	}

	// Error propagation: a bad signature must fail before claims are ever decoded, and
	// VerifyAs must still return a usable (nil) *VerifiedToken and the zero value of T.
	if _, verifiedToken, err := VerifyAs[customClaims](testAlg, []byte("othersecret"), token); err != ErrTokenSignature {
		t.Fatalf("expected %v but got: %v (verifiedToken: %v)", ErrTokenSignature, err, verifiedToken)
	}
}

func TestVerifyWithSingleAudienceString_CustomClaims(t *testing.T) {
	type customClaims struct {
		Key      string `json:"key"`
		Audience string `json:"aud"` // test custom struct with a single string as audience (see #3).
	}

	tok := customClaims{"test key", "api"}
	token, err := Sign(testAlg, testSecret, tok)
	if err != nil {
		t.Fatal(err)
	}

	verifiedToken, err := Verify(testAlg, testSecret, token)
	if err != nil {
		t.Fatal(err)
	}

	var got customClaims
	err = verifiedToken.Claims(&got)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(got, tok) {
		t.Fatalf("expected:\n%#+v\n\nbut got:\n%#+v", tok, got)
	}
}

func TestVerifyWithSingleAudienceString_CustomClaimsAndStandard(t *testing.T) {
	type customClaims struct {
		Key string `json:"key"`
	}

	standardClaims := Claims{Audience: []string{"api"}}

	custom := customClaims{"test key"}
	token, err := Sign(testAlg, testSecret, custom, standardClaims)
	if err != nil {
		t.Fatal(err)
	}

	verifiedToken, err := Verify(testAlg, testSecret, token)
	if err != nil {
		t.Fatal(err)
	}

	var gotCustom customClaims
	err = verifiedToken.Claims(&gotCustom)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(gotCustom, custom) {
		t.Fatalf("expected:\n%#+v\n\nbut got:\n%#+v", custom, gotCustom)
	}

	var gotStandard Claims
	err = verifiedToken.Claims(&gotStandard)
	if err != nil {
		t.Fatal(err)
	}

	// here we validate the Audience.UnmarshalJSON
	if !reflect.DeepEqual(gotStandard, standardClaims) {
		t.Fatalf("expected:\n%#+v\n\nbut got:\n%#+v", standardClaims, gotStandard)
	}

	if !reflect.DeepEqual(verifiedToken.StandardClaims, standardClaims) {
		t.Fatalf("expected:\n%#+v\n\nbut got:\n%#+v", standardClaims, gotStandard)
	}
}
