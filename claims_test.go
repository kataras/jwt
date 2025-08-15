package jwt

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"
)

func TestValidateClaims(t *testing.T) {
	now := time.Now()
	expiresAt := now.Add(time.Minute)
	claims := Claims{
		Expiry:    expiresAt.Unix(),
		NotBefore: now.Unix(),
		IssuedAt:  now.Unix(),
	}
	if err := validateClaims(now, claims); err != nil {
		t.Fatal(err)
	}

	time.Sleep(2 * time.Second)
	if got := claims.Timeleft(); got >= time.Minute {
		t.Fatalf("expected timeleft to be lower than a minute but got: %s", got)
	}

	if expected, got := time.Minute, claims.Age(); expected != got {
		t.Fatalf("expected claim's total age to be: %v but got: %v", expected, got)
	}

	if expected, got := expiresAt.Unix(), claims.ExpiresAt().Unix(); expected != got {
		t.Fatalf("expected expires at to match: %d but got: %d", expected, got)
	}
}

func TestValidateClaimsNotBefore(t *testing.T) {
	now := time.Now()
	claims := Claims{
		NotBefore: now.Add(1 * time.Minute).Unix(),
	}
	if err := validateClaims(now, claims); err != ErrNotValidYet {
		t.Fatalf("expected token error: %v but got: %v", ErrNotValidYet, err)
	}
}

func TestValidateClaimsIssuedAt(t *testing.T) {
	now := time.Now()
	claims := Claims{
		IssuedAt: now.Unix(),
	}
	past := now.Add(-2 * time.Minute)
	// t.Logf("Now: %s", now.String())
	// t.Logf("Before now: %s", past.String())
	// t.Logf("Now Unix: %d", now.Unix())
	// t.Logf("Before now Unix: %d", past.Unix())

	if err := validateClaims(past, claims); err != ErrIssuedInTheFuture {
		t.Fatalf("expected token error: %v but got: %v", ErrIssuedInTheFuture, err)
	}
}

func TestValidateClaimsExpiry(t *testing.T) {
	now := time.Now()
	claims := Claims{
		Expiry: now.Add(20 * time.Second).Unix(),
	}

	if err := validateClaims(now.Add(21*time.Second), claims); err != ErrExpired {
		t.Fatalf("expected token error: %v but got: %v", ErrExpired, err)
	}
}

func TestApplyClaims(t *testing.T) {
	claims := Claims{
		NotBefore: 1,
		IssuedAt:  1,
		Expiry:    1,
		ID:        "id",
		Issuer:    "issuer",
		Subject:   "subject",
		Audience:  []string{"aud"},
	}

	var dest Claims
	claims.ApplyClaims(&dest)

	if !reflect.DeepEqual(claims, dest) {
		t.Fatalf("expected claims:\n%#+v\n\nbut got:\n%#+v", claims, dest)
	}
}

func TestMaxAge(t *testing.T) {
	maxAge := 10 * time.Minute
	now := Clock()
	var claims Claims
	expectedClaims := Claims{
		Expiry:   now.Add(maxAge).Unix(),
		IssuedAt: now.Unix(),
	}
	MaxAge(maxAge)(&claims)

	if !reflect.DeepEqual(claims, expectedClaims) {
		t.Fatalf("expected claims:\n%#+v\n\nbut got:\n%#+v", expectedClaims, claims)
	}

	// test not set.
	claims = Claims{}
	MaxAge(time.Second)(&claims)
	if !reflect.DeepEqual(claims, Claims{}) {
		t.Fatalf("expected Expiry and IssuedAt not be set because the given max age was less than a second")
	}
}

func TestMaxAgeMap(t *testing.T) {
	prevClock := Clock
	defer func() {
		Clock = prevClock
	}()
	Clock = func() time.Time {
		return time.Date(2020, 10, 26, 1, 1, 1, 1, time.Local) // dupl the value just to resolve the test race cond.
	}

	var (
		maxAge      = 10 * time.Minute
		now         = time.Date(2020, 10, 26, 1, 1, 1, 1, time.Local)
		expectedExp = now.Add(maxAge).Unix()
		expectedIat = now.Unix()
	)

	claims := make(Map)
	MaxAgeMap(maxAge, claims)

	if got := claims["exp"]; got != expectedExp {
		t.Fatalf("expected map[exp]: %v but got: %v", expectedExp, got)
	}

	if got := claims["iat"]; got != expectedIat {
		t.Fatalf("expected map[iat]: %v but got: %v", expectedIat, got)
	}

	// test no set.
	claims = make(Map)
	MaxAgeMap(time.Second, claims)
	if claims["exp"] != nil || claims["iat"] != nil {
		t.Fatalf("expected map's exp and iat not be set because the given max age was less than a second")
	}

	// test no panic if nil.
	MaxAgeMap(maxAge, nil)
}

func TestClaimsSubAsInt(t *testing.T) {
	secret := "secret"
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEyMywibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.QzFnWiase0tPyeNzn8ecl-kVfDVEZ1ctbf9ztM0Qjqg"

	verifiedToken, err := Verify(HS256, []byte(secret), []byte(token))
	if err != nil {
		t.Fatal(err)
	}

	expectedClaims := Claims{NotBefore: 0, IssuedAt: 1516239022, Expiry: 0, ID: "", Issuer: "", Subject: "123", Audience: nil}
	if !reflect.DeepEqual(verifiedToken.StandardClaims, expectedClaims) {
		t.Fatalf("expected: %#+v but got: %#+v\n", expectedClaims, verifiedToken.StandardClaims)
	}
}

func TestMerge(t *testing.T) {
	now := time.Now().Unix()
	expiry := time.Now().Add(15 * time.Minute).Unix()

	tests := []struct {
		name     string
		claims   any
		other    any
		expected map[string]any
	}{
		{
			name:     "merge with empty object",
			claims:   map[string]any{"foo": "bar"},
			other:    map[string]any{},
			expected: map[string]any{"foo": "bar"},
		},
		{
			name:     "merge two maps",
			claims:   map[string]any{"foo": "bar"},
			other:    map[string]any{"baz": "qux"},
			expected: map[string]any{"foo": "bar", "baz": "qux"},
		},
		{
			name: "merge with Claims struct",
			claims: map[string]any{
				"custom": "value",
			},
			other: Claims{
				Issuer:   "test-issuer",
				IssuedAt: now,
				Expiry:   expiry,
			},
			expected: map[string]any{
				"custom": "value",
				"iss":    "test-issuer",
				"iat":    float64(now), // JSON numbers are decoded as float64
				"exp":    float64(expiry),
			},
		},
		{
			name:     "merge with nil",
			claims:   map[string]any{"foo": "bar"},
			other:    nil,
			expected: map[string]any{"foo": "bar"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Merge(tt.claims, tt.other)
			if err != nil {
				t.Fatalf("Failed to merge: %v", err)
			}

			var got map[string]any
			if err := json.Unmarshal(result, &got); err != nil {
				t.Fatalf("Failed to unmarshal result: %v", err)
			}

			if !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("Merge() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestMergeAndSign(t *testing.T) {
	now := time.Now().Unix()
	expiry := time.Now().Add(15 * time.Minute).Unix()

	tests := []struct {
		name     string
		claims   any
		other    any
		expected map[string]any
	}{
		{
			name:     "merge and sign with empty object",
			claims:   map[string]any{"foo": "bar"},
			other:    map[string]any{},
			expected: map[string]any{"foo": "bar"},
		},
		{
			name:     "merge and sign two maps",
			claims:   map[string]any{"foo": "bar"},
			other:    map[string]any{"baz": "qux"},
			expected: map[string]any{"foo": "bar", "baz": "qux"},
		},
		{
			name: "merge and sign with Claims struct",
			claims: map[string]any{
				"custom": "value",
			},
			other: Claims{
				Issuer:   "test-issuer",
				IssuedAt: now,
				Expiry:   expiry,
			},
			expected: map[string]any{
				"custom": "value",
				"iss":    "test-issuer",
				"iat":    fmt.Sprintf("%d", now),
				"exp":    fmt.Sprintf("%d", expiry),
			},
		},
	}

	key := []byte("secret")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mergedClaims, err := Merge(tt.claims, tt.other)
			if err != nil {
				t.Fatalf("Failed to merge: %v", err)
			}

			token, err := Sign(HS256, key, mergedClaims)
			if err != nil {
				t.Fatalf("Failed to sign token: %v", err)
			}

			t.Logf("Generated token: %s", string(token))

			var verifiedClaims map[string]any
			verifiedToken, err := Verify(HS256, key, token)
			if err != nil {
				t.Fatalf("Failed to verify token: %v", err)
			}

			err = verifiedToken.Claims(&verifiedClaims)
			if err != nil {
				t.Fatalf("Failed to get claims from token: %v", err)
			}

			if exp, ok := verifiedClaims["exp"].(json.Number); ok {
				verifiedClaims["exp"] = exp.String()
			}
			if iat, ok := verifiedClaims["iat"].(json.Number); ok {
				verifiedClaims["iat"] = iat.String()
			}

			t.Logf("Expected exp type: %T, value: %v", tt.expected["exp"], tt.expected["exp"])
			t.Logf("Actual exp type: %T, value: %v", verifiedClaims["exp"], verifiedClaims["exp"])
			t.Logf("Expected iat type: %T, value: %v", tt.expected["iat"], tt.expected["iat"])
			t.Logf("Actual iat type: %T, value: %v", verifiedClaims["iat"], verifiedClaims["iat"])

			if !reflect.DeepEqual(verifiedClaims, tt.expected) {
				t.Errorf("Claims after merge and verify = %#v, want %#v", verifiedClaims, tt.expected)
			}
		})
	}
}

func TestMergeJSONNilValues(t *testing.T) {
	// When all values are nil, expect an empty object.
	merged, err := Merge(nil, nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	expected := "{}"
	if string(merged) != expected {
		t.Errorf("Expected %s, got %s", expected, string(merged))
	}
}

func TestMergeJSONEmptyObjects(t *testing.T) {
	// When all values are empty objects, expect an empty object.
	merged, err := Merge(map[string]int{}, map[string]int{})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	expected := "{}"
	if string(merged) != expected {
		t.Errorf("Expected %s, got %s", expected, string(merged))
	}
}

func TestMergeJSONSingleObject(t *testing.T) {
	// Single non-empty object should be returned as is.
	input := map[string]int{"a": 1}
	merged, err := Merge(input)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	expectedBytes, _ := json.Marshal(input)
	if string(merged) != string(expectedBytes) {
		t.Errorf("Expected %s, got %s", string(expectedBytes), string(merged))
	}
}

func TestMergeJSONTwoObjects(t *testing.T) {
	// Merge two objects.
	obj1 := map[string]int{"a": 1}
	obj2 := map[string]int{"b": 2}
	merged, err := Merge(obj1, obj2)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	var result map[string]int
	if err := json.Unmarshal(merged, &result); err != nil {
		t.Fatalf("Error unmarshalling merged JSON: %v", err)
	}
	expected := map[string]int{"a": 1, "b": 2}
	if len(result) != len(expected) {
		t.Errorf("Expected %d keys, got %d", len(expected), len(result))
	}
	for k, v := range expected {
		if result[k] != v {
			t.Errorf("For key %s, expected %d, got %d", k, v, result[k])
		}
	}
}

func TestMergeJSONMultipleObjects(t *testing.T) {
	// Test merging with a mix of nil, empty, and valid objects.
	obj1 := map[string]int{"a": 1}
	obj2 := map[string]int{"b": 2}
	obj3 := map[string]int{"c": 3}
	merged, err := Merge(obj1, nil, map[string]int{}, obj2, obj3)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	var result map[string]int
	if err := json.Unmarshal(merged, &result); err != nil {
		t.Fatalf("Error unmarshalling merged JSON: %v", err)
	}
	expected := map[string]int{"a": 1, "b": 2, "c": 3}
	if len(result) != len(expected) {
		t.Errorf("Expected %d keys, got %d", len(expected), len(result))
	}
	for k, v := range expected {
		if result[k] != v {
			t.Errorf("For key %s, expected %d, got %d", k, v, result[k])
		}
	}
}

func TestMergeJSONOverlappingKeys(t *testing.T) {
	// In case of overlapping keys, the later object will contribute its value.
	obj1 := map[string]int{"a": 1, "b": 2}
	obj2 := map[string]int{"b": 3, "c": 4}
	merged, err := Merge(obj1, obj2)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	var result map[string]int
	if err := json.Unmarshal(merged, &result); err != nil {
		t.Fatalf("Error unmarshalling merged JSON: %v", err)
	}
	// In Go's map unmarshalling, duplicate keys result in the last one taking effect.
	expected := map[string]int{"a": 1, "b": 3, "c": 4}
	if len(result) != len(expected) {
		t.Errorf("Expected %d keys, got %d", len(expected), len(result))
	}
	for k, v := range expected {
		if result[k] != v {
			t.Errorf("For key %s, expected %d, got %d", k, v, result[k])
		}
	}
}

func TestMergeJSONNestedObjects(t *testing.T) {
	// Test merging objects that contain nested objects.
	obj1 := map[string]any{"a": map[string]int{"x": 1}}
	obj2 := map[string]any{"b": map[string]int{"y": 2}}
	merged, err := Merge(obj1, obj2)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	var result map[string]any
	if err := json.Unmarshal(merged, &result); err != nil {
		t.Fatalf("Error unmarshalling merged JSON: %v", err)
	}
	// Validate nested content.
	a, ok := result["a"].(map[string]any)
	if !ok {
		t.Errorf("Expected key 'a' to be a nested object")
	} else if a["x"].(float64) != 1 {
		t.Errorf("Expected nested key 'x' to be 1, got %v", a["x"])
	}
	b, ok := result["b"].(map[string]any)
	if !ok {
		t.Errorf("Expected key 'b' to be a nested object")
	} else if b["y"].(float64) != 2 {
		t.Errorf("Expected nested key 'y' to be 2, got %v", b["y"])
	}
}

func TestMergeJSONNonObject(t *testing.T) {
	// If a value does not marshal to a JSON object, expect an error.
	_, err := Merge("not an object")
	if err == nil {
		t.Error("Expected error when value is not a JSON object")
	}
}

func TestMergeJSONArray(t *testing.T) {
	// If a value is an array, it is not considered a JSON object.
	_, err := Merge([]int{1, 2, 3})
	if err == nil {
		t.Error("Expected error when value is not a JSON object")
	}
}
