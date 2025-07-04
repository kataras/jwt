package jwt

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestEnrich(t *testing.T) {
	// Create a test token to enrich
	originalClaims := map[string]any{
		"sub":      "user123",
		"username": "kataras",
		"email":    "user@example.com",
	}

	originalToken, err := Sign(testAlg, testSecret, originalClaims)
	if err != nil {
		t.Fatalf("failed to create original token: %v", err)
	}

	t.Run("basic enrichment", func(t *testing.T) {
		extraClaims := map[string]any{
			"role":        "admin",
			"permissions": []string{"read", "write", "delete"},
		}

		enrichedToken, err := Enrich(testSecret, originalToken, extraClaims)
		if err != nil {
			t.Fatalf("enrich failed: %v", err)
		}

		// Verify the enriched token
		verifiedToken, err := Verify(testAlg, testSecret, enrichedToken)
		if err != nil {
			t.Fatalf("failed to verify enriched token: %v", err)
		}

		var claims map[string]any
		if err := verifiedToken.Claims(&claims); err != nil {
			t.Fatalf("failed to extract claims: %v", err)
		}

		// Check original claims are preserved
		if claims["sub"] != "user123" {
			t.Errorf("expected sub to be 'user123', got %v", claims["sub"])
		}
		if claims["username"] != "kataras" {
			t.Errorf("expected username to be 'kataras', got %v", claims["username"])
		}
		if claims["email"] != "user@example.com" {
			t.Errorf("expected email to be 'user@example.com', got %v", claims["email"])
		}

		// Check extra claims are added
		if claims["role"] != "admin" {
			t.Errorf("expected role to be 'admin', got %v", claims["role"])
		}

		permissions, ok := claims["permissions"].([]any)
		if !ok {
			t.Errorf("expected permissions to be []any, got %T", claims["permissions"])
		} else {
			expectedPermissions := []string{"read", "write", "delete"}
			if len(permissions) != len(expectedPermissions) {
				t.Errorf("expected %d permissions, got %d", len(expectedPermissions), len(permissions))
			}
		}
	})

	t.Run("enrichment with claim override", func(t *testing.T) {
		extraClaims := map[string]any{
			"username": "admin_user", // Override existing claim
			"role":     "admin",
		}

		enrichedToken, err := Enrich(testSecret, originalToken, extraClaims)
		if err != nil {
			t.Fatalf("enrich failed: %v", err)
		}

		verifiedToken, err := Verify(testAlg, testSecret, enrichedToken)
		if err != nil {
			t.Fatalf("failed to verify enriched token: %v", err)
		}

		var claims map[string]any
		if err := verifiedToken.Claims(&claims); err != nil {
			t.Fatalf("failed to extract claims: %v", err)
		}

		// Check that username was overridden
		if claims["username"] != "admin_user" {
			t.Errorf("expected username to be overridden to 'admin_user', got %v", claims["username"])
		}

		// Check other original claims are preserved
		if claims["sub"] != "user123" {
			t.Errorf("expected sub to be preserved as 'user123', got %v", claims["sub"])
		}
	})

	t.Run("enrichment with struct claims", func(t *testing.T) {
		type RoleInfo struct {
			Role        string   `json:"role"`
			Permissions []string `json:"permissions"`
			Level       int      `json:"access_level"`
		}

		extraClaims := RoleInfo{
			Role:        "manager",
			Permissions: []string{"user_management", "reporting"},
			Level:       5,
		}

		enrichedToken, err := Enrich(testSecret, originalToken, extraClaims)
		if err != nil {
			t.Fatalf("enrich failed: %v", err)
		}

		verifiedToken, err := Verify(testAlg, testSecret, enrichedToken)
		if err != nil {
			t.Fatalf("failed to verify enriched token: %v", err)
		}

		var claims map[string]any
		if err := verifiedToken.Claims(&claims); err != nil {
			t.Fatalf("failed to extract claims: %v", err)
		}

		if claims["role"] != "manager" {
			t.Errorf("expected role to be 'manager', got %v", claims["role"])
		}
		if claims["access_level"] != json.Number("5") { // JSON numbers become float64
			t.Errorf("expected access_level to be 5, got %v (%T)", claims["access_level"], claims["access_level"])
		}
	})

	t.Run("enrichment with empty extra claims", func(t *testing.T) {
		extraClaims := map[string]any{}

		enrichedToken, err := Enrich(testSecret, originalToken, extraClaims)
		if err != nil {
			t.Fatalf("enrich failed: %v", err)
		}

		verifiedToken, err := Verify(testAlg, testSecret, enrichedToken)
		if err != nil {
			t.Fatalf("failed to verify enriched token: %v", err)
		}

		var claims map[string]any
		if err := verifiedToken.Claims(&claims); err != nil {
			t.Fatalf("failed to extract claims: %v", err)
		}

		// All original claims should be preserved
		if claims["username"] != "kataras" {
			t.Errorf("expected username to be preserved as 'kataras', got %v", claims["username"])
		}
	})
}

func TestEnrichErrors(t *testing.T) {
	// Create a valid token for some tests
	originalClaims := map[string]any{"sub": "user123"}
	validToken, err := Sign(testAlg, testSecret, originalClaims)
	if err != nil {
		t.Fatalf("failed to create valid token: %v", err)
	}

	tests := []struct {
		name          string
		key           PrivateKey
		accessToken   []byte
		extraClaims   any
		expectError   bool
		errorContains string
	}{
		{
			name:          "invalid token format",
			key:           testSecret,
			accessToken:   []byte("invalid.token"),
			extraClaims:   map[string]any{"role": "admin"},
			expectError:   true,
			errorContains: "failed to parse original token",
		},
		{
			name:          "malformed token",
			key:           testSecret,
			accessToken:   []byte("not-a-token"),
			extraClaims:   map[string]any{"role": "admin"},
			expectError:   true,
			errorContains: "failed to parse original token",
		},
		{
			name:          "token with invalid header",
			key:           testSecret,
			accessToken:   []byte("aW52YWxpZC1oZWFkZXI.eyJzdWIiOiJ1c2VyMTIzIn0.signature"),
			extraClaims:   map[string]any{"role": "admin"},
			expectError:   true,
			errorContains: "decode token: signature",
		},
		{
			name:          "invalid extra claims",
			key:           testSecret,
			accessToken:   validToken,
			extraClaims:   func() {}, // Functions can't be marshaled to JSON
			expectError:   true,
			errorContains: "failed to merge claims",
		},
		{
			name:          "invalid signing key",
			key:           "invalid-key",
			accessToken:   validToken,
			extraClaims:   map[string]any{"role": "admin"},
			expectError:   true,
			errorContains: "signature",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Enrich(tt.key, tt.accessToken, tt.extraClaims)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				} else if tt.errorContains != "" && !containsError(err.Error(), tt.errorContains) {
					t.Errorf("expected error to contain '%s', got: %v", tt.errorContains, err)
				}
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestEnrichWithDifferentAlgorithms(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping algorithm tests in short mode")
	}

	// Test with different algorithms
	tests := []struct {
		name string
		alg  Alg
		key  PrivateKey
	}{
		{"HS256", HS256, testSecret},
		{"HS384", HS384, testSecret},
		{"HS512", HS512, testSecret},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			originalClaims := map[string]any{
				"sub":      "user123",
				"username": "kataras",
			}

			originalToken, err := Sign(tt.alg, tt.key, originalClaims)
			if err != nil {
				t.Fatalf("failed to create original token with %s: %v", tt.name, err)
			}

			extraClaims := map[string]any{
				"role": "admin",
			}

			enrichedToken, err := Enrich(tt.key, originalToken, extraClaims)
			if err != nil {
				t.Fatalf("enrich failed with %s: %v", tt.name, err)
			}

			// Verify the enriched token
			verifiedToken, err := Verify(tt.alg, tt.key, enrichedToken)
			if err != nil {
				t.Fatalf("failed to verify enriched token with %s: %v", tt.name, err)
			}

			var claims map[string]any
			if err := verifiedToken.Claims(&claims); err != nil {
				t.Fatalf("failed to extract claims: %v", err)
			}

			// Check that both original and extra claims are present
			if claims["username"] != "kataras" {
				t.Errorf("expected username to be 'kataras', got %v", claims["username"])
			}
			if claims["role"] != "admin" {
				t.Errorf("expected role to be 'admin', got %v", claims["role"])
			}
		})
	}
}

func TestEnrichPreservesTokenStructure(t *testing.T) {
	// Create a token with custom header
	originalClaims := map[string]any{"sub": "user123"}
	originalToken, err := Sign(testAlg, testSecret, originalClaims)
	if err != nil {
		t.Fatalf("failed to create original token: %v", err)
	}

	// Decode the original token to get its header
	originalDecoded, err := Decode(originalToken)
	if err != nil {
		t.Fatalf("failed to decode original token: %v", err)
	}

	extraClaims := map[string]any{"role": "admin"}
	enrichedToken, err := Enrich(testSecret, originalToken, extraClaims)
	if err != nil {
		t.Fatalf("enrich failed: %v", err)
	}

	// Decode the enriched token
	enrichedDecoded, err := Decode(enrichedToken)
	if err != nil {
		t.Fatalf("failed to decode enriched token: %v", err)
	}

	// Headers should be identical
	if !reflect.DeepEqual(originalDecoded.Header, enrichedDecoded.Header) {
		t.Errorf("header changed during enrichment")
		t.Errorf("original header: %s", originalDecoded.Header)
		t.Errorf("enriched header: %s", enrichedDecoded.Header)
	}

	// Verify the algorithm is preserved
	var originalHeader, enrichedHeader map[string]any
	if err := json.Unmarshal(originalDecoded.Header, &originalHeader); err != nil {
		t.Fatalf("failed to parse original header: %v", err)
	}
	if err := json.Unmarshal(enrichedDecoded.Header, &enrichedHeader); err != nil {
		t.Fatalf("failed to parse enriched header: %v", err)
	}

	if originalHeader["alg"] != enrichedHeader["alg"] {
		t.Errorf("algorithm changed: original=%v, enriched=%v",
			originalHeader["alg"], enrichedHeader["alg"])
	}
}

func BenchmarkEnrich(b *testing.B) {
	originalClaims := map[string]any{
		"sub":      "user123",
		"username": "kataras",
		"email":    "user@example.com",
	}

	originalToken, err := Sign(testAlg, testSecret, originalClaims)
	if err != nil {
		b.Fatalf("failed to create original token: %v", err)
	}

	extraClaims := map[string]any{
		"role":        "admin",
		"permissions": []string{"read", "write", "delete"},
		"department":  "engineering",
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := Enrich(testSecret, originalToken, extraClaims)
		if err != nil {
			b.Fatalf("enrich failed: %v", err)
		}
	}
}

// Helper function to check if error message contains expected text
func containsError(errorMsg, expected string) bool {
	return len(errorMsg) > 0 && len(expected) > 0 &&
		(errorMsg == expected ||
			len(errorMsg) >= len(expected) &&
				errorMsg[:len(expected)] == expected ||
			len(errorMsg) >= len(expected) &&
				errorMsg[len(errorMsg)-len(expected):] == expected ||
			contains(errorMsg, expected))
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) &&
		(s == substr ||
			(len(s) > len(substr) &&
				(s[:len(substr)] == substr ||
					s[len(s)-len(substr):] == substr ||
					containsSubstring(s, substr))))
}

func containsSubstring(s, substr string) bool {
	if len(substr) > len(s) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
