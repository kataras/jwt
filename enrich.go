package jwt

import (
	"fmt"
)

// Enrich creates a new JWT token by merging claims from an existing token with additional claims.
//
// This function takes an existing JWT token, extracts its claims,
// merges them with the provided extra claims, and creates a new properly signed token using the same
// algorithm as the original token. This is useful for scenarios where external systems need to add
// role-based fields or other metadata to existing tokens while preserving the original claims.
//
// Important: It's not possible to modify just the payload of a JWT without changing
// the signature, since the signature is calculated over the entire header.payload content.
// This function creates a completely new token with a new signature.
//
// Parameters:
//   - key: Key for both verifying the original token and signing the new token
//   - accessToken: Existing JWT token to extract claims from
//   - extraClaims: Additional claims to merge with existing claims
//
// Algorithm Detection: The algorithm is automatically extracted from the original token's header,
// ensuring the enriched token uses the same algorithm as the original.
//
// Claim Merging Behavior:
//   - Original token claims are preserved
//   - Extra claims are merged without extra validation
//   - Uses the same merging logic as the Sign function
//
// Security Considerations:
//   - The original token should be verified by the caller before claim extraction
//   - The new token is properly signed with the same algorithm and provided key
//   - Consider the security implications of merging untrusted extra claims
//   - Validate extra claims before passing them to this function
//   - Encrypted tokens are not supported
//
// Use Cases:
//   - Adding role-based permissions to existing user tokens
//   - Enriching tokens with organization-specific data
//   - Token transformation in microservice architectures
//   - Adding audit trails or metadata to existing tokens
//
// Example usage:
//
//	// Basic enrichment with role information
//	extraClaims := map[string]any{
//	    "role":        "admin",
//	    "permissions": []string{"read", "write", "delete"},
//	    "department":  "engineering",
//	}
//
//	enrichedToken, err := jwt.Enrich(signingKey, existingToken, extraClaims)
//	if err != nil {
//	    log.Printf("Token enrichment failed: %v", err)
//	    return
//	}
//
//	// Enrichment with additional standard claims
//	organizationInfo := jwt.Map{
//	    "org_id":   "org123",
//	    "org_name": "MyCompany",
//	    "tenant":   "tenant456",
//	}
//
//	enrichedToken, err := jwt.Enrich(signingKey, userToken,
//	    organizationInfo,
//	    jwt.MaxAge(2 * time.Hour),        // Extend expiration
//	    jwt.Audience{"enriched-api"})     // Add new audience
//
//	// Role-based enrichment
//	roleData := struct {
//	    Role        string   `json:"role"`
//	    Permissions []string `json:"permissions"`
//	    Level       int      `json:"access_level"`
//	}{
//	    Role:        "manager",
//	    Permissions: []string{"user_management", "reporting"},
//	    Level:       5,
//	}
//
//	enrichedToken, err := jwt.Enrich(signingKey, originalToken, roleData)
//
// Error Conditions:
//   - Unsupported or invalid algorithm in original token
//   - Claim extraction or merging failures
//   - New token signing failures
//   - Invalid extra claims (non-JSON serializable)
//
// Performance Notes:
//   - It does not verify the original token
//   - Performs JSON marshaling and unmarshaling operations
//   - Creates a completely new token with new signature
//   - Consider caching enriched tokens if appropriate for your use case
func Enrich(key PrivateKey, accessToken []byte, extraClaims any) ([]byte, error) {
	decodedToken, err := Decode(accessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to parse original token: %w", err)
	}

	return decodedToken.Enrich(key, extraClaims)
}
