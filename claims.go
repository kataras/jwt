package jwt

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	// ErrExpired indicates that a JWT token has passed its expiration time.
	// This error occurs when the current time (determined by the Clock function) is after
	// the time specified in the "exp" (expiry) claim. This is a critical security validation
	// that prevents the use of tokens beyond their intended lifetime.
	//
	// Common scenarios:
	//   - Token has naturally expired after its MaxAge duration
	//   - Clock skew between token issuer and verifier
	//   - Long-running operations that outlast token validity
	//   - Cached tokens that weren't refreshed in time
	//
	// Handling strategies:
	//   - Refresh the token if refresh tokens are available
	//   - Re-authenticate the user
	//   - Return 401 Unauthorized to the client
	//   - Implement token auto-renewal mechanisms
	//
	// Note: Some applications implement leeway (time tolerance) to handle
	// minor clock differences between systems. Use appropriate validators for this.
	ErrExpired = errors.New("jwt: token expired")

	// ErrNotValidYet indicates that a JWT token is being used before its valid time period.
	// This error occurs when the current time is before the time specified in the "nbf"
	// (not before) claim. This prevents premature use of tokens that are intended for
	// future activation.
	//
	// Common use cases for "nbf" claim:
	//   - Scheduled token activation for batch operations
	//   - Pre-issued tokens for future events or sessions
	//   - Time-delayed access grants
	//   - Coordinated multi-system token activation
	//
	// This validation ensures that tokens cannot be used until their intended
	// activation time, providing temporal access control capabilities.
	//
	// Example scenarios:
	//   - Tokens issued now but valid from midnight
	//   - Conference tickets valid only during event dates
	//   - Subscription tokens that activate on payment confirmation
	ErrNotValidYet = errors.New("jwt: token not valid yet")

	// ErrIssuedInTheFuture indicates that a JWT token has an "iat" (issued at) claim
	// set to a future time. This error occurs when the token's issue time is after
	// the current time, which suggests either clock skew or potentially malicious
	// token manipulation.
	//
	// This validation prevents acceptance of tokens that claim to be issued in the future,
	// which could indicate:
	//   - Significant clock synchronization issues between systems
	//   - Attempted token forgery with manipulated timestamps
	//   - Misconfigured token generation systems
	//   - Time zone handling errors in token issuance
	//
	// Security implications:
	//   - Helps detect potentially tampered tokens
	//   - Ensures logical consistency of token timestamps
	//   - Prevents replay attacks using future-dated tokens
	//
	// Consider implementing reasonable time leeway (e.g., 5 minutes) to handle
	// minor clock differences in distributed systems while maintaining security.
	ErrIssuedInTheFuture = errors.New("jwt: token issued in the future")
)

// Claims represents the standard JWT claims (registered claims) as defined by RFC 7519.
//
// This structure contains the standardized fields that provide common token metadata
// and timing controls. It implements the SignOption interface, allowing it to be
// passed directly to Sign functions to set standard claims automatically.
//
// **Standard Claims Included**:
//   - Timing claims: nbf (not before), iat (issued at), exp (expiry)
//   - Identity claims: iss (issuer), sub (subject), aud (audience)
//   - Tracking claims: jti (JWT ID)
//   - Extension: origin_jti (non-standard origin tracking)
//
// **Usage Patterns**:
//   - Embed in custom claim structures for type safety
//   - Use directly for simple tokens with only standard claims
//   - Pass as SignOption to automatically apply standard claims
//   - Validate using built-in time-based validation methods
//
// Example usage:
//
//	// Direct usage
//	claims := jwt.Claims{
//	    Subject:  "user123",
//	    Issuer:   "myapp.com",
//	    Audience: jwt.Audience{"api", "web"},
//	    Expiry:   time.Now().Add(time.Hour).Unix(),
//	    IssuedAt: time.Now().Unix(),
//	}
//
//	// As SignOption
//	token, err := jwt.Sign(jwt.HS256, secretKey, userClaims, claims)
//
//	// Embedded in custom struct
//	type UserClaims struct {
//	    Username string `json:"username"`
//	    Role     string `json:"role"`
//	    jwt.Claims
//	}
type Claims struct {
	// NotBefore represents the "nbf" (not before) claim as Unix timestamp.
	// Defines the earliest time the token is considered valid. Tokens cannot
	// be accepted before this time to prevent premature usage.
	NotBefore int64 `json:"nbf,omitempty"`

	// IssuedAt represents the "iat" (issued at) claim as Unix timestamp.
	// Records when the token was created. Used for age validation and
	// detecting tokens issued in the future.
	IssuedAt int64 `json:"iat,omitempty"`

	// Expiry represents the "exp" (expiration) claim as Unix timestamp.
	// Defines when the token becomes invalid. Critical for security
	// as it limits token lifetime and prevents indefinite usage.
	Expiry int64 `json:"exp,omitempty"`

	// ID represents the "jti" (JWT ID) claim.
	// Unique identifier for this token, useful for tracking, blacklisting,
	// and preventing replay attacks. Must be unique per issuer.
	ID string `json:"jti,omitempty"`

	// OriginID represents a custom "origin_jti" claim (non-standard).
	// May reference a parent token's ID for tracking token hierarchies,
	// refresh chains, or related token invalidation scenarios.
	OriginID string `json:"origin_jti,omitempty"`

	// Issuer represents the "iss" (issuer) claim.
	// Identifies the principal that issued the token. Can be a URL,
	// domain name, or other unique identifier for the token authority.
	Issuer string `json:"iss,omitempty"`

	// Subject represents the "sub" (subject) claim.
	// Identifies the principal that is the subject of the token
	// (typically the user). Must be unique within the issuer's context.
	Subject string `json:"sub,omitempty"`

	// Audience represents the "aud" (audience) claim.
	// Identifies the intended recipients of the token. Recipients must
	// validate they are included in the audience before accepting the token.
	Audience Audience `json:"aud,omitempty"`
}

type claimsSecondChance struct {
	NotBefore json.Number `json:"nbf,omitempty"`
	IssuedAt  json.Number `json:"iat,omitempty"`
	Expiry    json.Number `json:"exp,omitempty"`
	ID        string      `json:"jti,omitempty"`
	OriginID  string      `json:"origin_jti,omitempty"`
	Issuer    any         `json:"iss,omitempty"`
	Subject   any         `json:"sub,omitempty"`
	Audience  Audience    `json:"aud,omitempty"`
}

func (c claimsSecondChance) toClaims() Claims {
	nbf, _ := c.NotBefore.Float64() // some authorities generates floats for unix timestamp (1-35 seconds), with the leeway of 1 minute we really don't care.
	iat, _ := c.IssuedAt.Float64()
	exp, _ := c.Expiry.Float64()

	return Claims{
		NotBefore: int64(nbf),
		IssuedAt:  int64(iat),
		Expiry:    int64(exp),
		ID:        c.ID,
		OriginID:  c.OriginID,
		Issuer:    getStr(c.Issuer),
		Subject:   getStr(c.Subject),
		Audience:  c.Audience,
	}
}

func getStr(v any) string {
	if v == nil {
		return ""
	}

	if s, ok := v.(string); ok {
		return s
	} else {
		return fmt.Sprintf("%v", v)
	}
}

// Audience represents the "aud" (audience) claim for JWT tokens.
//
// The audience claim identifies the intended recipients of the JWT token.
// Recipients should verify that they are included in the audience before
// accepting and processing the token. This provides an additional security
// layer by ensuring tokens are only used by their intended consumers.
//
// **JWT Specification**: The "aud" claim can be either:
//   - A single string value (single recipient)
//   - An array of strings (multiple recipients)
//
// This type handles both formats transparently during JSON marshaling/unmarshaling.
//
// **Security Considerations**:
//   - Always validate that your application/service is in the audience
//   - Reject tokens where your identifier is not present in the audience
//   - Use specific, non-ambiguous audience identifiers
//   - Consider using URLs or URIs for globally unique audience values
//
// **Common Usage Patterns**:
//   - API service names: []string{"api-service", "user-service"}
//   - Application domains: []string{"app.example.com", "admin.example.com"}
//   - Service endpoints: []string{"https://api.example.com/v1"}
//   - Role-based audiences: []string{"admin-users", "premium-subscribers"}
//
// Example usage:
//
//	// Single audience
//	aud := jwt.Audience{"api-service"}
//
//	// Multiple audiences
//	aud := jwt.Audience{"api-service", "user-service", "admin-panel"}
//
//	// Use in claims
//	claims := jwt.Claims{
//	    Subject:  "user123",
//	    Audience: jwt.Audience{"api-service", "web-app"},
//	}
//
//	// Or as SignOption
//	token, err := jwt.Sign(jwt.HS256, key, userClaims, jwt.Audience{"api"})
//
//	// Validation
//	if !slices.Contains(claims.Audience, "my-service") {
//	    return errors.New("token not intended for this service")
//	}
type Audience []string

// UnmarshalJSON implements the json.Unmarshaler interface for flexible audience parsing.
//
// The JWT specification allows the "aud" claim to be either a single string or an
// array of strings. This method handles both formats transparently, normalizing
// them into a consistent slice representation.
//
// **Supported Input Formats**:
//   - Single string: "api-service" becomes ["api-service"]
//   - Array of strings: ["api", "web"] remains ["api", "web"]
//   - Empty/null values are handled gracefully
//
// **Implementation Details**:
//   - Detects format by examining the first byte of JSON data
//   - Uses standard json.Unmarshal for actual parsing
//   - Maintains compatibility with various JWT implementations
//   - Handles edge cases like empty arrays and null values
//
// This ensures compatibility with JWT tokens from different sources that may
// use either format for the audience claim, providing a consistent interface
// for audience validation regardless of the original format.
//
// Example JSON inputs:
//   - "aud": "single-service"           -> Audience{"single-service"}
//   - "aud": ["service1", "service2"]   -> Audience{"service1", "service2"}
//   - "aud": []                         -> Audience{} (empty)
//   - "aud": null                       -> Audience{} (empty)
func (aud *Audience) UnmarshalJSON(data []byte) (err error) {
	// Fixes #3.
	if len(data) > 0 {
		switch data[0] {
		case '"': // it's a single string.
			var audString string
			err = json.Unmarshal(data, &audString)
			if err == nil {
				*aud = []string{audString}
			}
		case '[': // it's an array of strings.
			var audStrings []string
			err = json.Unmarshal(data, &audStrings)
			*aud = audStrings
		}
	}

	return
}

// String returns a space-separated string representation of the audience.
//
// This method provides a human-readable format for the audience claim,
// which is useful for logging, debugging, and display purposes. Multiple
// audience values are joined with space separators.
//
// **Usage Scenarios**:
//   - Logging audience information for debugging
//   - Displaying token recipients in admin interfaces
//   - Creating readable audit trails
//   - Generating user-friendly error messages
//
// **Output Format**: Space-separated string of all audience values
//
// Example:
//
//	aud := jwt.Audience{"api-service", "web-app", "mobile-app"}
//	fmt.Println(aud.String()) // Output: "api-service web-app mobile-app"
//
//	// Single audience
//	aud2 := jwt.Audience{"api-service"}
//	fmt.Println(aud2.String()) // Output: "api-service"
//
//	// Empty audience
//	aud3 := jwt.Audience{}
//	fmt.Println(aud3.String()) // Output: ""
//
//	// Use in logging
//	log.Printf("Token intended for: %s", claims.Audience.String())
func (auth Audience) String() string {
	return strings.Join(auth, " ")
}

// ApplyClaims implements the SignOption interface to set audience claims during token signing.
//
// This method allows Audience to be used as a SignOption parameter in Sign functions,
// providing a convenient way to specify intended token recipients during token creation.
// The audience will be automatically included in the token's standard claims.
//
// **SignOption Interface**: This implementation enables Audience to be passed
// directly to signing functions alongside other options like MaxAge, custom claims,
// and other SignOption implementations.
//
// **Usage Patterns**:
//   - Single audience specification for dedicated services
//   - Multiple audiences for tokens shared across services
//   - Dynamic audience assignment based on user context
//   - Integration with role-based access patterns
//
// **Security Benefits**:
//   - Ensures tokens are properly scoped to intended recipients
//   - Enables fine-grained access control
//   - Facilitates service-to-service authentication validation
//   - Supports multi-tenant architectures
//
// Example usage:
//
//	// Single audience for API access
//	token, err := jwt.Sign(jwt.HS256, secretKey, userClaims, jwt.Audience{"api-service"})
//
//	// Multiple audiences for cross-service access
//	token, err := jwt.Sign(jwt.HS256, secretKey, userClaims,
//	    jwt.Audience{"api-service", "user-service", "admin-panel"},
//	    jwt.MaxAge(15 * time.Minute))
//
//	// Role-based audience assignment
//	var audiences jwt.Audience
//	if user.IsAdmin {
//	    audiences = jwt.Audience{"admin-api", "user-api"}
//	} else {
//	    audiences = jwt.Audience{"user-api"}
//	}
//	token, err := jwt.Sign(jwt.HS256, secretKey, userClaims, audiences)
func (aud Audience) ApplyClaims(dest *Claims) {
	dest.Audience = aud
}

// Age returns the total lifetime duration of the token based on its claims.
//
// This method calculates the intended lifespan of the token by computing the
// difference between the expiration time ("exp") and issued time ("iat").
// This represents the maximum duration the token was designed to be valid.
//
// **Calculation**: expiry_time - issued_time = token_lifetime
//
// **Use Cases**:
//   - Token lifetime analysis for security auditing
//   - Monitoring token usage patterns and lifespans
//   - Validating token configuration policies
//   - Debugging token expiration issues
//   - Generating metrics for token management
//
// **Return Value**:
//   - Positive duration: Normal token with valid lifetime
//   - Zero duration: Token with missing or invalid timing claims
//   - Negative duration: Invalid token with expiry before issue time
//
// **Important Notes**:
//   - This returns the designed lifetime, not remaining time (use Timeleft for that)
//   - Zero values in timing claims will result in zero or incorrect duration
//   - Does not account for clock skew between issuer and current system
//
// Example usage:
//
//	claims := jwt.Claims{
//	    IssuedAt: time.Now().Unix(),
//	    Expiry:   time.Now().Add(time.Hour).Unix(),
//	}
//
//	lifetime := claims.Age()
//	fmt.Printf("Token designed for: %v", lifetime) // Output: 1h0m0s
//
//	// Use for monitoring
//	if claims.Age() > 24*time.Hour {
//	    log.Printf("Long-lived token detected: %v", claims.Age())
//	}
func (c Claims) Age() time.Duration {
	return time.Duration(c.Expiry-c.IssuedAt) * time.Second
	// return c.ExpiresAt().Sub(time.Unix(c.IssuedAt, 0))
}

// ExpiresAt returns the time when this token will expire.
//
// This method converts the Unix timestamp stored in the Expiry field to a
// time.Time value, providing a convenient way to work with expiration times
// in Go's time package format. The returned time is rounded to the nearest second.
//
// **Conversion Details**:
//   - Uses time.Unix() to convert the Unix timestamp to time.Time
//   - Nanosecond component is set to 0 (second precision)
//   - Handles zero values gracefully (returns Unix epoch if Expiry is 0)
//
// **Use Cases**:
//   - Comparing expiration time with current time
//   - Calculating time remaining until expiration
//   - Formatting expiration time for display
//   - Time-based conditional logic
//   - Integration with time-based APIs
//
// **Zero Value Behavior**:
//   - If Expiry is 0, returns time.Unix(0, 0) (Unix epoch: 1970-01-01 00:00:00 UTC)
//   - This typically indicates a token without an expiration time
//
// Example usage:
//
//	claims := jwt.Claims{
//	    Expiry: time.Now().Add(time.Hour).Unix(),
//	}
//
//	expireTime := claims.ExpiresAt()
//	fmt.Printf("Token expires: %v", expireTime.Format(time.RFC3339))
//
//	// Check if token is expired
//	if time.Now().After(claims.ExpiresAt()) {
//	    fmt.Println("Token has expired")
//	}
//
//	// Calculate time until expiration
//	timeLeft := claims.ExpiresAt().Sub(time.Now())
//	fmt.Printf("Time remaining: %v", timeLeft)
func (c Claims) ExpiresAt() time.Time {
	return time.Unix(c.Expiry, 0)
}

// Timeleft returns the remaining time until the token expires.
//
// This method calculates how much time is left before the token becomes invalid
// by computing the difference between the expiration time and the current time.
// The calculation uses the Clock() function to get the current time, allowing
// for consistent time handling across the JWT library.
//
// **Calculation**: expiry_time - current_time = remaining_time
//
// **Return Values**:
//   - Positive duration: Token is still valid, shows time remaining
//   - Zero duration: Token has just expired or has no expiry set
//   - Negative duration: Token has already expired
//
// **Use Cases**:
//   - Pre-expiration warnings and refresh logic
//   - Token lifetime monitoring and metrics
//   - Conditional token renewal decisions
//   - User interface countdown displays
//   - Proactive token management in applications
//
// **Important Notes**:
//   - Uses the configurable Clock() function for current time
//   - Returns duration rounded to the nearest second
//   - Zero Expiry field results in zero duration (no expiration)
//   - Negative values indicate already expired tokens
//
// **Clock Function**: The calculation uses the package-level Clock variable,
// which can be customized for testing or specific time zone requirements.
//
// Example usage:
//
//	claims := jwt.Claims{
//	    Expiry: time.Now().Add(15 * time.Minute).Unix(),
//	}
//
//	remaining := claims.Timeleft()
//	if remaining > 5*time.Minute {
//	    fmt.Println("Token has plenty of time left")
//	} else if remaining > 0 {
//	    fmt.Printf("Token expires soon: %v remaining", remaining)
//	    // Consider refreshing the token
//	} else {
//	    fmt.Println("Token has expired")
//	}
//
//	// Use in middleware for early refresh
//	if claims.Timeleft() < 2*time.Minute {
//	    // Trigger token refresh process
//	    refreshToken()
//	}
func (c Claims) Timeleft() time.Duration {
	return time.Duration(c.Expiry-Clock().Unix()) * time.Second
	// return c.ExpiresAt().Sub(Clock())
}

// validateClaims performs time-based validation of JWT standard claims.
//
// This internal function validates the timing-related claims (nbf, iat, exp) against
// a provided reference time. It ensures that tokens are used within their valid
// time windows and catches common timing-related security issues.
//
// **Validation Checks Performed**:
//   - NotBefore (nbf): Ensures token is not used before its activation time
//   - IssuedAt (iat): Prevents acceptance of tokens claiming future issue times
//   - Expiry (exp): Rejects tokens that have passed their expiration time
//
// **Parameters**:
//   - t: Reference time for validation (typically current time)
//   - claims: JWT claims structure containing timing information
//
// **Zero Value Handling**:
//   - Claims with zero values (0) are considered unset and skip validation
//   - This allows flexibility for tokens that don't use all timing claims
//   - Only non-zero claim values are validated against the reference time
//
// **Time Precision**: All comparisons are performed at second-level precision
// by rounding the reference time to the nearest second, matching JWT standard
// practices for Unix timestamp handling.
//
// **Error Returns**:
//   - ErrNotValidYet: Token used before its NotBefore time
//   - ErrIssuedInTheFuture: Token claims to be issued in the future
//   - ErrExpired: Token has passed its expiration time
//   - nil: All timing validations passed successfully
//
// **Usage Context**: This function is called internally during token verification
// processes. For custom validation logic, implement TokenValidator interfaces
// which provide more flexibility and can incorporate this function's logic.
//
// **Security Considerations**:
//   - Helps prevent replay attacks with expired tokens
//   - Detects clock synchronization issues between systems
//   - Ensures temporal access control policies are enforced
//   - Provides basic protection against token manipulation
//
// See TokenValidator and its implementations for additional validation options
// and more sophisticated validation workflows.
func validateClaims(t time.Time, claims Claims) error {
	now := t.Round(time.Second).Unix()

	if claims.NotBefore > 0 {
		if now < claims.NotBefore {
			return ErrNotValidYet
		}
	}

	if claims.IssuedAt > 0 {
		if now < claims.IssuedAt {
			return ErrIssuedInTheFuture
		}
	}

	if claims.Expiry > 0 {
		if now > claims.Expiry {
			return ErrExpired
		}
	}

	return nil
}

// ApplyClaims implements the SignOption interface to merge standard claims during token signing.
//
// This method allows Claims to be used as a SignOption parameter in Sign functions,
// enabling automatic application of standard JWT claims during token creation.
// Only non-zero and non-empty values are applied, allowing selective claim setting.
//
// **SignOption Interface**: This implementation enables Claims structs to be passed
// directly to signing functions alongside other options like MaxAge, Audience,
// and custom claim structures.
//
// **Selective Application**: The method only applies claims that have meaningful values:
//   - Timing claims (NotBefore, IssuedAt, Expiry): Applied only if > 0
//   - String claims (ID, OriginID, Issuer, Subject): Applied only if not empty
//   - Audience claim: Applied only if slice has length > 0
//
// **Non-Destructive Merging**: This method merges claims into the destination
// without overwriting existing values unnecessarily. Zero values are considered
// "unset" and are skipped during the merge process.
//
// **Usage Patterns**:
//   - Template claims for consistent token issuance
//   - Default claim values for all tokens from an issuer
//   - Partial claim updates during token renewal
//   - Combining multiple claim sources
//
// Example usage:
//
//	// Define standard claims for your application
//	standardClaims := jwt.Claims{
//	    Issuer:  "myapp.com",
//	    Subject: "user123",
//	    Expiry:  time.Now().Add(time.Hour).Unix(),
//	}
//
//	// Use as SignOption with custom claims
//	customClaims := map[string]any{
//	    "role":     "admin",
//	    "username": "john_doe",
//	}
//
//	token, err := jwt.Sign(jwt.HS256, secretKey, customClaims, standardClaims)
//
//	// Or combine with other SignOptions
//	token, err := jwt.Sign(jwt.HS256, secretKey, customClaims,
//	    standardClaims,
//	    jwt.Audience{"api-service"},
//	    jwt.MaxAge(30 * time.Minute))
func (c Claims) ApplyClaims(dest *Claims) {
	if v := c.NotBefore; v > 0 {
		dest.NotBefore = v
	}

	if v := c.IssuedAt; v > 0 {
		dest.IssuedAt = v
	}

	if v := c.Expiry; v > 0 {
		dest.Expiry = v
	}

	if v := c.ID; v != "" {
		dest.ID = v
	}

	if v := c.OriginID; v != "" {
		dest.OriginID = v
	}

	if v := c.Issuer; v != "" {
		dest.Issuer = v
	}

	if v := c.Subject; v != "" {
		dest.Subject = v
	}

	if v := c.Audience; len(v) > 0 {
		dest.Audience = v
		// dest.RawAudience, _ = json.Marshal(v) // lint: ignore
	}
}

// MaxAge creates a SignOption to set expiration and issued-at claims for JWT tokens.
//
// This function generates a SignOptionFunc that automatically sets both the "exp"
// (expiry) and "iat" (issued at) claims based on the current time and specified
// duration. It provides a convenient way to create tokens with consistent lifetimes.
//
// **Parameters**:
//   - maxAge: Duration the token should remain valid from issuance time
//
// **Behavior**:
//   - If maxAge <= 1 second: Returns NoMaxAge (removes expiration)
//   - If maxAge > 1 second: Sets expiry to current time + maxAge
//   - Always sets IssuedAt to current time when expiry is set
//
// **Claims Set**:
//   - Expiry (exp): Current time + maxAge duration (Unix timestamp)
//   - IssuedAt (iat): Current time (Unix timestamp)
//
// **Time Source**: Uses the configurable Clock() function for current time,
// allowing consistent time handling and testing flexibility.
//
// **Usage Patterns**:
//   - Standard token lifetimes: 15 minutes, 1 hour, 24 hours
//   - Session tokens with auto-expiry
//   - Short-lived tokens for sensitive operations
//   - API tokens with controlled access windows
//
// **Security Benefits**:
//   - Prevents indefinite token usage
//   - Enables automatic token expiration
//   - Reduces risk of token compromise over time
//   - Facilitates token rotation policies
//
// Example usage:
//
//	// 15-minute token for API access
//	token, err := jwt.Sign(jwt.HS256, secretKey, userClaims,
//	    jwt.MaxAge(15 * time.Minute))
//
//	// 1-hour token for web sessions
//	token, err := jwt.Sign(jwt.HS256, secretKey, userClaims,
//	    jwt.MaxAge(time.Hour))
//
//	// Combine with other options
//	token, err := jwt.Sign(jwt.HS256, secretKey, userClaims,
//	    jwt.MaxAge(30 * time.Minute),
//	    jwt.Audience{"api-service"},
//	    jwt.Claims{Issuer: "myapp.com"})
//
//	// Very short duration returns NoMaxAge
//	signOption := jwt.MaxAge(500 * time.Millisecond) // Returns NoMaxAge
//
// See the Clock package-level variable to customize the current time function
// for testing or specific timezone requirements.
func MaxAge(maxAge time.Duration) SignOptionFunc {
	if maxAge <= time.Second {
		return NoMaxAge
	}

	return func(c *Claims) {
		now := Clock()
		c.Expiry = now.Add(maxAge).Unix()
		c.IssuedAt = now.Unix()
	}
}

// NoMaxAge is a SignOption that removes expiration constraints from JWT tokens.
//
// This SignOptionFunc sets both the "exp" (expiry) and "iat" (issued at) claims
// to zero, effectively creating tokens without time-based expiration. This is
// useful for long-lived tokens, permanent API keys, or testing scenarios.
//
// **Security Warning**: Tokens without expiration pose security risks as they
// remain valid indefinitely if compromised. Use only when absolutely necessary
// and implement alternative revocation mechanisms.
//
// **Claims Modified**:
//   - Expiry (exp): Set to 0 (no expiration)
//   - IssuedAt (iat): Set to 0 (no issue time tracking)
//
// **Use Cases**:
//   - Permanent API keys for system-to-system communication
//   - Long-lived refresh tokens (with alternative revocation)
//   - Development and testing environments
//   - Legacy system integration where expiration isn't supported
//
// **Alternative Approaches**: Consider implementing:
//   - Very long durations instead of no expiration
//   - Token rotation policies
//   - Manual revocation systems
//   - Refresh token patterns with shorter access tokens
//
// Example usage:
//
//	// Create token without expiration
//	token, err := jwt.Sign(jwt.HS256, secretKey, userClaims, jwt.NoMaxAge)
//
//	// Override MaxAge with NoMaxAge
//	token, err := jwt.Sign(jwt.HS256, secretKey, userClaims,
//	    jwt.MaxAge(time.Hour),    // This would set expiration
//	    jwt.NoMaxAge)             // This removes expiration
//
//	// Use with other options
//	token, err := jwt.Sign(jwt.HS256, secretKey, userClaims,
//	    jwt.NoMaxAge,
//	    jwt.Audience{"api-service"},
//	    jwt.Claims{Issuer: "system"})
//
// **Security Best Practice**: When using NoMaxAge, implement alternative
// security measures such as token blacklisting, regular key rotation,
// or application-level session management.
var NoMaxAge SignOptionFunc = func(c *Claims) {
	c.Expiry = 0
	c.IssuedAt = 0
}

// MaxAgeMap sets expiration and issued-at claims directly in a map-based claims structure.
//
// This helper function provides expiration functionality for map-based claims
// (Map type) by directly setting the "exp" and "iat" fields. It's designed for
// use with custom claim structures that don't embed the standard Claims struct.
//
// **Parameters**:
//   - maxAge: Duration the token should remain valid from current time
//   - claims: Map containing JWT claims (modified in-place)
//
// **Behavior**:
//   - If claims is nil: Function returns immediately (no-op)
//   - If maxAge <= 1 second: Function returns immediately (no expiration set)
//   - If "exp" already exists: Preserves existing expiration (no overwrite)
//   - Otherwise: Sets both "exp" and "iat" to calculated values
//
// **Claims Set**:
//   - "exp": Current time + maxAge duration (Unix timestamp)
//   - "iat": Current time (Unix timestamp)
//
// **Time Source**: Uses the configurable Clock() function for current time,
// ensuring consistency with other JWT timing operations.
//
// **Use Cases**:
//   - Custom claim structures using map[string]any
//   - Dynamic claim building without predefined structs
//   - Legacy codebases using map-based claims
//   - Flexible claim composition patterns
//
// **Preservation Logic**: The function checks if "exp" is already set to avoid
// overwriting existing expiration times, allowing for selective application.
//
// Example usage:
//
//	// Create custom claims with expiration
//	claims := jwt.Map{
//	    "user_id": "12345",
//	    "role":    "admin",
//	    "scope":   []string{"read", "write"},
//	}
//
//	// Add 15-minute expiration
//	jwt.MaxAgeMap(15 * time.Minute, claims)
//	token, err := jwt.Sign(jwt.HS256, secretKey, claims)
//
//	// Respects existing expiration
//	claimsWithExpiry := jwt.Map{
//	    "user_id": "12345",
//	    "exp":     time.Now().Add(time.Hour).Unix(), // Preserved
//	}
//	jwt.MaxAgeMap(15 * time.Minute, claimsWithExpiry) // No change to exp
//
//	// Use before signing
//	claims := jwt.Map{"foo": "bar"}
//	jwt.MaxAgeMap(15 * time.Minute, claims)
//	jwt.Sign(alg, key, claims)
func MaxAgeMap(maxAge time.Duration, claims Map) {
	if claims == nil {
		return
	}

	if maxAge <= time.Second {
		return
	}

	now := Clock()
	if claims["exp"] == nil {
		claims["exp"] = now.Add(maxAge).Unix()
		claims["iat"] = now.Unix()
	}
}

// Merge combines multiple values into a single JSON object for JWT claims.
//
// This utility function merges a variadic number of values into a unified JSON
// object, enabling flexible composition of JWT claims from multiple sources.
// It's used internally by the Sign function and can be used directly for
// custom claim composition scenarios.
//
// **Input Requirements**:
//   - Each non-nil value must marshal to a valid JSON object
//   - Objects must start with '{' and end with '}'
//   - Nil values are safely ignored
//   - Empty objects ("{}") are skipped during merging
//
// **Supported Input Types**:
//   - Structs with JSON tags (Claims, custom claim structs)
//   - map[string]any and similar map types
//   - []byte containing valid JSON object
//   - string containing valid JSON object
//   - Any type implementing json.Marshaler for objects
//
// **Merging Logic**:
//   - Values are processed in order (left to right)
//   - Later values can override earlier values for same keys
//   - Object contents are merged at the top level
//   - Returns combined JSON as []byte
//
// **Error Conditions**:
//   - Returns error if any value fails to marshal
//   - Returns error if marshaled result is not a JSON object
//   - Includes position information in error messages
//
// **Automatic Usage**: This function is automatically called by Sign when
// multiple SignOption values are provided, enabling seamless claim composition.
//
// Example usage:
//
//	// Merge standard and custom claims
//	standardClaims := jwt.Claims{
//	    Issuer:  "myapp.com",
//	    Subject: "user123",
//	    Expiry:  time.Now().Add(time.Hour).Unix(),
//	}
//
//	customClaims := map[string]any{
//	    "role":        "admin",
//	    "permissions": []string{"read", "write", "delete"},
//	    "department":  "engineering",
//	}
//
//	// Direct merge usage
//	combined, err := jwt.Merge(standardClaims, customClaims)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	token, err := jwt.Sign(jwt.HS256, secretKey, combined)
//
//	// Automatic merge in Sign function
//	token, err := jwt.Sign(jwt.HS256, secretKey, customClaims,
//	    jwt.MaxAge(15 * time.Minute),  // Adds exp, iat
//	    jwt.Claims{Issuer: "myapp.com"}) // Adds iss
//
//	// Multiple map merging
//	userInfo := map[string]any{"user_id": "123", "email": "user@example.com"}
//	permissions := map[string]any{"role": "user", "scope": "read"}
//	metadata := map[string]any{"version": "1.0", "client": "mobile"}
//
//	allClaims, err := jwt.Merge(userInfo, permissions, metadata)
//
// **Note**: When the same key exists in multiple objects, the last occurrence
// takes precedence, allowing for override patterns in claim composition.
func Merge(values ...any) ([]byte, error) {
	parts := make([][]byte, 0, len(values))

	for i, value := range values {
		if value == nil {
			continue
		}

		var (
			jsonBytes []byte
			err       error
		)

		switch v := value.(type) {
		case string:
			// If the value is a string, treat it as a JSON object.
			jsonBytes = []byte(v)
		case []byte:
			// If the value is a byte slice, treat it as a JSON object.
			jsonBytes = v
		default:
			jsonBytes, err = json.Marshal(value)
		}

		if err != nil {
			return nil, fmt.Errorf("part: %d: %w", i+1, err)
		}

		// Check that the marshaled JSON is an object.
		if len(jsonBytes) < 2 || jsonBytes[0] != '{' || jsonBytes[len(jsonBytes)-1] != '}' {
			return nil, fmt.Errorf("value does not marshal to a JSON object: %v", value)
		}
		// Skip empty objects ("{}")
		if len(jsonBytes) == 2 {
			continue
		}
		// Remove the leading '{' and trailing '}'.
		inner := jsonBytes[1 : len(jsonBytes)-1]
		parts = append(parts, inner)
	}

	var combined []byte
	if len(parts) == 0 {
		combined = []byte("{}")
	} else {
		// Join inner parts with commas and wrap with curly braces.
		combined = bytes.Join([][]byte{[]byte("{"), bytes.Join(parts, []byte(",")), []byte("}")}, nil)
	}

	return combined, nil
}
