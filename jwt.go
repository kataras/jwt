package jwt

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"time"
)

// Map is a convenient type alias for map[string]any, commonly used for dynamic JWT claims.
//
// This type provides a flexible way to work with JWT payloads that contain dynamic
// or unknown claim structures. It's particularly useful when:
//   - Working with tokens from external sources with varying claim structures
//   - Building generic JWT processing utilities
//   - Handling tokens where claim types are determined at runtime
//   - Prototyping and development scenarios
//
// While Map provides flexibility, consider using typed structs for production
// applications where claim structure is known and type safety is important.
//
// Example usage:
//
//	// Create claims dynamically
//	claims := jwt.Map{
//	    "sub":      "user123",
//	    "role":     "admin",
//	    "permissions": []string{"read", "write"},
//	    "iat":      time.Now().Unix(),
//	    "exp":      time.Now().Add(time.Hour).Unix(),
//	}
//
//	token, err := jwt.Sign(jwt.HS256, secretKey, claims)
//
//	// Verify and extract claims
//	var verifiedClaims jwt.Map
//	err = jwt.Verify(jwt.HS256, secretKey, token, &verifiedClaims)
//
//	// Access claims dynamically
//	userID := verifiedClaims["sub"].(string)
//	role := verifiedClaims["role"].(string)
//	permissions := verifiedClaims["permissions"].([]any)
type Map = map[string]any

// Clock provides the current time for JWT expiration and time-based claim validation.
//
// This variable is used throughout the library for all time-related validations including:
//   - Token expiration (exp claim) verification
//   - Not-before (nbf claim) validation
//   - Issued-at (iat claim) verification
//   - Leeway calculations for time-based validators
//
// The default implementation uses time.Now(), but it can be overridden for:
//   - **Testing**: Set fixed times to create deterministic test scenarios
//   - **Time zones**: Use custom time sources for specific timezone requirements
//   - **Simulation**: Simulate future or past times for testing edge cases
//   - **Synchronized time**: Use network time protocols for distributed systems
//
// **Thread Safety**: Modifications to Clock should be done during application
// initialization before concurrent operations begin. The function itself should
// be thread-safe as it may be called from multiple goroutines simultaneously.
//
// Example usage:
//
//	// Default usage (production)
//	now := jwt.Clock() // Returns current time
//
//	// Testing with fixed time
//	fixedTime := time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC)
//	jwt.Clock = func() time.Time { return fixedTime }
//
//	// Testing with relative time
//	startTime := time.Now()
//	jwt.Clock = func() time.Time { return startTime.Add(2 * time.Hour) }
//
//	// Reset to default
//	jwt.Clock = time.Now
//
// When testing time-sensitive functionality, remember to restore the original
// Clock function after tests complete to avoid affecting other tests.
var Clock = time.Now

// CompareHeader is the global header validator used for JWT token verification.
//
// This package-level variable defines the default behavior for validating JWT headers
// across all verification operations in the application. It implements the HeaderValidator
// interface and is responsible for algorithm validation and basic header consistency checking.
//
// **Default Behavior**: The default implementation (compareHeader) performs:
//   - Algorithm matching between expected and token header
//   - Header structure validation (standard vs reversed field order)
//   - Support for headers with and without "typ": "JWT" field
//   - Fast byte-level comparison for known algorithm patterns
//
// **Customization Use Cases**:
//   - **Cross-platform compatibility**: Handle tokens from other JWT libraries
//   - **Legacy token support**: Accept non-standard header formats
//   - **Third-party integration**: Support tokens from external services
//   - **Custom validation**: Add application-specific header validation logic
//
// **Global vs Per-Token Validation**:
//   - Modifying CompareHeader affects ALL token verification in the application
//   - For per-token validation, use VerifyWithHeaderValidator instead
//   - Consider thread safety when modifying this global variable
//
// **Thread Safety**: Changes should be made during application initialization
// before concurrent verification operations begin.
//
// Example customization:
//
//	// Custom validator for third-party tokens
//	jwt.CompareHeader = func(alg string, headerDecoded []byte) (jwt.Alg, jwt.PublicKey, jwt.InjectFunc, error) {
//	    // Parse header to extract algorithm
//	    var header struct {
//	        Alg string `json:"alg"`
//	        Typ string `json:"typ"`
//	        // Add custom fields as needed
//	    }
//
//	    if err := json.Unmarshal(headerDecoded, &header); err != nil {
//	        return nil, nil, nil, err
//	    }
//
//	    // Validate algorithm matches expectation
//	    if alg != "" && header.Alg != alg {
//	        return nil, nil, nil, jwt.ErrTokenAlg
//	    }
//
//	    // Accept both "JWT" and "jwt" type values (case insensitive)
//	    if header.Typ != "" && strings.ToUpper(header.Typ) != "JWT" {
//	        return nil, nil, nil, jwt.ErrTokenAlg
//	    }
//
//	    return nil, nil, nil, nil // Use provided algorithm and key
//	}
//
// To restore default behavior: jwt.CompareHeader = jwt.compareHeader
var CompareHeader HeaderValidator = compareHeader

// ReadFile defines the file reading function used by key loading utilities.
//
// This package-level variable allows customization of how the library reads
// key files when using helper functions like MustLoadRSA, LoadRSA, and similar
// key loading utilities. The default implementation uses os.ReadFile for
// standard filesystem access.
//
// **Use Cases for Customization**:
//   - **Embedded files**: Read keys from embedded filesystem (embed.FS)
//   - **Remote storage**: Fetch keys from cloud storage, databases, or APIs
//   - **Encrypted storage**: Read and decrypt keys from secure storage
//   - **Virtual filesystems**: Support non-standard file sources
//   - **Testing**: Use in-memory file systems for unit tests
//
// **Function Signature**: Must match `func(filename string) ([]byte, error)`
// to be compatible with standard os.ReadFile behavior.
//
// **Thread Safety**: This variable should be set during application initialization
// before concurrent key loading operations. The function itself should be thread-safe
// as it may be called from multiple goroutines.
//
// Example customizations:
//
//	// Embedded filesystem (Go 1.16+)
//	//go:embed keys/*
//	var keyFiles embed.FS
//	jwt.ReadFile = keyFiles.ReadFile
//
//	// Remote key storage
//	jwt.ReadFile = func(filename string) ([]byte, error) {
//	    resp, err := http.Get("https://keyserver.com/keys/" + filename)
//	    if err != nil {
//	        return nil, err
//	    }
//	    defer resp.Body.Close()
//	    return io.ReadAll(resp.Body)
//	}
//
//	// Database storage
//	jwt.ReadFile = func(filename string) ([]byte, error) {
//	    var keyData []byte
//	    err := db.QueryRow("SELECT key_data FROM keys WHERE filename = ?", filename).Scan(&keyData)
//	    return keyData, err
//	}
//
//	// Testing with in-memory files
//	testFiles := map[string][]byte{
//	    "test.pem": []byte("-----BEGIN PRIVATE KEY-----\n..."),
//	}
//	jwt.ReadFile = func(filename string) ([]byte, error) {
//	    if data, ok := testFiles[filename]; ok {
//	        return data, nil
//	    }
//	    return nil, os.ErrNotExist
//	}
var ReadFile = os.ReadFile

// Marshal defines the JSON marshaling function used for encoding JWT payloads.
//
// This package-level variable allows customization of how claims are serialized
// to JSON before being included in JWT tokens. The default implementation handles
// both raw byte slices and arbitrary Go values using the standard json.Marshal.
//
// **Default Behavior**:
//   - Raw []byte values are passed through unchanged (for pre-serialized JSON)
//   - All other values are marshaled using standard json.Marshal
//   - Supports any type that implements json.Marshaler interface
//
// **Customization Use Cases**:
//   - **Custom JSON encoding**: Use alternative JSON libraries (e.g., jsoniter, gojay)
//   - **Field transformation**: Apply custom field naming, omission, or formatting
//   - **Compression**: Compress payloads before encoding for large claims
//   - **Encryption**: Encrypt sensitive fields before marshaling
//   - **Validation**: Add payload validation during marshaling
//   - **Debugging**: Add logging or monitoring to track payload sizes
//
// **Performance Considerations**: The Marshal function is called for every token
// generation, so performance optimizations here can significantly impact throughput.
//
// **Thread Safety**: This variable should be set during application initialization.
// The function itself must be thread-safe as it's called from concurrent operations.
//
// Example customizations:
//
//	// Use jsoniter for better performance
//	import jsoniter "github.com/json-iterator/go"
//	jwt.Marshal = jsoniter.Marshal
//
//	// Add payload size logging
//	originalMarshal := jwt.Marshal
//	jwt.Marshal = func(v any) ([]byte, error) {
//	    data, err := originalMarshal(v)
//	    if err == nil {
//	        log.Printf("JWT payload size: %d bytes", len(data))
//	    }
//	    return data, err
//	}
//
//	// Custom field formatting
//	jwt.Marshal = func(v any) ([]byte, error) {
//	    if b, ok := v.([]byte); ok {
//	        return b, nil
//	    }
//
//	    // Apply custom transformations
//	    transformed := applyCustomFormatting(v)
//	    return json.Marshal(transformed)
//	}
var Marshal = func(v any) ([]byte, error) {
	if b, ok := v.([]byte); ok {
		return b, nil
	}

	return json.Marshal(v)
}

// Unmarshal defines the JSON unmarshaling function used for decoding JWT payloads.
//
// This package-level variable allows customization of how JWT payload JSON is
// deserialized into Go data structures. The default implementation uses json.Decoder
// with UseNumber() enabled to preserve numeric precision and avoid float64 conversion
// issues common with JSON parsing.
//
// **Default Behavior (defaultUnmarshal)**:
//   - Uses json.Decoder with UseNumber() to handle integers correctly
//   - Prevents automatic conversion of all numbers to float64
//   - Preserves numeric precision for large integers
//   - Decodes JSON numbers as json.Number type when destination is interface{}
//
// **Why UseNumber() Matters**:
//   - Standard json.Unmarshal converts all numbers to float64
//   - Float64 cannot accurately represent large integers (>53 bits)
//   - JWT claims like "iat", "exp", "nbf" are Unix timestamps (large integers)
//   - User IDs and other identifiers may be large integers
//
// **Customization Use Cases**:
//   - **Alternative JSON libraries**: Use faster or feature-rich JSON libraries
//   - **Custom number handling**: Different numeric type preferences
//   - **Field validation**: Add validation during unmarshaling
//   - **Field transformation**: Apply custom transformations to incoming data
//   - **Debugging**: Add logging to monitor claim structures
//   - **Security**: Add input sanitization or filtering
//
// **Thread Safety**: This variable should be set during application initialization.
// The function itself must be thread-safe as it's called from concurrent operations.
//
// Example customizations:
//
//	// Use jsoniter for better performance
//	import jsoniter "github.com/json-iterator/go"
//	jwt.Unmarshal = jsoniter.Unmarshal
//
//	// Add claim logging for debugging
//	originalUnmarshal := jwt.Unmarshal
//	jwt.Unmarshal = func(data []byte, v any) error {
//	    log.Printf("Unmarshaling JWT claims: %s", string(data))
//	    return originalUnmarshal(data, v)
//	}
//
//	// Custom number handling without UseNumber()
//	jwt.Unmarshal = func(data []byte, v any) error {
//	    return json.Unmarshal(data, v) // Standard behavior
//	}
//
//	// Add validation during unmarshaling
//	jwt.Unmarshal = func(data []byte, v any) error {
//	    if err := defaultUnmarshal(data, v); err != nil {
//	        return err
//	    }
//	    return validateClaimsStructure(v) // Custom validation
//	}
var Unmarshal = defaultUnmarshal

// UnmarshalWithRequired provides JSON unmarshaling with required field validation.
//
// This function extends the standard unmarshaling behavior by validating that all
// fields marked with the "required" JSON tag are present and non-empty in the
// JWT payload. It's particularly useful for enforcing strict claim requirements
// in security-critical applications.
//
// **Required Field Validation**:
//   - Checks struct fields tagged with `json:"fieldname,required"`
//   - Validates that required fields are present in the JSON payload
//   - Ensures required fields have non-zero values (not nil, empty string, etc.)
//   - Returns ErrMissingKey if any required field is missing or empty
//
// **Usage Pattern**: Replace the global Unmarshal function to enable required
// field validation for all token verification operations in the application.
//
// **Field Tag Format**: Use standard JSON tags with "required" option:
//
//	`json:"field_name,required"` - Field is required and must be present
//	`json:"field_name,omitempty,required"` - Cannot combine omitempty with required
//
// **Validation Rules**:
//   - String fields: Must not be empty ("")
//   - Numeric fields: Must not be zero value (0, 0.0)
//   - Boolean fields: Must be explicitly set (false is valid)
//   - Slice/Map fields: Must not be nil or empty
//   - Pointer fields: Must not be nil
//   - Interface fields: Must not be nil
//
// **Performance**: Adds reflection-based validation overhead after unmarshaling.
// Consider the performance impact for high-throughput applications.
//
// Parameters:
//   - payload: Raw JSON bytes from the JWT payload
//   - dest: Pointer to destination struct with required field tags
//
// Returns:
//   - error: JSON unmarshaling errors or ErrMissingKey for missing required fields
//
// Example usage:
//
//	// Define claims struct with required fields
//	type UserClaims struct {
//	    Username  string    `json:"username,required"`    // Must be present and non-empty
//	    UserID    int       `json:"user_id,required"`     // Must be present and non-zero
//	    Role      string    `json:"role,required"`        // Must be present and non-empty
//	    Email     string    `json:"email"`                // Optional field
//	    IssuedAt  time.Time `json:"iat,required"`         // Must be present
//	}
//
//	// Enable required field validation globally
//	jwt.Unmarshal = jwt.UnmarshalWithRequired
//
//	// Verify token - will fail if required fields are missing
//	var claims UserClaims
//	err := jwt.Verify(jwt.HS256, secretKey, token, &claims)
//	if err != nil {
//	    // Could be ErrMissingKey if required fields are missing
//	    log.Printf("Token verification failed: %v", err)
//	}
//
//	// Token with missing required field will fail:
//	// {"user_id": 123, "email": "user@example.com"} // Missing username and role
//
//	// Valid token:
//	// {"username": "john", "user_id": 123, "role": "admin", "iat": 1609459200}
func UnmarshalWithRequired(payload []byte, dest any) error {
	if err := defaultUnmarshal(payload, dest); err != nil {
		return err
	}

	return meetRequirements(reflect.ValueOf(dest))
}

func defaultUnmarshal(payload []byte, dest any) error {
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber() // fixes the issue of setting float64 instead of int64 on maps.
	return dec.Decode(&dest)
}

// InjectFunc defines a function type for modifying JWT payload data during token processing.
//
// This function type enables payload transformation before signing (encoding) or after
// verification but before unmarshaling (decoding). It's the foundation for advanced
// JWT features like payload encryption, compression, and custom data transformations.
//
// **Function Signature**:
//   - Input: plainPayload []byte - The raw payload data to transform
//   - Output: []byte - The transformed payload data
//   - Output: error - Any transformation error
//
// **Use Cases**:
//   - **Encryption**: Encrypt sensitive payload data (see GCM function)
//   - **Compression**: Compress large payloads to reduce token size
//   - **Encoding**: Apply custom encoding schemes (base32, hex, etc.)
//   - **Validation**: Add payload validation with transformation
//   - **Filtering**: Remove or redact sensitive fields
//   - **Augmentation**: Add computed fields or metadata
//
// **Usage Contexts**:
//   - **Signing**: Applied before payload is base64-encoded and signed
//   - **Verification**: Applied after signature verification but before claims extraction
//   - **Multi-key scenarios**: Different InjectFunc per key in Keys registry
//   - **Custom algorithms**: Algorithm-specific payload processing
//
// **Implementation Requirements**:
//   - Must be deterministic for the same input (especially for signing)
//   - Should be reversible if used for both encoding and decoding
//   - Must handle edge cases gracefully (empty payloads, invalid data)
//   - Should be thread-safe for concurrent operations
//   - Error handling should be comprehensive and descriptive
//
// **Built-in Implementations**:
//   - GCM(): Creates encrypt/decrypt function pair for AES-GCM encryption
//   - Custom implementations for specific transformation needs
//
// Example implementations:
//
//	// Simple compression function
//	func compress(payload []byte) ([]byte, error) {
//	    var buf bytes.Buffer
//	    writer := gzip.NewWriter(&buf)
//	    if _, err := writer.Write(payload); err != nil {
//	        return nil, err
//	    }
//	    if err := writer.Close(); err != nil {
//	        return nil, err
//	    }
//	    return buf.Bytes(), nil
//	}
//
//	// Field filtering function
//	func filterSensitiveFields(payload []byte) ([]byte, error) {
//	    var claims map[string]any
//	    if err := json.Unmarshal(payload, &claims); err != nil {
//	        return nil, err
//	    }
//
//	    // Remove sensitive fields
//	    delete(claims, "password")
//	    delete(claims, "ssn")
//
//	    return json.Marshal(claims)
//	}
//
//	// Usage with signing
//	encryptFunc, decryptFunc, err := jwt.GCM(encryptionKey, nil)
//	if err != nil {
//	    return err
//	}
//
//	token, err := jwt.SignEncrypted(jwt.HS256, secretKey, encryptFunc, claims)
//
//	// Usage with verification (automatic with Keys)
//	keys := make(jwt.Keys)
//	keys["key1"] = &jwt.Key{
//	    Alg:     jwt.HS256,
//	    Private: secretKey,
//	    Public:  secretKey,
//	    Encrypt: encryptFunc,
//	    Decrypt: decryptFunc,
//	}
type InjectFunc func(plainPayload []byte) ([]byte, error)
