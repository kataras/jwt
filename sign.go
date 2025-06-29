package jwt

// Sign creates and signs a JWT token using the specified algorithm, key, and claims.
//
// This is the primary function for generating JWT tokens. It creates a complete
// JWT token by encoding the claims as the payload, applying any SignOptions for
// standard claims, and signing the result with the specified algorithm and key.
//
// **Parameters**:
//   - alg: Cryptographic algorithm to use for signing (HS256, RS256, ES256, etc.)
//   - key: Private key material appropriate for the algorithm
//   - claims: Payload data to include in the token (any JSON-serializable type)
//   - opts: Optional SignOption implementations for standard claims
//
// **Payload Security**: The claims payload is NOT encrypted by default and is
// base64-encoded only. Do not include sensitive information unless using
// encryption functions (see SignEncrypted and GCM for encrypted payloads).
//
// **Supported Claim Types**:
//   - jwt.Claims struct for standard claims
//   - map[string]any for flexible custom claims
//   - Custom structs with JSON tags
//   - jwt.Map type alias for convenience
//   - Any type that marshals to valid JSON
//
// **SignOption Processing**: When SignOptions are provided, they are processed
// to create standard claims which are then merged with the provided claims.
// Standard claims from options take precedence over conflicting claims.
//
// **Return Value**: Returns the complete JWT token as a []byte slice in the
// standard format: header.payload.signature (base64url-encoded segments).
//
// **Error Conditions**:
//   - Invalid algorithm or key combination
//   - Claims that cannot be marshaled to JSON
//   - SignOption processing failures
//   - Cryptographic signing failures
//
// Example usage:
//
//	// Basic token with standard claims only
//	standardClaims := jwt.Claims{
//	    Subject: "user123",
//	    Issuer:  "myapp.com",
//	    Expiry:  time.Now().Add(time.Hour).Unix(),
//	}
//	token, err := jwt.Sign(jwt.HS256, secretKey, standardClaims)
//
//	// Custom claims with manual timing
//	now := time.Now()
//	customClaims := map[string]any{
//	    "iat":      now.Unix(),
//	    "exp":      now.Add(15 * time.Minute).Unix(),
//	    "user_id":  "12345",
//	    "role":     "admin",
//	    "permissions": []string{"read", "write"},
//	}
//	token, err := jwt.Sign(jwt.HS256, secretKey, customClaims)
//
//	// Custom claims with SignOptions for standard claims
//	userClaims := jwt.Map{
//	    "username": "john_doe",
//	    "role":     "user",
//	    "email":    "john@example.com",
//	}
//	token, err := jwt.Sign(jwt.HS256, secretKey, userClaims,
//	    jwt.MaxAge(15 * time.Minute),
//	    jwt.Audience{"api-service"},
//	    jwt.Claims{Issuer: "myapp.com"})
//
//	// Custom struct with embedded standard claims
//	type UserToken struct {
//	    Username string `json:"username"`
//	    Role     string `json:"role"`
//	    jwt.Claims
//	}
//	userToken := UserToken{
//	    Username: "alice",
//	    Role:     "admin",
//	    Claims:   jwt.Claims{Subject: "user456"},
//	}
//	token, err := jwt.Sign(jwt.RS256, rsaPrivateKey, userToken,
//	    jwt.MaxAge(30 * time.Minute))
//
// See Verify for token validation and SignEncrypted for encrypted payloads.
func Sign(alg Alg, key PrivateKey, claims any, opts ...SignOption) ([]byte, error) {
	return signToken(alg, key, nil, claims, nil, opts...)
}

// SignEncrypted creates and signs a JWT token with encrypted payload.
//
// This function extends Sign by adding payload encryption capability. The claims
// are marshaled to JSON, then encrypted using the provided encrypt function,
// and finally signed. This provides confidentiality for sensitive payload data.
//
// **Parameters**:
//   - alg: Cryptographic algorithm to use for signing (HS256, RS256, ES256, etc.)
//   - key: Private key material appropriate for the signing algorithm
//   - encrypt: Function to encrypt the marshaled payload (see InjectFunc)
//   - claims: Payload data to include in the token (any JSON-serializable type)
//   - opts: Optional SignOption implementations for standard claims
//
// **Encryption Process**:
//  1. Claims are processed and merged with SignOptions
//  2. Merged claims are marshaled to JSON
//  3. JSON payload is encrypted using the encrypt function
//  4. Encrypted payload is base64url-encoded and signed
//
// **Security Benefits**:
//   - Payload confidentiality (claims are encrypted)
//   - Protection of sensitive information in tokens
//   - Prevents payload inspection without decryption
//   - Maintains JWT structure and signature verification
//
// **InjectFunc Signature**: The encrypt function receives []byte (marshaled claims)
// and returns []byte (encrypted data) and error. It's called after JSON marshaling
// but before base64url encoding and signing.
//
// **Decryption**: Tokens created with SignEncrypted must be verified using
// VerifyEncrypted with the corresponding decrypt function.
//
// Example usage:
//
//	// Using AES-GCM encryption (see GCM function)
//	encryptKey := []byte("my-32-byte-encryption-key-here!")
//	encrypt, decrypt := jwt.GCM(encryptKey, nil)
//
//	// Create encrypted token
//	sensitiveData := map[string]any{
//	    "ssn":           "123-45-6789",
//	    "credit_card":   "4111-1111-1111-1111",
//	    "bank_account":  "9876543210",
//	    "user_id":       "12345",
//	}
//
//	token, err := jwt.SignEncrypted(jwt.HS256, signingKey, encrypt,
//	    sensitiveData, jwt.MaxAge(time.Hour))
//
//	// Custom encryption function
//	customEncrypt := func(payload []byte) ([]byte, error) {
//	    // Your custom encryption logic here
//	    return encryptedData, nil
//	}
//
//	token, err := jwt.SignEncrypted(jwt.RS256, rsaKey, customEncrypt,
//	    userClaims, jwt.Audience{"secure-api"})
//
// **Important Notes**:
//   - The encrypt function is called AFTER claims marshaling
//   - Both signing and encryption keys should be securely managed
//   - Use GCM function for authenticated encryption with AES-GCM
//   - Consider key rotation policies for both signing and encryption keys
//
// See GCM for ready-to-use authenticated encryption and VerifyEncrypted for
// decryption and verification of encrypted tokens.
func SignEncrypted(alg Alg, key PrivateKey, encrypt InjectFunc, claims any, opts ...SignOption) ([]byte, error) {
	return signToken(alg, key, encrypt, claims, nil, opts...)
}

// SignWithHeader creates and signs a JWT token with custom header fields.
//
// This function extends Sign by allowing custom fields to be added to the JWT
// header in addition to the standard "alg" and "typ" fields. Custom headers
// are useful for adding metadata or additional algorithm parameters.
//
// **Parameters**:
//   - alg: Cryptographic algorithm to use for signing (HS256, RS256, ES256, etc.)
//   - key: Private key material appropriate for the signing algorithm
//   - claims: Payload data to include in the token (any JSON-serializable type)
//   - customHeader: Additional header fields to include (any JSON-serializable type)
//   - opts: Optional SignOption implementations for standard claims
//
// **Header Structure**: The JWT header will contain:
//   - Standard fields: "alg" (algorithm), "typ" (always "JWT")
//   - Custom fields: Any fields from the customHeader parameter
//   - Conflict resolution: Custom fields override standard fields except "alg"
//
// **Common Custom Header Use Cases**:
//   - "kid" (Key ID): Identifies which key was used for signing
//   - "x5t" (X.509 Thumbprint): Certificate thumbprint
//   - "jku" (JWK Set URL): URL pointing to JWK Set
//   - "cty" (Content Type): Content type of the secured payload
//   - Custom application-specific metadata
//
// **Security Considerations**:
//   - Header fields are not encrypted and are visible to token bearers
//   - Do not include sensitive information in custom headers
//   - Validate custom header fields during token verification
//   - Be cautious with fields that could affect security decisions
//
// Example usage:
//
//	// Token with key identifier
//	customHeader := map[string]any{
//	    "kid": "key-2023-01",
//	    "x5t": "dGhpcyBpcyBhIFNIQTEgdGVzdA",
//	}
//
//	token, err := jwt.SignWithHeader(jwt.RS256, rsaKey, userClaims,
//	    customHeader, jwt.MaxAge(time.Hour))
//
//	// Header with JWK Set URL
//	headerWithJKU := jwt.Map{
//	    "kid": "rsa-key-1",
//	    "jku": "https://myapp.com/.well-known/jwks.json",
//	}
//
//	token, err := jwt.SignWithHeader(jwt.RS256, rsaKey, userClaims,
//	    headerWithJKU, jwt.Audience{"api-service"})
//
//	// Custom content type for non-JSON payload
//	headerWithCty := map[string]any{
//	    "cty": "example-content",
//	    "kid": "hmac-key-1",
//	}
//
//	token, err := jwt.SignWithHeader(jwt.HS256, hmacKey, customPayload,
//	    headerWithCty, jwt.MaxAge(30 * time.Minute))
//
//	// Struct-based custom header
//	type CustomHeader struct {
//	    KeyID     string `json:"kid"`
//	    Algorithm string `json:"alg"` // Will be overridden by actual algorithm
//	    Version   string `json:"ver"`
//	}
//
//	header := CustomHeader{
//	    KeyID:   "signing-key-v2",
//	    Version: "2.0",
//	}
//
//	token, err := jwt.SignWithHeader(jwt.ES256, ecdsaKey, userClaims,
//	    header, jwt.Claims{Issuer: "myapp.com"})
//
// **Header Merging**: Custom header fields are merged with standard JWT header
// fields. The "alg" field is always set to the specified algorithm and cannot
// be overridden by custom headers.
func SignWithHeader(alg Alg, key PrivateKey, claims any, customHeader any, opts ...SignOption) ([]byte, error) {
	return signToken(alg, key, nil, claims, customHeader, opts...)
}

// SignEncryptedWithHeader creates and signs a JWT token with encrypted payload and custom headers.
//
// This function combines the functionality of SignEncrypted and SignWithHeader,
// providing both payload encryption and custom header support in a single operation.
// It's ideal for scenarios requiring both payload confidentiality and header metadata.
//
// **Parameters**:
//   - alg: Cryptographic algorithm to use for signing (HS256, RS256, ES256, etc.)
//   - key: Private key material appropriate for the signing algorithm
//   - encrypt: Function to encrypt the marshaled payload (see InjectFunc)
//   - claims: Payload data to include in the token (any JSON-serializable type)
//   - customHeader: Additional header fields to include (any JSON-serializable type)
//   - opts: Optional SignOption implementations for standard claims
//
// **Processing Order**:
//  1. SignOptions are processed and merged with claims
//  2. Claims are marshaled to JSON
//  3. JSON payload is encrypted using the encrypt function
//  4. Custom header fields are merged with standard JWT headers
//  5. Token is assembled and signed with the specified algorithm
//
// **Combined Benefits**:
//   - Payload confidentiality through encryption
//   - Header metadata for token identification and routing
//   - Standard claims management through SignOptions
//   - Complete JWT structure with signature verification
//
// **Security Considerations**:
//   - Headers remain unencrypted and visible to all token bearers
//   - Payload is encrypted and requires decryption function to access
//   - Both signing and encryption keys must be securely managed
//   - Custom headers should not contain sensitive information
//
// **Use Cases**:
//   - Multi-tenant systems with encrypted user data and tenant identification
//   - Key rotation systems with encrypted payloads and key identifiers
//   - Content-type specific tokens with encrypted sensitive data
//   - Audit systems requiring both data protection and metadata
//
// Example usage:
//
//	// Multi-tenant encrypted token with key identification
//	encryptKey := []byte("tenant-specific-encryption-key!")
//	encrypt, decrypt := jwt.GCM(encryptKey, nil)
//
//	tenantHeader := map[string]any{
//	    "kid":       "tenant-123-key-v2",
//	    "tenant_id": "tenant-123",
//	    "env":       "production",
//	}
//
//	sensitiveData := map[string]any{
//	    "user_ssn":     "123-45-6789",
//	    "bank_account": "9876543210",
//	    "salary":       75000,
//	}
//
//	token, err := jwt.SignEncryptedWithHeader(jwt.RS256, rsaKey, encrypt,
//	    sensitiveData, tenantHeader, jwt.MaxAge(time.Hour))
//
//	// Key rotation with encrypted payload
//	rotationHeader := jwt.Map{
//	    "kid": "rotation-key-2023-q4",
//	    "ver": "2.0",
//	    "cty": "sensitive+json",
//	}
//
//	encryptedUserData := map[string]any{
//	    "personal_data": sensitiveUserInfo,
//	    "permissions":   userPermissions,
//	}
//
//	token, err := jwt.SignEncryptedWithHeader(jwt.ES256, ecdsaKey, encrypt,
//	    encryptedUserData, rotationHeader,
//	    jwt.Audience{"secure-api", "admin-panel"},
//	    jwt.Claims{Issuer: "auth-service"})
//
// **Decryption and Verification**: Tokens created with this function must be
// verified using VerifyEncrypted with the corresponding decrypt function.
// Custom headers can be accessed from the returned VerifiedToken structure.
//
// See GCM for authenticated encryption, VerifyEncrypted for token verification,
// and SignWithHeader for header-only customization without encryption.
func SignEncryptedWithHeader(alg Alg, key PrivateKey, encrypt InjectFunc, claims any, customHeader any, opts ...SignOption) ([]byte, error) {
	return signToken(alg, key, encrypt, claims, customHeader, opts...)
}

// signToken is the internal token creation function used by all Sign variants.
//
// This function implements the core JWT token creation logic, handling claim
// processing, payload encryption (optional), and token encoding. It serves as
// the common implementation for Sign, SignEncrypted, SignWithHeader, and
// SignEncryptedWithHeader functions.
//
// **Parameters**:
//   - alg: Cryptographic algorithm for signing
//   - key: Private key material for the specified algorithm
//   - encrypt: Optional encryption function for payload (nil for no encryption)
//   - claims: Primary claims data to include in token
//   - customHeader: Optional custom header fields (nil for standard header only)
//   - opts: SignOption slice for applying standard claims
//
// **Processing Pipeline**:
//  1. SignOption Processing: Collects standard claims from all SignOptions
//  2. Claim Merging: Merges original claims with standard claims using Merge
//  3. Payload Marshaling: Converts final claims to JSON using Marshal
//  4. Optional Encryption: Applies encrypt function if provided
//  5. Token Encoding: Creates final JWT using encodeToken
//
// **SignOption Handling**:
//   - Processes all non-nil SignOptions in order
//   - Accumulates standard claims into a single Claims struct
//   - Merges accumulated claims with provided claims
//   - Later SignOptions can override earlier ones for same claim fields
//
// **Error Propagation**: Returns errors from:
//   - Claim merging failures (invalid JSON structures)
//   - Marshaling failures (non-serializable claims)
//   - Encryption failures (encrypt function errors)
//   - Token encoding failures (algorithm/key issues, header problems)
//
// **Internal Usage**: This function is not exported and serves as the
// implementation detail for the public Sign* functions. It provides
// consistency across all signing variants while allowing specific
// customizations through parameters.
//
// **Encryption Integration**: When encrypt is non-nil, it's applied after
// marshaling but before base64url encoding, allowing the encryption function
// to work with the raw JSON payload.
func signToken(alg Alg, key PrivateKey, encrypt InjectFunc, claims any, customHeader any, opts ...SignOption) ([]byte, error) {
	if len(opts) > 0 {
		var standardClaims Claims
		for _, opt := range opts {
			if opt == nil {
				continue
			}
			opt.ApplyClaims(&standardClaims)
		}

		var err error
		claims, err = Merge(claims, standardClaims)
		if err != nil {
			return nil, err
		}
	}

	payload, err := Marshal(claims)
	if err != nil {
		return nil, err
	}

	if encrypt != nil {
		payload, err = encrypt(payload)
		if err != nil {
			return nil, err
		}
	}

	return encodeToken(alg, key, payload, customHeader)
}

// SignOption provides a flexible interface for applying standard JWT claims during token signing.
//
// This interface enables a composable approach to token creation by allowing various
// types to implement standard claim application logic. SignOptions are processed
// during token signing to automatically set common JWT claims without manual management.
//
// **Interface Contract**: Implementers must provide an ApplyClaims method that
// modifies the provided Claims struct to set appropriate standard claim values.
// The method should be idempotent and handle nil or zero values gracefully.
//
// **Built-in Implementations**:
//   - MaxAge(duration): Sets exp and iat claims for token expiration
//   - NoMaxAge: Removes exp and iat claims (no expiration)
//   - Audience: Sets aud claim for intended recipients
//   - Claims: Applies any standard claims from a Claims struct
//   - SignOptionFunc: Function wrapper for custom claim logic
//
// **Usage Pattern**: SignOptions are passed as variadic parameters to Sign
// functions and are processed in order. Later options can override earlier
// ones if they set the same claims, enabling override patterns.
//
// **Design Benefits**:
//   - Composable claim management
//   - Type-safe standard claim application
//   - Reusable claim configuration
//   - Clean separation of concerns between custom and standard claims
//
// **Implementation Guidelines**:
//   - Only modify non-zero fields unless explicitly clearing values
//   - Handle concurrent access if the implementation will be shared
//   - Avoid side effects beyond modifying the provided Claims struct
//   - Document which specific claims are modified by the implementation
//
// Example implementations:
//
//	// Custom SignOption for organization claims
//	type OrgClaims struct {
//	    OrgID   string
//	    OrgName string
//	}
//
//	func (o OrgClaims) ApplyClaims(dest *jwt.Claims) {
//	    dest.Issuer = o.OrgName
//	    dest.Subject = o.OrgID
//	}
//
//	// Usage with custom SignOption
//	orgClaims := OrgClaims{OrgID: "org123", OrgName: "MyCompany"}
//	token, err := jwt.Sign(jwt.HS256, key, userClaims,
//	    orgClaims,
//	    jwt.MaxAge(time.Hour))
//
//	// Function-based SignOption
//	tenantOption := jwt.SignOptionFunc(func(c *jwt.Claims) {
//	    c.Issuer = "tenant-" + tenantID
//	    c.Audience = jwt.Audience{tenantID + "-api"}
//	})
//
//	token, err := jwt.Sign(jwt.HS256, key, claims, tenantOption)
//
// Available built-in SignOptions:
//   - MaxAge(time.Duration): Token expiration management
//   - NoMaxAge: Removes expiration constraints
//   - Audience{"service1", "service2"}: Intended recipients
//   - Claims{Issuer: "app", Subject: "user"}: Standard claim values
type SignOption interface {
	// ApplyClaims applies standard JWT claims to the destination Claims struct.
	//
	// This method is called during token signing to set standard claims
	// based on the SignOption's configuration. Implementations should
	// modify the destination Claims struct to include their claim values.
	//
	// **Parameters**:
	//   - dest: Pointer to Claims struct to modify with standard claims
	//
	// **Implementation Notes**:
	//   - Should only set meaningful (non-zero) values unless explicitly clearing
	//   - Must handle nil destination gracefully (though framework prevents this)
	//   - Should be idempotent and free of side effects
	//   - Can override existing values in destination if appropriate
	//
	// **Threading**: Implementations should be thread-safe if the SignOption
	// instance will be shared across goroutines.
	ApplyClaims(*Claims)
}

// SignOptionFunc is a function type that implements the SignOption interface.
//
// This type provides a convenient way to create SignOption implementations using
// function literals or existing functions, eliminating the need to define new
// types for simple claim application logic.
//
// **Function Signature**: The function receives a pointer to a Claims struct
// and should modify it to apply the desired standard claims. The function
// should follow the same guidelines as other SignOption implementations.
//
// **Use Cases**:
//   - Quick inline SignOption creation with function literals
//   - Converting existing claim-setting functions to SignOptions
//   - Dynamic claim logic based on runtime conditions
//   - Conditional claim application
//
// **Benefits**:
//   - Reduces boilerplate for simple SignOption implementations
//   - Enables functional programming patterns for claim management
//   - Allows capturing closure variables for dynamic behavior
//   - Facilitates testing with mock claim functions
//
// Example usage:
//
//	// Inline function literal
//	dynamicIssuer := jwt.SignOptionFunc(func(c *jwt.Claims) {
//	    c.Issuer = "app-" + os.Getenv("ENVIRONMENT")
//	    c.Subject = getCurrentUserID()
//	})
//
//	token, err := jwt.Sign(jwt.HS256, key, userClaims, dynamicIssuer)
//
//	// Conditional claim application
//	conditionalClaims := jwt.SignOptionFunc(func(c *jwt.Claims) {
//	    if isProduction {
//	        c.Issuer = "prod.myapp.com"
//	    } else {
//	        c.Issuer = "dev.myapp.com"
//	    }
//	})
//
//	// Converting existing function
//	setOrgClaims := func(c *jwt.Claims) {
//	    c.Issuer = organization.Name
//	    c.Subject = organization.ID
//	}
//	orgOption := jwt.SignOptionFunc(setOrgClaims)
//
//	// Multiple conditional options
//	getUserRole := jwt.SignOptionFunc(func(c *jwt.Claims) {
//	    switch user.Role {
//	    case "admin":
//	        c.Audience = jwt.Audience{"admin-api", "user-api"}
//	    case "user":
//	        c.Audience = jwt.Audience{"user-api"}
//	    default:
//	        c.Audience = jwt.Audience{"public-api"}
//	    }
//	})
//
//	token, err := jwt.Sign(jwt.HS256, key, userClaims,
//	    getUserRole,
//	    jwt.MaxAge(time.Hour))
type SignOptionFunc func(*Claims)

// ApplyClaims implements the SignOption interface by calling the underlying function.
//
// This method enables SignOptionFunc to satisfy the SignOption interface by
// simply invoking the wrapped function with the provided Claims pointer.
// It provides the bridge between functional and interface-based SignOption usage.
//
// **Parameters**:
//   - c: Pointer to Claims struct to be modified by the function
//
// **Behavior**: Directly calls the wrapped function with the provided Claims
// pointer, delegating all claim modification logic to the function implementation.
//
// **Error Handling**: Since the SignOption interface doesn't support error
// returns, any error handling must be performed within the wrapped function,
// typically through logging or panic for critical failures.
//
// **Thread Safety**: The thread safety of this method depends entirely on
// the implementation of the wrapped function. Functions that only modify
// the provided Claims struct are generally safe.
//
// Example usage:
//
//	// The function is called automatically during token signing
//	customOption := jwt.SignOptionFunc(func(c *jwt.Claims) {
//	    c.Issuer = "myapp.com"
//	    c.Subject = "system"
//	})
//
//	// ApplyClaims is called internally by the Sign function
//	token, err := jwt.Sign(jwt.HS256, key, userClaims, customOption)
//
//	// Direct usage (rarely needed)
//	var claims jwt.Claims
//	customOption.ApplyClaims(&claims)
//	fmt.Printf("Issuer: %s", claims.Issuer) // Output: myapp.com
func (f SignOptionFunc) ApplyClaims(c *Claims) {
	f(c)
}
