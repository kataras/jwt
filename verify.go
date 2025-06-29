package jwt

import (
	"encoding/json"
	"errors"
)

// Verify validates and decodes a JWT token, returning verified token information.
//
// This is the primary function for JWT token verification. It performs signature
// validation, standard claims verification, and optional custom validation through
// TokenValidator implementations. The function ensures token integrity and validity.
//
// **Parameters**:
//   - alg: Algorithm used to sign the token (must match signing algorithm)
//   - key: Public key material for verification (corresponding to signing key)
//   - token: JWT token bytes to verify and decode
//   - validators: Optional TokenValidator implementations for custom validation
//
// **Verification Process**:
//  1. Token format validation (header.payload.signature structure)
//  2. Signature verification using algorithm and public key
//  3. Payload decoding and JSON parsing
//  4. Standard claims validation (exp, nbf, iat if present)
//  5. Custom validator execution (if provided)
//
// **Standard Claims Validation**: Automatically validates timing claims:
//   - "exp" (expiry): Ensures token hasn't expired
//   - "nbf" (not before): Ensures token is active
//   - "iat" (issued at): Ensures token wasn't issued in the future
//
// **Return Value**: VerifiedToken containing:
//   - Original token bytes
//   - Decoded header, payload, and signature
//   - Parsed standard claims
//   - Claims() method for custom claim extraction
//
// **Error Conditions**:
//   - Invalid token format or structure
//   - Signature verification failure
//   - Algorithm mismatch
//   - Standard claims validation failure (expired, not yet valid, etc.)
//   - Custom validator rejection
//
// **Security Features**:
//   - Cryptographic signature verification
//   - Timing-based access control
//   - Algorithm validation to prevent algorithm confusion attacks
//   - Extensible validation through TokenValidator interface
//
// Example usage:
//
//	// Basic token verification
//	verifiedToken, err := jwt.Verify(jwt.HS256, secretKey, tokenBytes)
//	if err != nil {
//	    log.Printf("Token verification failed: %v", err)
//	    return
//	}
//
//	// Access standard claims
//	fmt.Printf("Subject: %s", verifiedToken.StandardClaims.Subject)
//	fmt.Printf("Expires: %v", verifiedToken.StandardClaims.ExpiresAt())
//
//	// Extract custom claims
//	var customClaims struct {
//	    UserID   string   `json:"user_id"`
//	    Role     string   `json:"role"`
//	    Permissions []string `json:"permissions"`
//	}
//	err = verifiedToken.Claims(&customClaims)
//	if err != nil {
//	    log.Printf("Failed to parse custom claims: %v", err)
//	    return
//	}
//
//	// Using map for flexible claim access
//	var allClaims map[string]any
//	err = verifiedToken.Claims(&allClaims)
//	if err == nil {
//	    userID := allClaims["user_id"].(string)
//	    role := allClaims["role"].(string)
//	}
//
//	// With custom validators
//	verifiedToken, err := jwt.Verify(jwt.RS256, rsaPublicKey, tokenBytes,
//	    jwt.Expected{Issuer: "myapp.com"},
//	    jwt.Leeway(5 * time.Minute),
//	    customValidator)
//
// **Algorithm Support**: Works with all supported algorithms (HMAC, RSA, ECDSA, EdDSA).
// The key parameter type varies by algorithm family - use appropriate key type.
//
// See VerifyEncrypted for encrypted payload tokens and TokenValidator implementations
// for custom validation logic.
func Verify(alg Alg, key PublicKey, token []byte, validators ...TokenValidator) (*VerifiedToken, error) {
	return verifyToken(alg, key, nil, token, nil, validators...)
}

// VerifyEncrypted validates and decodes a JWT token with encrypted payload.
//
// This function extends Verify by adding payload decryption capability. It verifies
// the token signature and then decrypts the payload before parsing claims. This
// is used for tokens created with SignEncrypted that contain confidential data.
//
// **Parameters**:
//   - alg: Algorithm used to sign the token (must match signing algorithm)
//   - key: Public key material for signature verification
//   - decrypt: Function to decrypt the payload (see InjectFunc)
//   - token: JWT token bytes with encrypted payload to verify and decode
//   - validators: Optional TokenValidator implementations for custom validation
//
// **Verification and Decryption Process**:
//  1. Token format validation and signature verification
//  2. Payload base64url decoding
//  3. Payload decryption using the decrypt function
//  4. Decrypted payload JSON parsing
//  5. Standard claims validation and custom validator execution
//
// **InjectFunc Decryption**: The decrypt function receives []byte (base64-decoded
// encrypted payload) and returns []byte (decrypted JSON) and error. It's called
// after base64url decoding but before JSON unmarshaling.
//
// **Security Requirements**:
//   - Correct decryption key corresponding to encryption key used during signing
//   - Proper verification key corresponding to signing key
//   - Authenticated encryption recommended (see GCM function)
//   - Secure key management for both signing and encryption keys
//
// **Error Conditions**:
//   - All standard Verify errors (signature, format, timing)
//   - Decryption failures (wrong key, corrupted data, authentication failure)
//   - JSON parsing errors after decryption
//
// Example usage:
//
//	// Using AES-GCM encryption (see GCM function)
//	encryptKey := []byte("my-32-byte-encryption-key-here!")
//	encrypt, decrypt := jwt.GCM(encryptKey, nil)
//
//	// Verify encrypted token
//	verifiedToken, err := jwt.VerifyEncrypted(jwt.HS256, signingKey, decrypt, tokenBytes)
//	if err != nil {
//	    log.Printf("Token verification/decryption failed: %v", err)
//	    return
//	}
//
//	// Extract sensitive claims (now decrypted)
//	var sensitiveData struct {
//	    SSN         string `json:"ssn"`
//	    CreditCard  string `json:"credit_card"`
//	    BankAccount string `json:"bank_account"`
//	    UserID      string `json:"user_id"`
//	}
//	err = verifiedToken.Claims(&sensitiveData)
//
//	// Custom decryption function
//	customDecrypt := func(encrypted []byte) ([]byte, error) {
//	    // Your custom decryption logic here
//	    return decryptedJSON, nil
//	}
//
//	verifiedToken, err := jwt.VerifyEncrypted(jwt.RS256, rsaPublicKey,
//	    customDecrypt, tokenBytes, jwt.Expected{Issuer: "secure-service"})
//
//	// With multiple validators for encrypted tokens
//	verifiedToken, err := jwt.VerifyEncrypted(jwt.ES256, ecdsaPublicKey, decrypt,
//	    encryptedToken,
//	    jwt.Leeway(time.Minute),
//	    jwt.Blocklist(revokedTokens),
//	    customSecurityValidator)
//
// **Important Notes**:
//   - Tokens created with SignEncrypted MUST be verified with VerifyEncrypted
//   - The decrypt function must use the same algorithm and key as encryption
//   - Decryption errors are treated as verification failures
//   - Standard claims validation occurs after successful decryption
//
// **Performance Considerations**:
//   - Decryption adds computational overhead compared to standard verification
//   - Use appropriate encryption algorithms for your performance requirements
//   - Consider caching decrypted results for frequently accessed tokens
//
// See GCM for authenticated encryption, SignEncrypted for creating encrypted tokens,
// and Verify for standard (non-encrypted) token verification.
func VerifyEncrypted(alg Alg, key PublicKey, decrypt InjectFunc, token []byte, validators ...TokenValidator) (*VerifiedToken, error) {
	return verifyToken(alg, key, decrypt, token, nil, validators...)
}

// VerifyWithHeaderValidator validates a JWT token with custom header validation.
//
// This function extends Verify by adding custom header validation capability.
// It allows validation of JWT header fields beyond the standard "alg" and "typ"
// fields, enabling verification of custom header claims like "kid", "jku", etc.
//
// **Parameters**:
//   - alg: Algorithm used to sign the token (must match signing algorithm)
//   - key: Public key material for signature verification
//   - token: JWT token bytes to verify and decode
//   - headerValidator: Custom validator for JWT header fields
//   - validators: Optional TokenValidator implementations for payload validation
//
// **Header Validation Process**:
//  1. Token format validation and header decoding
//  2. Custom header validation using headerValidator
//  3. Standard signature verification
//  4. Payload processing and claims validation
//  5. Custom payload validator execution
//
// **HeaderValidator Interface**: The headerValidator receives the decoded header
// as a map[string]any and returns an error if validation fails. This allows
// custom logic for validating header fields.
//
// **Common Header Validation Use Cases**:
//   - "kid" (Key ID): Validate key identifier matches expected values
//   - "jku" (JWK Set URL): Verify JWK Set URL is from trusted domain
//   - "x5t" (X.509 Thumbprint): Validate certificate thumbprint
//   - "cty" (Content Type): Ensure correct content type
//   - Custom fields: Application-specific header validation
//
// **Security Benefits**:
//   - Prevents use of tokens with invalid or malicious headers
//   - Enables key rotation validation through "kid" checks
//   - Supports certificate-based validation
//   - Allows whitelist/blacklist validation of header values
//
// Example usage:
//
//	// Validate key identifier
//	keyIDValidator := func(header map[string]any) error {
//	    kid, ok := header["kid"].(string)
//	    if !ok {
//	        return errors.New("missing kid header")
//	    }
//	    if !isValidKeyID(kid) {
//	        return errors.New("invalid key identifier")
//	    }
//	    return nil
//	}
//
//	verifiedToken, err := jwt.VerifyWithHeaderValidator(jwt.RS256, rsaKey,
//	    tokenBytes, keyIDValidator)
//
//	// Validate JWK Set URL
//	jkuValidator := func(header map[string]any) error {
//	    jku, ok := header["jku"].(string)
//	    if ok && !strings.HasPrefix(jku, "https://trusted.domain.com/") {
//	        return errors.New("untrusted JWK Set URL")
//	    }
//	    return nil
//	}
//
//	// Combined header and payload validation
//	verifiedToken, err := jwt.VerifyWithHeaderValidator(jwt.ES256, ecdsaKey,
//	    tokenBytes, jkuValidator,
//	    jwt.Expected{Issuer: "trusted-issuer"},
//	    jwt.Leeway(time.Minute))
//
//	// Multiple header field validation
//	multiHeaderValidator := func(header map[string]any) error {
//	    // Validate key ID
//	    if kid, ok := header["kid"].(string); ok {
//	        if !isValidKeyID(kid) {
//	            return errors.New("invalid key ID")
//	        }
//	    }
//
//	    // Validate content type
//	    if cty, ok := header["cty"].(string); ok {
//	        if cty != "application/json" {
//	            return errors.New("unsupported content type")
//	        }
//	    }
//
//	    return nil
//	}
//
//	verifiedToken, err := jwt.VerifyWithHeaderValidator(jwt.HS256, hmacKey,
//	    tokenBytes, multiHeaderValidator)
//
// **Error Conditions**:
//   - All standard Verify errors
//   - Header validation failures from headerValidator
//   - Missing or invalid header fields
//
// **Performance Note**: Header validation adds minimal overhead as it operates
// on the already-decoded header data.
//
// See HeaderValidator type definition and VerifyEncryptedWithHeaderValidator
// for encrypted payload tokens with header validation.
func VerifyWithHeaderValidator(alg Alg, key PublicKey, token []byte, headerValidator HeaderValidator, validators ...TokenValidator) (*VerifiedToken, error) {
	return verifyToken(alg, key, nil, token, headerValidator, validators...)
}

// VerifyEncryptedWithHeaderValidator validates a JWT token with encrypted payload and custom header validation.
//
// This function combines the functionality of VerifyEncrypted and VerifyWithHeaderValidator,
// providing both payload decryption and custom header validation in a single operation.
// It's ideal for scenarios requiring both payload confidentiality and header metadata validation.
//
// **Parameters**:
//   - alg: Algorithm used to sign the token (must match signing algorithm)
//   - key: Public key material for signature verification
//   - decrypt: Function to decrypt the payload (see InjectFunc)
//   - token: JWT token bytes with encrypted payload to verify and decode
//   - headerValidator: Custom validator for JWT header fields
//   - validators: Optional TokenValidator implementations for payload validation
//
// **Processing Order**:
//  1. Token format validation and header decoding
//  2. Custom header validation using headerValidator
//  3. Signature verification using algorithm and key
//  4. Payload base64url decoding and decryption
//  5. Standard claims validation and custom validator execution
//
// **Combined Benefits**:
//   - Header metadata validation for token identification and routing
//   - Payload confidentiality through decryption
//   - Standard claims validation after decryption
//   - Complete JWT security verification workflow
//
// **Security Considerations**:
//   - Headers remain unencrypted and are validated before payload processing
//   - Payload is encrypted and requires correct decryption function
//   - Both header and payload validation must pass for successful verification
//   - Multiple layers of validation provide defense in depth
//
// **Use Cases**:
//   - Multi-tenant systems with encrypted user data and tenant header validation
//   - Key rotation systems requiring both key ID validation and payload decryption
//   - Content-type validation with encrypted sensitive data
//   - Certificate-based systems with encrypted payloads
//
// Example usage:
//
//	// Multi-tenant encrypted token with header validation
//	encryptKey := []byte("tenant-specific-encryption-key!")
//	encrypt, decrypt := jwt.GCM(encryptKey, nil)
//
//	tenantValidator := func(header map[string]any) error {
//	    kid, ok := header["kid"].(string)
//	    if !ok {
//	        return errors.New("missing key ID in header")
//	    }
//
//	    tenantID, ok := header["tenant_id"].(string)
//	    if !ok || !isValidTenant(tenantID) {
//	        return errors.New("invalid tenant ID")
//	    }
//
//	    if !isValidKeyForTenant(kid, tenantID) {
//	        return errors.New("key ID not valid for tenant")
//	    }
//
//	    return nil
//	}
//
//	verifiedToken, err := jwt.VerifyEncryptedWithHeaderValidator(
//	    jwt.RS256, rsaKey, decrypt, tokenBytes, tenantValidator,
//	    jwt.Expected{Issuer: "tenant-service"})
//
//	// Certificate-based validation with encrypted payload
//	certValidator := func(header map[string]any) error {
//	    x5t, ok := header["x5t"].(string)
//	    if ok && !isValidCertThumbprint(x5t) {
//	        return errors.New("invalid certificate thumbprint")
//	    }
//
//	    jku, ok := header["jku"].(string)
//	    if ok && !strings.HasPrefix(jku, "https://trusted.certs.com/") {
//	        return errors.New("untrusted certificate URL")
//	    }
//
//	    return nil
//	}
//
//	verifiedToken, err := jwt.VerifyEncryptedWithHeaderValidator(
//	    jwt.ES256, ecdsaKey, decrypt, encryptedToken, certValidator,
//	    jwt.Leeway(time.Minute),
//	    jwt.Blocklist(revokedTokens))
//
//	// Extract decrypted sensitive data after all validation
//	var sensitiveData struct {
//	    PersonalInfo map[string]any `json:"personal_info"`
//	    Financial    map[string]any `json:"financial"`
//	}
//	err = verifiedToken.Claims(&sensitiveData)
//
// **Error Conditions**:
//   - All standard Verify and VerifyEncrypted errors
//   - Header validation failures from headerValidator
//   - Decryption failures (wrong key, corrupted data)
//   - Missing or invalid header fields
//
// **Performance Considerations**:
//   - Header validation occurs before expensive decryption operations
//   - Early header rejection can save computational resources
//   - Combine validation checks efficiently in headerValidator function
//
// See HeaderValidator for header validation patterns, GCM for authenticated
// encryption, and VerifyEncrypted for encrypted-only token verification.
func VerifyEncryptedWithHeaderValidator(alg Alg, key PublicKey, decrypt InjectFunc, token []byte, headerValidator HeaderValidator, validators ...TokenValidator) (*VerifiedToken, error) {
	return verifyToken(alg, key, decrypt, token, headerValidator, validators...)
}

// verifyToken is the internal token verification function used by all Verify variants.
//
// This function implements the core JWT token verification logic, handling signature
// validation, optional payload decryption, claims parsing, and custom validation.
// It serves as the common implementation for all public Verify* functions.
//
// **Parameters**:
//   - alg: Cryptographic algorithm for signature verification
//   - key: Public key material for the specified algorithm
//   - decrypt: Optional decryption function for payload (nil for no decryption)
//   - token: JWT token bytes to verify
//   - headerValidator: Optional custom header validator (nil for no header validation)
//   - validators: TokenValidator slice for custom validation logic
//
// **Processing Pipeline**:
//  1. Empty token check (returns ErrMissing if empty)
//  2. Token decoding and signature verification via decodeToken
//  3. Optional payload decryption using decrypt function
//  4. Claims parsing with fallback handling for non-JSON payloads
//  5. Standard claims validation (timing claims)
//  6. Custom validator execution with early termination on failure
//  7. VerifiedToken construction and return
//
// **Claims Parsing Strategy**:
//   - Primary attempt: Direct unmarshaling to Claims struct
//   - Fallback: Uses claimsSecondChance for flexible type handling
//   - Error handling: Sets errPayloadNotJSON for non-JSON payloads
//   - Validator compatibility: Allows validators to handle JSON errors
//
// **Validator Processing**:
//   - Processes validators in order until first failure
//   - Each validator receives: token bytes, parsed claims, and any previous error
//   - Validators can override previous errors by returning nil
//   - Early termination on validator failure for efficiency
//
// **Error Handling Strategy**:
//   - JSON parsing errors are preserved for validator inspection
//   - Standard claims validation only proceeds without JSON errors
//   - Validator errors override standard validation errors
//   - Comprehensive error propagation maintains context
//
// **Internal Usage**: This function is not exported and serves as the
// implementation detail for all public Verify* functions. It provides
// consistency across verification variants while allowing specific
// customizations through parameters.
//
// **Performance Optimizations**:
//   - Early termination on empty tokens
//   - Conditional decryption only when needed
//   - Fallback claims parsing for compatibility
//   - Short-circuit validator processing on errors
func verifyToken(alg Alg, key PublicKey, decrypt InjectFunc, token []byte, headerValidator HeaderValidator, validators ...TokenValidator) (*VerifiedToken, error) {
	if len(token) == 0 {
		return nil, ErrMissing
	}

	header, payload, signature, err := decodeToken(alg, key, token, headerValidator)
	if err != nil {
		return nil, err
	}

	if decrypt != nil {
		payload, err = decrypt(payload)
		if err != nil {
			return nil, err
		}
	}

	var standardClaims Claims
	standardClaimsErr := json.Unmarshal(payload, &standardClaims) // Use the standard one instead of the custom, no need to support "required" feature here.
	// Do not exist on this error now, the payload may not be a JSON one.
	if standardClaimsErr != nil {
		var secondChange claimsSecondChance // try again with a different structure, which always converted to the standard jwt claims.
		if err = json.Unmarshal(payload, &secondChange); err != nil {
			err = errPayloadNotJSON // allow validators to catch this error.
		}

		standardClaims = secondChange.toClaims()
	}

	if err != nil { // do not proceed if we have a JSON error.
		err = validateClaims(Clock(), standardClaims)
	}

	for _, validator := range validators {
		// A token validator can skip the builtin validation and return a nil error,
		// in that case the previous error is skipped.
		if err = validator.ValidateToken(token, standardClaims, err); err != nil {
			break
		}
	}

	if err != nil {
		// Exit on parsing standard claims error(when Plain is missing) or standard claims validation error or custom validators.
		return nil, err
	}

	verifiedTok := &VerifiedToken{
		Token:          token,
		Header:         header,
		Payload:        payload,
		Signature:      signature,
		StandardClaims: standardClaims,
		// We could store the standard claims error when Plain token validator is applied
		// but there is no a single case of its usability, so we don't, unless is requested.
	}
	return verifiedTok, nil
}

// VerifiedToken contains the results of successful JWT token verification.
//
// This structure holds all the decoded components of a verified JWT token,
// providing access to both the raw token data and parsed standard claims.
// It serves as the return value for all successful token verification operations.
//
// **Field Details**:
//   - Token: Original token bytes as provided to verification functions
//   - Header: Decoded JWT header (base64url decoded JSON)
//   - Payload: Decoded JWT payload (base64url decoded, possibly decrypted JSON)
//   - Signature: Decoded JWT signature bytes (base64url decoded)
//   - StandardClaims: Parsed standard JWT claims (exp, nbf, iat, iss, sub, aud, jti)
//
// **Security Assurance**: The presence of a VerifiedToken instance guarantees:
//   - Signature has been cryptographically verified
//   - Token format is valid (header.payload.signature)
//   - Standard claims have passed timing validation
//   - Any provided custom validators have approved the token
//   - Optional header validation has passed (if HeaderValidator was used)
//   - Optional payload decryption was successful (if decrypt function was used)
//
// **Usage Patterns**:
//   - Access standard claims directly via StandardClaims field
//   - Extract custom claims using the Claims() method
//   - Inspect raw token components for debugging or logging
//   - Pass to other functions requiring verified token context
//
// **Thread Safety**: VerifiedToken instances are safe for concurrent read access
// once created, as all fields are populated during verification and not modified.
//
// Example usage:
//
//	verifiedToken, err := jwt.Verify(jwt.HS256, secretKey, tokenBytes)
//	if err != nil {
//	    log.Printf("Verification failed: %v", err)
//	    return
//	}
//
//	// Access standard claims directly
//	subject := verifiedToken.StandardClaims.Subject
//	issuer := verifiedToken.StandardClaims.Issuer
//	expiresAt := verifiedToken.StandardClaims.ExpiresAt()
//
//	// Check if token is near expiration
//	timeLeft := verifiedToken.StandardClaims.Timeleft()
//	if timeLeft < 5*time.Minute {
//	    log.Printf("Token expires soon: %v remaining", timeLeft)
//	}
//
//	// Extract custom claims
//	var userClaims struct {
//	    UserID      string   `json:"user_id"`
//	    Role        string   `json:"role"`
//	    Permissions []string `json:"permissions"`
//	}
//	err = verifiedToken.Claims(&userClaims)
//	if err != nil {
//	    log.Printf("Failed to parse custom claims: %v", err)
//	}
//
//	// Access raw components for logging
//	log.Printf("Verified token: %s", string(verifiedToken.Token))
//	log.Printf("Header: %s", string(verifiedToken.Header))
//	log.Printf("Payload: %s", string(verifiedToken.Payload))
//
// **Memory Considerations**: VerifiedToken holds references to the decoded
// token components. For high-throughput applications, consider extracting
// needed claims and discarding the VerifiedToken to free memory.
type VerifiedToken struct {
	// Token contains the original JWT token bytes as provided to verification functions.
	// This is useful for logging, passing to other services, or debugging purposes.
	Token []byte

	// Header contains the decoded JWT header as raw JSON bytes.
	// The header includes algorithm information and any custom header fields.
	Header []byte

	// Payload contains the decoded JWT payload as raw JSON bytes.
	// For encrypted tokens, this contains the decrypted payload.
	// Use the Claims() method to parse this into structured data.
	Payload []byte

	// Signature contains the decoded JWT signature bytes.
	// This is the raw signature that was cryptographically verified.
	Signature []byte

	// StandardClaims contains parsed standard JWT claims extracted from the payload.
	// These claims have been validated during the verification process.
	// Includes: exp, nbf, iat, iss, sub, aud, jti, and origin_jti.
	StandardClaims Claims
}

// Claims extracts and unmarshals the token's payload into the provided destination.
//
// This method is the primary way to access custom claims from a verified JWT token.
// It unmarshals the token's payload (claims) into the destination pointer, allowing
// access to application-specific data beyond the standard JWT claims.
//
// **Parameters**:
//   - dest: Pointer to destination struct, map, or any JSON-unmarshallable type
//
// **Supported Destination Types**:
//   - Struct with JSON tags: For type-safe custom claim extraction
//   - map[string]any: For flexible dynamic claim access
//   - Custom types implementing json.Unmarshaler
//   - Any pointer to JSON-compatible Go types
//
// **JSON Unmarshaling**: Uses the package-level Unmarshal function, which
// respects the configured JSON unmarshaling behavior and any custom unmarshalers.
//
// **Standard Claims**: The StandardClaims field is always populated and validated
// during verification. No additional validation is needed for standard timing
// claims (exp, nbf, iat) as they are automatically verified.
//
// **Performance Note**: This method performs JSON unmarshaling on each call.
// For frequently accessed claims, consider unmarshaling once and caching the result.
//
// **Error Conditions**:
//   - JSON unmarshaling errors (invalid JSON, type mismatches)
//   - Destination is not a pointer
//   - Incompatible types between JSON and destination
//
// Example usage:
//
//	verifiedToken, err := jwt.Verify(jwt.HS256, secretKey, tokenBytes)
//	if err != nil {
//	    return err
//	}
//
//	// Extract to custom struct
//	var userClaims struct {
//	    UserID      string   `json:"user_id"`
//	    Role        string   `json:"role"`
//	    Permissions []string `json:"permissions"`
//	    Email       string   `json:"email"`
//	}
//	err = verifiedToken.Claims(&userClaims)
//	if err != nil {
//	    return fmt.Errorf("failed to parse user claims: %w", err)
//	}
//
//	// Extract to map for dynamic access
//	var allClaims map[string]any
//	err = verifiedToken.Claims(&allClaims)
//	if err != nil {
//	    return err
//	}
//
//	// Access claims dynamically
//	if userID, ok := allClaims["user_id"].(string); ok {
//	    log.Printf("User ID: %s", userID)
//	}
//
//	// Combine with standard claims
//	log.Printf("User %s (%s) expires at %v",
//	    userClaims.UserID,
//	    userClaims.Role,
//	    verifiedToken.StandardClaims.ExpiresAt())
//
//	// Extract partial claims
//	var roleInfo struct {
//	    Role        string   `json:"role"`
//	    Permissions []string `json:"permissions"`
//	}
//	err = verifiedToken.Claims(&roleInfo)
//
//	// Type assertion for specific claim types
//	var metadata struct {
//	    CreatedAt time.Time `json:"created_at"`
//	    UpdatedAt time.Time `json:"updated_at"`
//	    Version   int       `json:"version"`
//	}
//	err = verifiedToken.Claims(&metadata)
//
// **Best Practices**:
//   - Use struct types for known claim schemas (type safety)
//   - Use maps for dynamic or unknown claim structures
//   - Handle unmarshaling errors appropriately
//   - Consider caching unmarshaled results for repeated access
//   - Validate custom claims as needed (standard claims are pre-validated)
func (t *VerifiedToken) Claims(dest any) error {
	return Unmarshal(t.Payload, dest)
}

// errPayloadNotJSON indicates that a JWT payload is not valid JSON.
//
// This error is used internally during token verification when the payload
// cannot be parsed as JSON. It can occur with malformed JSON or when the
// payload contains non-JSON data (e.g., plain text, binary data).
//
// **Common Causes**:
//   - Corrupted token payload during transmission
//   - Intentionally non-JSON payloads (e.g., plain text tokens)
//   - Encryption/decryption errors resulting in malformed data
//   - Custom token formats that don't use JSON payloads
//
// **Handling**: This error can be caught by TokenValidator implementations
// to allow non-JSON payloads. The Plain validator specifically handles this
// error to enable verification of tokens with non-JSON payloads.
//
// **Internal Usage**: This error is set during the claims parsing phase
// of token verification when JSON unmarshaling fails. Validators can
// inspect and potentially override this error.
var errPayloadNotJSON = errors.New("jwt: payload is not a type of JSON") // malformed JSON or it's not a JSON at all.

// Plain is a TokenValidator that allows verification of tokens with non-JSON payloads.
//
// This validator enables successful verification of JWT tokens that contain
// plain text or other non-JSON data in their payload. It works by catching
// and ignoring the errPayloadNotJSON error that would normally cause
// verification to fail.
//
// **Use Cases**:
//   - Legacy tokens with plain text payloads
//   - Simple tokens without structured claims
//   - Custom token formats that don't use JSON
//   - Debugging and testing with malformed tokens
//   - Integration with non-standard JWT implementations
//
// **Behavior**: When errPayloadNotJSON occurs during verification, this
// validator returns nil (success) instead of the error, allowing the
// verification process to continue. All other errors are passed through
// unchanged.
//
// **Payload Access**: With Plain validator, the raw payload bytes can be
// accessed via VerifiedToken.Payload field, but the Claims() method will
// likely fail since the payload is not JSON.
//
// **Security Considerations**:
//   - Standard claims validation (exp, nbf, iat) is bypassed for non-JSON payloads
//   - Application must implement custom validation for plain payloads
//   - Signature verification still occurs normally
//   - Use only when non-JSON payloads are expected and acceptable
//
// Example usage:
//
//	// Verify token that may have plain text payload
//	verifiedToken, err := jwt.Verify(jwt.HS256, secretKey, tokenBytes, jwt.Plain)
//	if err != nil {
//	    log.Printf("Verification failed: %v", err)
//	    return
//	}
//
//	// Access raw payload (likely plain text)
//	payloadText := string(verifiedToken.Payload)
//	log.Printf("Plain payload: %s", payloadText)
//
//	// Standard claims will be empty for non-JSON payloads
//	log.Printf("Subject: %s", verifiedToken.StandardClaims.Subject) // Will be empty
//
//	// Custom payload validation
//	if !isValidPlainPayload(payloadText) {
//	    return errors.New("invalid plain payload content")
//	}
//
//	// Combined with other validators (Plain should come last)
//	verifiedToken, err := jwt.Verify(jwt.HS256, secretKey, tokenBytes,
//	    customHeaderValidator,
//	    jwt.Plain) // Plain overrides JSON errors
//
// **Validator Order**: When using Plain with other validators, place it last
// in the validator list so it can catch JSON errors that other validators
// might depend on.
var Plain = TokenValidatorFunc(func(token []byte, standardClaims Claims, err error) error {
	if err == errPayloadNotJSON {
		return nil // skip this error entirely.
	}

	return err
})

type (
	// TokenValidator provides further token and claims validation.
	TokenValidator interface {
		// ValidateToken accepts the token, the claims extracted from that
		// and any error that may caused by claims validation (e.g. ErrExpired)
		// or the previous validator.
		// A token validator can skip the builtin validation and return a nil error.
		// Usage:
		//  func(v *myValidator) ValidateToken(token []byte, standardClaims Claims, err error) error {
		//    if err!=nil { return err } <- to respect the previous error
		//    // otherwise return nil or any custom error.
		//  }
		//
		// Look `Blocklist`, `Expected` and `Leeway` for builtin implementations.
		ValidateToken(token []byte, standardClaims Claims, err error) error
	}

	// TokenValidatorFunc is the interface-as-function shortcut for a TokenValidator.
	TokenValidatorFunc func(token []byte, standardClaims Claims, err error) error
)

// ValidateToken completes the ValidateToken interface.
// It calls itself.
func (fn TokenValidatorFunc) ValidateToken(token []byte, standardClaims Claims, err error) error {
	return fn(token, standardClaims, err)
}
