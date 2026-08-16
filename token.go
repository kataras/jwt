package jwt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

var (
	// ErrMissing indicates that a JWT token is empty or nil when passed to verification functions.
	// This error occurs when attempting to verify a token that has no content, preventing
	// any meaningful validation or parsing operations.
	//
	// Common scenarios that trigger this error:
	//   - Passing nil or empty byte slice to Verify functions
	//   - Missing Authorization header in HTTP requests
	//   - Empty token strings after extraction from requests
	//
	// Example:
	//   err := jwt.Verify(jwt.HS256, hmacKey, nil, &claims)
	//   // Returns: ErrMissing
	ErrMissing = errors.New("jwt: token is empty")

	// ErrTokenForm indicates that a JWT token does not have the expected three-part structure.
	// Valid JWT tokens must follow the format: header.payload.signature (exactly three parts
	// separated by dots). This error occurs during token parsing when the structure is malformed.
	//
	// Common causes:
	//   - Truncated tokens missing parts (e.g., "header.payload")
	//   - Extra dots creating more than three parts
	//   - Completely malformed token strings
	//   - Binary data passed instead of base64-encoded JWT
	//
	// Example of invalid tokens:
	//   "header.payload"           // Missing signature
	//   "header.payload.sig.extra" // Too many parts
	//   "invalid-token-format"     // Wrong structure
	ErrTokenForm = errors.New("jwt: invalid token form")

	// ErrTokenAlg indicates an algorithm mismatch between the expected algorithm and
	// the algorithm specified in the JWT header. This is a critical security validation
	// that prevents algorithm substitution attacks.
	//
	// This error occurs when:
	//   - Token header "alg" field doesn't match the verification algorithm
	//   - Header structure is malformed or unexpected
	//   - Algorithm field ordering differs from standard format
	//   - Header contains unsupported or unknown algorithm names
	//
	// Security note: This validation is essential to prevent attacks where
	// malicious tokens specify weaker algorithms than expected.
	//
	// Example:
	//   // Token header: {"alg":"HS256","typ":"JWT"}
	//   // But verifying with: jwt.Verify(jwt.RS256, ...)
	//   // Returns: ErrTokenAlg
	ErrTokenAlg = errors.New("jwt: unexpected token algorithm")

	// ErrTokenSize indicates that a token is longer than MaxTokenSize.
	//
	// Verification allocates in proportion to the token it is handed, and that token
	// arrives from whoever is calling. Without a ceiling, one unauthenticated request can
	// ask the process for as much memory as it can send.
	ErrTokenSize = errors.New("jwt: token is too large")
)

// MaxTokenSize is the largest token, in bytes, that Decode and the Verify family will
// look at. Anything longer is refused with ErrTokenSize before it is parsed.
//
// The default of 64 KB is far above any ordinary token. A JWT holding a handful of claims
// is a few hundred bytes; one carrying a certificate chain in its header might reach a few
// kilobytes. Raise it if you have a genuine reason, and lower it if you know your own
// tokens are small:
//
//	jwt.MaxTokenSize = 8 * 1024
//
// Set it during startup, before any concurrent verification. It is read without a lock.
var MaxTokenSize = 64 * 1024

type (
	// PrivateKey represents any private key type used for JWT token signing operations.
	//
	// This generic type alias allows the JWT library to work with various cryptographic
	// private key types without requiring specific type assertions in user code.
	// The actual key type depends on the algorithm being used:
	//
	// Supported private key types by algorithm:
	//   - HMAC (HS256/384/512): []byte (shared secret)
	//   - RSA (RS256/384/512, PS256/384/512): *rsa.PrivateKey
	//   - ECDSA (ES256/384/512): *ecdsa.PrivateKey
	//   - EdDSA: ed25519.PrivateKey
	//
	// The key must match the algorithm being used for signing, otherwise
	// the Sign operation will fail with type assertion errors.
	//
	// Example usage:
	//   var hmacKey PrivateKey = []byte("secret-key")
	//   var rsaKey PrivateKey = rsaPrivateKey
	//   var ecKey PrivateKey = ecdsaPrivateKey
	PrivateKey = any

	// PublicKey represents any public key type used for JWT token verification operations.
	//
	// This generic type alias allows the JWT library to work with various cryptographic
	// public key types without requiring specific type assertions in user code.
	// The actual key type depends on the algorithm being used:
	//
	// Supported public key types by algorithm:
	//   - HMAC (HS256/384/512): []byte (same shared secret as private key)
	//   - RSA (RS256/384/512, PS256/384/512): *rsa.PublicKey
	//   - ECDSA (ES256/384/512): *ecdsa.PublicKey
	//   - EdDSA: ed25519.PublicKey
	//
	// For symmetric algorithms (HMAC), the public key is the same as the private key.
	// For asymmetric algorithms, use the corresponding public key extracted from
	// the private key or loaded from external sources.
	//
	// Example usage:
	//   var hmacKey PublicKey = []byte("secret-key")      // Same as private
	//   var rsaKey PublicKey = &rsaPrivateKey.PublicKey   // Extract from private
	//   var ecKey PublicKey = &ecdsaPrivateKey.PublicKey  // Extract from private
	PublicKey = any
)

func encodeToken(alg Alg, key PrivateKey, payload []byte, customHeader any) ([]byte, error) {
	if err := checkAlgName(alg.Name()); err != nil {
		return nil, err
	}

	var header []byte
	if customHeader != nil {
		h, err := createCustomHeader(customHeader)
		if err != nil {
			return nil, err
		}
		header = h
	} else {
		header = createHeader(alg.Name())
	}

	payload = Base64Encode(payload)

	headerPayload := joinParts(header, payload)

	signature, err := createSignature(alg, key, headerPayload)
	if err != nil {
		return nil, fmt.Errorf("encodeToken: signature: %w", err)
	}

	// header.payload.signature
	token := joinParts(headerPayload, signature)

	return token, nil
}

// We could omit the "alg" because the token contains it
// BUT, for security reason the algorithm MUST explicitly match
// (even if we perform hash comparison later on).
//
// If the "compareHeaderFunc" is nil then it compares using the `CompareHeader` package-level function variable.
//
// Decodes and verifies the given compact "token".
// It returns the header, payoad and signature parts (decoded).
func decodeToken(alg Alg, key PublicKey, token []byte, compareHeaderFunc HeaderValidator) ([]byte, []byte, []byte, error) {
	if len(token) > MaxTokenSize {
		return nil, nil, nil, ErrTokenSize
	}

	parts := bytes.Split(token, sep)
	if len(parts) != 3 {
		return nil, nil, nil, ErrTokenForm
	}

	header := parts[0]
	payload := parts[1]
	signature := parts[2]

	headerDecoded, err := Base64Decode(header)
	if err != nil {
		return nil, nil, nil, err
	}

	// validate header equality.
	if compareHeaderFunc == nil {
		compareHeaderFunc = CompareHeader
	}

	// algorithm can be specified hard-coded
	// or extracted per token if a custom header validator given.
	algName := ""
	if alg != nil {
		algName = alg.Name()
	}

	dynamicAlg, pubKey, decrypt, err := compareHeaderFunc(algName, headerDecoded)
	if err != nil {
		return nil, nil, nil, err
	}

	if alg == nil {
		alg = dynamicAlg
	}

	// A HeaderValidator is allowed to return a nil Alg, meaning "use the one the caller
	// passed". If the caller passed nil too then nothing names an algorithm, and the
	// signature check below would panic on a nil interface.
	if alg == nil {
		return nil, nil, nil, ErrTokenAlg
	}

	// Override the key given, which could be a nil if this "pubKey" always expected on success.
	if pubKey != nil {
		key = pubKey
	}

	signatureDecoded, err := Base64Decode(signature)
	if err != nil {
		return nil, nil, nil, err
	}
	// validate signature.
	headerPayload := joinParts(header, payload)
	if err := alg.Verify(key, headerPayload, signatureDecoded); err != nil {
		return nil, nil, nil, err
	}

	payload, err = Base64Decode(payload)
	if err != nil {
		return nil, nil, nil, err
	}

	if decrypt != nil {
		payload, err = decrypt(payload)
		if err != nil {
			return nil, nil, nil, err
		}
	}

	return headerDecoded, payload, signatureDecoded, nil
}

var (
	sep = []byte(".")
	// padStr is the base64 padding character. Base64Encode trims it and Base64Decode
	// trims it again on the way back, because a JWT segment carries no padding.
	padStr = "="
)

func joinParts(parts ...[]byte) []byte {
	return bytes.Join(parts, sep)
}

// A builtin list of fixed headers for builtin algorithms (to boost the performance a bit).
// key = alg, value = the base64encoded full header
// (when kid or any other extra headers are not required to be inside).
type fixedHeader struct {
	// the json raw byte value.
	raw []byte
	// the base64 encoded value of raw.
	encoded []byte
	// same as raw but reversed order, e.g. first type then alg.
	// Useful to validate external jwt tokens that are not using the standard form order.
	reversed []byte
}

var fixedHeaders = make(map[string]*fixedHeader, len(allAlgs))

func init() {
	for _, alg := range allAlgs {
		k := alg.Name()

		fixedHeaders[k] = &fixedHeader{
			raw:      createHeaderRaw(k),
			encoded:  createHeader(k),
			reversed: createHeaderReversed(k),
		}
	}
}

func createHeader(alg string) []byte {
	if header := fixedHeaders[alg]; header != nil {
		return header.encoded
	}

	return Base64Encode([]byte(`{"alg":"` + alg + `","typ":"JWT"}`))
}

// checkAlgName reports whether an algorithm name can be placed into a header literal.
//
// The header is built by concatenation, so nothing escapes the name on the way in. The
// built-in algorithms are fine, but Alg is an exported interface, and a third-party
// implementation returning a name containing a quote could add header fields of its own
// choosing to a token signed with somebody else's key.
//
// The rule is the character set JWA actually uses for algorithm names, not an allowlist of
// the built-in ones, so a custom algorithm with a sensible name still works.
func checkAlgName(name string) error {
	if name == "" || len(name) > 64 {
		return fmt.Errorf("%w: algorithm name must be between 1 and 64 characters", ErrTokenAlg)
	}

	for _, c := range name {
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		case c == '-' || c == '+' || c == '.' || c == '_':
		default:
			return fmt.Errorf("%w: algorithm name contains %q", ErrTokenAlg, c)
		}
	}

	return nil
}

func createCustomHeader(header any) ([]byte, error) {
	b, err := Marshal(header)
	if err != nil {
		return nil, err
	}

	return Base64Encode(b), nil
}

func createHeaderRaw(alg string) []byte {
	if header := fixedHeaders[alg]; header != nil {
		return header.raw
	}

	return []byte(`{"alg":"` + alg + `","typ":"JWT"}`)
}

func createHeaderReversed(alg string) []byte {
	if header := fixedHeaders[alg]; header != nil {
		return header.reversed
	}

	return []byte(`{"typ":"JWT","alg":"` + alg + `"}`)
}

func createHeaderWithoutTyp(alg string) []byte {
	return []byte(`{"alg":"` + alg + `"}`)
}

// HeaderValidator defines a function type for custom JWT header validation logic.
//
// This interface enables sophisticated header validation beyond simple algorithm checking,
// including multi-key scenarios, dynamic algorithm selection, and custom header fields.
// It's the foundation for advanced JWT verification patterns like JWKS integration
// and multi-tenant key management.
//
// Function signature parameters:
//   - alg: Expected algorithm name (empty string allows dynamic algorithm selection)
//   - headerDecoded: Raw JSON bytes of the decoded JWT header
//
// Return values:
//   - Alg: Algorithm implementation to use for verification (nil uses the provided alg)
//   - PublicKey: Public key for verification (nil uses the key passed to Verify)
//   - InjectFunc: Optional payload decryption function (nil skips decryption)
//   - error: Validation error (non-nil indicates header rejection)
//
// Behavior and usage patterns:
//
//  1. Algorithm Validation: When alg is provided, validate that the header
//     contains the expected algorithm. When alg is empty, extract and return
//     the algorithm from the header for dynamic selection.
//
//  2. Key Selection: Return a non-nil PublicKey to override the key passed
//     to the Verify function. This enables multi-key scenarios where the key
//     is selected based on header content (e.g., "kid" field).
//
//  3. Payload Decryption: Return a non-nil InjectFunc to enable automatic
//     payload decryption using AES-GCM before signature verification.
//
//  4. Error Handling: Return an error for any validation failure, including
//     unknown algorithms, missing required fields, or security violations.
//
// Common implementations:
//   - CompareHeader: Default implementation for basic algorithm validation
//   - Keys.ValidateHeader: Multi-key validation using Key ID from header
//   - Custom validators for JWKS integration or tenant-specific logic
//
// Example custom validator:
//
//	func MyHeaderValidator(alg string, headerDecoded []byte) (jwt.Alg, jwt.PublicKey, jwt.InjectFunc, error) {
//	    var header struct {
//	        Alg string `json:"alg"`
//	        Kid string `json:"kid"`
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
//	    // Select key based on Key ID
//	    key := getKeyFromDatabase(header.Kid)
//	    if key == nil {
//	        return nil, nil, nil, jwt.ErrUnknownKid
//	    }
//
//	    // Return algorithm and key for verification
//	    return jwt.RS256, key.PublicKey, nil, nil
//	}
//
// Security considerations:
//   - Always validate algorithms to prevent algorithm substitution attacks
//   - Ensure key selection logic is secure and cannot be manipulated
//   - Validate all required header fields before accepting tokens
//   - Consider rate limiting and caching for external key lookups
type HeaderValidator func(alg string, headerDecoded []byte) (Alg, PublicKey, InjectFunc, error)

// Note that this check is fully hard coded for known
// algorithms and it is fully hard coded in terms of
// its serialized format.
func compareHeader(alg string, headerDecoded []byte) (Alg, PublicKey, InjectFunc, error) {
	if n := len(headerDecoded); n < 25 /* 28 but allow custom short algs*/ {
		if n == 15 { // header without "typ": "JWT".
			expectedHeader := createHeaderWithoutTyp(alg)
			if bytes.Equal(expectedHeader, headerDecoded) {
				return nil, nil, nil, nil
			}
		}

		return nil, nil, nil, ErrTokenAlg
	}

	// Fast check if the order is reversed.
	// The specification says otherwise but
	// some other programming languages' libraries
	// don't actually follow the correct order.
	if headerDecoded[2] == 't' {
		expectedHeader := createHeaderReversed(alg)
		if !bytes.Equal(expectedHeader, headerDecoded) {
			return nil, nil, nil, ErrTokenAlg
		}

		return nil, nil, nil, nil
	}

	expectedHeader := createHeaderRaw(alg)
	if !bytes.Equal(expectedHeader, headerDecoded) {
		return nil, nil, nil, ErrTokenAlg
	}

	return nil, nil, nil, nil
}

func createSignature(alg Alg, key PrivateKey, headerAndPayload []byte) ([]byte, error) {
	signature, err := alg.Sign(key, headerAndPayload)
	if err != nil {
		return nil, err
	}
	return Base64Encode(signature), nil
}

// Base64Encode encodes bytes to JWT-specific base64url format without padding.
//
// JWT tokens use base64url encoding (RFC 4648 Section 5) without trailing
// padding characters ('='). This function provides optimized encoding that
// follows JWT specifications exactly.
//
// The encoding process:
//   - Uses standard base64.URLEncoding for initial encoding
//   - Removes trailing '=' padding characters as required by JWT spec
//   - Returns URL-safe base64 encoded bytes
//
// This function is used internally for encoding JWT headers, payloads, and
// signatures. While optimized for internal use, it can be used externally
// for compatible base64url encoding needs.
//
// Parameters:
//   - src: Raw bytes to encode
//
// Returns:
//   - []byte: Base64url-encoded bytes without padding
//
// Example:
//
//	data := []byte(`{"alg":"HS256","typ":"JWT"}`)
//	encoded := jwt.Base64Encode(data)
//	// Result: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
//	// Note: No trailing '=' characters
func Base64Encode(src []byte) []byte {
	buf := make([]byte, base64.URLEncoding.EncodedLen(len(src)))
	base64.URLEncoding.Encode(buf, src)

	return bytes.TrimRight(buf, padStr) // JWT: no trailing '='.
}

// Base64Decode decodes JWT-specific base64url format bytes to raw data.
//
// JWT tokens use base64url encoding (RFC 4648 Section 5) without trailing
// padding characters. This function handles the JWT-specific decoding by
// automatically adding required padding before standard base64 decoding.
//
// The decoding process:
//   - Calculates missing padding length based on input length
//   - Adds appropriate number of '=' padding characters
//   - Performs standard base64.URLEncoding decode operation
//   - Returns the raw decoded bytes
//
// This function is used internally for decoding JWT headers, payloads, and
// signatures. It correctly handles the padding-free format used in JWT tokens.
//
// Parameters:
//   - src: Base64url-encoded bytes (without padding)
//
// Returns:
//   - []byte: Decoded raw bytes
//   - error: Decoding error if the input is invalid base64url
//
// The function automatically handles inputs with or without padding,
// making it compatible with both JWT format and standard base64url.
//
// Example:
//
//	encoded := []byte("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")
//	decoded, err := jwt.Base64Decode(encoded)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	// Result: []byte(`{"alg":"HS256","typ":"JWT"}`)
func Base64Decode(src []byte) ([]byte, error) {
	// Padding is removed rather than added, which is both safer and cheaper.
	//
	// The previous form appended '=' bytes to reach a multiple of four. bytes.Split does
	// not cap the capacity of the last part it returns, so the signature segment of a
	// token still owns the token's spare capacity, and that append wrote into the
	// caller's buffer past the end of the token. With a pooled read buffer, which is how
	// most servers hand a token to this package, that is a write into memory the next
	// request is about to use.
	//
	// RawURLEncoding wants no padding at all, so trimming is the whole conversion.
	// bytes.TrimRight returns a sub-slice and allocates nothing, and DecodedLen on the
	// trimmed input asks for fewer bytes than the padded form did.
	src = bytes.TrimRight(src, padStr)

	buf := make([]byte, base64.RawURLEncoding.DecodedLen(len(src)))
	n, err := base64.RawURLEncoding.Decode(buf, src)
	return buf[:n], err
}

// Decode parses a JWT token into its components WITHOUT any verification or validation.
//
// This function performs raw parsing of JWT tokens to extract header, payload, and
// signature components without cryptographic verification. It's designed for scenarios
// where token content needs to be inspected without validating authenticity.
//
// SECURITY WARNING: This function does NOT verify:
//   - Token signature (authenticity)
//   - Token expiration (exp claim)
//   - Token validity periods (nbf, iat claims)
//   - Algorithm security
//   - Any other security-related validations
//
// Use cases for Decode (all require trusted sources):
//   - Extracting claims from tokens generated by the same application
//   - Reading token metadata for logging or debugging
//   - Inspecting token structure during development
//   - Processing tokens from fully trusted internal sources
//
// For security-critical applications, use Verify, VerifyEncrypted, or
// VerifyWithHeaderValidator functions instead.
//
// Parameters:
//   - token: JWT token bytes in compact form (header.payload.signature)
//
// Returns:
//   - *UnverifiedToken: Parsed token components (header, payload, signature)
//   - error: Parsing errors including:
//   - ErrTokenForm if token structure is invalid
//   - Base64 decoding errors for malformed components
//
// The returned UnverifiedToken contains raw decoded bytes for each component.
// Use its Claims method to unmarshal the payload into structured data.
//
// Example:
//
//	// Only use with trusted tokens!
//	token := []byte("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
//
//	unverified, err := jwt.Decode(token)
//	if err != nil {
//	    log.Fatalf("Failed to decode token: %v", err)
//	}
//
//	// Extract claims without verification
//	var claims jwt.Map
//	err = unverified.Claims(&claims)
//	if err != nil {
//	    log.Fatalf("Failed to parse claims: %v", err)
//	}
//
//	fmt.Printf("Subject: %v\n", claims["sub"])
//	// WARNING: This token was NOT verified!
func Decode(token []byte) (*UnverifiedToken, error) {
	if len(token) > MaxTokenSize {
		return nil, ErrTokenSize
	}

	parts := bytes.Split(token, sep)
	if len(parts) != 3 {
		return nil, ErrTokenForm
	}

	header := parts[0]
	payload := parts[1]
	signature := parts[2]

	headerDecoded, err := Base64Decode(header)
	if err != nil {
		return nil, fmt.Errorf("decode token: header: %w", err)
	}

	signatureDecoded, err := Base64Decode(signature)
	if err != nil {
		return nil, fmt.Errorf("decode token: signature: %w", err)
	}

	payload, err = Base64Decode(payload)
	if err != nil {
		return nil, fmt.Errorf("decode token: payload: %w", err)
	}

	tok := &UnverifiedToken{
		Header:    headerDecoded,
		Payload:   payload,
		Signature: signatureDecoded,
	}
	return tok, nil
}

// UnverifiedToken represents the parsed components of a JWT token without verification.
//
// This structure contains the three decoded parts of a JWT token (header, payload, signature)
// as raw byte slices. It's returned by the Decode function and provides access to token
// components without performing any cryptographic verification.
//
// SECURITY WARNING: This structure contains unverified token data. The signature
// has not been validated, expiration has not been checked, and the token's authenticity
// is not guaranteed. Only use this with tokens from fully trusted sources.
//
// Fields:
//   - Header: JSON header containing algorithm and token type information
//   - Payload: JSON payload containing claims and application data
//   - Signature: Raw signature bytes used for verification (not validated)
//
// Common usage patterns:
//   - Development and debugging to inspect token structure
//   - Internal applications where tokens are generated and consumed by the same service
//   - Logging and monitoring to extract metadata without verification overhead
//   - Testing and validation tools that need to examine token content
//
// Use the Claims method to unmarshal the Payload into structured Go types.
// For production use with external tokens, use verified token structures instead.
//
// Example:
//
//	unverified, err := jwt.Decode(tokenBytes)
//	if err != nil {
//	    return err
//	}
//
//	// Inspect header
//	var header struct {
//	    Alg string `json:"alg"`
//	    Typ string `json:"typ"`
//	}
//	json.Unmarshal(unverified.Header, &header)
//	fmt.Printf("Algorithm: %s\n", header.Alg)
//
//	// Extract claims
//	var claims jwt.Map
//	unverified.Claims(&claims)
//	fmt.Printf("Subject: %v\n", claims["sub"])
type UnverifiedToken struct {
	Header    []byte // Decoded JWT header JSON bytes
	Payload   []byte // Decoded JWT payload JSON bytes
	Signature []byte // Decoded signature bytes (unverified)

	// cached.
	alg Alg
	kid string
}

// Claims unmarshals the JWT payload into the provided destination structure.
//
// This method decodes the raw JSON payload bytes into a Go data structure,
// enabling access to claims data in a type-safe manner. The destination can be
// any type that's compatible with JSON unmarshaling.
//
// SECURITY WARNING: The payload data has not been cryptographically verified.
// Do not trust this data for security-critical decisions unless the token source
// is completely trusted and internal to your application.
//
// Parameters:
//   - dest: Pointer to the destination where claims will be unmarshaled
//
// Returns:
//   - error: JSON unmarshaling error if the payload is malformed or incompatible
//
// Supported destination types:
//   - jwt.Map for dynamic claims access
//   - Custom structs with json tags for typed claims
//   - jwt.Claims for the standard claims
//   - Any type compatible with json.Unmarshal
//
// Example usage:
//
//	unverified, _ := jwt.Decode(tokenBytes)
//
//	// Extract to dynamic map
//	var claims jwt.Map
//	if err := unverified.Claims(&claims); err != nil {
//	    return err
//	}
//	fmt.Printf("Subject: %v\n", claims["sub"])
//
//	// Extract to custom struct
//	type MyClaims struct {
//	    UserID   string    `json:"sub"`
//	    Username string    `json:"username"`
//	    IssuedAt time.Time `json:"iat"`
//	}
//	var myClaims MyClaims
//	if err := unverified.Claims(&myClaims); err != nil {
//	    return err
//	}
//
//	// Extract standard claims
//	var registered jwt.Claims
//	if err := unverified.Claims(&registered); err != nil {
//	    return err
//	}
//	fmt.Printf("Expires: %v\n", registered.ExpiresAt)
func (t *UnverifiedToken) Claims(dest any) error {
	return Unmarshal(t.Payload, dest)
}

type headerWithAlg struct {
	Alg string `json:"alg"`
}

// Alg returns the algorithm used in the original token header.
// It extracts the "alg" field from the JWT header and returns the corresponding Alg implementation.
//
// If the header is malformed or the algorithm is unknown, it returns an error.
// This method is useful for determining the algorithm used to sign the token.
func (t *UnverifiedToken) Alg() (Alg, error) {
	if t.alg != nil {
		return t.alg, nil
	}

	// Extract algorithm from the original token header.
	var header headerWithAlg
	if err := json.Unmarshal(t.Header, &header); err != nil {
		return nil, fmt.Errorf("failed to parse original token header: %w", err)
	}

	alg := parseAlg(header.Alg)
	if alg == nil {
		return nil, fmt.Errorf("%w: %s", ErrTokenAlg, header.Alg)
	}

	t.alg = alg
	return alg, nil
}

// Kid returns the Key ID (kid) from the original token header.
// It extracts the "kid" field from the JWT header and returns its value.
// If the header is malformed or the "kid" field is missing, it returns an error.
func (t *UnverifiedToken) Kid() (string, error) {
	if t.kid != "" {
		return t.kid, nil
	}

	var header HeaderWithKid
	if err := json.Unmarshal(t.Header, &header); err != nil {
		return "", fmt.Errorf("failed to parse original token header: %w", err)
	}

	alg := parseAlg(header.Alg)
	if alg == nil {
		return "", fmt.Errorf("%w: %s", ErrTokenAlg, header.Alg)
	}

	// KID catches both "kid" and "kid" fields.
	t.alg = alg
	t.kid = header.Kid
	return t.kid, nil
}

// Enrich merges extra claims into this token's payload and signs the result under alg.
//
// Nothing here is verified. The token came from Decode, which parses without checking a
// signature, so its payload is whatever the sender wrote. Use this only when you have
// already established that the token is genuine; otherwise use the package-level Enrich,
// which checks the signature first.
//
// Because the input is unchecked, the header of the new token is built from alg rather
// than copied from the original. A copied header would put fields chosen by the sender,
// "kid" and "crit" among them, inside a signature made with your key. For the same reason
// alg is a parameter: reading the algorithm out of the header let a sender select NONE and
// walk away with an unsigned token bearing your claims. NONE is refused here too.
//
// A "kid" in the original header is therefore dropped. If you need it kept, verify the
// token first, with Enrich or Keys.EnrichToken, both of which carry a verified header
// through intact.
//
// Example:
//
//	unverified, err := jwt.Decode(tokenBytes)
//	if err != nil {
//	    return err
//	}
//
//	newToken, err := unverified.Enrich(jwt.HS256, signingKey, map[string]any{"role": "admin"})
//
// It returns ErrTokenAlg when alg is nil or NONE, and a wrapped merge error when the extra
// claims cannot be serialized.
func (t *UnverifiedToken) Enrich(alg Alg, key PrivateKey, extraClaims any) ([]byte, error) {
	return t.enrich(alg, key, extraClaims, nil)
}

// enrich merges extraClaims into the token's payload and signs the result under alg.
//
// encodedHeader, when not nil, is used verbatim as the header of the new token. Only the
// entry points that have already verified the original token pass it, because a verified
// header was covered by a signature made with the caller's own key and is therefore safe
// to carry forward, "kid" and all.
//
// When it is nil the header is built from alg instead. That is the case for the exported
// UnverifiedToken.Enrich, whose input is by definition unchecked: copying an unverified
// header would sign fields chosen by whoever supplied the token, and reading the
// algorithm out of it would let them choose that too, including the unsecured one.
func (t *UnverifiedToken) enrich(alg Alg, key PrivateKey, extraClaims any, encodedHeader []byte) ([]byte, error) {
	if alg == nil {
		return nil, ErrTokenAlg
	}

	if alg == NONE {
		return nil, fmt.Errorf("%w: refusing to enrich under the unsecured algorithm", ErrTokenAlg)
	}

	// Merge the original claims with the extra claims.
	payload, err := Merge(t.Payload, extraClaims)
	if err != nil {
		return nil, fmt.Errorf("failed to merge claims: %w", err)
	}
	payload = Base64Encode(payload)

	header := encodedHeader
	if header == nil {
		header = createHeader(alg.Name())
	}

	headerPayload := joinParts(header, payload)

	signature, err := createSignature(alg, key, headerPayload)
	if err != nil {
		return nil, fmt.Errorf("encodeToken: signature: %w", err)
	}

	// header.payload.signature
	token := joinParts(headerPayload, signature)
	return token, nil
}
