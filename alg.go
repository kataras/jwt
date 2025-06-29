package jwt

import (
	"crypto"
	"crypto/rsa"
	_ "crypto/sha256" // ignore:lint
	_ "crypto/sha512"
	"errors"
)

var (
	// ErrTokenSignature indicates that JWT signature verification has failed.
	//
	// This error is returned when the computed signature does not match the
	// signature provided in the JWT token. It indicates that either:
	//   - The token has been tampered with
	//   - The wrong key was used for verification
	//   - The token was signed with a different algorithm
	//   - The signature is corrupted or malformed
	//
	// **Security Implications**: This error should be treated as a security
	// event and may indicate an attack attempt. Always log these failures
	// for security monitoring.
	//
	// **Common Causes**:
	//   - Using wrong verification key
	//   - Algorithm mismatch between signing and verification
	//   - Token tampering or corruption
	//   - Clock skew causing timing-related signature issues
	//
	// Example usage:
	//
	//	verifiedToken, err := jwt.Verify(jwt.HS256, secretKey, token)
	//	if err == jwt.ErrTokenSignature {
	//	    log.Printf("Security alert: Invalid token signature from %s", clientIP)
	//	    http.Error(w, "Unauthorized", http.StatusUnauthorized)
	//	    return
	//	}
	ErrTokenSignature = errors.New("jwt: invalid token signature")

	// ErrInvalidKey indicates that the provided key is not valid for the algorithm.
	//
	// This error occurs when the key type doesn't match what the algorithm expects.
	// Each algorithm has specific key type requirements that must be satisfied
	// for proper cryptographic operations.
	//
	// **Algorithm Key Requirements**:
	//   - HMAC (HS256/384/512): []byte (shared secret)
	//   - RSA (RS256/384/512, PS256/384/512): *rsa.PrivateKey (sign), *rsa.PublicKey (verify)
	//   - ECDSA (ES256/384/512): *ecdsa.PrivateKey (sign), *ecdsa.PublicKey (verify)
	//   - EdDSA: ed25519.PrivateKey (sign), ed25519.PublicKey (verify)
	//
	// **Common Scenarios**:
	//   - Passing string instead of []byte for HMAC
	//   - Using wrong key type for asymmetric algorithms
	//   - Attempting to sign with public key or verify with private key incorrectly
	//   - Using keys from different cryptographic families
	//
	// **Prevention**: Always ensure key types match algorithm requirements
	// and validate keys before use in production systems.
	//
	// Example usage:
	//
	//	// Wrong: string instead of []byte for HMAC
	//	_, err := jwt.Sign(jwt.HS256, "secret", claims) // Returns ErrInvalidKey
	//
	//	// Correct: []byte for HMAC
	//	_, err = jwt.Sign(jwt.HS256, []byte("secret"), claims)
	//
	//	// Wrong: RSA key for HMAC algorithm
	//	_, err = jwt.Sign(jwt.HS256, rsaPrivateKey, claims) // Returns ErrInvalidKey
	//
	//	// Correct: RSA key for RSA algorithm
	//	_, err = jwt.Sign(jwt.RS256, rsaPrivateKey, claims)
	ErrInvalidKey = errors.New("jwt: invalid key")
)

// Alg represents a cryptographic algorithm for JWT signing and verification.
//
// This interface defines the contract that all JWT algorithms must implement.
// It provides a unified API for different cryptographic approaches (symmetric
// and asymmetric) while abstracting the underlying implementation details.
//
// **Algorithm Categories**:
//   - Symmetric: HMAC algorithms (HS256, HS384, HS512) using shared secrets
//   - Asymmetric: RSA, ECDSA, EdDSA using public/private key pairs
//   - Unsecured: None algorithm for testing and specific use cases
//
// **Implementation Requirements**:
//   - Thread-safe operations for concurrent use
//   - Constant-time signature verification to prevent timing attacks
//   - Proper error handling for invalid keys and malformed data
//   - RFC 7518 compliance for standard algorithms
//
// **Security Considerations**:
//   - Implementations must validate key types and sizes
//   - Signature operations should use cryptographically secure randomness
//   - Timing-sensitive operations should be constant-time
//   - Error messages should not leak cryptographic information
//
// Example custom algorithm implementation:
//
//	type CustomAlg struct {
//	    name string
//	}
//
//	func (a *CustomAlg) Name() string {
//	    return a.name
//	}
//
//	func (a *CustomAlg) Sign(key PrivateKey, data []byte) ([]byte, error) {
//	    // Custom signing logic
//	    return signature, nil
//	}
//
//	func (a *CustomAlg) Verify(key PublicKey, data, sig []byte) error {
//	    // Custom verification logic
//	    return nil
//	}
//
// **Built-in Algorithms**: The library provides implementations for all
// standard JWT algorithms. Custom algorithms can be created by implementing
// this interface.
type Alg interface {
	// Name returns the algorithm identifier for the JWT "alg" header field.
	//
	// This value must match the standard algorithm names defined in RFC 7518
	// or be a custom identifier for non-standard algorithms. The name is
	// case-sensitive and used for algorithm selection during verification.
	//
	// **Standard Names**:
	//   - "HS256", "HS384", "HS512" for HMAC
	//   - "RS256", "RS384", "RS512" for RSA PKCS#1 v1.5
	//   - "PS256", "PS384", "PS512" for RSA-PSS
	//   - "ES256", "ES384", "ES512" for ECDSA
	//   - "EdDSA" for Ed25519
	//   - "none" for unsecured tokens
	//
	// Example usage:
	//
	//	alg := jwt.HS256
	//	fmt.Println(alg.Name()) // Output: "HS256"
	Name() string

	// Sign creates a cryptographic signature for the JWT.
	//
	// This method takes a private key and the concatenated base64url-encoded
	// header and payload (separated by a dot) and produces a signature.
	// The signature is returned as raw bytes (not base64url-encoded).
	//
	// **Parameters**:
	//   - key: Private key material (type depends on algorithm)
	//   - headerAndPayload: Base64url-encoded "header.payload" string
	//
	// **Key Types by Algorithm**:
	//   - HMAC: []byte (shared secret)
	//   - RSA: *rsa.PrivateKey
	//   - ECDSA: *ecdsa.PrivateKey
	//   - EdDSA: ed25519.PrivateKey
	//
	// **Security Requirements**:
	//   - Must validate key type and size
	//   - Should use cryptographically secure randomness
	//   - Must handle errors securely without information leakage
	//
	// **Error Conditions**:
	//   - ErrInvalidKey: Wrong key type for algorithm
	//   - Other errors: Cryptographic failures, insufficient entropy
	//
	// Example usage:
	//
	//	headerAndPayload := []byte("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0")
	//	signature, err := alg.Sign(secretKey, headerAndPayload)
	//	if err != nil {
	//	    log.Printf("Signing failed: %v", err)
	//	    return
	//	}
	Sign(key PrivateKey, headerAndPayload []byte) ([]byte, error)

	// Verify validates a JWT signature against the expected value.
	//
	// This method takes a public key, the original data that was signed,
	// and the signature to verify. It returns nil if verification succeeds
	// or an error if verification fails.
	//
	// **Parameters**:
	//   - key: Public key material (type depends on algorithm)
	//   - headerAndPayload: Base64url-encoded "header.payload" string (same as used for signing)
	//   - signature: Raw signature bytes (base64url-decoded from JWT)
	//
	// **Key Types by Algorithm**:
	//   - HMAC: []byte (same shared secret as signing)
	//   - RSA: *rsa.PublicKey
	//   - ECDSA: *ecdsa.PublicKey
	//   - EdDSA: ed25519.PublicKey
	//
	// **Security Requirements**:
	//   - Must use constant-time comparison to prevent timing attacks
	//   - Must validate key type and parameters
	//   - Should not leak information through error messages or timing
	//
	// **Error Conditions**:
	//   - ErrTokenSignature: Signature verification failed
	//   - ErrInvalidKey: Wrong key type for algorithm
	//   - Other errors: Malformed signature, cryptographic failures
	//
	// Example usage:
	//
	//	err := alg.Verify(publicKey, headerAndPayload, signature)
	//	if err == jwt.ErrTokenSignature {
	//	    log.Printf("Invalid signature detected")
	//	    return errors.New("authentication failed")
	//	}
	//	if err != nil {
	//	    log.Printf("Verification error: %v", err)
	//	    return err
	//	}
	//	// Token is valid
	Verify(key PublicKey, headerAndPayload []byte, signature []byte) error
}

// AlgParser is an optional interface for algorithms that support key parsing.
//
// Algorithms can implement this interface to provide automatic key parsing
// from raw byte data. This is particularly useful for multi-key scenarios
// where keys are loaded from files, databases, or remote sources.
//
// **Use Cases**:
//   - Loading keys from PEM files
//   - Parsing keys from configuration data
//   - Automatic key format detection
//   - Multi-key management systems
//   - Key rotation and update scenarios
//
// **Implementation**: Algorithms that support key parsing should implement
// this interface to provide seamless integration with key management systems.
// The parsing should handle common key formats and provide clear error
// messages for unsupported formats.
//
// **Integration**: This interface is used by the kid_keys.go functionality
// to automatically parse and manage multiple keys with different algorithms.
//
// Example implementation:
//
//	func (a *rsaAlg) Parse(private, public []byte) (PrivateKey, PublicKey, error) {
//	    var privKey *rsa.PrivateKey
//	    var pubKey *rsa.PublicKey
//	    var err error
//
//	    if len(private) > 0 {
//	        privKey, err = parseRSAPrivateKey(private)
//	        if err != nil {
//	            return nil, nil, err
//	        }
//	        pubKey = &privKey.PublicKey
//	    } else if len(public) > 0 {
//	        pubKey, err = parseRSAPublicKey(public)
//	        if err != nil {
//	            return nil, nil, err
//	        }
//	    }
//
//	    return privKey, pubKey, nil
//	}
//
// **Error Handling**: Implementations should return descriptive errors
// that help identify the specific parsing failure (format, encoding, etc.).
type AlgParser interface {
	// Parse converts raw key data into cryptographic key objects.
	//
	// This method attempts to parse private and/or public key data from
	// byte arrays into the appropriate Go cryptographic types for the algorithm.
	// At least one of the parameters should be non-empty.
	//
	// **Parameters**:
	//   - private: Raw private key data (PEM, DER, or other format)
	//   - public: Raw public key data (PEM, DER, or other format)
	//
	// **Return Values**:
	//   - PrivateKey: Parsed private key (nil if not provided or not needed)
	//   - PublicKey: Parsed public key (derived from private key if available)
	//   - error: Parsing error or nil on success
	//
	// **Supported Formats**: Implementations should support standard formats:
	//   - PEM encoding with appropriate headers
	//   - DER binary encoding
	//   - PKCS#1, PKCS#8, or SEC1 formats as appropriate
	//   - X.509 format for public keys
	//
	// **Key Derivation**: If a private key is provided, the public key
	// should be derived from it automatically. If only public key data
	// is provided, the private key should be nil.
	//
	// Example usage:
	//
	//	// Parse RSA key pair
	//	privKey, pubKey, err := rsaAlg.Parse(privateKeyPEM, nil)
	//	if err != nil {
	//	    log.Printf("Failed to parse RSA keys: %v", err)
	//	    return
	//	}
	//
	//	// Parse only public key
	//	_, pubKey, err = rsaAlg.Parse(nil, publicKeyPEM)
	//	if err != nil {
	//	    log.Printf("Failed to parse RSA public key: %v", err)
	//	    return
	//	}
	Parse(private, public []byte) (PrivateKey, PublicKey, error)
}

// Algorithm Selection Guide
//
// **Quick Selection Guide**:
//   - High Performance + Shared Secret: Use HMAC (HS256/HS384/HS512)
//   - Public Key Infrastructure: Use RSA (RS256) or ECDSA (ES256)
//   - Modern High Security: Use EdDSA (Ed25519)
//   - Legacy RSA Systems: Use RSA-PSS (PS256) for enhanced security
//   - Testing/Development Only: Use NONE (never in production)
//
// **Algorithm Categories**:
//
// 1. **Symmetric Algorithms**: Single shared secret for signing and verification
//   - Pros: Fast, simple key management, well-tested
//   - Cons: Key distribution challenges, single point of failure
//   - Use when: Both parties can securely share a secret
//
// 2. **Asymmetric Algorithms**: Separate keys for signing and verification
//   - Pros: Better key distribution, non-repudiation, scalable
//   - Cons: Slower performance, larger tokens, more complex key management
//   - Use when: Need to distribute verification capability widely
//
// **Security vs Performance Trade-offs**:
//   - HMAC: Fastest, requires secure key sharing
//   - ECDSA/EdDSA: Good performance, smaller keys/signatures than RSA
//   - RSA: Widely supported, larger keys/signatures, moderate performance
//   - RSA-PSS: Enhanced RSA security, similar performance to RSA
//
// **Token Size Comparison** (approximate):
//   - HMAC: ~200-300 bytes
//   - ECDSA: ~300-400 bytes
//   - EdDSA: ~250-350 bytes
//   - RSA: ~500-800 bytes
var (
	// NONE represents the "none" algorithm for unsecured JWTs.
	//
	// **SECURITY WARNING**: This algorithm provides NO cryptographic security.
	// Tokens signed with NONE can be modified by anyone without detection.
	// Use ONLY in specific scenarios where security is handled by other means.
	//
	// **Valid Use Cases**:
	//   - Client-side data storage where tampering doesn't matter
	//   - Development and testing environments
	//   - Public information distribution
	//   - Session data that's validated by other mechanisms
	//
	// **Invalid Use Cases**:
	//   - Authentication tokens
	//   - Authorization decisions
	//   - Any security-sensitive data
	//   - Production environments (generally)
	//
	// **Example Scenario**: Single-page application storing user preferences
	// and navigation state. Even if modified, no security impact occurs since
	// all security decisions are made server-side with separate authentication.
	//
	// Example payload (safe for NONE algorithm):
	//
	//	{
	//	  "sub": "user123",
	//	  "session": "ch72gsb320000udocl363eofy",
	//	  "displayName": "John Doe",
	//	  "lastPage": "/dashboard",
	//	  "theme": "dark",
	//	  "language": "en"
	//	}
	//
	// **Implementation**: Always returns empty signature and accepts any signature
	// as valid. The verification process succeeds for any input.
	//
	// **Compliance**: Defined in RFC 7518 Section 3.6 as the "none" algorithm.
	NONE Alg = &algNONE{}
	// HMAC-SHA signing algorithms (symmetric algorithms).
	//
	// **Algorithm Family**: Hash-based Message Authentication Code using SHA-2
	// **Key Type**: []byte (shared secret)
	// **Security Model**: Symmetric - same key for signing and verification
	//
	// **Performance**: HMAC algorithms are the fastest JWT algorithms available,
	// making them ideal for high-throughput applications where both parties
	// can securely share a secret key.
	//
	// **Critical Security Requirements**:
	//
	// **Key Length**: RFC 7518 mandates minimum key lengths equal to hash output:
	//   - HS256: 256 bits (32 bytes) minimum
	//   - HS384: 384 bits (48 bytes) minimum
	//   - HS512: 512 bits (64 bytes) minimum
	//
	// **SECURITY WARNING**: Short keys are vulnerable to brute force attacks.
	// This is NOT a theoretical concern - practical attacks exist for weak keys.
	//
	// **Key Generation Best Practices**:
	//   - Use cryptographically secure random generation
	//   - Minimum 32 ASCII characters for human-readable secrets
	//   - Prefer base64-encoded random bytes for maximum entropy
	//   - Never use passwords, dictionary words, or predictable patterns
	//
	// **Key Management**:
	//   - Rotate keys regularly (monthly/quarterly)
	//   - Store securely (environment variables, key vaults, HSMs)
	//   - Use different keys for different applications/environments
	//   - Implement secure key distribution mechanisms
	//
	// **When to Use HMAC**:
	//   - High-performance requirements
	//   - Both parties can share a secret securely
	//   - Simple key management scenarios
	//   - Internal APIs and microservices
	//
	// **When NOT to Use HMAC**:
	//   - Public key distribution needed
	//   - Third-party verification required
	//   - Non-repudiation requirements
	//   - Complex multi-party scenarios
	//
	// Example secure key generation:
	//
	//	// Generate cryptographically secure key
	//	key := make([]byte, 32) // 256 bits for HS256
	//	_, err := rand.Read(key)
	//	if err != nil {
	//	    log.Fatal("Failed to generate secure key")
	//	}
	//
	//	// Or use base64-encoded string
	//	keyB64 := base64.StdEncoding.EncodeToString(key)
	//
	//	// Sign token
	//	token, err := jwt.Sign(jwt.HS256, key, claims)

	// HS256 uses HMAC with SHA-256 hash function.
	//
	// **Security Level**: 128-bit security
	// **Key Requirement**: Minimum 32 bytes (256 bits)
	// **Hash Output**: 32 bytes
	// **Performance**: Fastest JWT algorithm
	//
	// **Most Common Choice**: HS256 is the most widely used JWT algorithm
	// due to its excellent balance of security and performance.
	//
	// **Compliance**: Defined in RFC 7518 Section 3.2
	HS256 Alg = &algHMAC{"HS256", crypto.SHA256}

	// HS384 uses HMAC with SHA-384 hash function.
	//
	// **Security Level**: 192-bit security
	// **Key Requirement**: Minimum 48 bytes (384 bits)
	// **Hash Output**: 48 bytes
	// **Performance**: Slightly slower than HS256, faster than HS512
	//
	// **Use Case**: Higher security requirements than HS256 while
	// maintaining good performance characteristics.
	//
	// **Compliance**: Defined in RFC 7518 Section 3.2
	HS384 Alg = &algHMAC{"HS384", crypto.SHA384}

	// HS512 uses HMAC with SHA-512 hash function.
	//
	// **Security Level**: 256-bit security
	// **Key Requirement**: Minimum 64 bytes (512 bits)
	// **Hash Output**: 64 bytes
	// **Performance**: Slowest HMAC variant, still faster than asymmetric algorithms
	//
	// **Use Case**: Maximum security in symmetric algorithm family.
	// Larger signatures may impact network performance.
	//
	// **Compliance**: Defined in RFC 7518 Section 3.2
	HS512 Alg = &algHMAC{"HS512", crypto.SHA512}
	// RSA signing algorithms using PKCS#1 v1.5 padding (asymmetric algorithms).
	//
	// **Algorithm Family**: RSA with PKCS#1 v1.5 padding scheme
	// **Sign Key**: *rsa.PrivateKey
	// **Verify Key**: *rsa.PublicKey (or *rsa.PrivateKey with PublicKey field)
	// **Security Model**: Asymmetric - different keys for signing and verification
	//
	// **Advantages**:
	//   - Wide industry support and compatibility
	//   - Well-established security properties
	//   - Suitable for public key infrastructure
	//   - Non-repudiation capabilities
	//   - No shared secret distribution required
	//
	// **Disadvantages**:
	//   - Larger token size compared to ECDSA/EdDSA
	//   - Slower performance than symmetric algorithms
	//   - Larger key sizes required for equivalent security
	//   - More complex key management
	//
	// **Key Size Recommendations**:
	//   - Minimum: 2048 bits (acceptable for most use cases)
	//   - Recommended: 3072 bits (good long-term security)
	//   - High Security: 4096 bits (maximum security, slower performance)
	//
	// **Security Considerations**:
	//   - PKCS#1 v1.5 padding has known theoretical vulnerabilities
	//   - Consider RSA-PSS (PS256/384/512) for enhanced security
	//   - Ensure proper random number generation during key creation
	//   - Validate key strength before use
	//
	// **Key Generation with OpenSSL**:
	//
	//	# Generate 2048-bit RSA private key
	//	$ openssl genpkey -algorithm rsa -out private_key.pem -pkeyopt rsa_keygen_bits:2048
	//
	//	# Extract public key from private key
	//	$ openssl rsa -pubout -in private_key.pem -out public_key.pem
	//
	//	# Generate 3072-bit key for higher security
	//	$ openssl genpkey -algorithm rsa -out private_key.pem -pkeyopt rsa_keygen_bits:3072
	//
	// **Key Generation in Go**:
	//
	//	// Generate RSA key pair
	//	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	//	if err != nil {
	//	    log.Fatal("Failed to generate RSA key:", err)
	//	}
	//	publicKey := &privateKey.PublicKey
	//
	//	// Sign token
	//	token, err := jwt.Sign(jwt.RS256, privateKey, claims)
	//
	//	// Verify token
	//	verifiedToken, err := jwt.Verify(jwt.RS256, publicKey, token)
	//
	// **When to Use RSA**:
	//   - Public key infrastructure requirements
	//   - Third-party token verification
	//   - Legacy system compatibility
	//   - Non-repudiation requirements
	//
	// **When to Consider Alternatives**:
	//   - Performance is critical (use HMAC)
	//   - Token size matters (use ECDSA/EdDSA)
	//   - Modern security preferences (use EdDSA)

	// RS256 uses RSA with SHA-256 hash and PKCS#1 v1.5 padding.
	//
	// **Security Level**: 112-bit security (2048-bit keys)
	// **Hash Function**: SHA-256
	// **Padding**: PKCS#1 v1.5
	// **Key Size**: Minimum 2048 bits recommended
	//
	// **Most Popular Asymmetric Algorithm**: RS256 is the most widely
	// used asymmetric JWT algorithm due to broad support and compatibility.
	//
	// **Compliance**: Defined in RFC 7518 Section 3.3
	RS256 Alg = &algRSA{"RS256", crypto.SHA256}

	// RS384 uses RSA with SHA-384 hash and PKCS#1 v1.5 padding.
	//
	// **Security Level**: 112-bit security (2048-bit keys)
	// **Hash Function**: SHA-384
	// **Padding**: PKCS#1 v1.5
	// **Key Size**: Minimum 2048 bits recommended
	//
	// **Use Case**: Higher hash security than RS256 while maintaining
	// RSA algorithm compatibility.
	//
	// **Compliance**: Defined in RFC 7518 Section 3.3
	RS384 Alg = &algRSA{"RS384", crypto.SHA384}

	// RS512 uses RSA with SHA-512 hash and PKCS#1 v1.5 padding.
	//
	// **Security Level**: 112-bit security (2048-bit keys)
	// **Hash Function**: SHA-512
	// **Padding**: PKCS#1 v1.5
	// **Key Size**: Minimum 2048 bits recommended
	//
	// **Use Case**: Maximum hash security in RSA PKCS#1 v1.5 family.
	// Larger signature size may impact performance.
	//
	// **Compliance**: Defined in RFC 7518 Section 3.3
	RS512 Alg = &algRSA{"RS512", crypto.SHA512}
	// RSASSA-PSS signing algorithms using probabilistic signature scheme (asymmetric algorithms).
	//
	// **Algorithm Family**: RSA with PSS (Probabilistic Signature Scheme) padding
	// **Sign Key**: *rsa.PrivateKey
	// **Verify Key**: *rsa.PublicKey (or *rsa.PrivateKey with PublicKey field)
	// **Security Model**: Asymmetric - different keys for signing and verification
	//
	// **PSS Advantages over PKCS#1 v1.5**:
	//   - Enhanced security properties and provable security
	//   - Resistance to certain theoretical attacks
	//   - Probabilistic signatures (different each time)
	//   - Better security margins and future-proofing
	//   - Recommended by security standards for new systems
	//
	// **Technical Details**:
	//   - Uses probabilistic padding with salt
	//   - Requires cryptographically secure random number generator
	//   - Salt length automatically determined (PSSSaltLengthAuto)
	//   - Each signature is unique even for identical messages
	//
	// **Security Considerations**:
	//   - Significantly more secure than PKCS#1 v1.5 padding
	//   - Provides better security guarantees under standard assumptions
	//   - Resistant to chosen-message attacks
	//   - Future-proof against cryptographic advances
	//
	// **Compatibility**:
	//   - Newer standard, may have limited support in legacy systems
	//   - OpenSSL generates different OIDs to prevent key reuse between schemes
	//   - Preferred for new implementations and security-critical applications
	//   - May require explicit support in JWT libraries and validators
	//
	// **Key Requirements**: Same as RSA PKCS#1 v1.5
	//   - Minimum: 2048 bits (acceptable for most use cases)
	//   - Recommended: 3072 bits (good long-term security)
	//   - High Security: 4096 bits (maximum security)
	//
	// **When to Use RSA-PSS**:
	//   - New systems with high security requirements
	//   - Applications requiring provable security
	//   - Long-term security considerations
	//   - Regulatory compliance requiring modern cryptography
	//
	// **When to Use RSA PKCS#1 v1.5 Instead**:
	//   - Legacy system compatibility required
	//   - Broad interoperability needed
	//   - Existing infrastructure uses RS256/384/512
	//
	// **Performance**: Similar to RSA PKCS#1 v1.5 algorithms, slightly slower
	// due to additional randomness and padding computation.
	//
	// Example usage:
	//
	//	// Same key generation as RSA PKCS#1 v1.5
	//	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	//	if err != nil {
	//	    log.Fatal("Failed to generate RSA key:", err)
	//	}
	//
	//	// Sign with PSS algorithm
	//	token, err := jwt.Sign(jwt.PS256, privateKey, claims)
	//
	//	// Verify with public key
	//	verifiedToken, err := jwt.Verify(jwt.PS256, &privateKey.PublicKey, token)

	// PS256 uses RSA with SHA-256 hash and PSS padding.
	//
	// **Security Level**: 112-bit security (2048-bit keys)
	// **Hash Function**: SHA-256
	// **Padding**: PSS with automatic salt length
	// **Key Size**: Minimum 2048 bits recommended
	//
	// **Recommended Choice**: PS256 provides the best balance of security,
	// performance, and compatibility for new RSA-based JWT implementations.
	//
	// **Compliance**: Defined in RFC 7518 Section 3.3
	PS256 Alg = &algRSAPSS{"PS256", &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: crypto.SHA256}}

	// PS384 uses RSA with SHA-384 hash and PSS padding.
	//
	// **Security Level**: 112-bit security (2048-bit keys)
	// **Hash Function**: SHA-384
	// **Padding**: PSS with automatic salt length
	// **Key Size**: Minimum 2048 bits recommended
	//
	// **Use Case**: Higher hash security than PS256 with enhanced
	// PSS padding security properties.
	//
	// **Compliance**: Defined in RFC 7518 Section 3.3
	PS384 Alg = &algRSAPSS{"PS384", &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: crypto.SHA384}}

	// PS512 uses RSA with SHA-512 hash and PSS padding.
	//
	// **Security Level**: 112-bit security (2048-bit keys)
	// **Hash Function**: SHA-512
	// **Padding**: PSS with automatic salt length
	// **Key Size**: Minimum 2048 bits recommended
	//
	// **Use Case**: Maximum hash and padding security in the RSA family.
	// Provides the highest security level for RSA-based JWT algorithms.
	//
	// **Compliance**: Defined in RFC 7518 Section 3.3
	PS512 Alg = &algRSAPSS{"PS512", &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: crypto.SHA512}}
	// ECDSA signing algorithms using elliptic curve cryptography (asymmetric algorithms).
	//
	// **Algorithm Family**: Elliptic Curve Digital Signature Algorithm
	// **Sign Key**: *ecdsa.PrivateKey
	// **Verify Key**: *ecdsa.PublicKey (or *ecdsa.PrivateKey with PublicKey field)
	// **Security Model**: Asymmetric - different keys for signing and verification
	//
	// **Advantages**:
	//   - Smaller key sizes for equivalent RSA security
	//   - Faster signature generation and verification than RSA
	//   - Significantly smaller tokens (~3x smaller than RSA)
	//   - Lower bandwidth and storage requirements
	//   - Modern cryptographic foundation
	//   - Better performance on mobile and embedded devices
	//
	// **Security Properties**:
	//   - Based on elliptic curve discrete logarithm problem
	//   - Provides equivalent security to RSA with much smaller keys
	//   - Well-studied and standardized curves (NIST P-curves)
	//   - Suitable for long-term security
	//
	// **Key Size Comparison** (equivalent security):
	//   - P-256 (ES256) ≈ RSA 3072-bit ≈ 128-bit security
	//   - P-384 (ES384) ≈ RSA 7680-bit ≈ 192-bit security
	//   - P-521 (ES512) ≈ RSA 15360-bit ≈ 256-bit security
	//
	// **Performance Benefits**:
	//   - Faster than RSA for both signing and verification
	//   - Lower CPU and memory usage
	//   - Reduced network overhead due to smaller tokens
	//   - Efficient on constrained devices
	//
	// **Key Generation with OpenSSL**:
	//
	//	# Generate P-256 private key (ES256)
	//	$ openssl ecparam -name prime256v1 -genkey -noout -out ecdsa_private_key.pem
	//
	//	# Extract public key from private key
	//	$ openssl ec -in ecdsa_private_key.pem -pubout -out ecdsa_public_key.pem
	//
	//	# Generate P-384 private key (ES384)
	//	$ openssl ecparam -name secp384r1 -genkey -noout -out ecdsa_private_key.pem
	//
	//	# Generate P-521 private key (ES512)
	//	$ openssl ecparam -name secp521r1 -genkey -noout -out ecdsa_private_key.pem
	//
	// **Key Generation in Go**:
	//
	//	// Generate P-256 key pair (ES256)
	//	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	//	if err != nil {
	//	    log.Fatal("Failed to generate ECDSA key:", err)
	//	}
	//	publicKey := &privateKey.PublicKey
	//
	//	// Sign token
	//	token, err := jwt.Sign(jwt.ES256, privateKey, claims)
	//
	//	// Verify token
	//	verifiedToken, err := jwt.Verify(jwt.ES256, publicKey, token)
	//
	// **Curve Selection**:
	//   - P-256: Most common, broad compatibility, good performance
	//   - P-384: Higher security, moderate performance impact
	//   - P-521: Maximum security, highest performance cost
	//
	// **When to Use ECDSA**:
	//   - Token size is important (mobile, IoT, high-frequency APIs)
	//   - Performance matters more than broad compatibility
	//   - Modern cryptographic preferences
	//   - Bandwidth-constrained environments
	//
	// **When to Consider Alternatives**:
	//   - Legacy system compatibility required (use RSA)
	//   - Maximum performance needed (use HMAC)
	//   - Cutting-edge security preference (use EdDSA)

	// ES256 uses ECDSA with P-256 curve and SHA-256 hash.
	//
	// **Security Level**: 128-bit security
	// **Curve**: P-256 (secp256r1/prime256v1)
	// **Hash Function**: SHA-256
	// **Key Size**: 256-bit curve (32-byte coordinates)
	//
	// **Most Popular ECDSA Algorithm**: ES256 provides excellent balance
	// of security, performance, and compatibility. Widely supported and
	// recommended for most ECDSA use cases.
	//
	// **Token Size**: Approximately 3 times smaller than equivalent RSA tokens.
	//
	// **Compliance**: Defined in RFC 7518 Section 3.4
	ES256 Alg = &algECDSA{"ES256", crypto.SHA256, 32, 256}

	// ES384 uses ECDSA with P-384 curve and SHA-384 hash.
	//
	// **Security Level**: 192-bit security
	// **Curve**: P-384 (secp384r1)
	// **Hash Function**: SHA-384
	// **Key Size**: 384-bit curve (48-byte coordinates)
	//
	// **Use Case**: Higher security than ES256 while maintaining ECDSA
	// performance advantages. Good choice for high-security applications.
	//
	// **Compliance**: Defined in RFC 7518 Section 3.4
	ES384 Alg = &algECDSA{"ES384", crypto.SHA384, 48, 384}

	// ES512 uses ECDSA with P-521 curve and SHA-512 hash.
	//
	// **Security Level**: 256-bit security
	// **Curve**: P-521 (secp521r1)
	// **Hash Function**: SHA-512
	// **Key Size**: 521-bit curve (66-byte coordinates)
	//
	// **Use Case**: Maximum security in ECDSA family. Provides the highest
	// security level available in standard ECDSA algorithms.
	//
	// **Note**: Despite the name "ES512", this uses the P-521 curve (521 bits),
	// not a 512-bit curve. The naming follows the hash function.
	//
	// **Compliance**: Defined in RFC 7518 Section 3.4
	ES512 Alg = &algECDSA{"ES512", crypto.SHA512, 66, 521}
	// EdDSA represents the Edwards-curve Digital Signature Algorithm using Ed25519.
	//
	// **Algorithm Family**: Edwards-curve Digital Signature Algorithm
	// **Sign Key**: ed25519.PrivateKey (64 bytes)
	// **Verify Key**: ed25519.PublicKey (32 bytes)
	// **Security Model**: Asymmetric - different keys for signing and verification
	// **Algorithm Name**: "EdDSA" (in JWT header)
	//
	// **Modern Cryptographic Algorithm**: EdDSA represents the latest generation
	// of elliptic curve cryptography, offering significant advantages over both
	// traditional ECDSA and RSA algorithms.
	//
	// **Key Advantages**:
	//   - Exceptional performance (comparable to or better than ECDSA)
	//   - Strong security guarantees and resistance to side-channel attacks
	//   - Deterministic signatures (same message always produces same signature)
	//   - Simple implementation with fewer opportunities for errors
	//   - No need for secure random number generation during signing
	//   - Immunity to certain classes of implementation vulnerabilities
	//   - Fast verification suitable for high-throughput scenarios
	//
	// **Security Properties**:
	//   - 128-bit security level (equivalent to RSA-3072 or ECDSA P-256)
	//   - Resistant to timing attacks by design
	//   - No malleable signatures
	//   - Strong unforgeability guarantees
	//   - Collision-resistant and second-preimage resistant
	//
	// **Key and Signature Sizes**:
	//   - Private Key: 64 bytes (includes 32-byte seed + 32-byte public key)
	//   - Public Key: 32 bytes (very compact)
	//   - Signature: 64 bytes (smaller than equivalent ECDSA signatures)
	//   - Total overhead significantly smaller than RSA
	//
	// **Performance Characteristics**:
	//   - Signing: Very fast, deterministic (no random number generation)
	//   - Verification: Extremely fast, often faster than ECDSA
	//   - Key generation: Fast and simple
	//   - Batch verification: Excellent performance for multiple signatures
	//
	// **Ed25519 Curve Properties**:
	//   - Uses the Edwards25519 elliptic curve
	//   - Designed specifically for high performance and security
	//   - Avoids many pitfalls of other elliptic curves
	//   - No known cryptographic weaknesses
	//
	// **Key Generation in Go**:
	//
	//	// Generate Ed25519 key pair
	//	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	//	if err != nil {
	//	    log.Fatal("Failed to generate Ed25519 key:", err)
	//	}
	//
	//	// Sign token
	//	token, err := jwt.Sign(jwt.EdDSA, privateKey, claims)
	//
	//	// Verify token
	//	verifiedToken, err := jwt.Verify(jwt.EdDSA, publicKey, token)
	//
	// **OpenSSL Support**: Ed25519 support was added in OpenSSL 1.1.1:
	//
	//	# Generate Ed25519 private key
	//	$ openssl genpkey -algorithm ed25519 -out ed25519_private_key.pem
	//
	//	# Extract public key
	//	$ openssl pkey -in ed25519_private_key.pem -pubout -out ed25519_public_key.pem
	//
	// **When to Use EdDSA**:
	//   - New systems with no legacy constraints
	//   - High-performance requirements
	//   - Security-critical applications
	//   - Mobile and IoT applications (small keys/signatures)
	//   - Systems requiring deterministic signatures
	//   - Applications needing resistance to side-channel attacks
	//
	// **Considerations**:
	//   - Newer algorithm with less ecosystem support than RSA/ECDSA
	//   - Requires Go 1.13+ for standard library support
	//   - May not be supported in older JWT libraries or validators
	//   - Limited HSM support compared to RSA/ECDSA
	//
	// **Standards Compliance**:
	//   - RFC 8037: CFRG Elliptic Curve Diffie-Hellman (ECDH) and Signatures in JOSE
	//   - RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA)
	//   - Widely adopted in modern cryptographic protocols
	//
	// **Recommendation**: EdDSA is the recommended choice for new applications
	// that can accommodate its requirements. It provides the best combination of
	// security, performance, and simplicity among asymmetric algorithms.
	EdDSA Alg = &algEdDSA{"EdDSA"}

	allAlgs = []Alg{
		NONE,
		RS256,
		RS384,
		RS512,
		PS256,
		PS384,
		PS512,
		ES256,
		ES384,
		ES512,
		EdDSA,
	}
)

// parseAlg returns the algorithm implementation by its name or nil if not found.
//
// This function performs a case-sensitive lookup of the algorithm name against
// all registered algorithms in the library. It's used internally during JWT
// verification to select the appropriate algorithm based on the "alg" header field.
//
// **Parameters**:
//   - name: Algorithm name string (e.g., "HS256", "RS256", "ES256", "EdDSA", "none")
//
// **Return Value**:
//   - Alg: Algorithm implementation if found, nil otherwise
//
// **Supported Algorithm Names**:
//   - "none": Unsecured tokens (NONE algorithm)
//   - "HS256", "HS384", "HS512": HMAC with SHA-2
//   - "RS256", "RS384", "RS512": RSA with PKCS#1 v1.5 padding
//   - "PS256", "PS384", "PS512": RSA with PSS padding
//   - "ES256", "ES384", "ES512": ECDSA with P-curves
//   - "EdDSA": Ed25519 Edwards-curve signatures
//
// **Case Sensitivity**: The lookup is case-sensitive. "hs256" will not match "HS256".
// This follows RFC 7518 which specifies exact algorithm names.
//
// **Security**: Unknown algorithms return nil, which should be treated as an error
// during verification. This prevents algorithm confusion attacks.
//
// **Usage**: This function is primarily used internally by the JWT verification
// process, but can be useful for algorithm validation or dynamic algorithm selection.
//
// Example usage:
//
//	// Validate algorithm name
//	alg := parseAlg("HS256")
//	if alg == nil {
//	    return errors.New("unsupported algorithm")
//	}
//	fmt.Println(alg.Name()) // Output: "HS256"
//
//	// Check for unsupported algorithm
//	alg = parseAlg("HS128") // Non-standard algorithm
//	if alg == nil {
//	    log.Printf("Algorithm HS128 is not supported")
//	}
//
//	// Case sensitivity
//	alg = parseAlg("hs256") // Wrong case
//	if alg == nil {
//	    log.Printf("Algorithm names are case-sensitive")
//	}
//
// **Internal Implementation**: The function iterates through all registered
// algorithms and compares their Name() return value with the input string.
// The comparison is performed using exact string matching.
func parseAlg(name string) Alg {
	for _, alg := range allAlgs {
		if alg.Name() == name {
			return alg
		}
	}

	return nil
}
