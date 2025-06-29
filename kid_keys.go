package jwt

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

var (
	// ErrEmptyKid indicates that a JWT header is missing the required "kid" (Key ID) field.
	// This error occurs when using key-based validation but the token doesn't specify which key to use.
	ErrEmptyKid = errors.New("jwt: kid is empty")

	// ErrUnknownKid indicates that a JWT header contains a "kid" field that doesn't match
	// any registered key. This typically means the token was signed with a key not known to this application.
	ErrUnknownKid = errors.New("jwt: unknown kid")
)

type (
	// HeaderWithKid represents a JWT header containing Key ID and algorithm information.
	// This structure is used for parsing and generating JWT headers when working with multiple keys.
	//
	// The "kid" field identifies which key was used to sign the token, while "alg" specifies
	// the cryptographic algorithm. Both fields are essential for proper multi-key JWT validation.
	HeaderWithKid struct {
		Kid string `json:"kid"` // Key ID - identifies which key was used
		Alg string `json:"alg"` // Algorithm - cryptographic algorithm used
	}

	// Key represents a complete cryptographic key configuration for JWT operations.
	// It combines algorithm specification, key material, and optional features like
	// expiration and encryption into a single manageable unit.
	//
	// This structure supports:
	//   - Asymmetric keys (RSA, ECDSA, EdDSA) with separate public/private components
	//   - Symmetric keys (HMAC) where public and private are the same
	//   - Automatic token expiration via MaxAge
	//   - Payload encryption/decryption for enhanced security
	//
	// Use the package-level parsing functions like ParsePublicKeyRSA, ParsePrivateKeyRSA,
	// etc., to populate the Public and Private fields from PEM data.
	Key struct {
		ID      string        // Unique identifier for this key
		Alg     Alg           // Algorithm implementation for this key
		Public  PublicKey     // Public key for verification (can be nil for HMAC)
		Private PrivateKey    // Private key for signing (required for signing)
		MaxAge  time.Duration // Optional: automatic token expiration
		Encrypt InjectFunc    // Optional: payload encryption function
		Decrypt InjectFunc    // Optional: payload decryption function
	}

	// Keys is a thread-safe registry of cryptographic keys indexed by Key ID.
	//
	// This map-based structure allows applications to manage multiple keys simultaneously,
	// which is essential for:
	//   - Key rotation without service interruption
	//   - Supporting multiple token issuers
	//   - Separating keys by purpose (API access, refresh tokens, etc.)
	//   - Integration with external key sources (JWKS, AWS Cognito, etc.)
	//
	// The Keys type implements HeaderValidator, making it directly usable with
	// VerifyWithHeaderValidator for automatic key selection based on token headers.
	//
	// IMPORTANT: Keys is NOT safe for concurrent modification. Initialize all keys
	// before starting concurrent operations, or use external synchronization.
	//
	// Example:
	//
	//	keys := make(jwt.Keys)
	//	keys.Register(jwt.RS256, "api-key", publicKey, privateKey)
	//	keys.Register(jwt.ES256, "backup-key", backupPublic, backupPrivate)
	//
	//	// Signing automatically includes "kid" header
	//	token, err := keys.SignToken("api-key", claims, jwt.MaxAge(15*time.Minute))
	//
	//	// Verification automatically selects key based on "kid" header
	//	var claims MyClaims
	//	err = keys.VerifyToken(token, &claims)
	//
	//	// Generate JWKS for external consumption
	//	jwks, err := keys.JWKS()
	Keys map[string]*Key

	// KeysConfiguration represents a serializable configuration for multiple JWT keys.
	//
	// This slice-based structure is designed for loading key configurations from
	// external sources like JSON, YAML, TOML, or INI files. It provides a declarative
	// way to define multiple keys with their algorithms, key material, and options.
	//
	// Each KeyConfiguration is converted to a Key during the Load() process,
	// which parses the string-based key data into actual cryptographic objects.
	//
	// See _examples/multiple-kids for a complete usage example.
	//
	// Example JSON configuration:
	//
	//	[
	//	  {
	//	    "id": "api-key",
	//	    "alg": "RS256",
	//	    "private": "-----BEGIN RSA PRIVATE KEY-----\n...",
	//	    "public": "-----BEGIN PUBLIC KEY-----\n...",
	//	    "max_age": "15m"
	//	  }
	//	]
	KeysConfiguration []KeyConfiguration

	// KeyConfiguration defines a single key's configuration in serializable format.
	//
	// This structure uses string fields to represent all key data, making it suitable
	// for JSON/YAML/TOML/INI serialization. The string-based key fields support both
	// PEM-encoded key data and quoted strings for flexibility.
	//
	// The EncryptionKey field enables payload encryption using AES-GCM when specified.
	// The key should be hex-encoded and of appropriate length (16, 24, or 32 bytes
	// for AES-128, AES-192, or AES-256 respectively).
	KeyConfiguration struct {
		ID string `json:"id" yaml:"ID" toml:"ID" ini:"id"`
		// Alg declares the algorithm name.
		// Available values:
		//  * HS256
		//  * HS384
		//  * HS512
		//  * RS256
		//  * RS384
		//  * RS512
		//  * PS256
		//  * PS384
		//  * PS512
		//  * ES256
		//  * ES384
		//  * ES512
		//  * EdDSA
		Alg     string `json:"alg" yaml:"Alg" toml:"Alg" ini:"alg"`
		Private string `json:"private" yaml:"Private" toml:"Private" ini:"private"`
		Public  string `json:"public" yaml:"Public" toml:"Public" ini:"public"`
		// MaxAge sets the token expiration. It is optional.
		// If greater than zero then the MaxAge token validation
		// will be appended to the "VerifyToken" and the token is invalid
		// after expiration of its sign time.
		MaxAge time.Duration `json:"max_age" yaml:"MaxAge" toml:"MaxAge" ini:"max_age"`

		// EncryptionKey enables encryption on the generated token. It is optional.
		// Encryption using the Galois Counter mode of operation with
		// AES cipher symmetric-key cryptographic.
		//
		// It should be HEX-encoded string value.
		//
		// The value should be the AES key,
		// either 16, 24, or 32 bytes to select
		// AES-128, AES-192, or AES-256.
		EncryptionKey string `json:"encryption_key" yaml:"EncryptionKey" toml:"EncryptionKey" ini:"encryption_key"`
	}
)

// Configuration converts a Key instance to a KeyConfiguration for serialization.
//
// This method extracts the key material and converts it to PEM-encoded strings
// suitable for storage in configuration files. It's useful for:
//   - Exporting key configurations for backup
//   - Converting runtime keys to persistent storage format
//   - Creating templates for deployment configurations
//
// Returns an error if:
//   - The key includes encryption functions (not serializable)
//   - The key material cannot be encoded to PEM format
//   - The key type is not supported for encoding
//
// Example:
//
//	key := &jwt.Key{
//	    ID: "my-key",
//	    Alg: jwt.RS256,
//	    Private: privateKey,
//	    Public: publicKey,
//	    MaxAge: 1 * time.Hour,
//	}
//
//	config, err := key.Configuration()
//	// config can now be marshaled to JSON/YAML/etc.
func (key *Key) Configuration() (KeyConfiguration, error) {
	if key.Encrypt != nil || key.Decrypt != nil {
		return KeyConfiguration{}, errors.New("jwt: cannot export keys with encryption")
	}

	var privatePEM, publicPEM string
	if key.Private != nil {
		text, err := EncodePrivateKeyToPEM(key.Private)
		if err != nil {
			return KeyConfiguration{}, fmt.Errorf("jwt: %w", err)
		}
		privatePEM = text
	}
	if key.Public != nil {
		text, err := EncodePublicKeyToPEM(key.Public)
		if err != nil {
			return KeyConfiguration{}, fmt.Errorf("jwt: %w", err)
		}
		publicPEM = text
	}

	config := KeyConfiguration{
		ID:      key.ID,
		Alg:     key.Alg.Name(),
		Private: privatePEM,
		Public:  publicPEM,
		MaxAge:  key.MaxAge,
	}

	return config, nil
}

// Configuration converts a Keys registry to a KeysConfiguration for serialization.
//
// This method processes all keys in the registry and converts them to their
// serializable KeyConfiguration representations. It's particularly useful for:
//   - Creating configuration backups
//   - Exporting keys loaded from JWKS endpoints
//   - Converting runtime key registries to file-based configurations
//   - Template generation for deployment automation
//
// Returns an error if any key in the registry:
//   - Includes encryption functions (not serializable)
//   - Contains key material that cannot be encoded to PEM
//   - Uses unsupported key types
//
// This method is often used in conjunction with JWKS.PublicKeys() to convert
// downloaded public keys into persistent configuration format.
//
// Example:
//
//	// Load keys from JWKS endpoint
//	keys, err := jwt.FetchPublicKeys("https://auth.example.com/.well-known/jwks.json")
//
//	// Convert to configuration for local storage
//	config, err := keys.Configuration()
//
//	// Save to configuration file
//	data, _ := json.MarshalIndent(config, "", "  ")
//	os.WriteFile("keys.json", data, 0644)
func (keys Keys) Configuration() (KeysConfiguration, error) {
	config := make(KeysConfiguration, 0, len(keys))
	for _, key := range keys {
		keyConfig, err := key.Configuration()
		if err != nil {
			return nil, err
		}
		config = append(config, keyConfig)
	}

	return config, nil
}

// EncodePrivateKeyToPEM converts a private key to PEM-encoded string format.
//
// This function supports encoding of private keys for the following algorithms:
//   - RSA: Encodes as PKCS#1 format ("RSA PRIVATE KEY")
//   - ECDSA: Encodes as SEC1 format ("EC PRIVATE KEY")
//   - Ed25519: Encodes as PKCS#8 format ("PRIVATE KEY")
//
// The resulting PEM string can be saved to files, stored in configuration,
// or transmitted securely. It's the inverse operation of the Parse* functions.
//
// Returns an error if the key type is not supported for PEM encoding.
//
// Example:
//
//	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
//	pemString, err := jwt.EncodePrivateKeyToPEM(privateKey)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Save to file
//	err = os.WriteFile("private.pem", []byte(pemString), 0600)
func EncodePrivateKeyToPEM(key PrivateKey) (string, error) {
	var pemBlock *pem.Block

	switch k := key.(type) {
	case *rsa.PrivateKey:
		privBytes := x509.MarshalPKCS1PrivateKey(k)
		pemBlock = &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privBytes,
		}
	case *ecdsa.PrivateKey:
		privBytes, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return "", fmt.Errorf("failed to marshal ECDSA private key: %v", err)
		}
		pemBlock = &pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: privBytes,
		}
	case ed25519.PrivateKey:
		privBytes, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return "", fmt.Errorf("failed to marshal Ed25519 private key: %v", err)
		}
		pemBlock = &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: privBytes,
		}
	default:
		return "", fmt.Errorf("unsupported private key type: %T", key)
	}

	return string(pem.EncodeToMemory(pemBlock)), nil
}

// EncodePublicKeyToPEM converts a public key to PEM-encoded string format.
//
// This function supports encoding of public keys for the following algorithms:
//   - RSA: Encodes in PKIX format ("PUBLIC KEY")
//   - ECDSA: Encodes in PKIX format ("PUBLIC KEY")
//   - Ed25519: Encodes in PKIX format ("PUBLIC KEY")
//
// The resulting PEM string is safe to share publicly and can be distributed
// for token verification. It's commonly used for JWKS generation and
// configuration file storage.
//
// Returns an error if the key type is not supported for PEM encoding.
//
// Example:
//
//	publicKey := &privateKey.PublicKey // From RSA private key
//	pemString, err := jwt.EncodePublicKeyToPEM(publicKey)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Include in JWKS or configuration
//	config := KeyConfiguration{
//	    Public: pemString,
//	    // ... other fields
//	}
func EncodePublicKeyToPEM(key PublicKey) (string, error) {
	var pemBlock *pem.Block

	switch k := key.(type) {
	case *rsa.PublicKey:
		pubBytes, err := x509.MarshalPKIXPublicKey(k)
		if err != nil {
			return "", fmt.Errorf("failed to marshal RSA public key: %v", err)
		}
		pemBlock = &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubBytes,
		}
	case *ecdsa.PublicKey:
		pubBytes, err := x509.MarshalPKIXPublicKey(k)
		if err != nil {
			return "", fmt.Errorf("failed to marshal ECDSA public key: %v", err)
		}
		pemBlock = &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubBytes,
		}
	case ed25519.PublicKey:
		pubBytes, err := x509.MarshalPKIXPublicKey(k)
		if err != nil {
			return "", fmt.Errorf("failed to marshal Ed25519 public key: %v", err)
		}
		pemBlock = &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubBytes,
		}
	default:
		return "", fmt.Errorf("unsupported public key type: %T", key)
	}

	return string(pem.EncodeToMemory(pemBlock)), nil
}

// Clone creates a deep copy of the KeyConfiguration.
//
// This method returns a new KeyConfiguration with all string fields copied.
// Since all fields are strings or basic types, this is equivalent to a deep copy.
// This is useful for creating variations of configurations or ensuring isolation
// when passing configurations between goroutines.
//
// Example:
//
//	original := KeyConfiguration{ID: "key1", Alg: "RS256"}
//	copy := original.Clone()
//	copy.ID = "key2" // Doesn't affect original
func (c KeyConfiguration) Clone() KeyConfiguration {
	return KeyConfiguration{
		ID:            c.ID,
		Alg:           c.Alg,
		Private:       c.Private,
		Public:        c.Public,
		MaxAge:        c.MaxAge,
		EncryptionKey: c.EncryptionKey,
	}
}

// Clone creates a deep copy of the KeysConfiguration.
//
// This method returns a new slice with cloned copies of all KeyConfiguration entries.
// The cloned configuration is independent and can be modified without affecting
// the original. However, the cloned configuration must still be processed with
// Load() or MustLoad() to parse the key material.
//
// This is useful for:
//   - Creating environment-specific configuration variants
//   - Template-based configuration generation
//   - Safe concurrent access to configuration data
//
// Example:
//
//	original := KeysConfiguration{...}
//	development := original.Clone()
//	development[0].EncryptionKey = "dev-encryption-key"
//
//	devKeys := development.MustLoad()
func (c KeysConfiguration) Clone() KeysConfiguration {
	cloned := make(KeysConfiguration, len(c))
	for i, v := range c {
		cloned[i] = v.Clone()
	}
	return cloned
}

// Get retrieves a KeyConfiguration by its ID from the configuration slice.
//
// This method performs a linear search through the configuration slice to find
// a KeyConfiguration with the matching ID. It returns the configuration and
// a boolean indicating whether the key was found.
//
// Example:
//
//	config := KeysConfiguration{...}
//	keyConfig, found := config.Get("api-key")
//	if found {
//	    fmt.Printf("Found key: %s", keyConfig.Alg)
//	}
func (c KeysConfiguration) Get(kid string) (KeyConfiguration, bool) {
	for _, entry := range c {
		if entry.ID == kid {
			return entry, true
		}
	}

	return KeyConfiguration{}, false
}

// MustLoad parses the KeysConfiguration into a Keys registry, panicking on error.
//
// This is a convenience wrapper around Load() that panics if any error occurs
// during key parsing or configuration processing. Use this when you want to
// fail fast during application startup if key configuration is invalid.
//
// Only use MustLoad when:
//   - Configuration is known to be valid (e.g., embedded keys)
//   - Application cannot function without valid keys
//   - You want immediate failure during startup rather than runtime errors
//
// For production applications with external configuration, prefer Load()
// for proper error handling.
//
// Example:
//
//	// Embedded configuration that should always be valid
//	config := KeysConfiguration{...}
//	keys := config.MustLoad() // Panics if invalid
func (c KeysConfiguration) MustLoad() Keys {
	keys, err := c.Load()
	if err != nil {
		panic(err)
	}

	return keys
}

// Load parses the KeysConfiguration into a usable Keys registry.
//
// This method processes each KeyConfiguration entry and converts string-based
// key data into actual cryptographic objects. The parsing process includes:
//   - Algorithm name resolution to Alg implementations
//   - PEM decoding and cryptographic key parsing
//   - Encryption key processing (hex decoding and GCM setup)
//   - Key validation and error checking
//
// The method supports configuration loaded from JSON, YAML, TOML, or INI files.
// String fields may be quoted and will be automatically unquoted during processing.
//
// Returns an error if:
//   - Any algorithm name is not recognized
//   - Key material cannot be parsed (invalid PEM, wrong format, etc.)
//   - Encryption keys are invalid (wrong length, invalid hex, etc.)
//   - GCM cipher initialization fails
//
// Example:
//
//	// Load from JSON file
//	var config KeysConfiguration
//	data, _ := os.ReadFile("keys.json")
//	json.Unmarshal(data, &config)
//
//	keys, err := config.Load()
//	if err != nil {
//	    log.Fatalf("Failed to load keys: %v", err)
//	}
func (c KeysConfiguration) Load() (Keys, error) {
	parsedKeys := make(Keys, len(c))

	for _, entry := range c {
		alg := RS256

		for _, algo := range allAlgs {
			if strings.EqualFold(algo.Name(), entry.Alg) {
				alg = algo
				break
			}
		}

		p := &Key{
			ID:     entry.ID,
			Alg:    alg,
			MaxAge: entry.MaxAge,
		}

		if public, err := strconv.Unquote(entry.Public); err == nil {
			entry.Public = public
		}
		if private, err := strconv.Unquote(entry.Private); err == nil {
			entry.Private = private
		}

		if parser, ok := alg.(AlgParser); ok {
			var err error
			p.Private, p.Public, err = parser.Parse([]byte(entry.Private), []byte(entry.Public))
			if err != nil {
				return nil, fmt.Errorf("jwt: load keys: parse: %w", err)
			}
		} else {
			p.Private = entry.Private
			p.Public = entry.Public
		}

		if entry.EncryptionKey != "" {
			encryptionKey, err := hex.DecodeString(entry.EncryptionKey)
			if err != nil {
				return nil, fmt.Errorf("jwt: load keys: decode encryption key (hex): %w", err)
			}
			encrypt, decrypt, err := GCM([]byte(encryptionKey), nil)
			if err != nil {
				return nil, fmt.Errorf("jwt: load keys: build encryption: %w", err)
			}

			p.Encrypt = encrypt
			p.Decrypt = decrypt
		}

		parsedKeys[entry.ID] = p
	}

	return parsedKeys, nil
}

// Get retrieves a Key from the registry by its Key ID.
//
// This method provides direct access to registered keys using their unique identifiers.
// It's the fundamental lookup mechanism used internally by SignToken, VerifyToken,
// and ValidateHeader methods.
//
// Parameters:
//   - kid: The Key ID to look up
//
// Returns:
//   - *Key: The key if found, nil if not found
//   - bool: true if the key exists, false otherwise
//
// The method is safe for concurrent read access, but the Keys registry itself
// is not safe for concurrent modification. Ensure all keys are registered
// before starting concurrent operations.
//
// Example:
//
//	keys := make(jwt.Keys)
//	keys.Register(jwt.RS256, "api-key", publicKey, privateKey)
//
//	key, exists := keys.Get("api-key")
//	if exists {
//	    fmt.Printf("Found key: %s algorithm\n", key.Alg.Name())
//	} else {
//	    fmt.Println("Key not found")
//	}
func (keys Keys) Get(kid string) (*Key, bool) {
	k, ok := keys[kid]
	return k, ok
}

// Register adds a cryptographic key pair to the Keys registry with a unique identifier.
//
// This method creates a new Key entry in the registry, making it available for
// token signing and verification operations. The registered key will be used
// automatically when its Key ID is referenced in JWT headers.
//
// Parameters:
//   - alg: The cryptographic algorithm implementation to use with this key
//   - kid: Unique Key ID string that will identify this key in JWT headers
//   - pubKey: Public key for token verification (can be nil for HMAC algorithms)
//   - privKey: Private key for token signing (required for signing operations)
//
// The method overwrites any existing key with the same ID without warning.
// This behavior supports key rotation scenarios where old keys are replaced
// with new ones using the same identifier.
//
// IMPORTANT: This method is NOT safe for concurrent use. Register all keys
// during application initialization before starting concurrent operations,
// or use external synchronization if runtime registration is required.
//
// Example:
//
//	keys := make(jwt.Keys)
//
//	// Register RSA key pair
//	keys.Register(jwt.RS256, "rsa-key", &rsaPrivateKey.PublicKey, rsaPrivateKey)
//
//	// Register ECDSA key pair
//	keys.Register(jwt.ES256, "ecdsa-key", &ecdsaPrivateKey.PublicKey, ecdsaPrivateKey)
//
//	// Register HMAC key (public key not needed)
//	keys.Register(jwt.HS256, "hmac-key", nil, hmacSecret)
//
//	// Now keys can be used for signing and verification
//	token, err := keys.SignToken("rsa-key", claims)
func (keys Keys) Register(alg Alg, kid string, pubKey PublicKey, privKey PrivateKey) {
	keys[kid] = &Key{
		ID:      kid,
		Alg:     alg,
		Public:  pubKey,
		Private: privKey,
	}
}

// ValidateHeader validates JWT header and selects the appropriate key for verification.
//
// This method implements the HeaderValidator interface, enabling automatic key selection
// based on the "kid" (Key ID) field in JWT headers. It performs comprehensive validation
// of the token header and returns the cryptographic components needed for verification.
//
// The validation process includes:
//   - JSON unmarshaling of the decoded header
//   - Presence check for required "kid" field
//   - Key lookup in the registry using the Key ID
//   - Algorithm consistency verification between header and key
//   - Optional algorithm parameter validation
//
// Parameters:
//   - alg: Optional algorithm constraint (empty string means no constraint)
//   - headerDecoded: Base64-decoded JWT header JSON data
//
// Returns:
//   - Alg: The algorithm implementation for this key
//   - PublicKey: The public key for signature verification
//   - InjectFunc: Optional decryption function (nil if not configured)
//   - error: Various validation errors (see below)
//
// Possible errors:
//   - JSON unmarshal errors if header is malformed
//   - ErrEmptyKid if "kid" field is missing or empty
//   - ErrUnknownKid if the Key ID is not registered
//   - ErrTokenAlg if algorithms don't match
//
// This method is used internally by VerifyToken and VerifyWithHeaderValidator
// to enable automatic key selection for multi-key JWT verification.
//
// Example usage (typically internal):
//
//	// This is usually called automatically by VerifyToken
//	alg, pubKey, decrypt, err := keys.ValidateHeader("", headerBytes)
//	if err != nil {
//	    return fmt.Errorf("header validation failed: %v", err)
//	}
func (keys Keys) ValidateHeader(alg string, headerDecoded []byte) (Alg, PublicKey, InjectFunc, error) {
	var h HeaderWithKid

	err := Unmarshal(headerDecoded, &h)
	if err != nil {
		return nil, nil, nil, err
	}

	if h.Kid == "" {
		return nil, nil, nil, ErrEmptyKid
	}

	key, ok := keys.Get(h.Kid)
	if !ok {
		return nil, nil, nil, ErrUnknownKid
	}

	if h.Alg != key.Alg.Name() {
		return nil, nil, nil, ErrTokenAlg
	}

	// If for some reason a specific alg was given by the caller then check that as well.
	if alg != "" && alg != h.Alg {
		return nil, nil, nil, ErrTokenAlg
	}

	return key.Alg, key.Public, key.Decrypt, nil
}

// SignToken creates and signs a JWT using the specified key from the registry.
//
// This method provides a high-level interface for JWT creation with multi-key support.
// It automatically includes the Key ID in the JWT header and applies any configured
// key-specific options like MaxAge. The resulting token can be verified using
// VerifyToken or any JWT library that supports the same algorithm.
//
// The method performs the following operations:
//   - Looks up the key by its ID in the registry
//   - Applies key-specific MaxAge if configured
//   - Includes "kid" and "alg" fields in the JWT header
//   - Signs the token using the key's algorithm and private key
//   - Applies optional payload encryption if configured
//
// Parameters:
//   - kid: Key ID identifying which registered key to use for signing
//   - claims: The claims to include in the JWT payload (any JSON-serializable type)
//   - opts: Optional signing options (MaxAge, custom headers, etc.)
//
// Returns:
//   - []byte: The complete JWT token as bytes
//   - error: ErrUnknownKid if the key ID is not registered, or signing errors
//
// The SignOptions are applied in addition to any key-specific options.
// If both the key and the options specify MaxAge, the key's MaxAge takes precedence
// by being applied first.
//
// Example:
//
//	keys := make(jwt.Keys)
//	keys.Register(jwt.RS256, "api-key", publicKey, privateKey)
//
//	claims := jwt.Map{"sub": "user123", "role": "admin"}
//	token, err := keys.SignToken("api-key", claims, jwt.MaxAge(15*time.Minute))
//	if err != nil {
//	    log.Fatalf("Failed to sign token: %v", err)
//	}
//
//	// Token header will include: {"kid":"api-key","alg":"RS256"}
//	fmt.Printf("Token: %s\n", token)
func (keys Keys) SignToken(kid string, claims any, opts ...SignOption) ([]byte, error) {
	k, ok := keys.Get(kid)
	if !ok {
		return nil, ErrUnknownKid
	}

	if k.MaxAge > 0 {
		opts = append([]SignOption{MaxAge(k.MaxAge)}, opts...)
	}

	return SignEncryptedWithHeader(k.Alg, k.Private, k.Encrypt, claims, HeaderWithKid{
		Kid: kid,
		Alg: k.Alg.Name(),
	}, opts...)
}

// VerifyToken verifies a JWT token using automatic key selection and extracts claims.
//
// This method provides a high-level interface for JWT verification with multi-key support.
// It automatically selects the appropriate key based on the "kid" header field and
// performs comprehensive token validation including signature verification and claims validation.
//
// The verification process includes:
//   - JWT header parsing and validation
//   - Automatic key selection based on "kid" field
//   - Algorithm consistency checking
//   - Signature verification using the selected public key
//   - Optional payload decryption if configured
//   - Standard claims validation (exp, nbf, iat, etc.)
//   - Custom claims extraction to the provided destination
//
// Parameters:
//   - token: The JWT token bytes to verify
//   - claimsPtr: Pointer to a structure where verified claims will be unmarshaled
//   - validators: Optional token validators for additional validation logic
//
// Returns:
//   - error: Various validation errors including:
//   - ErrEmptyKid if the token lacks a "kid" header
//   - ErrUnknownKid if the key ID is not registered
//   - ErrTokenAlg if algorithms don't match
//   - Signature verification errors
//   - Claims validation errors
//   - JSON unmarshaling errors for claims
//
// The method supports any claims structure that can be JSON-unmarshaled.
// Use jwt.Map for dynamic claims or custom structs for typed claims.
//
// Example:
//
//	keys := make(jwt.Keys)
//	keys.Register(jwt.RS256, "api-key", publicKey, privateKey)
//
//	// Verify with custom claims struct
//	type MyClaims struct {
//	    Sub  string `json:"sub"`
//	    Role string `json:"role"`
//	    jwt.RegisteredClaims
//	}
//
//	var claims MyClaims
//	err := keys.VerifyToken(token, &claims)
//	if err != nil {
//	    log.Fatalf("Token verification failed: %v", err)
//	}
//
//	fmt.Printf("User: %s, Role: %s\n", claims.Sub, claims.Role)
//
//	// Or verify with dynamic claims
//	var dynamicClaims jwt.Map
//	err = keys.VerifyToken(token, &dynamicClaims)
func (keys Keys) VerifyToken(token []byte, claimsPtr any, validators ...TokenValidator) error {
	verifiedToken, err := VerifyWithHeaderValidator(nil, nil, token, keys.ValidateHeader, validators...)
	if err != nil {
		return err
	}

	return verifiedToken.Claims(&claimsPtr)
}

// JWKS generates a JSON Web Key Set (JWKS) from all registered public keys.
//
// This method creates a JWKS structure containing the public keys from all
// registered keys in the registry. The resulting JWKS is ready for serving
// at the standard /.well-known/jwks.json endpoint to enable external services
// to verify tokens signed by this application.
//
// The JWKS generation process:
//   - Iterates through all registered keys in the registry
//   - Extracts public key material from each key
//   - Converts keys to JWK (JSON Web Key) format with appropriate parameters
//   - Includes algorithm and key ID information for each key
//   - Assembles all JWKs into a JWKS structure
//
// Returns:
//   - *JWKS: Complete JSON Web Key Set ready for serialization
//   - error: Key conversion errors if any key cannot be processed
//
// The generated JWKS follows RFC 7517 specifications and includes:
//   - "kty" (Key Type): RSA, EC, or OKP depending on the algorithm
//   - "kid" (Key ID): Unique identifier for each key
//   - "alg" (Algorithm): The intended algorithm for the key
//   - Key-specific parameters (n, e for RSA; x, y, crv for ECDSA; etc.)
//
// Only public keys are included in the JWKS for security reasons.
// Private keys are never exposed through this interface.
//
// Example:
//
//	keys := make(jwt.Keys)
//	keys.Register(jwt.RS256, "rsa-key", rsaPublic, rsaPrivate)
//	keys.Register(jwt.ES256, "ec-key", ecdsaPublic, ecdsaPrivate)
//
//	jwks, err := keys.JWKS()
//	if err != nil {
//	    log.Fatalf("Failed to generate JWKS: %v", err)
//	}
//
//	// Serve the JWKS at /.well-known/jwks.json
//	http.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
//	    w.Header().Set("Content-Type", "application/json")
//	    json.NewEncoder(w).Encode(jwks)
//	})
//
// See RFC 7517 (https://tools.ietf.org/html/rfc7517) for complete JWKS specifications.
func (keys Keys) JWKS() (*JWKS, error) {
	sets := make([]*JWK, 0, len(keys))

	for _, key := range keys {
		alg := ""
		if key.Alg != nil {
			alg = key.Alg.Name()
		}
		jwk, err := GenerateJWK(key.ID, alg, key.Public)
		if err != nil {
			return nil, err
		}
		sets = append(sets, jwk)
	}

	jwks := JWKS{Keys: sets}
	return &jwks, nil
}
