package jwt

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	_ "crypto/sha256" // ignore:lint
	_ "crypto/sha512"
	"encoding/base64"
	"fmt"
	"os"
)

// algHMAC implements the Alg interface for HMAC-based JWT signature algorithms.
//
// This structure provides the core implementation for HMAC (Hash-based Message
// Authentication Code) algorithms used in JWT signing and verification. HMAC
// algorithms are symmetric, meaning the same key is used for both signing and
// verification operations.
//
// **Supported Variants**:
//   - HS256: HMAC with SHA-256 (most common, 32-byte output)
//   - HS384: HMAC with SHA-384 (48-byte output)
//   - HS512: HMAC with SHA-512 (64-byte output)
//
// **Security Properties**:
//   - Symmetric algorithm requiring shared secret key
//   - Provides both authenticity and integrity verification
//   - Resistant to length extension attacks (unlike plain hashing)
//   - Fast computation suitable for high-throughput scenarios
//
// **Key Requirements**:
//   - Must be []byte type for compatibility
//   - Minimum length should match hash output size for security
//   - Should use cryptographically secure random generation
//   - Must be kept secret and shared securely between parties
//
// **Thread Safety**: This implementation is thread-safe and can be used
// concurrently across multiple goroutines. Each signing/verification
// operation creates a new HMAC instance.
//
// **Performance**: HMAC operations are highly optimized and typically
// faster than asymmetric algorithms (RSA, ECDSA, EdDSA), making them
// ideal for high-frequency token operations.
type algHMAC struct {
	name   string      // Algorithm name (e.g., "HS256", "HS384", "HS512")
	hasher crypto.Hash // Hash function to use (SHA256, SHA384, or SHA512)
}

// Name returns the HMAC algorithm identifier used in JWT headers.
//
// This method satisfies the Alg interface requirement and returns the
// standard algorithm name that will be included in the JWT "alg" header field.
//
// **Return Values**:
//   - "HS256" for HMAC-SHA256
//   - "HS384" for HMAC-SHA384
//   - "HS512" for HMAC-SHA512
//
// **Usage**: This value is automatically included in JWT headers during
// token creation and used for algorithm validation during verification.
//
// Example:
//
//	alg := jwt.HS256
//	fmt.Println(alg.Name()) // Output: "HS256"
func (a *algHMAC) Name() string {
	return a.name
}

// Sign implements the Alg interface for HMAC signature generation.
// It creates an HMAC signature using the provided shared secret key.
//
// The key must be a []byte containing the shared secret. For security,
// the key should be at least as long as the hash output:
// - HS256: 32 bytes minimum
// - HS384: 48 bytes minimum
// - HS512: 64 bytes minimum
//
// Returns an error if the key is not a []byte.
func (a *algHMAC) Sign(key PrivateKey, headerAndPayload []byte) ([]byte, error) {
	secret, ok := key.([]byte)
	if !ok {
		return nil, fmt.Errorf("expected a string: %w", ErrInvalidKey)
	}

	// We can improve its performance (if we store the secret on the same structure)
	// by using a pool and its Reset method.
	h := hmac.New(a.hasher.New, secret)
	// header.payload
	_, err := h.Write(headerAndPayload)
	if err != nil {
		return nil, err // this should never happen according to the internal docs.
	}

	return h.Sum(nil), nil
}

// Verify implements the Alg interface for HMAC signature verification.
// It verifies an HMAC signature using the provided shared secret key.
//
// This method uses constant-time comparison to prevent timing attacks.
// The key should be the same []byte secret used for signing.
func (a *algHMAC) Verify(key PublicKey, headerAndPayload []byte, signature []byte) error {
	expectedSignature, err := a.Sign(key, headerAndPayload)
	if err != nil {
		return err
	}

	if !hmac.Equal(expectedSignature, signature) {
		return ErrTokenSignature
	}

	return nil
}

// Key Helpers.

// panicHandler is used by Must* functions to handle panics.
// It can be overridden for testing purposes.
var panicHandler = func(v any) {
	panic(v)
}

// MustGenerateRandom generates a cryptographically secure random byte slice of length n.
// This is suitable for creating HMAC keys.
//
// For HMAC algorithms, recommended key sizes are:
// - HS256: 32 bytes
// - HS384: 48 bytes
// - HS512: 64 bytes
//
// This function panics if random generation fails.
// Use crypto/rand.Read directly for error handling.
//
// Example:
//
//	key := jwt.MustGenerateRandom(32) // For HS256
//	token, err := jwt.Sign(jwt.HS256, key, claims)
func MustGenerateRandom(n int) []byte {
	key := make([]byte, n)
	_, err := rand.Read(key)
	// _, err := io.ReadFull(rand.Reader, key)
	if err != nil {
		panicHandler(err)
	}

	return key
}

// Constants for random string generation.
const (
	letterBytes   = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" // 52 possibilities
	letterIdxBits = 6                                                      // 6 bits to represent 64 possibilities / indexes
	letterIdxMask = 1<<letterIdxBits - 1                                   // All 1-bits, as many as letterIdxBits
)

// MustGenerateRandomString generates a cryptographically secure random string of the specified length.
// The string contains only letters (a-z, A-Z).
//
// This function uses a secure random number generator and efficient bit manipulation
// to generate random strings suitable for keys, tokens, or identifiers.
//
// This function panics if random generation fails.
//
// Example:
//
//	randomStr := jwt.MustGenerateRandomString(32)
//	fmt.Println(randomStr) // Output: "aBcDeFgHiJkLmNoPqRsTuVwXyZ..."
func MustGenerateRandomString(length int) string {
	result := make([]byte, length)
	bufferSize := int(float64(length) * 1.3)
	for i, j, randomBytes := 0, 0, []byte{}; i < length; j++ {
		if j%bufferSize == 0 {
			randomBytes = MustGenerateRandom(bufferSize)
		}
		if idx := int(randomBytes[j%length] & letterIdxMask); idx < len(letterBytes) {
			result[i] = letterBytes[idx]
			i++
		}
	}

	return string(result)
}

// NoPadding is an alias for base64.NoPadding for convenience.
const NoPadding = base64.NoPadding

// MustGenerateRandomBase64 generates a cryptographically secure random base64-encoded string.
//
// The length parameter specifies the number of random bytes to generate before encoding.
// The padding parameter controls base64 padding ('=' characters).
// Use jwt.NoPadding or base64.NoPadding to disable padding.
//
// This function panics if random generation fails.
//
// Example:
//
//	// Generate 32 random bytes, base64-encoded without padding
//	randomB64 := jwt.MustGenerateRandomBase64(32, jwt.NoPadding)
//
//	// Generate 24 random bytes, base64-encoded with standard padding
//	randomB64 := jwt.MustGenerateRandomBase64(24, base64.StdPadding)
func MustGenerateRandomBase64(length int, padding rune) string {
	b := MustGenerateRandom(length)
	return base64.StdEncoding.WithPadding(padding).EncodeToString(b)
}

//

// MustLoadHMAC loads an HMAC key from a file or treats the input as raw key data.
//
// If the input is a valid file path, it reads the file contents as the key.
// Otherwise, it treats the input string as raw key data and converts it to []byte.
// This provides flexibility for both file-based and inline key configuration.
//
// Pass the returned value to both Sign and Verify functions.
//
// This function panics if the file cannot be read. Use LoadHMAC for error handling.
//
// Example:
//
//	// Load from file
//	key := jwt.MustLoadHMAC("secret.key")
//
//	// Use raw string
//	key := jwt.MustLoadHMAC("my-secret-key-here")
//
//	token, err := jwt.Sign(jwt.HS256, key, claims)
func MustLoadHMAC(filenameOrRaw string) []byte {
	key, err := LoadHMAC(filenameOrRaw)
	if err != nil {
		panicHandler(err)
	}

	return key
}

// LoadHMAC loads an HMAC key from a file or treats the input as raw key data.
//
// If the input is a valid file path, it reads the file contents as the key.
// Otherwise, it treats the input string as raw key data and converts it to []byte.
// This provides flexibility for both file-based and inline key configuration.
//
// Pass the returned value to both Sign and Verify functions.
//
// Returns an error if the file exists but cannot be read.
//
// Example:
//
//	// Load from file
//	key, err := jwt.LoadHMAC("secret.key")
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Use raw string (never fails)
//	key, _ := jwt.LoadHMAC("my-secret-key-here")
//
//	token, err := jwt.Sign(jwt.HS256, key, claims)
func LoadHMAC(filenameOrRaw string) ([]byte, error) {
	if fileExists(filenameOrRaw) {
		// load contents from file.
		return ReadFile(filenameOrRaw)
	}

	// otherwise just cast the argument to []byte
	return []byte(filenameOrRaw), nil
}

// fileExists checks whether the given path exists and is a regular file (not a directory).
// This is used internally to determine whether to treat input as a filename or raw data.
func fileExists(path string) bool {
	if f, err := os.Stat(path); err != nil {
		return os.IsExist(err) && !f.IsDir()
	}

	return true
}
