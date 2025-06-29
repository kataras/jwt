package jwt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

// ErrDecrypt indicates a failure during payload decryption.
// This error is returned when GCM authentication fails, which could indicate
// tampering, corruption, or use of the wrong decryption key.
var ErrDecrypt = errors.New("jwt: decrypt: payload authentication failed")

// GCM creates encrypt and decrypt functions for JWT payload encryption
// using AES-GCM (Galois/Counter Mode) authenticated encryption.
//
// This function provides an additional layer of security by encrypting the JWT payload
// before signing. The encrypted payload is opaque to intermediate parties and provides
// both confidentiality and integrity protection.
//
// Parameters:
//   - key: AES encryption key, must be 16, 24, or 32 bytes for AES-128, AES-192, or AES-256
//   - additionalData: Optional authenticated data (AAD), can be nil
//
// Returns two InjectFunc functions for encryption and decryption, or an error if
// the key size is invalid or cipher initialization fails.
//
// The encryption function prepends a random nonce to the ciphertext.
// The decryption function extracts the nonce and authenticates the data.
//
// Example:
//
//	// Generate keys
//	encKey := jwt.MustGenerateRandom(32)  // AES-256 key
//	sigKey := jwt.MustGenerateRandom(32)  // HMAC key
//
//	// Create encrypt/decrypt functions
//	encrypt, decrypt, err := jwt.GCM(encKey, nil)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Sign with encryption
//	token, err := jwt.SignEncrypted(jwt.HS256, sigKey, encrypt, claims, jwt.MaxAge(15*time.Minute))
//
//	// Verify with decryption
//	verifiedToken, err := jwt.VerifyEncrypted(jwt.HS256, sigKey, decrypt, token)
func GCM(key, additionalData []byte) (encrypt, decrypt InjectFunc, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	encrypt = func(payload []byte) ([]byte, error) {
		nonce := make([]byte, gcm.NonceSize())
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return nil, err
		}

		ciphertext := gcm.Seal(nonce, nonce, payload, additionalData)
		return ciphertext, nil
	}

	decrypt = func(ciphertext []byte) ([]byte, error) {
		nonce := ciphertext[:gcm.NonceSize()]
		ciphertext = ciphertext[gcm.NonceSize():]

		plainPayload, err := gcm.Open(nil, nonce, ciphertext, additionalData)
		if err != nil {
			return nil, ErrDecrypt
		}

		return plainPayload, nil
	}

	return
}
