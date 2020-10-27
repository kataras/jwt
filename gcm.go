package jwt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

// ErrDecrypt indicates a failure on payload decryption.
var ErrDecrypt = errors.New("decrypt: payload authentication failed")

// GCM sets the `Encrypt` and `Decrypt` package-level functions
// to provide encryption over the token's payload on Sign and decryption on Verify
// using the Galois Counter mode of operation with AES cipher symmetric-key cryptographic.
// It should be called once on initialization of the program and before any Sign/Verify operation.
//
// The key argument should be the AES key,
// either 16, 24, or 32 bytes to select
// AES-128, AES-192, or AES-256.
//
// The additionalData argument is optional.
// Can be set to nil to ignore.
//
// Usage:
// var secretEncryptionKey = MustGenerateRandom(32)
// func init() {
//   GCM(secretEncryptionKey, nil)
// }
// [...]
// And call `Sign` and `Verify` as usual.
func GCM(key, additionalData []byte) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	encrypter := func(payload []byte) ([]byte, error) {
		nonce := make([]byte, gcm.NonceSize())
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return nil, err
		}

		ciphertext := gcm.Seal(nonce, nonce, payload, additionalData)
		return ciphertext, nil
	}

	decrypter := func(ciphertext []byte) ([]byte, error) {
		nonce := ciphertext[:gcm.NonceSize()]
		ciphertext = ciphertext[gcm.NonceSize():]

		plainPayload, err := gcm.Open(nil, nonce, ciphertext, additionalData)
		if err != nil {
			return nil, ErrDecrypt
		}

		return plainPayload, nil
	}

	Encrypt = encrypter
	Decrypt = decrypter

	return nil
}
