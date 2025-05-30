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

type algHMAC struct {
	name   string
	hasher crypto.Hash
}

func (a *algHMAC) Name() string {
	return a.name
}

// func (a *algHMAC) Parse(secret string) (string, error) {
// 	return secret, nil
// }

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

// Key Helper.

var panicHandler = func(v any) {
	panic(v)
}

// MustGenerateRandom returns a random HMAC key.
// Usage:
//
//	MustGenerateRandom(64)
func MustGenerateRandom(n int) []byte {
	key := make([]byte, n)
	_, err := rand.Read(key)
	// _, err := io.ReadFull(rand.Reader, key)
	if err != nil {
		panicHandler(err)
	}

	return key
}

// AI-generated.
const (
	letterBytes   = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" // 52 possibilities
	letterIdxBits = 6                                                      // 6 bits to represent 64 possibilities / indexes
	letterIdxMask = 1<<letterIdxBits - 1                                   // All 1-bits, as many as letterIdxBits
)

// MustGenerateRandomString returns a random string based on the passed length.
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

// NoPadding is the base64.NoPadding.
const NoPadding = base64.NoPadding

// MustGenerateRandomBase64 returns a random base64 string based on the passed length.
//
// Usage:
//
//	MustGenerateRandomBase64(32, jwt.NoPadding)
func MustGenerateRandomBase64(length int, padding rune) string {
	b := MustGenerateRandom(length)
	return base64.StdEncoding.WithPadding(padding).EncodeToString(b)
}

//

// MustLoadHMAC accepts a single filename
// which its plain text data should contain the HMAC shared key.
// Pass the returned value to both `Token` and `Verify` functions.
//
// It panics if the file was not found or unable to read from.
func MustLoadHMAC(filenameOrRaw string) []byte {
	key, err := LoadHMAC(filenameOrRaw)
	if err != nil {
		panicHandler(err)
	}

	return key
}

// LoadHMAC accepts a single filename
// which its plain text data should contain the HMAC shared key.
// Pass the returned value to both `Token` and `Verify` functions.
func LoadHMAC(filenameOrRaw string) ([]byte, error) {
	if fileExists(filenameOrRaw) {
		// load contents from file.
		return ReadFile(filenameOrRaw)
	}

	// otherwise just cast the argument to []byte
	return []byte(filenameOrRaw), nil
}

// fileExists tries to report whether the local physical "path" exists and it's not a directory.
func fileExists(path string) bool {
	if f, err := os.Stat(path); err != nil {
		return os.IsExist(err) && !f.IsDir()
	}

	return true
}
