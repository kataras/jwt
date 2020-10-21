package jwt

import (
	"crypto"
	"crypto/hmac"
	_ "crypto/sha256" // ignore:lint
	_ "crypto/sha512"
	"os"
)

type algHMAC struct {
	name   string
	hasher crypto.Hash
}

func (a *algHMAC) Name() string {
	return a.name
}

func (a *algHMAC) Sign(key PrivateKey, headerAndPayload []byte) ([]byte, error) {
	secret, ok := key.([]byte)
	if !ok {
		return nil, ErrInvalidKey
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

// MustLoadHMAC accepts a single filename
// which its plain text data should contain the HMAC shared key.
// Pass the returned value to both `Token` and `VerifyToken` functions.
//
// It panics if the file was not found or unable to read from.
func MustLoadHMAC(filenameOrRaw string) []byte {
	key, err := LoadHMAC(filenameOrRaw)
	if err != nil {
		panic(err)
	}

	return key
}

// LoadHMAC accepts a single filename
// which its plain text data should contain the HMAC shared key.
// Pass the returned value to both `Token` and `VerifyToken` functions.
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
