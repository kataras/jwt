package jwt

import (
	"testing"
)

var testToken = []byte("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImthdGFyYXMifQ.HX22uANEy1qEG0m0utORW4YYfyNeuG9FzvRPMxpSaTc")

func TestEncodeDecodeTokenHMAC(t *testing.T) {
	key := testSecret
	expectedToken := testToken
	testEncodeDecodeToken(t, HS256, key, key, expectedToken)
}

func TestMustLoadHMAC(t *testing.T) {
	catchPanic(t, false, func() {
		MustLoadHMAC("./_testfiles/hmac.key")
		MustLoadHMAC(string(testSecret))
	})
}

func catchPanic(t *testing.T, shouldPanic bool, fn func()) {
	t.Helper()

	got := false
	var val interface{}
	prevHandler := panicHandler
	panicHandler = func(v interface{}) {
		got = true
		val = v
	}

	fn()
	panicHandler = prevHandler

	if shouldPanic != got {
		t.Fatalf("expected panic: %v: %v", got, val)
	}
}
