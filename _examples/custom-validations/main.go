package main

import (
	"log"
	"time"

	"github.com/kataras/jwt"
)

// Replace with your own keys and keep them secret.
// The "encKey" is used for the encryption and
// the "sigKey" is used for the selected JSON Web Algorithm
// (shared/symmetric HMAC in that case).
var (
	sigKey = jwt.MustGenerateRandom(32)
	encKey = jwt.MustGenerateRandom(32)
)

type myClaims struct {
	Foo string `json:"bar"`
}

func main() {
	token, err := jwt.Sign(jwt.HS256, sigKey, myClaims{Foo: "bar"}, jwt.MaxAge(10*time.Second))
	if err != nil {
		log.Fatal(err)
	}

	verifyWithStandardExpected(token)
	verifyWithLeeway(token)
	verifyWithCustomExpectations(token)

	log.Print("Sleeping for 6 seconds...")
	time.Sleep(6 * time.Second)
	verifyWithCustomExpectations(token) // this should pass.
	// Now sleep for 6 seconds, even if it's not expired,
	// the Leeway adds 5 seconds; 11 > 10, so it should fail with ErrExpired.
	verifyWithLeeway(token) // this should fail.
}

func verifyWithStandardExpected(token []byte) {
	// The last argument of Verify/VerifyEncrypted optionally
	// accepts one or more TokenValidators.
	// Builtin validators: The Blocklist, Expected and Leeway.
	_, err := jwt.Verify(jwt.HS256, sigKey, token, jwt.Expected{
		Issuer: "my-app",
	})

	if err != nil {
		// Should fail with:
		// errors.Is(err, jwt.ErrExpected)
		log.Printf("(verifyWithStandardExpected) token is invalid: %v", err)
		return
	}
}

func verifyWithLeeway(token []byte) {
	verifiedToken, err := jwt.Verify(jwt.HS256, sigKey, token, jwt.Leeway(5*time.Second) /* you can add more validators, e.g. jwt.Expected{} too */)
	if err != nil {
		log.Printf("(verifyWithLeeway) token is invalid: %v", err)
		return
	}

	var claims myClaims
	verifiedToken.Claims(&claims)

	log.Printf("(verifyWithLeeway) Got claims: %#+v", claims)
}

func verifyWithCustomExpectations(token []byte) {
	verifiedToken, err := jwt.Verify(jwt.HS256, sigKey, token)
	if err != nil {
		log.Printf("(verifyWithCustomExpectations) token is invalid: %v", err)
	}

	var claims myClaims
	verifiedToken.Claims(&claims)

	// Here you can add custom type validations.
	if claims.Foo != "bar" {
		log.Printf("expected foo==bar but got: %v", claims.Foo)
		return
	}

	log.Printf("(verifyWithCustomExpectations) Got claims: %#+v", claims)
}
