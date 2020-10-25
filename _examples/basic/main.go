package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/kataras/jwt"
)

func main() {
	http.HandleFunc("/", getTokenHandler)
	http.HandleFunc("/protected", verifyTokenHandler)

	log.Printf("Server listening on: http://localhost:8080")
	http.ListenAndServe(":8080", nil)
}

/*
Pass the "privateKey" to `Token` (signing) function
and the "publicKey" to the `Verify` function.

// RSA | jwt.RS256/RS384/RS512:
var privateKey, publicKey = jwt.MustLoadRSA(
	"../../_testfiles/rsa_private_key.pem",
	"../../_testfiles/rsa_public_key.pem",
)

// ECDSA | jwt.ES256/ES384/ES512:
var privateKey, publicKey = jwt.MustLoadECDSA(
	"../../_testfiles/ecdsa_private_key.pem",
	"../../_testfiles/ecdsa_public_key.pem",
)

// EdDSA | jwt.EdDSA:
var privateKey, publicKey = jwt.MustLoadEdDSA(
	"../../_testfiles/ed25519_private_key.pem",
	"../../_testfiles/ed25519_public_key.pem",
)
*/

// HMAC | jwt.HS256/HS384/HS512,
// pass the same key on both `Token` and `Verify`.
// Keep it secret; do NOT share this to parties that are not
// responsible to sign and verify tokens
// that were produced by your application.
var sharedKey = []byte("sercrethatmaycontainch@r$32chars") // OR jwt.MustGenerateRandom(32)

// generate token to use.
func getTokenHandler(w http.ResponseWriter, r *http.Request) {
	// now := time.Now()
	// token, err := jwt.Sign(jwt.HS256, sharedKey, map[string]interface{}{
	// 	"iat": now.Unix(),
	// 	"exp": now.Add(15 * time.Minute).Unix(),
	// 	"foo": "bar",
	// })
	// OR:
	claims := jwt.Map{"foo": "bar"} // <- can be any type.
	token, err := jwt.Sign(jwt.HS256, sharedKey, claims, jwt.MaxAge(15*time.Hour))

	if err != nil {
		log.Printf("Generate token failure: %v", err)
		http.Error(w, "failure: sign and encode the token", http.StatusInternalServerError)
		return
	}

	// The jwt package has a helper which returns a string from a []byte token
	// without a memory allocation (unless --tags=safe is added to the go build command).
	// tokenString := jwt.BytesToString(token)
	// OR just:
	tokenString := string(token)

	w.Header().Set("Content-Type", "text/html;charset=utf-8")
	fmt.Fprintf(w, `Token: %s<br/><br/><a href="/protected?token=%s">/protected?token=%s</a>`,
		tokenString, tokenString, tokenString)
}

func verifyTokenHandler(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		log.Printf("Token is missing")
		unauthorized(w)
		return
	}

	// Verify the token and acquire a verified token instance
	// which can be used to bind the custom claims (see `Claims` below).
	verifiedToken, err := jwt.Verify(jwt.HS256, sharedKey, []byte(token))
	if err != nil {
		log.Printf("Verify error: %v", err)
		unauthorized(w)
		return
	}

	// Parse custom claims...
	var claims map[string]interface{}
	// ^ can be any type, e.g.
	// var claims = struct {
	// 	Foo string `json:"foo"`
	// }{}
	if err = verifiedToken.Claims(&claims); err != nil {
		log.Printf("Verify: decode claims: %v", err)
		unauthorized(w)
		return
	}

	fmt.Fprintf(w, "This is an authenticated request made of token: %q\n\n", token)
	for key, value := range claims {
		fmt.Fprintf(w, "%s = %v (%T)\n", key, value, value)
	}

	fmt.Fprintf(w, "\nStandard Claims:\n%#+v", verifiedToken.StandardClaims)
}

func unauthorized(w http.ResponseWriter) {
	http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
}
