package main

import (
	"crypto/rsa"
	"fmt"
	"log"
	"net/http"

	"github.com/kataras/jwt"
)

var publicKey *rsa.PublicKey

func init() {
	var err error
	publicKey, err = jwt.LoadPublicKeyRSA("./public_key.pem")
	if err != nil {
		panic(err)
	}

	// Customize header and public key. This is useful when you want to accept different type of algorithms.
	// compareHeader := func(alg string, headerDecoded []byte) (jwt.Alg, jwt.PublicKey, error) {
	// 	return jwt.RS512, publicKey, nil
	// }
	//
	// jwt.CompareHeader = compareHeader
	// OR if you don't want to change it globally, use the VerifyWithHeaderValidator when verifying a token:
	// verifiedToken, err := jwt.VerifyWithHeaderValidator(jwt.RS256, publicKey, token, compareHeader)
}

func main() {

	http.HandleFunc("/protected", verifyTokenHandler)

	log.Printf("Server listening on: http://localhost:8080")
	http.ListenAndServe(":8080", nil)
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
	verifiedToken, err := jwt.Verify(jwt.RS512, publicKey, []byte(token))
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
