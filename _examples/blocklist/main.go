package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/kataras/jwt"
)

func main() {
	// Blocklist is an in-memory storage of tokens that should be
	// immediately invalidated by the server-side.
	// The most common way to invalidate a token, e.g. on user logout,
	// is to make the client-side remove the token itself.
	// /
	// To add your own, e.g. redis, just implement the `jwt.TokenValidator`
	// and use your own methods to force-invalidate a token.
	blocklist := jwt.NewBlocklist(10 * time.Minute)

	http.HandleFunc("/", getTokenHandler)
	http.HandleFunc("/protected", verifyTokenHandler(blocklist))

	log.Printf("Server listening on: http://localhost:8080")

	// http://localhost:8080
	// http://localhost:8080/protected?token=$token
	// http://localhost:8080/protected?token=$token&block=true
	// http://localhost:8080/protected?token=$token (ErrBlocked)
	http.ListenAndServe(":8080", nil)
}

var sharedKey = []byte("sercrethatmaycontainch@r$32chars")

// generate token to use.
func getTokenHandler(w http.ResponseWriter, r *http.Request) {
	customClaims := jwt.Map{
		"foo": "bar",
	}

	token, err := jwt.Sign(jwt.HS256, sharedKey, customClaims, jwt.MaxAge(15*time.Minute))
	if err != nil {
		log.Printf("Generate token failure: %v", err)
		http.Error(w, "failure: sign and encode the token", http.StatusInternalServerError)
		return
	}

	tokenString := jwt.BytesToString(token)

	w.Header().Set("Content-Type", "text/html;charset=utf-8")
	fmt.Fprintf(w, `Token: %s<br/><br/><a href="/protected?token=%s">/protected?token=%s</a>`,
		tokenString, tokenString, tokenString)
}

func verifyTokenHandler(blocklist *jwt.Blocklist) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		if token == "" {
			log.Printf("Token is missing")
			unauthorized(w)
			return
		}

		// Of course in production, this should be replaced
		// by your own custom logic to decide whenever a token should be blocked (e.g user logout).
		shouldBlock := r.URL.Query().Get("block") == "true"

		// Add the "blocklist" to the optional last variadic input arguments of jwt.TokenValidator.
		// It will return `jwt.ErrBlocked` if at least one previous request was
		// made with a "?block=true" url query parameter.
		verifiedToken, err := jwt.Verify(jwt.HS256, sharedKey, []byte(token), blocklist)
		if err != nil {
			log.Printf("Verify error: %v", err)
			unauthorized(w)
			return
		}

		if shouldBlock {
			blocklist.InvalidateToken(verifiedToken.Token, verifiedToken.StandardClaims)
			log.Printf(`The token has been blocked now.
Navigate to http://localhost:8080/protected?token=%s and you should see an ErrBlocked`, token)
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
}

func unauthorized(w http.ResponseWriter) {
	http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
}
