package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/kataras/jwt"
)

var sharedKey = []byte("sercrethatmaycontainch@r$32chars")

func main() {
	http.HandleFunc("/", getTokenHandler)
	http.HandleFunc("/protected", verify(protectedHandler))

	log.Printf("Server listening on: http://localhost:8080")
	http.ListenAndServe(":8080", nil)
}

// Generate token.
func getTokenHandler(w http.ResponseWriter, r *http.Request) {
	now := time.Now()

	token, err := jwt.Sign(jwt.HS256, sharedKey, map[string]interface{}{
		"iat": now.Unix(),
		"exp": now.Add(15 * time.Minute).Unix(),
		"foo": "bar",
	})

	if err != nil {
		log.Printf("Generate token failure: %v", err)
		http.Error(w, "failure: sign and encode the token", http.StatusInternalServerError)
		return
	}

	tokenString := string(token)

	w.Header().Set("Content-Type", "text/html;charset=utf-8")
	fmt.Fprintf(w, `Token: %s<br/><br/><a href="/protected?token=%s">/protected?token=%s</a>`,
		tokenString, tokenString, tokenString)
}

// A route handler that always executed on verified requests.
func protectedHandler(w http.ResponseWriter, r *http.Request) {
	verifiedToken := r.Context().Value(tokenContextKey).(*jwt.VerifiedToken)

	var claims map[string]interface{}
	// ^ can be any type, e.g.
	// var claims = struct {
	// 	Foo string `json:"foo"`
	// }{}
	if err := verifiedToken.Claims(&claims); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	fmt.Fprintf(w, "This is an authenticated request made of token: %q\n\n", verifiedToken.Token)
	for key, value := range claims {
		fmt.Fprintf(w, "%s = %v (%T)\n", key, value, value)
	}

	fmt.Fprintf(w, "\nStandard Claims:\n%#+v\n", verifiedToken.StandardClaims)
}

// -----------------------------------|
// Our HTTP middleware implementation |
// -----------------------------------|

type contextKey uint8

const tokenContextKey contextKey = 1

// Our JWT middleware.
// Usage: http.HandleFunc("/route", verify(routeHandler))
// and see the `protectedHandler`.
func verify(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		if token == "" {
			unauthorized(w)
			return
		}

		verifiedToken, err := jwt.Verify(jwt.HS256, sharedKey, []byte(token))
		if err != nil {
			unauthorized(w)
			return
		}
		// OK, the token is verified.
		//
		// Store the verified token instance to the context of the Request instance,
		// to give the ability to the handler itself decode the custom claims to a custom Go value type.
		// If the last is not required, you can store and share
		// the map or the go structure value instead of the "verifiedToken" instance (see the 'verify2' example).
		r = r.WithContext(context.WithValue(r.Context(), tokenContextKey, verifiedToken))
		// Finally, execute the next handler.
		next(w, r)
	}
}

// Usage:
// http.HandleFunc("/route", verify(routeHandler))
// claims := r.Context().Value(tokenContextKey).(jwt.Map)
func verify2(next http.HandlerFunc) http.HandlerFunc {
	/*
		Another idea, when you want a single middleware to support different
		Go structs (benefit: type safety when access the claims fields):
		verify2(getClaimsPtr func() interface{}, next http.HandlerFunc) {
			// [...]
			claimsPtr := getClaimsPtr()
			verifiedToken.Claims(claimsPtr)
			// [...]
		}
		Another idea's usage:
		verify2(func() interface{} {
			return &userClaims{}
		}, routeHandler)
		Inside the handler:
		claims := r.Context().Value(tokenContextKey).(*userClaims)
	*/
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		if token == "" {
			unauthorized(w)
			return
		}

		verifiedToken, err := jwt.Verify(jwt.HS256, sharedKey, []byte(token))
		if err != nil {
			unauthorized(w)
			return
		}

		var claims jwt.Map
		// Another idea:
		// claimsPtr := getClaimsFunc()
		// verifiedToken.Claims(claimsPtr)
		if err = verifiedToken.Claims(&claims); err != nil {
			unauthorized(w)
			return
		}

		// Store the the map or the go structure claims value directly.
		r = r.WithContext(context.WithValue(r.Context(), tokenContextKey, claims))
		// Finally, execute the next handler.
		next(w, r)
	}
}

func unauthorized(w http.ResponseWriter) {
	http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
}
