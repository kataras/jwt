package benchmarks

import (
	"testing"
	"time"

	jwtgo "github.com/dgrijalva/jwt-go"
	josejwt "github.com/go-jose/go-jose/v3/jwt"
	jwt "github.com/kataras/jwt"
)

func createTestToken() ([]byte, error) {
	claims := jwt.Map{"foo": "bar"}
	return jwt.Sign(jwt.HS256, testSecret, claims, jwt.MaxAge(15*time.Minute))
}

// Test performance of Verify.

func BenchmarkVerify(b *testing.B) {
	token, err := createTestToken()
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err = jwt.Verify(jwt.HS256, testSecret, token)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerify_jwt_go(b *testing.B) {
	token, err := createTestToken()
	if err != nil {
		b.Fatal(err)
	}

	tokenString := string(token)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := jwtgo.Parse(tokenString, func(token *jwtgo.Token) (interface{}, error) {
			return testSecret, nil
		})
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerify_go_jose(b *testing.B) {
	token, err := createTestToken()
	if err != nil {
		b.Fatal(err)
	}

	tokenString := string(token)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Note: the go-jose package's `ParseSigned` does not actually verify the token,
		// it just decodes it, we have to call its `Claims` method without a destination (2nd arg)
		// to make it to verify the signature (the fastest way to do it on that package)
		// unlike the rest (kataras/jwt and dgrijalva/jwt-go).
		parsedToken, err := josejwt.ParseSigned(tokenString)
		if err != nil {
			b.Fatal(err)
		}

		err = parsedToken.Claims(testSecret)
		if err != nil {
			b.Fatal(err)
		}
	}
}
