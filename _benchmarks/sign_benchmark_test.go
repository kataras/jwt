package benchmarks

import (
	"testing"
	"time"

	jwtgo "github.com/dgrijalva/jwt-go"
	jose "github.com/go-jose/go-jose/v3"
	josejwt "github.com/go-jose/go-jose/v3/jwt"
	jwt "github.com/kataras/jwt"
)

var testSecret = []byte("sercrethatmaycontainch@r$32chars")

func BenchmarkSign_Map(b *testing.B) {
	type testStruct struct {
		Foo string `json:"foo"`
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// supports custom types and expiration helper.
		now := time.Now()
		claims := map[string]interface{}{
			"foo": "bar",
			"exp": now.Add(15 * time.Minute).Unix(),
			"iat": now.Unix(),
		}
		_, err := jwt.Sign(jwt.HS256, testSecret, claims)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSign_Struct(b *testing.B) {
	type testStruct struct {
		Foo string `json:"foo"`
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// supports custom types and expiration helper.
		claims := testStruct{Foo: "bar"}
		_, err := jwt.Sign(jwt.HS256, testSecret, claims, jwt.MaxAge(15*time.Minute))
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSign_jwt_go_Map(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		now := time.Now()
		claims := jwtgo.MapClaims{
			"foo": "bar",
			"exp": time.Now().Add(15 * time.Minute).Unix(),
			"iat": now.Unix(),
		}
		token := jwtgo.NewWithClaims(jwtgo.SigningMethodHS256, claims)
		_, err := token.SignedString(testSecret)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSign_jwt_go_Struct(b *testing.B) {
	// This is the official example as shown at:
	// https://github.com/dgrijalva/jwt-go/blob/dc14462fd58732591c7fa58cc8496d6824316a82/example_test.go#L31
	type MyCustomClaims struct {
		Foo string `json:"foo"`
		jwtgo.StandardClaims
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		now := time.Now()
		claims := MyCustomClaims{
			Foo: "bar",
			StandardClaims: jwtgo.StandardClaims{
				ExpiresAt: now.Add(15 * time.Minute).Unix(),
				IssuedAt:  time.Now().Unix(),
			},
		}

		token := jwtgo.NewWithClaims(jwtgo.SigningMethodHS256, claims)
		_, err := token.SignedString(testSecret)
		if err != nil {
			b.Fatal(err)
		}
	}
}

type testStructJwtGo struct {
	Foo      string `json:"foo"`
	Expiry   int64  `json:"exp"`
	IssuedAt int64  `json:"iat"`
}

var _ jwtgo.Claims = testStructJwtGo{}

func (c testStructJwtGo) Valid() error { return nil }

func BenchmarkSign_jwt_go_Struct2(b *testing.B) {
	// This is our example, which performs better than its official docs
	// (in order to have a fair benchmark between the rest).
	//
	// Does support custom type but:
	// 1. Should implement a Valid() error although it's never called on its Signing process(...)
	// 2. it should provide the "exp", "iat" by its own and
	// 3. it does not provide automatic validation on its Verify status(!)
	// It does not support separate helper for max age, so it needs a separate jwt claims struct,
	// unlike kataras/jwt which you can specify an already defined struct without a single modification of its fields.
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		now := time.Now()
		// Reproduce the behavior of the kataras/jwtgo.MaxAge helper.
		claims := testStructJwtGo{
			Foo:      "bar",
			Expiry:   now.Add(15 * time.Minute).Unix(),
			IssuedAt: now.Unix(),
		}
		token := jwtgo.NewWithClaims(jwtgo.SigningMethodHS256, claims)
		_, err := token.SignedString(testSecret)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSign_go_jose_Map(b *testing.B) {
	// To be fair with the rest benchmarks,
	// the signer should be part of the benchmark time,
	// however, let's move it outside, even with that test-benefit,
	// this is the slower implementation by far:/
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.HS256,
		Key:       testSecret,
	}, (&jose.SignerOptions{}).WithType("JWT"))

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Support custom types but not expiration helper, so use map here to set the "exp" too.
		// If we define a struct with an "exp" json tag we should be able to reproduce
		// the same, however this means that you need separate structs for JWT and other usage,
		// unlike kataras/jwt which u can use already defined structs.
		// We will benchmark it with structs (see below test).
		now := time.Now()
		claims := map[string]interface{}{
			"foo": "bar",
			"exp": now.Add(15 * time.Minute).Unix(),
			"iat": now.Unix(),
		}
		_, err = josejwt.Signed(signer).Claims(claims).CompactSerialize()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSign_go_jose_Struct(b *testing.B) {
	// We define a struct with an "exp" json tag we should be able to reproduce
	// the same, however this means that you need separate structs for JWT and other usage,
	// unlike kataras/jwt which u can use already defined structs.
	//
	// This is slower than its map test because internally the go-jose library converts
	// the structure to a map and then marshals again...
	type testStructWithStandardClaim struct {
		Foo      string `json:"foo"`
		Expiry   int64  `json:"exp"`
		IssuedAt int64  `json:"iat"`
	}

	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.HS256,
		Key:       testSecret,
	}, (&jose.SignerOptions{}).WithType("JWT"))

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		now := time.Now()
		// Reproduce the behavior of the kataras/jwtgo.MaxAge helper.
		claims := testStructWithStandardClaim{
			Foo:      "bar",
			Expiry:   now.Add(15 * time.Minute).Unix(),
			IssuedAt: now.Unix(),
		}
		_, err = josejwt.Signed(signer).Claims(claims).CompactSerialize()
		if err != nil {
			b.Fatal(err)
		}
	}
}
