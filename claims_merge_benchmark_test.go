package jwt

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"
)

type testStruct struct {
	Username string `json:"username"`
	Age      int    `json:"age"`
}

func BenchmarkSignWithMerge(b *testing.B) { // faster.
	for i := 0; i < b.N; i++ {
		if _, err := Sign(testAlg, testSecret, testStruct{ // init in the test.
			Username: "kataras",
			Age:      27,
		}, MaxAge(15*time.Minute)); err != nil {
			b.Fatal(err)
		}
	}
}

var testStructValue = testStruct{
	Username: "kataras",
	Age:      27,
}

// Follows benchmarks to see which way is fastest to automatically add "exp" and "iat" standard JWT claims.
// The initial and unique idea of the `Merge` function is the fastest(x3) implementation one.

func BenchmarkSignWithoutMerge(b *testing.B) { // slower
	for i := 0; i < b.N; i++ {
		claims := Map{"username": "kataras", "age": 27} // init in the test.
		MaxAgeMap(15*time.Minute, claims)
		if _, err := Sign(testAlg, testSecret, claims); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMerge(b *testing.B) { // Our way is the fastest and others' advandages are not worth, keep it.
	now := Clock()
	iat := now.Unix()
	exp := now.Add(15 * time.Minute).Unix()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		claims := Merge(testStructValue, Claims{Expiry: exp, IssuedAt: iat})
		payload, err := Marshal(claims)
		if err != nil {
			b.Fatal(err)
		}
		if len(payload) == 0 {
			b.Fatal("empty payload")
		}
	}
}

func BenchmarkStructToMapJSON(b *testing.B) {
	now := Clock()
	iat := now.Unix()
	exp := now.Add(15 * time.Minute).Unix()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		claims, err := structToMapJSON(testStructValue)
		if err != nil {
			b.Fatal(err)
		}

		if claims["exp"] == nil {
			claims["exp"] = exp
			claims["iat"] = iat
		}

		payload, err := Marshal(claims)
		if err != nil {
			b.Fatal(err)
		}
		if len(payload) == 0 {
			b.Fatal("empty payload")
		}
	}
}

func BenchmarkStructToMapReflection(b *testing.B) {
	now := Clock()
	iat := now.Unix()
	exp := now.Add(15 * time.Minute).Unix()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		claims, err := structToMapReflection(testStructValue)
		if err != nil {
			b.Fatal(err)
		}

		if claims["exp"] == nil {
			claims["exp"] = exp
			claims["iat"] = iat
		}

		payload, err := Marshal(claims)
		if err != nil {
			b.Fatal(err)
		}
		if len(payload) == 0 {
			b.Fatal("empty payload")
		}
	}
}

func structToMapJSON(i interface{}) (Map, error) {
	if m, ok := i.(Map); ok {
		return m, nil
	}

	m := make(Map)

	raw, err := json.Marshal(i)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}

	return m, nil
}

func structToMapReflection(i interface{}) (Map, error) {
	if m, ok := i.(Map); ok {
		return m, nil
	}

	v := reflect.Indirect(reflect.ValueOf(i))
	if v.Kind() != reflect.Struct {
		return nil, fmt.Errorf("structToMapReflection only accepts structs; got %T", v)
	}

	n := v.NumField()
	m := make(map[string]interface{}, n)

	typ := v.Type()
	for i := 0; i < n; i++ {
		fieldTyp := typ.Field(i)
		if fieldTyp.PkgPath != "" {
			continue
		}

		if tag := fieldTyp.Tag.Get("json"); tag != "" {
			m[tag] = v.Field(i).Interface()
		}
	}
	return m, nil
}
