module benchmarks

go 1.24

replace github.com/kataras/jwt => ../

require (
	github.com/go-jose/go-jose/v3 v3.0.4
	github.com/golang-jwt/jwt v3.2.2+incompatible
	github.com/kataras/jwt v0.0.0-00010101000000-000000000000
)

require golang.org/x/crypto v0.19.0 // indirect
