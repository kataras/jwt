module benchmarks

go 1.19

replace github.com/kataras/jwt => ../

require (
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/go-jose/go-jose/v3 v3.0.0
	github.com/kataras/jwt v0.0.0-00010101000000-000000000000
)

require golang.org/x/crypto v0.6.0 // indirect
