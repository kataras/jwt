package main

// Check the https://github.com/kataras/jwt/blob/main/kid_keys.go too.

import (
	"fmt"
	"log"
	"time"

	"github.com/kataras/jwt"
)

// Claims is an example of custom claims.
type Claims struct {
	Email string `json:"email"`
}

func main() {
	privateKey, err := jwt.LoadPrivateKeyRSA("../../_testfiles/rsa_private_key.pem")
	if err != nil {
		log.Fatal(err)
	}

	// Generate a token with custom claims and custom jwt header.
	claims := Claims{Email: "kataras2006@hotmail.com"}
	header := Header{
		Kid: "my_key_id_1",
		Alg: jwt.RS256.Name(),
	}
	token, err := jwt.SignWithHeader(jwt.RS256, privateKey, claims, header, jwt.MaxAge(10*time.Minute))
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Generated token: %s", token)

	// Verify the token with a custom header validator and public key per-token.
	verifiedToken, err := jwt.VerifyWithHeaderValidator(jwt.RS256, nil, token, validateHeader)
	if err != nil {
		log.Fatal(err)
	}

	var getClaims Claims
	err = verifiedToken.Claims(&getClaims)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Verified claims: %#+v", getClaims)
}

var keys = map[string][]byte{
	"my_key_id_1": []byte(`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw6OJ4K9LUz6MugrF7uB+
/oZw8/f3J4CSPYZFXMTsWNVQSLlen6/pr7ZvyPsgLvBGikybxRu7ff6ufmHTWTm7
mlpxEv/bgFFUmfH/faY7SA1PJcWMaEMT6s7E96orefyTMNdLi4OKhUGYJ56L8cE1
yRIya+B2UMCg2ItK11TRQlHLwvKRGsFFirc23oHX8gMuduEkIb5dSD6rEaopR3ZM
O1tipfNrlCZs5kTaIubFRJ6K1xy2Rk2hVhqdaX6Ud2aWwrb7o21REkDbqY9YuOGV
/FnDiqDtIoS7MHl5CAguaL9YiOv3RRvCrUttfuHqbljlD7m6/69rMB1cVfbdr5IB
RQIDAQAB
-----END PUBLIC KEY-----
`),
	// ...more keys
}

// Header is an example of custom header.
type Header struct {
	Kid string `json:"kid"`
	Alg string `json:"alg"`
}

func validateHeader(alg string, headerDecoded []byte) (jwt.Alg, jwt.PublicKey, jwt.InjectFunc, error) {
	var h Header
	err := jwt.Unmarshal(headerDecoded, &h)
	if err != nil {
		return nil, nil, nil, err
	}

	if h.Alg != alg {
		return nil, nil, nil, jwt.ErrTokenAlg
	}

	if h.Kid == "" {
		return nil, nil, nil, fmt.Errorf("kid is empty")
	}

	key, ok := keys[h.Kid]
	if !ok {
		return nil, nil, nil, fmt.Errorf("unknown kid")
	}

	publicKey, err := jwt.ParsePublicKeyRSA(key)
	if err != nil {
		return nil, nil, nil, jwt.ErrTokenAlg
	}

	return nil, publicKey, nil, nil
}
