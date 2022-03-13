package main

import (
	"log"
	"os"
	"time"

	"github.com/kataras/jwt"

	"gopkg.in/yaml.v3"
)

func main() {
	var c Configuration
	if err := bindConfigurationFile("./server.yml", &c); err != nil {
		panic(err)
	}

	//
	keys := c.WebKeys.MustLoad()
	//

	claims := UserClaims{
		Firstname: "Gerasimos",
	}

	//
	token, err := keys.SignToken("user", claims, jwt.MaxAge(2*time.Hour))
	//
	if err != nil {
		panic(err)
	}

	log.Printf("signed claims: %#+v\n token generated: %s\n\n\n", claims, string(token))

	var gotClaims UserClaims
	//
	err = keys.VerifyToken(token, &gotClaims)
	//
	if err != nil {
		panic(err)
	}

	log.Printf("verified token, custom claims got: %#+v\n", claims)
}

type UserClaims struct {
	Firstname string `json:"firstname"`
}

type Configuration struct {
	Port int `yaml:"Port"`

	WebKeys jwt.KeysConfiguration `yaml:"WebKeys"`
}

// bind configuration.
func bindConfigurationFile(filename string, c *Configuration) error {
	contents, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	return yaml.Unmarshal(contents, c)
}
