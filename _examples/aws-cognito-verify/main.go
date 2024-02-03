package main

import (
	"fmt"

	"github.com/kataras/jwt"
)

// |=================================================================================|
// | Amazon's AWS Cognito integration example for token validation and verification. |
// |=================================================================================|

func main() {
	/*
		cognitoConfig := jwt.AWSKeysConfiguration{
			Region:     "us-west-2",
			UserPoolID: "us-west-2_xxx",
		}

		keys, err := cognitoConfig.Load()
		if err != nil {
			panic(err)
		}
		OR:
	*/
	keys, err := jwt.LoadAWSCognitoKeys("us-west-2" /* region */, "us-west-2_xxx" /* user pool id */)
	if err != nil {
		panic(err) // handle error, e.g. pool does not exist in the region.
	}

	var tokenToValidate = `xxx.xxx.xxx` // put a token here issued by your own aws cognito user pool to test it.

	var claims jwt.Map // Your own custom claims here.
	if err := keys.VerifyToken([]byte(tokenToValidate), &claims); err != nil {
		panic(err) // handle error, e.g. token expired, or kid is empty.
	}

	for k, v := range claims {
		fmt.Printf("%s: %v\n", k, v)
	}
}
