package jwt

import (
	"encoding/json"
	"errors"
	"fmt"
)

// |=========================================================================|
// | Amazon's AWS Cognito integration for token validation and verification. |
// |=========================================================================|

// AWSCognitoError represents an error response from AWS Cognito.
// It implements the error interface.
type AWSCognitoError struct {
	StatusCode int
	Message    string `json:"message"`
}

// Error returns the error message.
func (e AWSCognitoError) Error() string {
	return e.Message
}

// FetchAWSCognitoPublicKeys fetches the JSON Web Key Set (JWKS) from the AWS Cognito endpoint
// and returns the public keys as Keys map.
// It returns an error if the request fails or the JWKS is invalid.
func FetchAWSCognitoPublicKeys(region, userPoolID string) (Keys, error) {
	url := fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json", region, userPoolID)

	keys, err := FetchPublicKeys(url)
	if err != nil {
		var httpErr httpError
		if errors.As(err, &httpErr) {
			var awsErr AWSCognitoError
			if jsonErr := json.Unmarshal(httpErr.Body, &awsErr); jsonErr == nil {
				return nil, awsErr
			}
		}

		return nil, err
	}

	return keys, nil
}
