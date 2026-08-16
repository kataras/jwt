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
	// StatusCode is the HTTP status Cognito returned.
	StatusCode int
	// Message is the text Cognito sent. It comes from a remote party, so it is prefixed
	// rather than returned bare when this value is formatted as an error.
	Message string `json:"message"`
}

// Error returns the error message, marked as coming from Cognito.
//
// The prefix matters. This text is chosen by a remote host and usually ends up in a log
// line, so a message that reads like the application's own wording, or that carries
// newlines, should be recognisable as somebody else's.
func (e AWSCognitoError) Error() string {
	return fmt.Sprintf("jwt: aws cognito: status code: %d: %q", e.StatusCode, e.Message)
}

// FetchAWSCognitoPublicKeys fetches the JSON Web Key Set (JWKS) for a Cognito user pool
// and returns its public keys.
//
// Both arguments go into the URL that is then fetched, so both are checked first. A region
// of "evil.com/x" would otherwise move the request to a host of the caller's choosing, and
// whatever keys came back would be used to verify tokens. Only lowercase letters, digits
// and hyphens are accepted in a region; a user pool identifier may also contain an
// underscore, since Cognito writes them as "us-east-1_AbC123".
//
// The keys are fetched once. There is no cache and no refresh, so a pool that rotates its
// signing key leaves this result stale until you call again.
//
// It returns an AWSCognitoError when Cognito answers with a status of 400 or above and a
// JSON body this package understands, and the underlying error otherwise.
func FetchAWSCognitoPublicKeys(region, userPoolID string) (Keys, error) {
	if err := checkCognitoField("region", region, false); err != nil {
		return nil, err
	}

	if err := checkCognitoField("user pool id", userPoolID, true); err != nil {
		return nil, err
	}

	url := fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json", region, userPoolID)

	keys, err := FetchPublicKeys(url)
	if err != nil {
		var httpErr *HTTPError
		if errors.As(err, &httpErr) {
			var awsErr AWSCognitoError
			if jsonErr := json.Unmarshal(httpErr.Body, &awsErr); jsonErr == nil {
				awsErr.StatusCode = httpErr.StatusCode
				return nil, awsErr
			}
		}

		return nil, err
	}

	return keys, nil
}

// checkCognitoField reports whether a value is safe to interpolate into a URL.
//
// A character allowlist rather than an escape, because neither of these fields has any
// business containing something that needs escaping. Rejecting is the honest answer.
func checkCognitoField(name, value string, allowUnderscore bool) error {
	if value == "" {
		return fmt.Errorf("jwt: aws cognito: %s is empty", name)
	}

	for _, c := range value {
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		case c == '-':
		case c == '_' && allowUnderscore:
		default:
			return fmt.Errorf("jwt: aws cognito: %s contains an unexpected character %q", name, c)
		}
	}

	return nil
}
