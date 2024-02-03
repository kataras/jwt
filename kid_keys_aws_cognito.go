package jwt

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
)

// |=========================================================================|
// | Amazon's AWS Cognito integration for token validation and verification. |
// |=========================================================================|

// AWSCognitoKeysConfiguration is a configuration for fetching the JSON Web Key Set from AWS Cognito.
// See `LoadAWSCognitoKeys` and its `Load` and `WithClient` methods.
type AWSCognitoKeysConfiguration struct {
	Region     string `json:"region" yaml:"Region" toml:"Region" env:"AWS_COGNITO_REGION"`                 // e.g. "us-west-2"
	UserPoolID string `json:"user_pool_id" yaml:"UserPoolID" toml:"Region" env:"AWS_COGNITO_USER_POOL_ID"` // e.g. "us-west-2_XXX"

	httpClient HTTPClient
}

// LoadAWSCognitoKeys loads the AWS Cognito JSON Web Key Set from the given region and user pool ID.
// It returns the Keys object or an error if the request fails.
// It uses the default http.Client to fetch the JSON Web Key Set.
// It is a shortcut for the following:
//
//	config := jwt.AWSKeysConfiguration{
//	 Region:     region,
//	 UserPoolID: userPoolID,
//	}
//	return config.Load()
func LoadAWSCognitoKeys(region, userPoolID string) (Keys, error) {
	config := AWSCognitoKeysConfiguration{
		Region:     region,
		UserPoolID: userPoolID,
	}
	return config.Load()
}

// WithClient sets the HTTP client to be used for fetching the JSON Web Key Set from AWS Cognito.
// If not set, the default http.Client is used.
func (c *AWSCognitoKeysConfiguration) WithClient(httpClient HTTPClient) *AWSCognitoKeysConfiguration {
	c.httpClient = httpClient
	return c
}

// Load fetches the JSON Web Key Set from AWS Cognito and parses it into a jwt.Keys object.
// It returns the Keys object or an error if the request fails.
// If the HTTP client is not set, the default http.Client is used.
//
// Calls the `ParseAWSCognitoKeys` function with the given configuration.
func (c *AWSCognitoKeysConfiguration) Load() (Keys, error) {
	httpClient := c.httpClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	return ParseAWSCognitoKeys(httpClient, c.Region, c.UserPoolID)
}

// JWKSet represents a JSON Web Key Set.
type JWKSet struct {
	Keys []*JWK `json:"keys"`
}

// JWK represents a JSON Web Key.
type JWK struct {
	Kty string `json:"kty"`
	N   string `json:"n"`
	E   string `json:"e"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
}

// HTTPClient is an interface that can be used to mock the http.Client.
// It is used to fetch the JSON Web Key Set from AWS Cognito.
type HTTPClient interface {
	Get(string) (*http.Response, error)
}

// ParseAWSCognitoKeys fetches the JSON Web Key Set from AWS Cognito and parses it into a jwt.Keys object.
func ParseAWSCognitoKeys(client HTTPClient, region, userPoolID string) (Keys, error) {
	set, err := fetchAWSCognitoJWKSet(client, region, userPoolID)
	if err != nil {
		return nil, err
	}

	return parseAWSCognitoJWKSet(set)
}

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

// fetchAWSCognitoJWKSet fetches the JSON Web Key Set from AWS Cognito.
// It returns the JWKSet object or an error if the request fails.
func fetchAWSCognitoJWKSet(
	client HTTPClient,
	region string,
	userPoolID string,
) (*JWKSet, error) {
	url := fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json", region, userPoolID)

	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		fetchErr := AWSCognitoError{
			StatusCode: resp.StatusCode,
		}

		err = json.NewDecoder(resp.Body).Decode(&fetchErr)
		if err != nil {
			return nil, fmt.Errorf("jwt: cannot decode error message: %w", err)
		}

		return nil, fetchErr
	}

	var jwkSet JWKSet
	err = json.NewDecoder(resp.Body).Decode(&jwkSet)
	if err != nil {
		return nil, err
	}

	return &jwkSet, nil
}

// parseAWSCognitoJWKSet parses the JWKSet object into a jwt.Keys object.
// It returns the Keys object or an error if the parsing fails.
// It filters out unsupported algorithms.
func parseAWSCognitoJWKSet(set *JWKSet) (Keys, error) {
	keys := make(Keys, len(set.Keys))
	for _, key := range set.Keys {
		alg := parseAlg(key.Alg)
		if alg == nil {
			continue
		}

		publicKey, err := convertJWKToPublicKey(key)
		if err != nil {
			return nil, err
		}

		keys[key.Kid] = &Key{
			ID:     key.Kid,
			Alg:    alg,
			Public: publicKey,
		}
	}

	return keys, nil
}

// convertJWKToPublicKey converts a JWK object to a *rsa.PublicKey object.
func convertJWKToPublicKey(jwk *JWK) (*rsa.PublicKey, error) {
	// decode the n and e values from base64.
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, err
	}

	// construct a big.Int from the n bytes.
	n := new(big.Int).SetBytes(nBytes)

	// construct an int from the e bytes.
	var e int
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}

	// construct a *rsa.PublicKey from the n and e values.
	pubKey := &rsa.PublicKey{
		N: n,
		E: e,
	}

	return pubKey, nil
}
