package jwt

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"time"
)

// FetchPublicKeys fetches a JSON Web Key Set (JWKS) from the specified URL
// and returns the public keys as a Keys map for JWT verification.
//
// This is a convenience function that combines FetchJWKS and JWKS.PublicKeys()
// operations. It uses the default HTTP client and is suitable for most
// standard JWKS fetching scenarios.
//
// Parameters:
//   - url: The JWKS endpoint URL, typically ending with /.well-known/jwks.json
//
// Supported Algorithms:
//   - RSA: RS256, RS384, RS512, PS256, PS384, PS512
//   - ECDSA: ES256 (P-256), ES384 (P-384), ES512 (P-521)
//   - EdDSA: Ed25519 curve
//
// Common JWKS Endpoints:
//   - Auth0: https://{domain}/.well-known/jwks.json
//   - AWS Cognito: https://cognito-idp.{region}.amazonaws.com/{userPoolId}/.well-known/jwks.json
//   - Google: https://www.googleapis.com/oauth2/v3/certs
//   - Microsoft: https://login.microsoftonline.com/common/discovery/v2.0/keys
//
// Error Handling: Returns error if:
//   - Network request fails (DNS, connection, timeout)
//   - HTTP response status >= 400
//   - Invalid JSON in JWKS response
//   - No valid keys found in the JWKS
//
// Security Considerations:
//   - Always use HTTPS URLs to prevent man-in-the-middle attacks
//   - Consider implementing caching and rate limiting for production use
//   - Validate that URLs are from trusted domains
//   - Keys are automatically filtered - only supported algorithms are included
//
// Example usage:
//
//	// Fetch keys from Auth0
//	keys, err := jwt.FetchPublicKeys("https://myapp.auth0.com/.well-known/jwks.json")
//	if err != nil {
//	    log.Printf("Failed to fetch keys: %v", err)
//	    return
//	}
//
//	// Use keys for verification with kid
//	verifiedToken, err := keys.Verify(tokenBytes)
//	if err != nil {
//	    log.Printf("Verification failed: %v", err)
//	    return
//	}
//
//	// Keys map allows multiple algorithms
//	for keyID, key := range keys {
//	    log.Printf("Key ID: %s, Algorithm: %s", keyID, key.Alg)
//	}
//
// Advanced Usage: For custom HTTP clients, timeouts, or headers,
// use FetchJWKS directly instead of this convenience function.
func FetchPublicKeys(url string) (Keys, error) {
	set, err := FetchJWKS(nil, url)
	if err != nil {
		return nil, err
	}

	return set.PublicKeys(), nil
}

// JWKS represents a JSON Web Key Set as defined in RFC 7517.
//
// A JSON Web Key Set (JWKS) is a JSON structure that represents a set of
// JSON Web Keys (JWKs). It is commonly used by authorization servers and
// identity providers to publish their public keys for JWT signature verification.
//
// Structure: The JWKS contains an array of JWK objects under the "keys" field.
// Each JWK represents a cryptographic key with metadata such as algorithm,
// key type, key ID, and the actual key material.
//
// Common Sources:
//   - OAuth 2.0 / OpenID Connect providers (/.well-known/jwks.json)
//   - JWT issuers publishing verification keys
//   - API gateways and authentication services
//   - Identity providers (Auth0, AWS Cognito, Google, Microsoft)
//
// Usage Pattern:
//  1. Fetch JWKS from a trusted endpoint
//  2. Parse into JWKS struct via JSON unmarshaling
//  3. Convert to Keys map using PublicKeys() method
//  4. Use Keys map for JWT verification with multiple key support
//
// Security: JWKS should always be fetched over HTTPS from trusted sources.
// The keys contained within are public keys, but their integrity is critical
// for JWT security.
//
// Example JWKS JSON structure:
//
//	{
//	  "keys": [
//	    {
//	      "kty": "RSA",
//	      "kid": "key1",
//	      "use": "sig",
//	      "alg": "RS256",
//	      "n": "base64url-encoded-modulus",
//	      "e": "AQAB"
//	    },
//	    {
//	      "kty": "EC",
//	      "kid": "key2",
//	      "use": "sig",
//	      "alg": "ES256",
//	      "crv": "P-256",
//	      "x": "base64url-x-coordinate",
//	      "y": "base64url-y-coordinate"
//	    }
//	  ]
//	}
type JWKS struct {
	Keys []*JWK `json:"keys"` // Array of JSON Web Keys
}

// PublicKeys parses the JWKS and returns the public keys as a Keys map.
//
// This method converts the JSON Web Key Set into a Keys map that can be
// used directly with JWT verification functions. It processes each JWK
// in the JWKS, validates the key format, and converts supported keys
// to their corresponding Go cryptographic types.
//
// Supported Key Types:
//   - RSA keys (kty: "RSA") -> *rsa.PublicKey for RS256/RS384/RS512/PS256/PS384/PS512
//   - ECDSA keys (kty: "EC") -> *ecdsa.PublicKey for ES256/ES384/ES512
//   - EdDSA keys (kty: "OKP") -> ed25519.PublicKey for Ed25519
//
// Key Filtering: Only keys with:
//   - Valid and supported key type (kty)
//   - Recognized algorithm (alg)
//   - Proper key material format
//   - Valid base64url encoding
//
// Key ID Mapping: The returned Keys map uses the JWK's "kid" (Key ID)
// field as the map key. This allows JWT verification to select the correct
// key based on the token's header "kid" claim.
//
// Error Handling: Invalid or unsupported keys are silently skipped
// rather than causing the entire operation to fail. This allows JWKS
// with mixed key types to work partially.
//
// Return Value: Keys map where:
//   - Key: kid (Key ID) from JWK
//   - Value: *Key struct containing ID, algorithm, and public key
//
// Example usage:
//
//	// Parse JWKS from JSON
//	var jwks jwt.JWKS
//	err := json.Unmarshal(jwksJSON, &jwks)
//	if err != nil {
//	    log.Printf("Failed to parse JWKS: %v", err)
//	    return
//	}
//
//	// Convert to Keys map
//	keys := jwks.PublicKeys()
//	log.Printf("Found %d valid keys", len(keys))
//
//	// Inspect available keys
//	for keyID, key := range keys {
//	    log.Printf("Key %s: %s algorithm", keyID, key.Alg)
//	}
//
//	// Use for JWT verification
//	verifiedToken, err := keys.Verify(tokenBytes)
//
//	// Keys can also be used with specific algorithms
//	if rsaKey, exists := keys["my-rsa-key"]; exists {
//	    verifiedToken, err := jwt.Verify(jwt.RS256, rsaKey.Public, tokenBytes)
//	}
//
// Performance: This method creates new Key structs and converts
// cryptographic keys, so consider caching the result for repeated use.
func (set *JWKS) PublicKeys() Keys {
	keys := make(Keys, len(set.Keys))

	for _, key := range set.Keys {
		alg := parseAlg(key.Alg)
		if alg == nil {
			continue
		}

		publicKey, err := convertJWKToPublicKey(key)
		if err != nil {
			continue
		}

		keys[key.Kid] = &Key{
			ID:     key.Kid,
			Alg:    alg,
			Public: publicKey,
		}
	}

	return keys
}

// HTTPError represents an HTTP error response from a JWKS endpoint.
//
// This error type is used internally by FetchJWKS when the HTTP response
// has a status code >= 400. It captures both the HTTP status code and
// response body to provide detailed error information for debugging
// JWKS fetching issues.
//
// Common Scenarios:
//   - 404 Not Found: JWKS endpoint doesn't exist
//   - 401/403: Authentication/authorization required
//   - 500: Server error at identity provider
//   - 503: Service temporarily unavailable
//
// Error Content: The Body field contains the raw response body,
// which may include error details in JSON or plain text format from
// the identity provider.
//
// Usage: This error is returned by FetchJWKS and can be type-asserted
// to access the status code and response body for custom error handling.
//
// Example error handling:
//
//	jwks, err := jwt.FetchJWKS(client, url)
//	if err != nil {
//	    var httpErr *jwt.HTTPError
//	    if errors.As(err, &httpErr) {
//	        log.Printf("HTTP %d: %s", httpErr.StatusCode, string(httpErr.Body))
//	        // Handle specific status codes
//	        switch httpErr.StatusCode {
//	        case 404:
//	            return errors.New("JWKS endpoint not found")
//	        case 503:
//	            return errors.New("identity provider temporarily unavailable")
//	        }
//	    }
//	    return err
//	}
//
// HTTPError reports a JWKS endpoint that answered with a status of 400 or above.
//
// It was unexported, so callers could not tell a 404 from a 503 even though the package's
// own documentation showed them doing exactly that. Use errors.As to reach it:
//
//	var httpErr *jwt.HTTPError
//	if errors.As(err, &httpErr) && httpErr.StatusCode == http.StatusNotFound {
//	    return errors.New("no key set at that address")
//	}
type HTTPError struct {
	// StatusCode is the HTTP status the endpoint returned. Always 400 or above.
	StatusCode int
	// Body is the response body, read up to MaxJWKSSize and possibly truncated.
	//
	// It is deliberately not part of the error message. The host being fetched from
	// chooses these bytes, and an error string ends up in logs, so putting them there
	// hands a remote party control of a log line, newlines and terminal escapes included.
	// Read this field yourself if you want the detail.
	Body []byte
}

// Error implements the error interface for HTTPError.
//
// The message carries the status code and nothing else, for example
// "jwt: jwks: status code: 404". The response body is available on the Body field but is
// kept out of the message on purpose: those bytes are chosen by the host being fetched
// from, and an error string usually ends up in a log.
func (err *HTTPError) Error() string {
	return fmt.Sprintf("jwt: jwks: status code: %d", err.StatusCode)
}

// FetchJWKS fetches a JSON Web Key Set (JWKS) from the specified URL using a custom HTTP client.
//
// This function provides fine-grained control over the HTTP request used to
// fetch JWKS, allowing custom timeouts, headers, authentication, and other
// HTTP client configurations. It's the lower-level function used by FetchPublicKeys.
//
// Parameters:
//   - client: HTTP client interface for making the request (nil uses http.DefaultClient)
//   - url: The JWKS endpoint URL, typically ending with /.well-known/jwks.json
//
// HTTP Client Configuration: The client parameter allows customization of:
//   - Request timeouts and retry policies
//   - Custom headers (User-Agent, Authorization, etc.)
//   - Proxy and TLS configuration
//   - Connection pooling and keep-alive settings
//   - Request middleware and logging
//
// Response Handling:
//   - Success: HTTP status 200-399 with valid JSON JWKS
//   - Error: HTTP status >= 400 returns *HTTPError carrying the status and body
//   - Network errors: DNS, connection, timeout failures
//   - JSON errors: Malformed JWKS response body
//
// Security Considerations:
//   - Always use HTTPS URLs in production
//   - Set reasonable timeouts to prevent hanging requests
//   - Validate the URL is from a trusted domain
//   - Consider rate limiting for repeated requests
//   - Use appropriate User-Agent headers
//
// Use Cases:
//   - Custom timeout requirements for slow identity providers
//   - Adding authentication headers for private JWKS endpoints
//   - Implementing request logging and metrics
//   - Using custom TLS configurations
//   - Adding retry logic with exponential backoff
//
// Example usage:
//
//	// Custom client with timeout
//	client := &http.Client{
//	    Timeout: 10 * time.Second,
//	}
//	jwks, err := jwt.FetchJWKS(client, "https://auth.example.com/.well-known/jwks.json")
//	if err != nil {
//	    log.Printf("Failed to fetch JWKS: %v", err)
//	    return
//	}
//
//	// Convert to usable keys
//	keys := jwks.PublicKeys()
//
//	// Custom client with headers
//	type authenticatedClient struct {
//	    *http.Client
//	    apiKey string
//	}
//
//	func (c *authenticatedClient) Get(url string) (*http.Response, error) {
//	    req, err := http.NewRequest("GET", url, nil)
//	    if err != nil {
//	        return nil, err
//	    }
//	    req.Header.Set("Authorization", "Bearer "+c.apiKey)
//	    return c.Client.Do(req)
//	}
//
//	authClient := &authenticatedClient{
//	    Client: &http.Client{Timeout: 15 * time.Second},
//	    apiKey: "your-api-key",
//	}
//	jwks, err = jwt.FetchJWKS(authClient, privateJWKSURL)
//
// Error Handling: Check for *HTTPError to handle HTTP-specific errors:
//
//	jwks, err := jwt.FetchJWKS(client, url)
//	if err != nil {
//	    var httpErr *jwt.HTTPError
//	    if errors.As(err, &httpErr) {
//	        log.Printf("HTTP error %d: %s", httpErr.StatusCode, httpErr.Body)
//	    }
//	    return err
//	}
func FetchJWKS(client HTTPClient, rawURL string) (*JWKS, error) {
	if err := checkJWKSURL(rawURL); err != nil {
		return nil, err
	}

	if client == nil {
		client = defaultJWKSClient
	}

	resp, err := client.Get(rawURL)
	if err != nil {
		return nil, err
	}
	defer func() {
		// Closing a response body only releases the connection; the error it can
		// report says nothing about the JWKS that was already decoded, so a
		// successful fetch must not turn into a failure here.
		_ = resp.Body.Close()
	}()

	// Bound both reads. The response comes from a host that decides how much to send,
	// and neither of these had a limit: a hostile or misbehaving endpoint could hand back
	// gigabytes and this function would hold all of it.
	body := io.LimitReader(resp.Body, MaxJWKSSize)

	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(body) // a truncated body is still worth reporting.
		return nil, &HTTPError{StatusCode: resp.StatusCode, Body: b}
	}

	var jwkSet JWKS
	if err = json.NewDecoder(body).Decode(&jwkSet); err != nil {
		return nil, err
	}

	return &jwkSet, nil
}

// MaxJWKSSize bounds how much of a JWKS response FetchJWKS will read, in bytes.
//
// A key set of a few dozen keys is a handful of kilobytes, so a megabyte is generous. The
// limit exists because the response length is chosen by the host being fetched from, which
// on this path is the host whose keys have not been established yet.
const MaxJWKSSize = 1 << 20

// defaultJWKSClient is used when FetchJWKS is called without one.
//
// http.DefaultClient was the previous default and has no timeout at all, so a JWKS
// endpoint that accepted the connection and then said nothing blocked the calling
// goroutine for the lifetime of the process. It also follows up to ten redirects wherever
// they lead, including from https to plain http.
var defaultJWKSClient = &http.Client{
	Timeout: 15 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("jwt: jwks: too many redirects")
		}

		return checkJWKSURL(req.URL.String())
	},
}

// checkJWKSURL rejects a JWKS location that cannot be trusted to carry key material.
//
// Verification keys fetched over plain http can be replaced in transit by anyone on the
// path, which turns the whole verification step into theatre. Loopback is allowed because
// that is where people run a local identity provider while developing.
func checkJWKSURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("jwt: jwks: %w", err)
	}

	if u.Scheme == "https" {
		return nil
	}

	if u.Scheme == "http" && isLoopback(u.Hostname()) {
		return nil
	}

	return fmt.Errorf("jwt: jwks: refusing to fetch keys over %q: use https", u.Scheme)
}

// isLoopback reports whether a hostname names the local machine.
func isLoopback(host string) bool {
	switch host {
	case "localhost", "127.0.0.1", "::1", "[::1]":
		return true
	default:
		return false
	}
}

//
// convert jwk to public key.
//

type (
	// HTTPClient is an interface for making HTTP requests to fetch JWKS.
	//
	// This interface allows custom HTTP client implementations and enables
	// mocking for testing. It abstracts the HTTP client dependency used
	// by FetchJWKS, providing flexibility for different HTTP configurations.
	//
	// Standard Implementation: The *http.Client from Go's standard library
	// implements this interface and is the most common choice.
	//
	// Custom Implementations: Can be created for:
	//   - Adding authentication headers
	//   - Implementing request/response logging
	//   - Adding retry logic with exponential backoff
	//   - Custom TLS configurations
	//   - Request metrics and monitoring
	//   - Rate limiting and circuit breaker patterns
	//
	// Testing: Mock implementations allow unit testing of JWKS fetching
	// without making actual HTTP requests.
	//
	// Example custom implementation:
	//
	//	type LoggingClient struct {
	//	    Client *http.Client
	//	    Logger *log.Logger
	//	}
	//
	//	func (c *LoggingClient) Get(url string) (*http.Response, error) {
	//	    c.Logger.Printf("Fetching JWKS from: %s", url)
	//	    resp, err := c.Client.Get(url)
	//	    if err != nil {
	//	        c.Logger.Printf("JWKS fetch failed: %v", err)
	//	        return nil, err
	//	    }
	//	    c.Logger.Printf("JWKS fetch success: %d", resp.StatusCode)
	//	    return resp, nil
	//	}
	//
	// Example mock for testing:
	//
	//	type MockHTTPClient struct {
	//	    Response *http.Response
	//	    Error    error
	//	}
	//
	//	func (m *MockHTTPClient) Get(url string) (*http.Response, error) {
	//	    return m.Response, m.Error
	//	}
	HTTPClient interface {
		Get(string) (*http.Response, error)
	}

	// JWK represents a JSON Web Key as defined in RFC 7517.
	//
	// A JSON Web Key (JWK) is a JSON data structure that represents a
	// cryptographic key. JWKs are commonly used in OAuth 2.0, OpenID Connect,
	// and other protocols for representing public keys used for signature
	// verification.
	//
	// Key Components:
	//   - kty: Key type (RSA, EC, OKP) - determines the key algorithm family
	//   - kid: Key ID - unique identifier for key selection
	//   - use: Key use (sig for signature, enc for encryption)
	//   - alg: Algorithm (RS256, ES256, EdDSA, etc.)
	//   - Key material: Algorithm-specific fields (n,e for RSA; x,y,crv for EC; x,crv for EdDSA)
	//
	// Supported Key Types:
	//   - RSA (kty="RSA"): Uses n (modulus) and e (exponent) fields
	//   - ECDSA (kty="EC"): Uses x, y (coordinates) and crv (curve) fields
	//   - EdDSA (kty="OKP"): Uses x (key material) and crv (curve) fields
	//
	// Security: JWKs contain public key material only. The corresponding
	// private keys must be kept secure and are never included in JWKs.
	//
	// Usage Pattern:
	//   1. Received as part of JWKS from identity provider
	//   2. Parsed into JWK struct via JSON unmarshaling
	//   3. Converted to Go crypto types using convertJWKToPublicKey
	//   4. Used for JWT signature verification
	//
	// Example RSA JWK JSON:
	//
	//	{
	//	  "kty": "RSA",
	//	  "kid": "rsa-key-1",
	//	  "use": "sig",
	//	  "alg": "RS256",
	//	  "n": "base64url-encoded-modulus",
	//	  "e": "AQAB"
	//	}
	//
	// Example ECDSA JWK JSON:
	//
	//	{
	//	  "kty": "EC",
	//	  "kid": "ec-key-1",
	//	  "use": "sig",
	//	  "alg": "ES256",
	//	  "crv": "P-256",
	//	  "x": "base64url-x-coordinate",
	//	  "y": "base64url-y-coordinate"
	//	}
	//
	// Example EdDSA JWK JSON:
	//
	//	{
	//	  "kty": "OKP",
	//	  "kid": "ed25519-key-1",
	//	  "use": "sig",
	//	  "alg": "EdDSA",
	//	  "crv": "Ed25519",
	//	  "x": "base64url-encoded-public-key"
	//	}
	JWK struct {
		// Kty is the key type: "RSA", "EC" or "OKP".
		Kty string `json:"kty"`
		// Kid is the key identifier a token's header names to select this key.
		Kid string `json:"kid"`
		// Use is the intended use: "sig" for signatures, "enc" for encryption.
		Use string `json:"use"`
		// Alg is the algorithm this key is for, such as "RS256", "ES256" or "EdDSA".
		Alg string `json:"alg"`
		// Crv is the curve name for EC and OKP keys: "P-256", "P-384", "P-521" or
		// "Ed25519". Absent for RSA.
		//
		// The parameters below are per key type, and each is omitted when it does not
		// apply. An EC key used to be published with empty "n" and "e" members and an RSA
		// key with an empty "crv", which RFC 7517 does not allow and which some consumers
		// reject outright.
		Crv string `json:"crv,omitempty"`
		// N is the RSA modulus, base64url encoded.
		N string `json:"n,omitempty"`
		// E is the RSA public exponent, base64url encoded.
		E string `json:"e,omitempty"`
		// X is the EC x coordinate, or the Ed25519 key itself, base64url encoded.
		//
		// X comes before Y because the struct field order decides the JSON member order,
		// and RFC 7518 presents an EC key as crv, x, y. Emitting y first is legal and
		// reads as a mistake to anybody comparing against the RFC.
		X string `json:"x,omitempty"`
		// Y is the EC y coordinate, base64url encoded.
		Y string `json:"y,omitempty"`
	}
)

// convertJWKToPublicKey converts a JWK to its corresponding Go cryptographic public key type.
//
// This function serves as the main dispatcher for converting JSON Web Keys
// to Go's standard cryptographic key types. It examines the key type (kty)
// and delegates to the appropriate specialized conversion function.
//
// Supported Key Types:
//   - "RSA": Converts to *rsa.PublicKey using convertJWKToPublicKeyRSA
//   - "EC": Converts to *ecdsa.PublicKey using convertJWKToPublicKeyEC
//   - "OKP": Converts to ed25519.PublicKey using convertJWKToPublicKeyEdDSA
//
// Parameters:
//   - jwk: Pointer to JWK struct containing the key material and metadata
//
// Return Values:
//   - PublicKey: Interface containing the converted Go cryptographic key
//   - error: Conversion error with wrapped context about key type
//
// Error Handling: Returns detailed errors that include:
//   - Unsupported key types (kty not in RSA, EC, OKP)
//   - Invalid key material (malformed base64url, invalid parameters)
//   - Cryptographic validation failures
//   - Missing required fields for the key type
//
// Usage: This function is used internally by JWKS.PublicKeys() to
// convert each JWK in a key set. It's also useful for converting
// individual JWKs received from APIs or configuration.
//
// Example usage:
//
//	// Convert individual JWK
//	var jwk jwt.JWK
//	err := json.Unmarshal(jwkJSON, &jwk)
//	if err != nil {
//	    return err
//	}
//
//	publicKey, err := convertJWKToPublicKey(&jwk)
//	if err != nil {
//	    log.Printf("Failed to convert JWK: %v", err)
//	    return err
//	}
//
//	// Use the key for verification
//	switch key := publicKey.(type) {
//	case *rsa.PublicKey:
//	    // Use with RS256, RS384, RS512, PS256, PS384, PS512
//	case *ecdsa.PublicKey:
//	    // Use with ES256, ES384, ES512
//	case ed25519.PublicKey:
//	    // Use with EdDSA
//	}
//
// Security: This function only handles public keys. Private key
// material should never be present in JWKs used for verification.
func convertJWKToPublicKey(jwk *JWK) (PublicKey, error) {
	// Parse the key based on its type
	switch jwk.Kty {
	case "RSA":
		publicKey, err := convertJWKToPublicKeyRSA(jwk)
		if err != nil {
			return nil, fmt.Errorf("parse RSA key: %w", err)
		}

		return publicKey, nil
	case "EC":
		publicKey, err := convertJWKToPublicKeyEC(jwk)
		if err != nil {
			return nil, fmt.Errorf("parse EC key: %w", err)
		}

		return publicKey, nil
	case "OKP":
		publicKey, err := convertJWKToPublicKeyEdDSA(jwk)
		if err != nil {
			return nil, fmt.Errorf("parse EdDSA key: %w", err)
		}

		return publicKey, nil
	default:
		return nil, fmt.Errorf("unsupported key type: %s", jwk.Kty)
	}
}

// convertJWKToPublicKeyRSA converts a JWK with RSA key material to *rsa.PublicKey.
//
// This function extracts the RSA modulus (n) and public exponent (e) from
// the JWK and constructs a Go rsa.PublicKey. It handles the base64url
// decoding and big integer conversion required for RSA keys.
//
// Required JWK Fields:
//   - kty: Must be "RSA"
//   - n: RSA modulus (base64url-encoded big integer)
//   - e: RSA public exponent (base64url-encoded integer, typically AQAB for 65537)
//
// RSA Key Parameters:
//   - Modulus (n): Large prime product, determines key size (1024, 2048, 4096 bits)
//   - Exponent (e): Small public exponent, commonly 65537 (0x010001)
//
// Security Considerations:
//   - Key size should be at least 2048 bits for security
//   - Public exponent should be a standard value (65537 recommended)
//   - Modulus should be properly generated with sufficient entropy
//
// Error Scenarios:
//   - Invalid base64url encoding in n or e fields
//   - Missing required fields
//   - Zero or invalid modulus
//   - Invalid exponent values
//
// Example RSA JWK input:
//
//	{
//	  "kty": "RSA",
//	  "kid": "rsa-key-1",
//	  "use": "sig",
//	  "alg": "RS256",
//	  "n": "very-long-base64url-encoded-modulus",
//	  "e": "AQAB"
//	}
//
// Usage: This function is called by convertJWKToPublicKey when
// processing RSA keys. The resulting *rsa.PublicKey can be used with
// RSA signature algorithms (RS256, RS384, RS512, PS256, PS384, PS512).
func convertJWKToPublicKeyRSA(jwk *JWK) (*rsa.PublicKey, error) {
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
	// or: e := int(new(big.Int).SetBytes(eBytes).Int64())

	// construct a *rsa.PublicKey from the n and e values.
	pubKey := &rsa.PublicKey{
		N: n,
		E: e,
	}

	return pubKey, nil
}

// convertJWKToPublicKeyEC converts a JWK with ECDSA key material to *ecdsa.PublicKey.
//
// This function extracts the elliptic curve parameters (x, y coordinates and curve type)
// from the JWK and constructs a Go ecdsa.PublicKey. It handles the base64url decoding
// and big integer conversion required for ECDSA keys.
//
// Required JWK Fields:
//   - kty: Must be "EC"
//   - crv: Curve name ("P-256", "P-384", "P-521")
//   - x: X-coordinate of the public key point (base64url-encoded)
//   - y: Y-coordinate of the public key point (base64url-encoded)
//
// Supported Curves:
//   - "P-256": NIST P-256 curve (secp256r1) for ES256 algorithm
//   - "P-384": NIST P-384 curve (secp384r1) for ES384 algorithm
//   - "P-521": NIST P-521 curve (secp521r1) for ES512 algorithm
//
// Elliptic Curve Parameters:
//   - Public key is a point (x, y) on the specified elliptic curve
//   - Coordinates are large integers specific to the curve
//   - Curve determines security level and compatible algorithms
//
// Security Considerations:
//   - P-256 provides ~128-bit security level
//   - P-384 provides ~192-bit security level
//   - P-521 provides ~256-bit security level
//   - Point must be valid on the specified curve
//
// Error Scenarios:
//   - Invalid key type (not "EC")
//   - Unsupported curve name
//   - Invalid base64url encoding in x or y coordinates
//   - Missing required fields
//   - Invalid point coordinates for the curve
//
// Example ECDSA JWK input:
//
//	{
//	  "kty": "EC",
//	  "kid": "ec-key-1",
//	  "use": "sig",
//	  "alg": "ES256",
//	  "crv": "P-256",
//	  "x": "base64url-x-coordinate",
//	  "y": "base64url-y-coordinate"
//	}
//
// Usage: This function is called by convertJWKToPublicKey when
// processing ECDSA keys. The resulting *ecdsa.PublicKey can be used with
// ECDSA signature algorithms (ES256, ES384, ES512).
func convertJWKToPublicKeyEC(jwk *JWK) (*ecdsa.PublicKey, error) {
	// Check key type
	if jwk.Kty != "EC" {
		return nil, fmt.Errorf("invalid key type: expected EC")
	}

	// Decode x and y coordinates
	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("failed to decode x-coordinate")
	}

	yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return nil, fmt.Errorf("failed to decode y-coordinate")
	}

	// Convert x and y to big.Int
	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	// Determine the elliptic curve
	var curve elliptic.Curve
	switch jwk.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported elliptic curve")
	}

	// Reconstruct the public key
	publicKey := &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}

	return publicKey, nil
}

// convertJWKToPublicKeyEdDSA converts a JWK with EdDSA key material to ed25519.PublicKey.
//
// This function extracts the Ed25519 public key bytes from the JWK and
// constructs a Go ed25519.PublicKey. EdDSA (Edwards-curve Digital Signature Algorithm)
// using the Ed25519 curve is a modern, high-performance signature algorithm.
//
// Required JWK Fields:
//   - kty: Must be "OKP" (Octet Key Pair)
//   - crv: Must be "Ed25519" (Edwards curve)
//   - x: Public key bytes (base64url-encoded, 32 bytes for Ed25519)
//
// Ed25519 Properties:
//   - Fixed 32-byte public keys
//   - High performance and security
//   - Deterministic signatures
//   - Resistance to side-channel attacks
//   - ~128-bit security level
//
// Key Material: Unlike RSA and ECDSA, EdDSA uses simple byte arrays
// rather than mathematical parameters. The 'x' field contains the entire
// 32-byte public key in base64url encoding.
//
// Security Considerations:
//   - Ed25519 is considered very secure and modern
//   - Fixed key size eliminates parameter choice vulnerabilities
//   - Fast verification with small signatures
//   - Resistant to timing attacks
//
// Error Scenarios:
//   - Invalid base64url encoding in x field
//   - Missing x field
//   - Wrong key length (not 32 bytes)
//
// Example EdDSA JWK input:
//
//	{
//	  "kty": "OKP",
//	  "kid": "ed25519-key-1",
//	  "use": "sig",
//	  "alg": "EdDSA",
//	  "crv": "Ed25519",
//	  "x": "base64url-encoded-32-byte-public-key"
//	}
//
// Usage: This function is called by convertJWKToPublicKey when
// processing EdDSA keys. The resulting ed25519.PublicKey can be used
// with the EdDSA signature algorithm.
//
// Performance: Ed25519 operations are generally faster than
// equivalent security RSA and ECDSA operations.
func convertJWKToPublicKeyEdDSA(jwk *JWK) (ed25519.PublicKey, error) {
	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, err
	}

	publicKey := ed25519.PublicKey(xBytes)
	return publicKey, nil
}

//
// convert public key to JWK.
//

// GenerateJWK creates a JSON Web Key (JWK) from a Go cryptographic public key.
//
// This function converts Go's standard cryptographic public key types into
// the JWK format suitable for publishing in JWKS endpoints or sharing with
// other services for JWT verification. It's the reverse operation of
// convertJWKToPublicKey.
//
// Parameters:
//   - kid: Key ID string for identifying this key in key sets
//   - alg: Algorithm string (e.g., "RS256", "ES256", "EdDSA")
//   - publicKey: Go cryptographic public key interface
//
// Supported Key Types:
//   - *rsa.PublicKey: Converted to RSA JWK with "kty": "RSA"
//   - ecdsa.PublicKey: Converted to ECDSA JWK with "kty": "EC"
//   - ed25519.PublicKey: Converted to EdDSA JWK with "kty": "OKP"
//
// Algorithm Mapping:
//   - RSA: RS256, RS384, RS512, PS256, PS384, PS512
//   - ECDSA: ES256 (P-256), ES384 (P-384), ES512 (P-521)
//   - EdDSA: EdDSA (Ed25519)
//
// JWK Structure: Generated JWKs include:
//   - Common fields: kty, kid, use ("sig"), alg
//   - RSA-specific: n (modulus), e (exponent)
//   - ECDSA-specific: crv (curve), x, y (coordinates)
//   - EdDSA-specific: crv ("Ed25519"), x (key material)
//
// Use Cases:
//   - Creating JWKS endpoints for token verification
//   - Sharing public keys with other services
//   - Key rotation and management systems
//   - Converting keys from other formats to JWK
//   - Testing and development with generated keys
//
// Security: Only public key material is included in the JWK.
// Private keys should be kept secure and never included in JWKs.
//
// Example usage:
//
//	// Generate RSA key pair
//	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
//	if err != nil {
//	    return err
//	}
//
//	// Create JWK from public key
//	jwk, err := jwt.GenerateJWK("rsa-key-1", "RS256", &privateKey.PublicKey)
//	if err != nil {
//	    log.Printf("Failed to generate JWK: %v", err)
//	    return err
//	}
//
//	// Serialize to JSON
//	jwkJSON, err := json.Marshal(jwk)
//	if err != nil {
//	    return err
//	}
//
//	// Use in JWKS
//	jwks := jwt.JWKS{
//	    Keys: []*jwt.JWK{jwk},
//	}
//
//	// ECDSA example
//	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
//	jwkEC, err := jwt.GenerateJWK("ec-key-1", "ES256", ecKey.PublicKey)
//
//	// EdDSA example
//	_, edKey, err := ed25519.GenerateKey(rand.Reader)
//	jwkEd, err := jwt.GenerateJWK("ed-key-1", "EdDSA", edKey)
//
// Error Handling: Returns error for unsupported key types or
// invalid key parameters (e.g., unsupported elliptic curves).
func GenerateJWK(kid string, alg string, publicKey PublicKey) (*JWK, error) {
	switch publicKey := publicKey.(type) {
	case *rsa.PublicKey:
		if publicKey == nil {
			return nil, ErrInvalidKey
		}

		return generateJWKFromPublicKeyRSA(kid, alg, publicKey), nil
	case *ecdsa.PublicKey:
		// The pointer case is the one that matters. Every ECDSA key this package produces
		// is a *ecdsa.PublicKey, so matching only the value type meant GenerateJWK, and
		// therefore Keys.JWKS, failed for every ES256, ES384 and ES512 key with
		// "unsupported public key type".
		if publicKey == nil {
			return nil, ErrInvalidKey
		}

		return generateJWKFromPublicKeyEC(kid, alg, *publicKey)
	case ecdsa.PublicKey:
		return generateJWKFromPublicKeyEC(kid, alg, publicKey)
	case ed25519.PublicKey:
		return generateJWKFromPublicKeyEdDSA(kid, publicKey), nil
	default:
		return nil, fmt.Errorf("unsupported public key type: %T", publicKey)
	}
}

// generateJWKFromPublicKeyRSA creates a JWK from an RSA public key.
//
// This function converts a Go rsa.PublicKey into a JWK with RSA-specific
// fields. It extracts the modulus (n) and public exponent (e) from the
// RSA key and encodes them as base64url strings.
//
// Parameters:
//   - kid: Key ID for identifying this key
//   - alg: Algorithm string (e.g., "RS256", "RS384", "RS512", "PS256", "PS384", "PS512")
//   - publicKey: RSA public key containing modulus and exponent
//
// Generated JWK Fields:
//   - kty: Set to "RSA"
//   - kid: Key ID parameter
//   - use: Set to "sig" (signature use)
//   - alg: Algorithm parameter
//   - n: RSA modulus encoded as base64url
//   - e: RSA public exponent encoded as base64url
//
// RSA Key Extraction:
//   - Modulus (N): Large integer representing the RSA modulus
//   - Exponent (E): Small integer, typically 65537 (0x010001)
//   - Both values are converted to byte arrays and base64url encoded
//
// Common Exponent Values:
//   - 65537 (0x010001) -> "AQAB" in base64url
//   - 3 (0x03) -> "Aw" in base64url
//   - Other values are rare and may indicate non-standard keys
//
// Usage: This function is called by GenerateJWK when processing
// RSA public keys. The resulting JWK can be used in JWKS or shared
// with services that need to verify RSA-signed JWTs.
//
// Example output JWK:
//
//	{
//	  "kty": "RSA",
//	  "kid": "rsa-key-1",
//	  "use": "sig",
//	  "alg": "RS256",
//	  "n": "very-long-base64url-encoded-modulus",
//	  "e": "AQAB"
//	}
//
// Security: Only public key material (n, e) is included. The private
// key components (d, p, q, etc.) are never included in JWKs.
func generateJWKFromPublicKeyRSA(kid string, alg string, publicKey *rsa.PublicKey) *JWK {
	// Extract modulus (n) and exponent (e).
	n := base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes())

	// Create JWK
	jwk := JWK{
		Kty: "RSA",
		Kid: kid,
		Use: "sig",
		Alg: alg,
		N:   n,
		E:   e,
	}

	return &jwk
}

// generateJWKFromPublicKeyEC creates a JWK from an ECDSA public key.
//
// This function converts a Go ecdsa.PublicKey into a JWK with ECDSA-specific
// fields. It extracts the curve type and coordinates (x, y) from the ECDSA
// key and encodes them appropriately for the JWK format.
//
// Parameters:
//   - kid: Key ID for identifying this key
//   - alg: Algorithm string (e.g., "ES256", "ES384", "ES512")
//   - publicKey: ECDSA public key with curve and coordinates
//
// Generated JWK Fields:
//   - kty: Set to "EC" (Elliptic Curve)
//   - kid: Key ID parameter
//   - use: Set to "sig" (signature use)
//   - alg: Algorithm parameter
//   - crv: Curve name ("P-256", "P-384", "P-521")
//   - x: X-coordinate encoded as base64url
//   - y: Y-coordinate encoded as base64url
//
// Supported Curves:
//   - P-256 (secp256r1): Used with ES256 algorithm
//   - P-384 (secp384r1): Used with ES384 algorithm
//   - P-521 (secp521r1): Used with ES512 algorithm
//
// Coordinate Encoding: The x and y coordinates are the affine coordinates
// of the public key point on the elliptic curve. Each is encoded as a
// fixed-width big-endian octet string, left-padded with zero bytes to the
// full size of the coordinate (32 bytes for P-256, 48 for P-384, 66 for
// P-521), then base64url encoded, as RFC 7518 section 6.2.1.2 requires.
//
// Algorithm Matching:
//   - P-256 curve typically used with ES256
//   - P-384 curve typically used with ES384
//   - P-521 curve typically used with ES512
//
// Error Scenarios:
//   - Unsupported elliptic curves not in the P-256/384/521 family
//   - Invalid curve parameters
//
// Example output JWK:
//
//	{
//	  "kty": "EC",
//	  "kid": "ec-key-1",
//	  "use": "sig",
//	  "alg": "ES256",
//	  "crv": "P-256",
//	  "x": "base64url-x-coordinate",
//	  "y": "base64url-y-coordinate"
//	}
//
// Usage: This function is called by GenerateJWK when processing
// ECDSA public keys. The resulting JWK can be used in JWKS or shared
// with services that need to verify ECDSA-signed JWTs.
//
// Security: Only public key coordinates are included. The private
// key scalar is never included in JWKs.
func generateJWKFromPublicKeyEC(kid string, alg string, publicKey ecdsa.PublicKey) (*JWK, error) {
	// Determine the curve name and the fixed width of one coordinate,
	// which is ceil(BitSize/8) for each of these curves.
	var (
		crv  string
		size int
	)
	switch publicKey.Curve {
	case elliptic.P256():
		crv, size = "P-256", 32
	case elliptic.P384():
		crv, size = "P-384", 48
	case elliptic.P521():
		crv, size = "P-521", 66
	default:
		return nil, fmt.Errorf("unsupported elliptic curve: %s", publicKey.Curve.Params().Name)
	}

	// Take the coordinates out of the SEC 1 uncompressed point, 0x04 || X || Y,
	// where each coordinate is already left-padded to the width of the curve.
	// RFC 7518 section 6.2.1.2 requires that fixed width; big.Int.Bytes() strips
	// leading zero bytes and so emits a short "x" or "y" for roughly one key in
	// 256 on P-256, which other implementations reject.
	point, err := publicKey.Bytes()
	if err != nil {
		return nil, fmt.Errorf("encode %s public key: %w", crv, err)
	}

	if len(point) != 1+2*size {
		return nil, fmt.Errorf("unexpected %s public key length: %d", crv, len(point))
	}

	x := base64.RawURLEncoding.EncodeToString(point[1 : 1+size])
	y := base64.RawURLEncoding.EncodeToString(point[1+size:])

	jwk := JWK{
		Kty: "EC",
		Kid: kid,
		Use: "sig",
		Alg: alg, // e.g., "ES256", "ES384", "ES512"
		Crv: crv,
		X:   x,
		Y:   y,
	}

	return &jwk, nil
}

// generateJWKFromPublicKeyEdDSA creates a JWK from an Ed25519 public key.
//
// This function converts a Go ed25519.PublicKey into a JWK with EdDSA-specific
// fields. Ed25519 keys are simpler than RSA and ECDSA keys, consisting of
// just 32 bytes of key material that are base64url encoded.
//
// Parameters:
//   - kid: Key ID for identifying this key
//   - publicKey: Ed25519 public key (32-byte array)
//
// Generated JWK Fields:
//   - kty: Set to "OKP" (Octet Key Pair)
//   - kid: Key ID parameter
//   - use: Set to "sig" (signature use)
//   - alg: Set to "EdDSA" (Ed25519 algorithm)
//   - crv: Set to "Ed25519" (Edwards curve)
//   - x: Public key bytes encoded as base64url
//
// Ed25519 Properties:
//   - Fixed 32-byte public keys
//   - No algorithm parameter needed (always EdDSA)
//   - Single supported curve (Ed25519)
//   - High performance and security
//   - Deterministic signatures
//
// Key Material: The entire 32-byte public key is encoded as base64url
// in the 'x' field. Unlike RSA (n, e) or ECDSA (x, y, crv), EdDSA only
// needs the single key material field.
//
// Standard Compliance: Follows RFC 8037 for EdDSA keys in JWK format.
// The "OKP" key type specifically supports EdDSA with Ed25519 and Ed448 curves.
//
// Example output JWK:
//
//	{
//	  "kty": "OKP",
//	  "kid": "ed25519-key-1",
//	  "use": "sig",
//	  "alg": "EdDSA",
//	  "crv": "Ed25519",
//	  "x": "base64url-encoded-32-byte-public-key"
//	}
//
// Usage: This function is called by GenerateJWK when processing
// Ed25519 public keys. The resulting JWK can be used in JWKS or shared
// with services that need to verify EdDSA-signed JWTs.
//
// Security: Only the public key material is included. The private
// key bytes are never included in JWKs.
//
// Performance: Ed25519 JWKs are smaller and simpler than RSA/ECDSA
// equivalents, making them efficient for transmission and storage.
func generateJWKFromPublicKeyEdDSA(kid string, publicKey ed25519.PublicKey) *JWK {
	// Base64 URL-encode the public key.
	x := base64.RawURLEncoding.EncodeToString(publicKey)

	// Create JWK
	jwk := JWK{
		Kty: "OKP",
		Kid: kid,
		Use: "sig",
		Alg: "EdDSA",
		Crv: "Ed25519",
		X:   x,
	}

	return &jwk
}

// HMAC is a symmetric algorithm, so it doesn’t use JWKS (which is for public keys).
// Instead, you share the secret key securely between parties.
