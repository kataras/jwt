package jwt

import "time"

// Sign signs and generates a new token based on the algorithm and a secret key.
// The claims is the payload, the actual body of the token, should
// contain information about a specific authorized client.
// Note that the payload part is not encrypted,
// therefore it should NOT contain any private information.
// See the `Verify` function to decode and verify the result token.
//
// Example Code:
//
//  token, err := jwt.Sign(jwt.HS256, []byte("secret"), jwt.Map{
//	  "foo":"bar"
//	}, jwt.MaxAge(15 * time.Minute))
// OR, jwt.WithClaims(jwt.Claims{ Expiry: time.Now().Add(15 * time.Minute).Unix(), ... })
//
// Alternatively:
//
//  now := time.Now()
//  token, err := jwt.Sign(jwt.HS256, []byte("secret"), map[string]interface{}{
//    "iat": now.Unix(),
//    "exp": now.Add(15 * time.Minute).Unix(),
//    "foo": "bar",
//  })
// OR
//  claims := map[string]interface{}{"foo": "bar"}
//  jwt.ExpiryMap(15 *time.Minute, claims)
//  token, err := jwt.Sign(jwt.HS256, []byte("secret"), claims)
func Sign(alg Alg, key PrivateKey, claims interface{}, opts ...SignOption) ([]byte, error) {
	if len(opts) > 0 {
		var standardClaims Claims
		for _, opt := range opts {
			opt(&standardClaims)
		}

		claims = Merge(claims, standardClaims)
	}

	return encodeToken(alg, key, claims)
}

// SignOption is just a helper which sets the standard claims at the `Sign` function.
type SignOption func(c *Claims)

// WithClaims is a SignOption to set multiple standard claims (e.g. id, issuer, subject)
// at once, simply by passing the Claims struct.
//
// See `MaxAge` too.
func WithClaims(standardClaims Claims) SignOption {
	return func(c *Claims) {
		if v := standardClaims.NotBefore; v > 0 {
			c.NotBefore = v
		}

		if v := standardClaims.IssuedAt; v > 0 {
			c.IssuedAt = v
		}

		if v := standardClaims.Expiry; v > 0 {
			c.Expiry = v
		}

		if v := standardClaims.ID; v != "" {
			c.ID = v
		}

		if v := standardClaims.Issuer; v != "" {
			c.Issuer = v
		}

		if v := standardClaims.Subject; v != "" {
			c.Subject = v
		}

		if v := standardClaims.Audience; len(v) > 0 {
			c.Audience = v
		}

		*c = standardClaims
	}
}

// MaxAge is a SignOption to set the expiration "exp", "iat" JWT standard claims.
// Can be passed as last input argument of the `Sign` function.
//
// If maxAge > second then sets expiration to the token.
// It's a helper field to set the `Expiry` and `IssuedAt`
// fields at once.
//
// See the `Clock` package-level variable to modify
// the current time function.
func MaxAge(maxAge time.Duration) SignOption {
	return func(c *Claims) {
		if maxAge <= time.Second {
			return
		}
		now := Clock()
		c.Expiry = now.Add(maxAge).Unix()
		c.IssuedAt = now.Unix()
	}
}

// MaxAgeMap is a helper to set "exp" and "iat" claims to a map claims.
// Usage:
// claims := map[string]interface{}{"foo": "bar"}
// MaxAgeMap(15 * time.Minute, claims)
// Sign(alg, key, claims)
func MaxAgeMap(maxAge time.Duration, claims Map) {
	if claims == nil {
		return
	}

	now := Clock()
	if claims["exp"] == nil {
		claims["exp"] = now.Add(maxAge).Unix()
		claims["iat"] = now.Unix()
	}
}
