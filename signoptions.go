package jwt

import "time"

// Shorthands for setting one standard claim at sign time.
//
// MaxAge, NoMaxAge, Audience and Claims were the only sign options, so anything wanting to
// set a "jti" or an "iss" had to build a SignOptionFunc by hand. Downstream packages did,
// and the hand-written version leaked the library's own type into a signature that was
// meant to hide it.
//
// They compose, and later options win:
//
//	token, err := jwt.Sign(jwt.HS256, key, claims,
//	    jwt.MaxAge(15*time.Minute),
//	    jwt.Issuer("auth.example.com"),
//	    jwt.Subject(user.ID),
//	    jwt.ID(uuid.NewString()),
//	)

// ID sets the "jti" claim, the token's unique identifier.
//
// Give every token one. Blocklist falls back to keying on the whole token without it, and
// the entry then holds a complete bearer credential in memory for as long as it lives.
func ID(id string) SignOptionFunc {
	return func(c *Claims) {
		c.ID = id
	}
}

// OriginID sets the "origin_jti" claim, which points at the token this one came from.
//
// It is not a registered claim. This package uses it to link a refresh token to the access
// token it was issued alongside, so that revoking the access token can revoke its refresh
// token too. SignPair sets it for you.
func OriginID(id string) SignOptionFunc {
	return func(c *Claims) {
		c.OriginID = id
	}
}

// Issuer sets the "iss" claim, naming whoever minted the token.
func Issuer(issuer string) SignOptionFunc {
	return func(c *Claims) {
		c.Issuer = issuer
	}
}

// Subject sets the "sub" claim, naming the principal the token is about.
func Subject(subject string) SignOptionFunc {
	return func(c *Claims) {
		c.Subject = subject
	}
}

// NotBefore sets the "nbf" claim, the time before which the token is not valid.
//
// A recipient whose clock runs behind yours will reject the token until it catches up. See
// Skew for the validator that tolerates that.
func NotBefore(t time.Time) SignOptionFunc {
	return func(c *Claims) {
		c.NotBefore = t.Round(time.Second).Unix()
	}
}

// IssuedAt sets the "iat" claim, overriding the time MaxAge would have used.
func IssuedAt(t time.Time) SignOptionFunc {
	return func(c *Claims) {
		c.IssuedAt = t.Round(time.Second).Unix()
	}
}

// ExpiresAt sets the "exp" claim to an absolute time.
//
// MaxAge is usually what you want, since it sets "iat" alongside "exp" from a duration.
// Use this when the expiry is dictated by something other than the moment of signing, such
// as the end of a session that started earlier.
func ExpiresAt(t time.Time) SignOptionFunc {
	return func(c *Claims) {
		c.Expiry = t.Round(time.Second).Unix()
	}
}
