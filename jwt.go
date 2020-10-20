package jwt

import (
	"time"
)

// Clock is used to validate tokens expiration if the "exp" (expiration) exists in the payload.
// It can be overridden to use any other time value, useful for testing.
//
// Usage: now := Clock()
var Clock = time.Now
