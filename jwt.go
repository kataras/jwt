package jwt

import (
	"io/ioutil"
	"time"
)

// Clock is used to validate tokens expiration if the "exp" (expiration) exists in the payload.
// It can be overridden to use any other time value, useful for testing.
//
// Usage: now := Clock()
var Clock = time.Now

// ReadFile can be used to customize the way the
// Must/Load Key function helpers are loading the filenames from.
// Example of usage: embedded key pairs.
// Defaults to the `ioutil.ReadFile` which reads the file from the physical disk.
var ReadFile = ioutil.ReadFile
