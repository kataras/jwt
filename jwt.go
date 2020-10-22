package jwt

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"time"
)

// Map is just a type alias, a shortcut of map[string]interface{}.
type Map = map[string]interface{}

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

// Marshal same as json.Marshal.
// This variable can be modified to enable custom encoder behavior
// for a signed payload.
var Marshal = func(v interface{}) ([]byte, error) {
	if v == nil {
		return nil, nil
	}

	if b, ok := v.([]byte); ok {
		return b, nil
	}

	return json.Marshal(v)
}

// Unmarshal same as json.Unmarshal
// but with the Decoder unmarshals a number into an interface{} as a
// json.Number instead of as a float64.
// This is the function being called on `VerifiedToken.Claims` method.
// This variable can be modified to enable custom decoder behavior.
var Unmarshal = func(payload []byte, dest interface{}) error {
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber() // fixes the issue of setting float64 instead of int64 on maps.
	return dec.Decode(&dest)
}
