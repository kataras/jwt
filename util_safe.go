// +build safe

package jwt

// BytesToString converts a slice of bytes to string by wrapping.
func BytesToString(b []byte) string {
	return string(b)
}

// StringToBytes converts a string into slice of bytes by wrapping.
func StringToBytes(s string) []byte {
	return []byte(s)
}
