package jwt

import "unsafe"

// BytesToString converts a slice of bytes to string without memory allocation.
func BytesToString(b []byte) string {
	return *(*string)(unsafe.Pointer(&b))
}

// StringToBytes converts a string into slice of bytes without memory allocation.
func StringToBytes(s string) []byte {
	return *(*[]byte)(unsafe.Pointer(&s))
}
