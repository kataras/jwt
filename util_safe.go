//go:build safe
// +build safe

package jwt

// BytesToString converts a byte slice to a string using safe memory allocation.
//
// This is the safe version of BytesToString that's used when the "safe" build tag
// is specified. It performs a standard Go conversion that allocates new memory
// for the string, ensuring memory safety at the cost of performance.
//
// Unlike the unsafe version, this implementation:
//   - Always allocates new memory for the string
//   - Provides complete memory safety
//   - Allows the byte slice to be modified without affecting the string
//   - Works with all Go versions
//
// To use this safe version, build with: go build -tags safe
//
// Example:
//
//	data := []byte("hello")
//	str := jwt.BytesToString(data) // Safe allocation
//	data[0] = 'H'                  // Safe to modify, doesn't affect str
func BytesToString(b []byte) string {
	return string(b)
}
