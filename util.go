package jwt

import "unsafe"

// BytesToString converts a byte slice to a string without memory allocation.
//
// This function uses unsafe operations to avoid copying the underlying byte data,
// providing better performance for frequent conversions. The resulting string
// shares the same underlying memory as the input byte slice.
//
// WARNING: This is unsafe because:
//   - If the byte slice is modified after conversion, the string changes too
//   - The string will be invalid if the byte slice is garbage collected
//   - Only use when you control the lifecycle of both the bytes and string
//
// This implementation requires Go 1.20+ for unsafe.String and unsafe.SliceData.
// For safer builds, use the "safe" build tag which provides a standard conversion.
//
// Example:
//
//	data := []byte("hello")
//	str := jwt.BytesToString(data) // No allocation
//	// Do NOT modify data after this point
func BytesToString(b []byte) string {
	return unsafe.String(unsafe.SliceData(b), len(b))
}
