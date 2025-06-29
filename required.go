package jwt

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
)

// ErrMissingKey indicates that a token is missing a required JSON field.
// This error is returned when using UnmarshalWithRequired and a struct field
// tagged with `json:"field,required"` is missing from the token payload.
//
// Use errors.Is(err, ErrMissingKey) to check for this specific error.
var ErrMissingKey = errors.New("jwt: token is missing a required field")

// HasRequiredJSONTag reports whether a struct field has the "required" JSON tag.
//
// This function checks if a struct field is marked as required using the
// `json:"fieldname,required"` tag syntax. It only considers exported fields
// (fields with uppercase first letter).
//
// This function is useful for:
//   - Pre-validation of struct definitions
//   - Building custom unmarshaling logic
//   - Debugging required field configurations
//
// Example:
//
//	type Claims struct {
//	    Username string `json:"username,required"`
//	    Email    string `json:"email"`
//	}
//
//	field, _ := reflect.TypeOf(Claims{}).FieldByName("Username")
//	isRequired := jwt.HasRequiredJSONTag(field) // returns true
func HasRequiredJSONTag(field reflect.StructField) bool {
	if isExported := field.PkgPath == ""; !isExported {
		return false
	}

	tag := field.Tag.Get("json")
	return strings.Contains(tag, ",required")
}

// meetRequirements validates that all required fields in a struct are non-zero.
// This function is used internally by UnmarshalWithRequired to enforce
// required field validation after JSON unmarshaling.
func meetRequirements(val reflect.Value) (err error) {
	val = reflect.Indirect(val)
	if val.Kind() != reflect.Struct {
		return nil
	}

	typ := val.Type()
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		// skip unexported fields here.
		if isExported := field.PkgPath == ""; !isExported {
			continue
		}

		if fieldTyp := indirectType(field.Type); fieldTyp.Kind() == reflect.Struct {
			if err = meetRequirements(val.Field(i)); err != nil {
				return err
			}

			continue
		}

		if HasRequiredJSONTag(field) {
			if val.Field(i).IsZero() {
				return fmt.Errorf("%w: %q", ErrMissingKey, field.Name)
			}
		}
	}

	return
}

// indirectType returns the underlying type for pointer and container types.
//
// This function "unwraps" pointer, array, channel, map, and slice types
// to get to the underlying element type. For other types, it returns
// the type unchanged.
//
// This is used internally for recursive struct field validation.
func indirectType(typ reflect.Type) reflect.Type {
	switch typ.Kind() {
	case reflect.Ptr, reflect.Array, reflect.Chan, reflect.Map, reflect.Slice:
		return typ.Elem()
	}
	return typ
}
