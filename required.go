package jwt

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
)

// ErrMissingKey when token does not contain a required JSON field.
// Check with errors.Is.
var ErrMissingKey = errors.New("token is missing a required field")

func meetRequirements(val reflect.Value) (err error) { // see `UnmarshalWithRequired`.
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

		if tag := field.Tag.Get("json"); tag != "" && strings.Contains(tag, ",required") {
			if val.Field(i).IsZero() {
				return fmt.Errorf("%w: %q", ErrMissingKey, field.Name)
			}
		}
	}

	return
}

// indirectType returns the value of a pointer-type "typ".
// If "typ" is a pointer, array, chan, map or slice it returns its Elem,
// otherwise returns the typ as it's.
func indirectType(typ reflect.Type) reflect.Type {
	switch typ.Kind() {
	case reflect.Ptr, reflect.Array, reflect.Chan, reflect.Map, reflect.Slice:
		return typ.Elem()
	}
	return typ
}
