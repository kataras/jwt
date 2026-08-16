package jwt

import (
	"net/http"
	"strings"
)

// Every service that puts this package behind an HTTP handler writes the same twenty lines
// to find the token first, and they do not agree with each other. Two packages in one
// codebase split the Authorization header differently, so one of them rejected a token
// containing a space and the other accepted it. That is a missing primitive, not a
// coincidence.
//
// net/http is the standard library, so this costs the package nothing: jwk.go already
// imports it.

// TokenExtractor pulls a raw token out of a request. It returns nil when the request does
// not carry one where this extractor looks.
type TokenExtractor func(r *http.Request) []byte

// BearerPrefix is the scheme name that precedes a token in an Authorization header.
// Matching against it is case insensitive, as RFC 7235 section 2.1 requires.
const BearerPrefix = "Bearer"

// FromHeader reads the token from a request header, accepting either a bare token or one
// behind the "Bearer" scheme.
//
// With no arguments it reads "Authorization". Pass names to look elsewhere, in order, and
// the first header carrying a value wins:
//
//	extract := jwt.FromHeader("Authorization", "X-Authorization")
//
// The scheme comparison ignores case, and only the first space separates it from the
// token, so a token is never truncated by a space inside it.
func FromHeader(names ...string) TokenExtractor {
	if len(names) == 0 {
		names = []string{"Authorization"}
	}

	return func(r *http.Request) []byte {
		for _, name := range names {
			value := r.Header.Get(name)
			if value == "" {
				continue
			}

			scheme, token, found := strings.Cut(value, " ")
			if !found {
				// A bare token with no scheme. Several gateways send this.
				return []byte(value)
			}

			if !strings.EqualFold(scheme, BearerPrefix) {
				continue
			}

			if token = strings.TrimSpace(token); token != "" {
				return []byte(token)
			}
		}

		return nil
	}
}

// FromQuery reads the token from a URL query parameter.
//
// With no arguments it looks at "access_token" and then "token". Query strings are logged
// by proxies and kept in browser history, so use this only where a header is impossible,
// such as an EventSource connection or a download link.
func FromQuery(names ...string) TokenExtractor {
	if len(names) == 0 {
		names = []string{"access_token", "token"}
	}

	return func(r *http.Request) []byte {
		query := r.URL.Query()
		for _, name := range names {
			if value := query.Get(name); value != "" {
				return []byte(value)
			}
		}

		return nil
	}
}

// FromCookie reads the token from a cookie.
//
// A cookie is sent by the browser on every request to the origin, so a token stored this
// way needs CSRF protection of its own. Set SameSite and HttpOnly when you write it.
func FromCookie(name string) TokenExtractor {
	return func(r *http.Request) []byte {
		cookie, err := r.Cookie(name)
		if err != nil {
			return nil
		}

		if cookie.Value == "" {
			return nil
		}

		return []byte(cookie.Value)
	}
}

// ExtractToken returns the first token any of the given extractors finds.
//
// With no extractors it reads the Authorization header, which is what almost every caller
// wants:
//
//	token := jwt.ExtractToken(r)
//	verifiedToken, err := jwt.Verify(jwt.HS256, key, token)
//
// Verify returns ErrMissing for a nil token, so a missing credential and a bad one arrive
// at the same place and you do not need to check for nil first.
func ExtractToken(r *http.Request, extractors ...TokenExtractor) []byte {
	if len(extractors) == 0 {
		extractors = []TokenExtractor{FromHeader()}
	}

	for _, extract := range extractors {
		if extract == nil {
			continue
		}

		if token := extract(r); len(token) > 0 {
			return token
		}
	}

	return nil
}
