package jwt

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

// The suite is hermetic and stays that way: nothing here opens a socket. The JWKS fetch
// path is exercised through the HTTPClient interface the package already exposes, which
// is what that interface is for.

// recordingClient answers every request from a canned response and remembers the URL it
// was asked for.
type recordingClient struct {
	status int
	body   string
	err    error

	requested []string
}

func (c *recordingClient) Get(url string) (*http.Response, error) {
	c.requested = append(c.requested, url)
	if c.err != nil {
		return nil, c.err
	}

	status := c.status
	if status == 0 {
		status = http.StatusOK
	}

	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(c.body)),
	}, nil
}

func TestFetchJWKSRefusesInsecureURLs(t *testing.T) {
	client := &recordingClient{body: `{"keys":[]}`}

	for _, rawURL := range []string{
		"http://auth.example.com/.well-known/jwks.json",
		"ftp://auth.example.com/keys",
		"file:///etc/passwd",
		"//auth.example.com/keys",
		"auth.example.com/keys",
	} {
		if _, err := FetchJWKS(client, rawURL); err == nil {
			t.Fatalf("%s: expected the fetch to be refused", rawURL)
		}
	}

	if len(client.requested) != 0 {
		t.Fatalf("a refused URL was still requested: %v", client.requested)
	}

	// https is fine, and so is plain http to the local machine, which is where a
	// development identity provider runs.
	for _, rawURL := range []string{
		"https://auth.example.com/.well-known/jwks.json",
		"http://localhost:8080/.well-known/jwks.json",
		"http://127.0.0.1:8080/keys",
	} {
		if _, err := FetchJWKS(client, rawURL); err != nil {
			t.Fatalf("%s: expected the fetch to be allowed but got: %v", rawURL, err)
		}
	}
}

func TestFetchJWKSBoundsTheResponse(t *testing.T) {
	// A JSON array of keys longer than the limit is truncated, which makes the decode
	// fail rather than letting the response size be chosen by the host.
	huge := `{"keys":[` + strings.Repeat(`{"kty":"RSA","kid":"`+strings.Repeat("k", 1024)+`"},`, 2048) + `]}`
	if len(huge) <= MaxJWKSSize {
		t.Fatalf("the test body is only %d bytes, which does not exceed the %d byte limit", len(huge), MaxJWKSSize)
	}

	client := &recordingClient{body: huge}
	if _, err := FetchJWKS(client, "https://auth.example.com/keys"); err == nil {
		t.Fatal("expected a decode error from the truncated body")
	}
}

func TestHTTPErrorKeepsTheRemoteBodyOutOfTheMessage(t *testing.T) {
	// The body is chosen by the host being fetched from and ends up in whatever the
	// caller logs, so it belongs on a field rather than in the error string.
	hostile := "unauthorized\n2026-01-01 FATAL forged log line\x1b[31m"
	client := &recordingClient{status: http.StatusUnauthorized, body: hostile}

	_, err := FetchJWKS(client, "https://auth.example.com/keys")
	if err == nil {
		t.Fatal("expected an error for a 401 response")
	}

	if strings.Contains(err.Error(), "forged log line") {
		t.Fatalf("the remote body reached the error message: %q", err.Error())
	}

	var httpErr *HTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("expected an *HTTPError but got %T", err)
	}
	if httpErr.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected status 401 but got %d", httpErr.StatusCode)
	}
	if string(httpErr.Body) != hostile {
		t.Fatalf("the body should still be readable on the field, got %q", httpErr.Body)
	}
}

func TestFetchAWSCognitoPublicKeysValidatesItsInputs(t *testing.T) {
	// Both values are interpolated into the URL that is then fetched, so a region that
	// escapes the host moves the request somewhere else entirely and whatever comes back
	// is used to verify tokens.
	for _, tt := range []struct{ region, poolID string }{
		{"evil.com/x", "us-east-1_abc"},
		{"us-east-1@evil.com", "us-east-1_abc"},
		{"us-east-1/../..", "us-east-1_abc"},
		{"us-east-1", "abc/../../evil"},
		{"us-east-1", "abc?x=1"},
		{"", "us-east-1_abc"},
		{"us-east-1", ""},
	} {
		if _, err := FetchAWSCognitoPublicKeys(tt.region, tt.poolID); err == nil {
			t.Fatalf("region %q pool %q: expected the call to be refused", tt.region, tt.poolID)
		} else if !strings.Contains(err.Error(), "aws cognito") {
			t.Fatalf("region %q pool %q: expected a validation error but got: %v", tt.region, tt.poolID, err)
		}
	}
}

func TestPublicKeysReportsNothingUsable(t *testing.T) {
	// A key set whose entries all fail to convert used to come back as an empty, non-nil
	// Keys with no error, so an operator saw "unknown kid" on every request instead of
	// "the key fetch is broken".
	set := &JWKS{Keys: []*JWK{
		{Kty: "RSA", Kid: "broken", N: "!!!not-base64!!!", E: "AQAB"},
	}}

	if keys := set.PublicKeys(); len(keys) != 0 {
		t.Fatalf("expected no usable keys, got %d", len(keys))
	}
}
