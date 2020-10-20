package jwt

import (
	"bytes"
	"encoding/json"
)

// TODO: https://tools.ietf.org/html/rfc7516#section-3

// createProtectedHeader generates a base64-encoded (raw url) JOSE protected header.
func createProtectedHeader(alg, kid string, extraHeaders ...json.RawMessage) ([]byte, error) {
	if kid == "" && len(extraHeaders) == 0 {
		return createHeader(alg), nil
	}

	var header bytes.Buffer
	if kid != "" {
		header.WriteString(`{"alg":"` + alg + `","kid":"` + kid + `","typ":"JWT"}`)
	} else {
		header.WriteString(`{"alg":"` + alg + `","typ":"JWT"}`)
	}

	// Add any extra headers as separated JSON objects.
	for _, v := range extraHeaders {
		header.WriteByte(',')
		err := json.Compact(&header, v) // validate minify and JSON.
		if err != nil {
			return nil, err
		}
	}

	return Base64Encode(header.Bytes()), nil
}
