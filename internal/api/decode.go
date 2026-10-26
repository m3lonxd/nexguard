package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"nexguard/internal/transport"
)

// decodeFindings accepts both a single Finding object and a JSON array of
// Findings, since the agent batches when it has buffered events but sends a
// single object in the common case.
func decodeFindings(r *http.Request) ([]transport.Finding, error) {
	data, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, errors.New("empty request body")
	}
	if data[0] == '[' {
		var list []transport.Finding
		if err := json.Unmarshal(data, &list); err != nil {
			return nil, err
		}
		return list, nil
	}
	var f transport.Finding
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, err
	}
	return []transport.Finding{f}, nil
}
