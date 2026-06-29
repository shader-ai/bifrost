package urai

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// hasFileID returns true if any message block contains a file_id reference
// that needs server-side resolution. Fast path — avoids the internal HTTP call
// for the overwhelming majority of requests that carry no files.
func hasFileID(body []byte) bool {
	return bytes.Contains(body, []byte(`"file_id"`))
}

// resolveFileReferences sends the raw request body to the Python internal
// resolve endpoint and returns the rewritten body with file data inlined.
func resolveFileReferences(internalAPIBase string, body []byte) ([]byte, error) {
	url := fmt.Sprintf("%s/internal/gateway/resolve-files", internalAPIBase)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("urai: resolve-files: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("urai: resolve-files: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("urai: resolve-files: read response: %w", err)
	}
	if resp.StatusCode >= 400 {
		var apiErr struct {
			Detail string `json:"detail"`
		}
		_ = json.Unmarshal(respBody, &apiErr)
		return nil, fmt.Errorf("urai: resolve-files returned %d: %s", resp.StatusCode, apiErr.Detail)
	}
	return respBody, nil
}
