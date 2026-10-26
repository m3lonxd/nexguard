package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	EnrollPath  = "/api/v1/enroll"
	EventsPath  = "/api/v1/events"
	ActionsPath = "/api/v1/actions"
	StreamPath  = "/api/v1/stream"
)

var httpClient = &http.Client{Timeout: 10 * time.Second}

func Enroll(serverURL, hostname, osName string) (string, string, error) {
	body, err := json.Marshal(EnrollRequest{Hostname: hostname, OS: osName})
	if err != nil {
		return "", "", err
	}
	req, err := http.NewRequest(http.MethodPost, serverURL+EnrollPath, bytes.NewReader(body))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("enroll request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return "", "", fmt.Errorf("enroll failed: status %d: %s", resp.StatusCode, string(b))
	}
	var er EnrollResponse
	if err := json.NewDecoder(resp.Body).Decode(&er); err != nil {
		return "", "", fmt.Errorf("decode enroll response: %w", err)
	}
	return er.ServerID, er.Token, nil
}

// PushFinding retries a few times with exponential backoff because the panel
// may be briefly unreachable (restart, network blip); it still returns an
// error on exhaustion so the caller can buffer the finding and try later.
func PushFinding(serverURL, token string, f Finding) error {
	body, err := json.Marshal(f)
	if err != nil {
		return err
	}
	return postWithRetry(serverURL+EventsPath, token, body)
}

func PushAction(serverURL, token string, a ActionLog) error {
	body, err := json.Marshal(a)
	if err != nil {
		return err
	}
	return postWithRetry(serverURL+ActionsPath, token, body)
}

func postWithRetry(url, token string, body []byte) error {
	const maxAttempts = 3
	backoff := 500 * time.Millisecond
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			cancel()
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := httpClient.Do(req)
		cancel()
		if err != nil {
			lastErr = fmt.Errorf("attempt %d: %w", attempt, err)
		} else {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
				return nil
			}
			lastErr = fmt.Errorf("attempt %d: status %d: %s", attempt, resp.StatusCode, string(b))
		}
		if attempt < maxAttempts {
			time.Sleep(backoff)
			backoff *= 2
		}
	}
	return fmt.Errorf("push to %s failed after %d attempts: %w", url, maxAttempts, lastErr)
}
