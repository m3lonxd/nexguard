package transport

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

type Finding struct {
	ID        string         `json:"id"`
	ServerID  string         `json:"server_id"`
	Type      string         `json:"type"`
	Severity  string         `json:"severity"`
	Summary   string         `json:"summary"`
	Evidence  map[string]any `json:"evidence"`
	CreatedAt time.Time      `json:"created_at"`
}

type EnrollRequest struct {
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
}

type EnrollResponse struct {
	ServerID string `json:"server_id"`
	Token    string `json:"token"`
}

type ActionLog struct {
	ID         string         `json:"id"`
	FindingID  string         `json:"finding_id"`
	Tier       string         `json:"tier"`
	ActionType string         `json:"action_type"`
	Params     map[string]any `json:"params"`
	AppliedAt  time.Time      `json:"applied_at"`
	RevertedAt *time.Time     `json:"reverted_at,omitempty"`
}

// NewID is shared by both sides: the agent pre-generates action IDs so a
// later revert can be pushed as an update to the same row, and the server
// falls back to it when a caller omits an ID.
func NewID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
