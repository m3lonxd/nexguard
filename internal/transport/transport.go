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

// Command panelin bir ajana gönderdiği tek seferlik iştir (IP engelle,
// engeli kaldır, izin listesi, honeypot ayarı). Ajan aynı kimliği ikinci kez
// alırsa yeniden çalıştırmaz, önceki sonucu yollar.
type Command struct {
	ID        string         `json:"id"`
	Type      string         `json:"type"`
	Params    map[string]any `json:"params"`
	CreatedAt time.Time      `json:"created_at"`
}

// CommandResult ajanın bir komut için panele döndüğü sonuçtur.
type CommandResult struct {
	ID     string         `json:"id"`
	OK     bool           `json:"ok"`
	Result map[string]any `json:"result,omitempty"`
	Error  string         `json:"error,omitempty"`
}

// AgentStatus ajanın bağlanınca ve durumu değişince yolladığı özettir.
type AgentStatus struct {
	Version  string          `json:"version,omitempty"`
	Honeypot *HoneypotStatus `json:"honeypot,omitempty"`
	Allow    []string        `json:"allow"`
	Blocked  []string        `json:"blocked"`
}

type HoneypotStatus struct {
	Enabled   bool              `json:"enabled"`
	SSHPort   int               `json:"ssh_port"`
	TCPPorts  []int             `json:"tcp_ports"`
	AutoBlock bool              `json:"auto_block"`
	Listening []int             `json:"listening"`
	Errors    map[string]string `json:"errors,omitempty"`
	Hits      int               `json:"hits"`
}

// AgentMessage ajan ile panel arasındaki /api/v1/agent soketinin zarfıdır.
// Panel -> ajan: kind "command". Ajan -> panel: kind "result" ya da "status".
type AgentMessage struct {
	Kind    string         `json:"kind"`
	Command *Command       `json:"command,omitempty"`
	Result  *CommandResult `json:"result,omitempty"`
	Status  *AgentStatus   `json:"status,omitempty"`
}
