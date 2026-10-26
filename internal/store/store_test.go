package store

import (
	"testing"
	"time"

	"nexguard/internal/transport"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestCreateServerAndVerifyToken(t *testing.T) {
	s := newTestStore(t)
	id := NewID()
	token := NewToken()
	if err := s.CreateServer(id, "web-01", "linux", HashToken(token)); err != nil {
		t.Fatalf("create server: %v", err)
	}

	gotID, ok, err := s.VerifyToken(token)
	if err != nil {
		t.Fatalf("verify token: %v", err)
	}
	if !ok {
		t.Fatalf("expected token to verify")
	}
	if gotID != id {
		t.Fatalf("expected server id %s, got %s", id, gotID)
	}

	_, ok, err = s.VerifyToken("wrong-token")
	if err != nil {
		t.Fatalf("verify wrong token: %v", err)
	}
	if ok {
		t.Fatalf("expected wrong token to fail verification")
	}
}

func TestListServers(t *testing.T) {
	s := newTestStore(t)
	if err := s.CreateServer(NewID(), "a", "linux", HashToken("t1")); err != nil {
		t.Fatalf("create server a: %v", err)
	}
	if err := s.CreateServer(NewID(), "b", "linux", HashToken("t2")); err != nil {
		t.Fatalf("create server b: %v", err)
	}
	servers, err := s.ListServers()
	if err != nil {
		t.Fatalf("list servers: %v", err)
	}
	if len(servers) != 2 {
		t.Fatalf("expected 2 servers, got %d", len(servers))
	}
}

func TestInsertAndListFindings(t *testing.T) {
	s := newTestStore(t)
	serverID := NewID()
	if err := s.CreateServer(serverID, "web-01", "linux", HashToken("tok")); err != nil {
		t.Fatalf("create server: %v", err)
	}

	f := transport.Finding{
		ServerID:  serverID,
		Type:      "ssh_bruteforce",
		Severity:  "high",
		Summary:   "6 failed logins from 1.2.3.4",
		Evidence:  map[string]any{"ip": "1.2.3.4", "attempts": float64(6)},
		CreatedAt: time.Now().UTC(),
	}
	if err := s.InsertFinding(f); err != nil {
		t.Fatalf("insert finding: %v", err)
	}

	findings, err := s.ListFindings()
	if err != nil {
		t.Fatalf("list findings: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	got := findings[0]
	if got.ServerID != serverID || got.Type != "ssh_bruteforce" || got.Severity != "high" {
		t.Fatalf("unexpected finding: %+v", got)
	}
	if got.Evidence["ip"] != "1.2.3.4" {
		t.Fatalf("expected evidence ip to round-trip, got %+v", got.Evidence)
	}
}

func TestInsertAndListActions(t *testing.T) {
	s := newTestStore(t)
	a := transport.ActionLog{
		FindingID:  NewID(),
		Tier:       "A",
		ActionType: "block_ip",
		Params:     map[string]any{"ip": "1.2.3.4", "ttl_seconds": float64(3600)},
		AppliedAt:  time.Now().UTC(),
	}
	if err := s.InsertAction(a); err != nil {
		t.Fatalf("insert action: %v", err)
	}

	actions, err := s.ListActions()
	if err != nil {
		t.Fatalf("list actions: %v", err)
	}
	if len(actions) != 1 {
		t.Fatalf("expected 1 action, got %d", len(actions))
	}
	got := actions[0]
	if got.Tier != "A" || got.ActionType != "block_ip" {
		t.Fatalf("unexpected action: %+v", got)
	}
	if got.RevertedAt != nil {
		t.Fatalf("expected nil reverted_at, got %v", got.RevertedAt)
	}
}

func TestInsertActionUpsertsRevert(t *testing.T) {
	s := newTestStore(t)
	id := NewID()
	original := transport.ActionLog{
		ID:         id,
		FindingID:  NewID(),
		Tier:       "A",
		ActionType: "block_ip",
		Params:     map[string]any{"status": "applied", "ip": "1.2.3.4"},
		AppliedAt:  time.Now().UTC(),
	}
	if err := s.InsertAction(original); err != nil {
		t.Fatalf("insert original action: %v", err)
	}

	revertedAt := time.Now().UTC()
	reverted := original
	reverted.Params = map[string]any{"status": "reverted", "ip": "1.2.3.4"}
	reverted.RevertedAt = &revertedAt
	if err := s.InsertAction(reverted); err != nil {
		t.Fatalf("insert reverted action: %v", err)
	}

	actions, err := s.ListActions()
	if err != nil {
		t.Fatalf("list actions: %v", err)
	}
	if len(actions) != 1 {
		t.Fatalf("expected revert to update the same row, got %d rows", len(actions))
	}
	if actions[0].RevertedAt == nil {
		t.Fatalf("expected reverted_at to be set after upsert")
	}
	if actions[0].Params["status"] != "reverted" {
		t.Fatalf("expected params to reflect the revert, got %+v", actions[0].Params)
	}
}
