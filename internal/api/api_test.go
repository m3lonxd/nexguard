package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"nexguard/internal/store"
	"nexguard/internal/transport"
)

func newTestServer(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return New(st), st
}

func enrollAgent(t *testing.T, srv *Server) transport.EnrollResponse {
	t.Helper()
	body, _ := json.Marshal(transport.EnrollRequest{Hostname: "web-01", OS: "linux"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/enroll", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("enroll: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var er transport.EnrollResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &er); err != nil {
		t.Fatalf("decode enroll response: %v", err)
	}
	if er.ServerID == "" || er.Token == "" {
		t.Fatalf("expected non-empty server id and token, got %+v", er)
	}
	return er
}

func TestEnroll(t *testing.T) {
	srv, _ := newTestServer(t)
	enrollAgent(t, srv)
}

func TestEventsRequiresAuth(t *testing.T) {
	srv, _ := newTestServer(t)
	body, _ := json.Marshal(transport.Finding{Type: "ssh_bruteforce", Severity: "high", Summary: "x"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/events", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", rec.Code)
	}
}

func TestEventsRejectsBadToken(t *testing.T) {
	srv, _ := newTestServer(t)
	body, _ := json.Marshal(transport.Finding{Type: "ssh_bruteforce", Severity: "high", Summary: "x"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/events", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer not-a-real-token")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 with invalid token, got %d", rec.Code)
	}
}

func TestEventsSingleAndBatchThenListFindings(t *testing.T) {
	srv, _ := newTestServer(t)
	enrolled := enrollAgent(t, srv)

	single := transport.Finding{Type: "ssh_bruteforce", Severity: "high", Summary: "single finding", Evidence: map[string]any{"ip": "1.1.1.1"}}
	body, _ := json.Marshal(single)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/events", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+enrolled.Token)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("single finding: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	batch := []transport.Finding{
		{Type: "ssh_bruteforce", Severity: "high", Summary: "batch 1", Evidence: map[string]any{"ip": "2.2.2.2"}},
		{Type: "ssh_bruteforce", Severity: "high", Summary: "batch 2", Evidence: map[string]any{"ip": "3.3.3.3"}},
	}
	body, _ = json.Marshal(batch)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/events", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+enrolled.Token)
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("batch findings: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/findings", nil)
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list findings: expected 200, got %d", rec.Code)
	}
	var findings []transport.Finding
	if err := json.Unmarshal(rec.Body.Bytes(), &findings); err != nil {
		t.Fatalf("decode findings: %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings stored, got %d", len(findings))
	}
	for _, f := range findings {
		if f.ServerID != enrolled.ServerID {
			t.Fatalf("expected finding to be tagged with the authenticated server id, got %+v", f)
		}
	}
}

func TestActionsRequiresAuth(t *testing.T) {
	srv, _ := newTestServer(t)
	body, _ := json.Marshal(transport.ActionLog{FindingID: "f1", Tier: "A", ActionType: "block_ip"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/actions", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", rec.Code)
	}
}

func TestActionsEndpointAndList(t *testing.T) {
	srv, _ := newTestServer(t)
	enrolled := enrollAgent(t, srv)
	action := transport.ActionLog{
		FindingID:  "f1",
		Tier:       "A",
		ActionType: "block_ip",
		Params:     map[string]any{"ip": "9.9.9.9", "status": "applied"},
	}
	body, _ := json.Marshal(action)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/actions", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+enrolled.Token)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/actions", nil)
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list actions: expected 200, got %d", rec.Code)
	}
	var actions []transport.ActionLog
	if err := json.Unmarshal(rec.Body.Bytes(), &actions); err != nil {
		t.Fatalf("decode actions: %v", err)
	}
	if len(actions) != 1 || actions[0].ActionType != "block_ip" {
		t.Fatalf("expected 1 block_ip action, got %+v", actions)
	}
}

func TestListServers(t *testing.T) {
	srv, _ := newTestServer(t)
	enrolled := enrollAgent(t, srv)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/servers", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var servers []store.Server
	if err := json.Unmarshal(rec.Body.Bytes(), &servers); err != nil {
		t.Fatalf("decode servers: %v", err)
	}
	if len(servers) != 1 || servers[0].ID != enrolled.ServerID {
		t.Fatalf("expected the enrolled server to be listed, got %+v", servers)
	}
}
