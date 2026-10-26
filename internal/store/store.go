package store

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	_ "modernc.org/sqlite"

	"nexguard/internal/transport"
)

//go:embed migrations/*.sql
var migrations embed.FS

type Server struct {
	ID         string    `json:"id"`
	Hostname   string    `json:"hostname"`
	OS         string    `json:"os"`
	EnrolledAt time.Time `json:"enrolled_at"`
}

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	db.SetMaxOpenConns(1) // modernc.org/sqlite + concurrent writers need serialization
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) migrate() error {
	entries, err := migrations.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("read migrations: %w", err)
	}
	for _, e := range entries {
		b, err := migrations.ReadFile("migrations/" + e.Name())
		if err != nil {
			return fmt.Errorf("read migration %s: %w", e.Name(), err)
		}
		if _, err := s.db.Exec(string(b)); err != nil {
			return fmt.Errorf("apply migration %s: %w", e.Name(), err)
		}
	}
	return nil
}

// NewID delegates to transport so agent and server generate IDs the same way
// (the agent needs to pre-generate action IDs itself; see BlockIP responder).
func NewID() string {
	return transport.NewID()
}

func NewToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (s *Store) CreateServer(id, hostname, osName, tokenHash string) error {
	_, err := s.db.Exec(
		`INSERT INTO servers (id, hostname, os, token_hash, enrolled_at) VALUES (?, ?, ?, ?, ?)`,
		id, hostname, osName, tokenHash, time.Now().UTC(),
	)
	return err
}

// VerifyToken hashes the candidate token and looks it up directly, since only
// the hash is ever persisted.
func (s *Store) VerifyToken(token string) (serverID string, ok bool, err error) {
	hash := HashToken(token)
	row := s.db.QueryRow(`SELECT id FROM servers WHERE token_hash = ?`, hash)
	err = row.Scan(&serverID)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return serverID, true, nil
}

func (s *Store) ListServers() ([]Server, error) {
	rows, err := s.db.Query(`SELECT id, hostname, os, enrolled_at FROM servers ORDER BY enrolled_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Server
	for rows.Next() {
		var srv Server
		if err := rows.Scan(&srv.ID, &srv.Hostname, &srv.OS, &srv.EnrolledAt); err != nil {
			return nil, err
		}
		out = append(out, srv)
	}
	return out, rows.Err()
}

func (s *Store) InsertFinding(f transport.Finding) error {
	evidence, err := json.Marshal(f.Evidence)
	if err != nil {
		return fmt.Errorf("marshal evidence: %w", err)
	}
	if f.ID == "" {
		f.ID = NewID()
	}
	if f.CreatedAt.IsZero() {
		f.CreatedAt = time.Now().UTC()
	}
	_, err = s.db.Exec(
		`INSERT INTO findings (id, server_id, type, severity, summary, evidence_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		f.ID, f.ServerID, f.Type, f.Severity, f.Summary, string(evidence), f.CreatedAt,
	)
	return err
}

func (s *Store) ListFindings() ([]transport.Finding, error) {
	rows, err := s.db.Query(`SELECT id, server_id, type, severity, summary, evidence_json, created_at FROM findings ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []transport.Finding
	for rows.Next() {
		var f transport.Finding
		var evidence string
		if err := rows.Scan(&f.ID, &f.ServerID, &f.Type, &f.Severity, &f.Summary, &evidence, &f.CreatedAt); err != nil {
			return nil, err
		}
		if evidence != "" {
			if err := json.Unmarshal([]byte(evidence), &f.Evidence); err != nil {
				return nil, fmt.Errorf("unmarshal evidence for finding %s: %w", f.ID, err)
			}
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// InsertAction upserts by ID: the responder pre-generates an action ID when
// it applies a block, then re-sends an ActionLog with the same ID and
// RevertedAt set once the TTL expires and the block is lifted, so the
// dashboard shows one row per action rather than a separate "unblock" row.
func (s *Store) InsertAction(a transport.ActionLog) error {
	params, err := json.Marshal(a.Params)
	if err != nil {
		return fmt.Errorf("marshal params: %w", err)
	}
	if a.ID == "" {
		a.ID = NewID()
	}
	if a.AppliedAt.IsZero() {
		a.AppliedAt = time.Now().UTC()
	}
	_, err = s.db.Exec(
		`INSERT INTO actions (id, finding_id, tier, action_type, params_json, applied_at, reverted_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET
		   params_json = excluded.params_json,
		   reverted_at = excluded.reverted_at`,
		a.ID, a.FindingID, a.Tier, a.ActionType, string(params), a.AppliedAt, a.RevertedAt,
	)
	return err
}

func (s *Store) ListActions() ([]transport.ActionLog, error) {
	rows, err := s.db.Query(`SELECT id, finding_id, tier, action_type, params_json, applied_at, reverted_at FROM actions ORDER BY applied_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []transport.ActionLog
	for rows.Next() {
		var a transport.ActionLog
		var params string
		var revertedAt sql.NullTime
		if err := rows.Scan(&a.ID, &a.FindingID, &a.Tier, &a.ActionType, &params, &a.AppliedAt, &revertedAt); err != nil {
			return nil, err
		}
		if params != "" {
			if err := json.Unmarshal([]byte(params), &a.Params); err != nil {
				return nil, fmt.Errorf("unmarshal params for action %s: %w", a.ID, err)
			}
		}
		if revertedAt.Valid {
			a.RevertedAt = &revertedAt.Time
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
