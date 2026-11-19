package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// Komut durumları: panelde oluşur (pending), ajana yazılır (sent), ajan
// sonucu döndürünce done ya da failed olur.
const (
	CommandPending = "pending"
	CommandSent    = "sent"
	CommandDone    = "done"
	CommandFailed  = "failed"
)

type Command struct {
	ID        string         `json:"id"`
	ServerID  string         `json:"server_id"`
	Type      string         `json:"type"`
	Params    map[string]any `json:"params"`
	Status    string         `json:"status"`
	Result    map[string]any `json:"result,omitempty"`
	Error     string         `json:"error,omitempty"`
	CreatedAt time.Time      `json:"created_at"`
	DoneAt    *time.Time     `json:"done_at,omitempty"`
}

func (s *Store) InsertCommand(c Command) error {
	params, err := json.Marshal(c.Params)
	if err != nil {
		return fmt.Errorf("marshal params: %w", err)
	}
	_, err = s.db.Exec(
		`INSERT INTO commands (id, server_id, type, params_json, status, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		c.ID, c.ServerID, c.Type, string(params), c.Status, c.CreatedAt.UTC(),
	)
	return err
}

// MarkCommandSent yalnızca henüz bitmemiş komutu "sent" yapar.
func (s *Store) MarkCommandSent(id string) error {
	_, err := s.db.Exec(`UPDATE commands SET status = ? WHERE id = ? AND status IN (?, ?)`, CommandSent, id, CommandPending, CommandSent)
	return err
}

// CompleteCommand sonucu kaydeder. Komut başka bir sunucuya aitse ya da zaten
// bitmişse hiçbir şey yapmaz ve false döner; böylece bir ajan başka sunucunun
// komutunu kapatamaz.
func (s *Store) CompleteCommand(serverID, id string, ok bool, result map[string]any, errMsg string) (bool, error) {
	if result == nil {
		result = map[string]any{}
	}
	res, err := json.Marshal(result)
	if err != nil {
		return false, fmt.Errorf("marshal result: %w", err)
	}
	status := CommandDone
	if !ok {
		status = CommandFailed
	}
	r, err := s.db.Exec(
		`UPDATE commands SET status = ?, result_json = ?, error = ?, done_at = ? WHERE id = ? AND server_id = ? AND status IN (?, ?)`,
		status, string(res), errMsg, time.Now().UTC(), id, serverID, CommandPending, CommandSent,
	)
	if err != nil {
		return false, err
	}
	n, _ := r.RowsAffected()
	return n > 0, nil
}

func (s *Store) GetCommand(id string) (Command, bool, error) {
	rows, err := s.queryCommands(`WHERE id = ?`, id)
	if err != nil || len(rows) == 0 {
		return Command{}, false, err
	}
	return rows[0], true, nil
}

// OpenCommands ajana (yeniden) gönderilecek, bitmemiş komutları eskiden
// yeniye döner.
func (s *Store) OpenCommands(serverID string) ([]Command, error) {
	return s.queryCommands(`WHERE server_id = ? AND status IN (?, ?) ORDER BY created_at ASC`, serverID, CommandPending, CommandSent)
}

func (s *Store) ListCommands(serverID string, limit int) ([]Command, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	return s.queryCommands(`WHERE server_id = ? ORDER BY created_at DESC LIMIT ?`, serverID, limit)
}

func (s *Store) ServerExists(id string) (bool, error) {
	var one int
	err := s.db.QueryRow(`SELECT 1 FROM servers WHERE id = ?`, id).Scan(&one)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return err == nil, err
}

func (s *Store) queryCommands(where string, args ...any) ([]Command, error) {
	rows, err := s.db.Query(`SELECT id, server_id, type, params_json, status, result_json, error, created_at, done_at FROM commands `+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Command{}
	for rows.Next() {
		var c Command
		var params, result string
		var done sql.NullTime
		if err := rows.Scan(&c.ID, &c.ServerID, &c.Type, &params, &c.Status, &result, &c.Error, &c.CreatedAt, &done); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(params), &c.Params); err != nil {
			return nil, fmt.Errorf("decode params for command %s: %w", c.ID, err)
		}
		if result != "" && result != "{}" {
			if err := json.Unmarshal([]byte(result), &c.Result); err != nil {
				return nil, fmt.Errorf("decode result for command %s: %w", c.ID, err)
			}
		}
		if done.Valid {
			t := done.Time
			c.DoneAt = &t
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
