package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"gopkg.in/yaml.v3"

	"nexguard/internal/honeypot"
)

// agentState panelden gelen ve yeniden başlatmada korunması gereken
// ayarlardır: izin listesi ve honeypot yapılandırması.
type agentState struct {
	Allow    []string        `yaml:"allow"`
	Honeypot honeypot.Config `yaml:"honeypot"`
}

type stateStore struct {
	path string
	mu   sync.Mutex
	st   agentState
}

func openState(path string) (*stateStore, error) {
	s := &stateStore{path: path}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(b, &s.st); err != nil {
		return nil, fmt.Errorf("parse state %s: %w", path, err)
	}
	return s, nil
}

func (s *stateStore) get() agentState {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.st
	out.Allow = append([]string{}, s.st.Allow...)
	out.Honeypot.TCPPorts = append([]int{}, s.st.Honeypot.TCPPorts...)
	return out
}

// update değişikliği uygular ve dosyaya atomik yazar (geçici dosya + rename).
func (s *stateStore) update(fn func(*agentState)) (agentState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.st
	next.Allow = append([]string{}, s.st.Allow...)
	fn(&next)
	sort.Strings(next.Allow)
	b, err := yaml.Marshal(next)
	if err != nil {
		return s.st, err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return s.st, fmt.Errorf("state dir: %w", err)
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return s.st, fmt.Errorf("write state: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return s.st, fmt.Errorf("write state: %w", err)
	}
	s.st = next
	return next, nil
}
