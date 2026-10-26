package main

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type Config struct {
	ServerURL string `yaml:"server_url"`
	ServerID  string `yaml:"server_id"`
	Token     string `yaml:"token"`
	Hostname  string `yaml:"hostname"`
}

func loadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	if cfg.ServerURL == "" || cfg.Token == "" {
		return Config{}, fmt.Errorf("config at %s is missing server_url/token", path)
	}
	return cfg, nil
}

// saveConfig writes the token in plaintext, since the agent needs it on
// every request; only the panel stores the hash. Keep this file's
// permissions and the directory it lives in restricted to the owner.
func saveConfig(path string, cfg Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}
