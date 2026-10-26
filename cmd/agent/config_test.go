package main

import (
	"path/filepath"
	"testing"
)

func TestSaveAndLoadConfigRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "agent.yaml")
	cfg := Config{ServerURL: "http://localhost:8842", ServerID: "srv-1", Token: "sekret", Hostname: "web-01"}

	if err := saveConfig(path, cfg); err != nil {
		t.Fatalf("saveConfig: %v", err)
	}

	got, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if got != cfg {
		t.Fatalf("round-tripped config mismatch: got %+v, want %+v", got, cfg)
	}
}

func TestLoadConfigMissingFile(t *testing.T) {
	_, err := loadConfig(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err == nil {
		t.Fatal("expected an error loading a missing config file")
	}
}

func TestLoadConfigRejectsIncompleteConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.yaml")
	if err := saveConfig(path, Config{ServerURL: "http://localhost:8842"}); err != nil {
		t.Fatalf("saveConfig: %v", err)
	}
	if _, err := loadConfig(path); err == nil {
		t.Fatal("expected an error loading a config with no token")
	}
}
