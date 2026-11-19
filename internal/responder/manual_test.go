package responder

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func newTestBlocker(t *testing.T) (*BlockIP, *fakeRunner) {
	t.Helper()
	runner := newFakeRunner()
	b := NewBlockIP(runner, filepath.Join(t.TempDir(), "actions.jsonl"), time.Hour)
	b.LookPath = lookPathFake("nft")
	return b, runner
}

func TestManualBlockAndUnblock(t *testing.T) {
	b, _ := newTestBlocker(t)
	a, err := b.Manual("198.51.100.7", 2*time.Hour, "cmd-1")
	if err != nil || a.Params["status"] != "applied" || a.Tier != "manual" || a.Params["command"] != "cmd-1" || a.Params["ttl"] != "2h0m0s" {
		t.Fatalf("manual block: %+v %v", a, err)
	}
	if got := b.Active(); len(got) != 1 || got[0] != "198.51.100.7" {
		t.Fatalf("active = %v", got)
	}
	// aynı ip ikinci kez engellenmez
	dup, _ := b.Manual("198.51.100.7", time.Hour, "cmd-2")
	if dup.Params["status"] != "skipped" || dup.Params["reason"] != "already blocked" {
		t.Fatalf("duplicate: %+v", dup)
	}
	r, err := b.Unblock("198.51.100.7")
	if err != nil || r.Params["status"] != "reverted" || r.ID != a.ID || r.RevertedAt == nil {
		t.Fatalf("unblock: %+v %v", r, err)
	}
	if len(b.Active()) != 0 {
		t.Fatalf("active after unblock = %v", b.Active())
	}
	if _, err := b.Unblock("198.51.100.7"); !errors.Is(err, ErrNotBlocked) {
		t.Fatalf("second unblock err = %v", err)
	}
}

func TestAllowlistSkipsBlocks(t *testing.T) {
	b, runner := newTestBlocker(t)
	b.SetAllow([]string{"198.51.100.9"})
	a, _ := b.Respond(bruteforceFinding("198.51.100.9"))
	if a.Params["status"] != "skipped" || a.Params["reason"] != "allowlisted" {
		t.Fatalf("allowlisted auto block: %+v", a)
	}
	m, _ := b.Manual("198.51.100.9", time.Hour, "c")
	if m.Params["status"] != "skipped" {
		t.Fatalf("allowlisted manual block: %+v", m)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("allowlisted ip için komut çalıştı: %+v", runner.calls)
	}
}

func TestAutoBlockTypes(t *testing.T) {
	b, _ := newTestBlocker(t)
	f := bruteforceFinding("198.51.100.10")
	f.Type = "honeypot_ssh"
	if a, _ := b.Respond(f); a != nil {
		t.Fatalf("honeypot bulgusu varsayılan olarak engellenmemeli: %+v", a)
	}
	b.SetAutoBlock("honeypot_ssh", true)
	if a, _ := b.Respond(f); a == nil || a.Params["status"] != "applied" {
		t.Fatalf("auto block açıkken engellenmeliydi: %+v", a)
	}
}

func TestNeverBlocksLocalAddresses(t *testing.T) {
	b, runner := newTestBlocker(t)
	for _, ip := range []string{"127.0.0.1", "::1", "0.0.0.0", "169.254.1.1", "fe80::1"} {
		a, err := b.Manual(ip, time.Hour, "c")
		if err != nil || a.Params["status"] != "skipped" || a.Params["reason"] != "local address" {
			t.Fatalf("%s engellenmemeliydi: %+v %v", ip, a, err)
		}
	}
	if len(runner.calls) != 0 {
		t.Fatalf("yerel adres için güvenlik duvarı komutu çalıştı: %+v", runner.calls)
	}
}
