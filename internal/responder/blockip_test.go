package responder

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"nexguard/internal/transport"
)

type call struct {
	name string
	args []string
}

type fakeRunner struct {
	mu          sync.Mutex
	calls       []call
	failExact   map[string]error
	lastComment string
}

func newFakeRunner() *fakeRunner {
	return &fakeRunner{failExact: make(map[string]error)}
}

func (f *fakeRunner) Run(name string, args ...string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call{name: name, args: append([]string{}, args...)})

	key := name + " " + strings.Join(args, " ")
	if err, ok := f.failExact[key]; ok {
		return "", err
	}

	if name == "nft" && len(args) > 0 && args[0] == "add" {
		f.lastComment = args[len(args)-1]
	}
	if name == "nft" && len(args) >= 2 && args[0] == "-a" && args[1] == "list" {
		if f.lastComment == "" {
			return "", nil
		}
		return fmt.Sprintf("\t\tip saddr 9.9.9.9 drop comment %s # handle 42\n", f.lastComment), nil
	}
	return "", nil
}

func lookPathFake(available ...string) func(string) (string, error) {
	set := make(map[string]bool)
	for _, a := range available {
		set[a] = true
	}
	return func(name string) (string, error) {
		if set[name] {
			return "/usr/sbin/" + name, nil
		}
		return "", fmt.Errorf("exec: %q: not found", name)
	}
}

func bruteforceFinding(ip string) transport.Finding {
	return transport.Finding{
		ID:       transport.NewID(),
		Type:     "ssh_bruteforce",
		Severity: "high",
		Summary:  "too many failed logins",
		Evidence: map[string]any{"ip": ip, "attempts": 6},
	}
}

func TestBlockIP_UsesNftWhenAvailable(t *testing.T) {
	runner := newFakeRunner()
	b := NewBlockIP(runner, filepath.Join(t.TempDir(), "actions.jsonl"), time.Hour)
	b.LookPath = lookPathFake("nft", "ufw")

	action, err := b.Respond(bruteforceFinding("9.9.9.9"))
	if err != nil {
		t.Fatalf("Respond returned error: %v", err)
	}
	if action.Params["status"] != "applied" || action.Params["backend"] != "nft" {
		t.Fatalf("expected nft to be applied, got %+v", action.Params)
	}

	if len(runner.calls) != 2 {
		t.Fatalf("expected 2 nft calls (chain check + add rule), got %d: %+v", len(runner.calls), runner.calls)
	}
	wantFirst := call{name: "nft", args: []string{"list", "chain", "inet", "filter", "input"}}
	if runner.calls[0].name != wantFirst.name || strings.Join(runner.calls[0].args, " ") != strings.Join(wantFirst.args, " ") {
		t.Fatalf("expected chain-check call first, got %+v", runner.calls[0])
	}
	second := runner.calls[1]
	if second.name != "nft" || second.args[0] != "add" {
		t.Fatalf("expected nft add rule call second, got %+v", second)
	}
	joined := strings.Join(second.args, " ")
	if !strings.Contains(joined, "ip saddr 9.9.9.9 drop") {
		t.Fatalf("expected nft rule to target the offending ip, got %q", joined)
	}
}

func TestBlockIP_FallsBackToUfwWhenNftChainMissing(t *testing.T) {
	runner := newFakeRunner()
	runner.failExact["nft list chain inet filter input"] = errors.New("No such file or directory")

	b := NewBlockIP(runner, filepath.Join(t.TempDir(), "actions.jsonl"), time.Hour)
	b.LookPath = lookPathFake("nft", "ufw")

	action, err := b.Respond(bruteforceFinding("8.8.8.8"))
	if err != nil {
		t.Fatalf("Respond returned error: %v", err)
	}
	if action.Params["status"] != "applied" || action.Params["backend"] != "ufw" {
		t.Fatalf("expected fallback to ufw, got %+v", action.Params)
	}

	var ufwCall *call
	for i := range runner.calls {
		if runner.calls[i].name == "ufw" {
			ufwCall = &runner.calls[i]
		}
	}
	if ufwCall == nil {
		t.Fatalf("expected a ufw call, got %+v", runner.calls)
	}
	if strings.Join(ufwCall.args, " ") != "insert 1 deny from 8.8.8.8" {
		t.Fatalf("unexpected ufw args: %+v", ufwCall.args)
	}
}

func TestBlockIP_NoBackendAvailableDoesNotCrash(t *testing.T) {
	runner := newFakeRunner()
	auditPath := filepath.Join(t.TempDir(), "actions.jsonl")
	b := NewBlockIP(runner, auditPath, time.Hour)
	b.LookPath = lookPathFake() // neither nft nor ufw present

	action, err := b.Respond(bruteforceFinding("7.7.7.7"))
	if err != nil {
		t.Fatalf("Respond must not return a hard error when no backend is available, got: %v", err)
	}
	if action.Params["status"] != "failed" {
		t.Fatalf("expected status=failed, got %+v", action.Params)
	}
	reason, _ := action.Params["reason"].(string)
	if !strings.Contains(reason, "no usable firewall backend") {
		t.Fatalf("expected reason to explain the failure, got %q", reason)
	}

	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("expected audit log to be written even on failure: %v", err)
	}
	if !strings.Contains(string(data), "failed") {
		t.Fatalf("expected audit log to mention the failure, got %q", data)
	}
}

func TestBlockIP_SkipsWhenFindingHasNoIP(t *testing.T) {
	runner := newFakeRunner()
	b := NewBlockIP(runner, filepath.Join(t.TempDir(), "actions.jsonl"), time.Hour)
	b.LookPath = lookPathFake("nft", "ufw")

	f := bruteforceFinding("")
	delete(f.Evidence, "ip")
	action, err := b.Respond(f)
	if err != nil {
		t.Fatalf("Respond returned error: %v", err)
	}
	if action.Params["status"] != "skipped" {
		t.Fatalf("expected status=skipped, got %+v", action.Params)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("expected no commands to run without an ip, got %+v", runner.calls)
	}
}

func TestBlockIP_SkipsWhenIPIsNotValid(t *testing.T) {
	runner := newFakeRunner()
	b := NewBlockIP(runner, filepath.Join(t.TempDir(), "actions.jsonl"), time.Hour)
	b.LookPath = lookPathFake("nft", "ufw")

	for _, badIP := range []string{"not-an-ip", "1.2.3.4; rm -rf /"} {
		f := bruteforceFinding(badIP)
		action, err := b.Respond(f)
		if err != nil {
			t.Fatalf("Respond returned error for %q: %v", badIP, err)
		}
		if action.Params["status"] != "skipped" {
			t.Fatalf("expected status=skipped for %q, got %+v", badIP, action.Params)
		}
		reason, _ := action.Params["reason"].(string)
		if !strings.Contains(reason, "invalid ip") {
			t.Fatalf("expected reason to mention invalid ip for %q, got %q", badIP, reason)
		}
		if len(runner.calls) != 0 {
			t.Fatalf("expected no firewall commands to run for invalid ip %q, got %+v", badIP, runner.calls)
		}
	}
}

func TestBlockIP_IgnoresNonBruteforceFindings(t *testing.T) {
	runner := newFakeRunner()
	b := NewBlockIP(runner, filepath.Join(t.TempDir(), "actions.jsonl"), time.Hour)
	b.LookPath = lookPathFake("nft", "ufw")

	f := bruteforceFinding("1.2.3.4")
	f.Type = "something_else"
	action, err := b.Respond(f)
	if err != nil {
		t.Fatalf("Respond returned error: %v", err)
	}
	if action != nil {
		t.Fatalf("expected no action for a non-bruteforce finding, got %+v", action)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("expected no commands to run, got %+v", runner.calls)
	}
}

func TestBlockIP_RevertsAfterTTL(t *testing.T) {
	runner := newFakeRunner()
	b := NewBlockIP(runner, filepath.Join(t.TempDir(), "actions.jsonl"), 20*time.Millisecond)
	b.LookPath = lookPathFake("nft", "ufw")

	published := make(chan transport.ActionLog, 4)
	b.Publish = func(a transport.ActionLog) { published <- a }

	f := bruteforceFinding("6.6.6.6")
	applied, err := b.Respond(f)
	if err != nil {
		t.Fatalf("Respond returned error: %v", err)
	}

	first := <-published
	if first.ID != applied.ID || first.Params["status"] != "applied" {
		t.Fatalf("expected first published action to be the applied block, got %+v", first)
	}

	select {
	case second := <-published:
		if second.ID != applied.ID {
			t.Fatalf("expected revert to reuse the same action ID %s, got %s", applied.ID, second.ID)
		}
		if second.RevertedAt == nil {
			t.Fatalf("expected RevertedAt to be set on revert, got %+v", second)
		}
		if second.Params["status"] != "reverted" {
			t.Fatalf("expected status=reverted, got %+v", second.Params)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for TTL-triggered unblock")
	}

	var deleteCall *call
	for i := range runner.calls {
		if runner.calls[i].name == "nft" && len(runner.calls[i].args) > 0 && runner.calls[i].args[0] == "delete" {
			deleteCall = &runner.calls[i]
		}
	}
	if deleteCall == nil {
		t.Fatalf("expected an nft delete rule call, got %+v", runner.calls)
	}
	if strings.Join(deleteCall.args, " ") != "delete rule inet filter input handle 42" {
		t.Fatalf("unexpected delete args: %+v", deleteCall.args)
	}
}
