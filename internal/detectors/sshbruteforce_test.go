package detectors

import (
	"testing"
	"time"

	"nexguard/internal/collectors"
)

func failedEvent(ip, user string, at time.Time) collectors.AuthEvent {
	return collectors.AuthEvent{Timestamp: at, IP: ip, User: user, Success: false}
}

func TestSSHBruteForce_BelowThresholdDoesNotFire(t *testing.T) {
	d := NewSSHBruteForce(5*time.Minute, 5)
	base := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)

	for i := 0; i < 4; i++ {
		ev := failedEvent("1.2.3.4", "root", base.Add(time.Duration(i)*time.Second))
		if f := d.Feed(ev); f != nil {
			t.Fatalf("attempt %d: expected no finding below threshold, got %+v", i, f)
		}
	}
}

func TestSSHBruteForce_AboveThresholdFires(t *testing.T) {
	d := NewSSHBruteForce(5*time.Minute, 5)
	base := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)

	var lastFinding = -1
	for i := 0; i < 5; i++ {
		ev := failedEvent("1.2.3.4", "root", base.Add(time.Duration(i)*time.Second))
		if f := d.Feed(ev); f != nil {
			lastFinding = i
			if f.Type != "ssh_bruteforce" || f.Severity != "high" {
				t.Fatalf("unexpected finding shape: %+v", f)
			}
			if f.Evidence["ip"] != "1.2.3.4" {
				t.Fatalf("expected ip in evidence, got %+v", f.Evidence)
			}
			if f.ID == "" {
				t.Fatalf("expected finding to have a generated ID")
			}
			if attempts, _ := f.Evidence["attempts"].(int); attempts != 5 {
				t.Fatalf("expected 5 attempts recorded, got %+v", f.Evidence["attempts"])
			}
		}
	}
	if lastFinding != 4 {
		t.Fatalf("expected finding to fire exactly on the 5th (index 4) event, fired on index %d", lastFinding)
	}
}

func TestSSHBruteForce_FiresOnceThenQuietUntilWindowClears(t *testing.T) {
	d := NewSSHBruteForce(5*time.Minute, 3)
	base := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)

	events := []time.Time{
		base,
		base.Add(1 * time.Second),
		base.Add(2 * time.Second), // 3rd attempt: should fire
		base.Add(3 * time.Second), // still within window, already fired: should stay quiet
	}
	fired := 0
	for _, at := range events {
		if f := d.Feed(failedEvent("9.9.9.9", "admin", at)); f != nil {
			fired++
		}
	}
	if fired != 1 {
		t.Fatalf("expected exactly 1 finding while burst continues inside window, got %d", fired)
	}
}

func TestSSHBruteForce_AttemptsOutsideWindowAreNotCounted(t *testing.T) {
	d := NewSSHBruteForce(5*time.Minute, 3)
	base := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)

	// Two early attempts fall outside the window by the time the 3rd+ arrive.
	if f := d.Feed(failedEvent("5.5.5.5", "root", base)); f != nil {
		t.Fatalf("unexpected early finding: %+v", f)
	}
	if f := d.Feed(failedEvent("5.5.5.5", "root", base.Add(1*time.Minute))); f != nil {
		t.Fatalf("unexpected early finding: %+v", f)
	}

	// These three arrive more than 5 minutes after the first two, so only
	// they (plus each other) should count toward the threshold.
	late := base.Add(10 * time.Minute)
	if f := d.Feed(failedEvent("5.5.5.5", "root", late)); f != nil {
		t.Fatalf("expected no finding yet (1 attempt in window), got %+v", f)
	}
	if f := d.Feed(failedEvent("5.5.5.5", "root", late.Add(1*time.Second))); f != nil {
		t.Fatalf("expected no finding yet (2 attempts in window), got %+v", f)
	}
	f := d.Feed(failedEvent("5.5.5.5", "root", late.Add(2*time.Second)))
	if f == nil {
		t.Fatalf("expected finding once 3 attempts fall inside the window")
	}
	if attempts, _ := f.Evidence["attempts"].(int); attempts != 3 {
		t.Fatalf("expected only the 3 in-window attempts to be counted, got %+v", f.Evidence["attempts"])
	}
}

func TestSSHBruteForce_DifferentIPsCountedSeparately(t *testing.T) {
	d := NewSSHBruteForce(5*time.Minute, 3)
	base := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)

	var findingsA, findingsB int
	for i := 0; i < 3; i++ {
		at := base.Add(time.Duration(i) * time.Second)
		if f := d.Feed(failedEvent("1.1.1.1", "root", at)); f != nil {
			findingsA++
		}
		if f := d.Feed(failedEvent("2.2.2.2", "root", at)); f != nil {
			findingsB++
		}
	}
	if findingsA != 1 {
		t.Fatalf("expected IP A to fire exactly once, fired %d times", findingsA)
	}
	if findingsB != 1 {
		t.Fatalf("expected IP B to fire exactly once, fired %d times", findingsB)
	}
}

func TestSSHBruteForce_SuccessfulLoginIgnored(t *testing.T) {
	d := NewSSHBruteForce(5*time.Minute, 3)
	base := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)

	for i := 0; i < 10; i++ {
		ev := collectors.AuthEvent{Timestamp: base.Add(time.Duration(i) * time.Second), IP: "3.3.3.3", User: "deploy", Success: true}
		if f := d.Feed(ev); f != nil {
			t.Fatalf("successful logins must never trigger a finding, got %+v", f)
		}
	}
}
