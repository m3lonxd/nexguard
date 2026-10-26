package detectors

import (
	"fmt"
	"sort"
	"time"

	"nexguard/internal/collectors"
	"nexguard/internal/transport"
)

const (
	DefaultWindow    = 5 * time.Minute
	DefaultThreshold = 5
)

type attempt struct {
	at   time.Time
	user string
}

// SSHBruteForce is deliberately not goroutine-safe; callers feed it events
// from a single consumer loop. Now is injectable so tests can drive the
// sliding window without real sleeps.
type SSHBruteForce struct {
	Window    time.Duration
	Threshold int
	Now       func() time.Time

	attemptsByIP map[string][]attempt
	firedByIP    map[string]bool
}

func NewSSHBruteForce(window time.Duration, threshold int) *SSHBruteForce {
	if window <= 0 {
		window = DefaultWindow
	}
	if threshold <= 0 {
		threshold = DefaultThreshold
	}
	return &SSHBruteForce{
		Window:       window,
		Threshold:    threshold,
		Now:          time.Now,
		attemptsByIP: make(map[string][]attempt),
		firedByIP:    make(map[string]bool),
	}
}

// Feed records one auth event and returns a Finding once the IP crosses the
// threshold within the window. It returns nil for successful logins and for
// IPs that haven't crossed the threshold yet. Once fired for an IP, it stays
// quiet for that IP until the attempts age back out of the window, so a
// single burst doesn't produce a Finding per subsequent failed attempt.
//
// The window is measured against each event's own Timestamp rather than a
// wall clock, so tests can drive the sliding window deterministically by
// feeding AuthEvents with synthetic timestamps.
func (d *SSHBruteForce) Feed(ev collectors.AuthEvent) *transport.Finding {
	if ev.Success {
		return nil
	}
	cutoff := ev.Timestamp.Add(-d.Window)

	attempts := append(d.attemptsByIP[ev.IP], attempt{at: ev.Timestamp, user: ev.User})
	attempts = pruneBefore(attempts, cutoff)
	d.attemptsByIP[ev.IP] = attempts

	if len(attempts) < d.Threshold {
		d.firedByIP[ev.IP] = false
		return nil
	}
	if d.firedByIP[ev.IP] {
		return nil
	}
	d.firedByIP[ev.IP] = true

	now := d.Now
	if now == nil {
		now = time.Now
	}

	users := uniqueUsers(attempts)
	return &transport.Finding{
		// Generated here, not left for the server, so the agent can link a
		// responder's ActionLog.FindingID before the panel is even reachable.
		ID:       transport.NewID(),
		Type:     "ssh_bruteforce",
		Severity: "high",
		Summary:  fmt.Sprintf("%d failed SSH logins from %s in %s", len(attempts), ev.IP, d.Window),
		Evidence: map[string]any{
			"ip":          ev.IP,
			"attempts":    len(attempts),
			"window":      d.Window.String(),
			"users_tried": users,
		},
		CreatedAt: now(),
	}
}

func pruneBefore(attempts []attempt, cutoff time.Time) []attempt {
	out := attempts[:0]
	for _, a := range attempts {
		if a.at.After(cutoff) {
			out = append(out, a)
		}
	}
	return out
}

func uniqueUsers(attempts []attempt) []string {
	seen := make(map[string]bool)
	var users []string
	for _, a := range attempts {
		if !seen[a.user] {
			seen[a.user] = true
			users = append(users, a.user)
		}
	}
	sort.Strings(users)
	return users
}
