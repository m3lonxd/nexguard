package collectors

import (
	"regexp"
	"time"
)

type AuthEvent struct {
	Timestamp time.Time
	IP        string
	User      string
	Success   bool
}

var (
	syslogPrefixRe = regexp.MustCompile(`^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s`)
	failedRe       = regexp.MustCompile(`Failed password for (?:invalid user )?(\S+) from (\S+) port \d+`)
	invalidUserRe  = regexp.MustCompile(`Invalid user (\S+) from (\S+)(?: port \d+)?`)
	acceptedRe     = regexp.MustCompile(`Accepted (?:password|publickey) for (\S+) from (\S+) port \d+`)
)

// ParseAuthLine understands both raw auth.log lines (with a syslog "Mon _2
// 15:04:05 host sshd[pid]:" prefix) and journalctl "-o cat" lines (message
// only, no prefix) by matching on the sshd message content rather than the
// prefix, and falling back to time.Now() when no timestamp is present.
func ParseAuthLine(line string) (*AuthEvent, bool) {
	ts := time.Now()
	if m := syslogPrefixRe.FindStringSubmatch(line); m != nil {
		if parsed, err := time.Parse("Jan _2 15:04:05", m[1]); err == nil {
			ts = time.Date(time.Now().Year(), parsed.Month(), parsed.Day(), parsed.Hour(), parsed.Minute(), parsed.Second(), 0, time.Local)
		}
	}

	if m := failedRe.FindStringSubmatch(line); m != nil {
		return &AuthEvent{Timestamp: ts, User: m[1], IP: m[2], Success: false}, true
	}
	if m := acceptedRe.FindStringSubmatch(line); m != nil {
		return &AuthEvent{Timestamp: ts, User: m[1], IP: m[2], Success: true}, true
	}
	if m := invalidUserRe.FindStringSubmatch(line); m != nil {
		return &AuthEvent{Timestamp: ts, User: m[1], IP: m[2], Success: false}, true
	}
	return nil, false
}
