package collectors

import "testing"

func TestParseAuthLine(t *testing.T) {
	tests := []struct {
		name        string
		line        string
		wantOK      bool
		wantIP      string
		wantUser    string
		wantSuccess bool
	}{
		{
			name:        "syslog failed password known user",
			line:        "Oct 24 10:23:45 myhost sshd[1234]: Failed password for root from 192.168.1.5 port 54321 ssh2",
			wantOK:      true,
			wantIP:      "192.168.1.5",
			wantUser:    "root",
			wantSuccess: false,
		},
		{
			name:        "syslog failed password invalid user",
			line:        "Oct 24 10:23:46 myhost sshd[1235]: Failed password for invalid user admin from 192.168.1.5 port 54322 ssh2",
			wantOK:      true,
			wantIP:      "192.168.1.5",
			wantUser:    "admin",
			wantSuccess: false,
		},
		{
			name:        "syslog invalid user line",
			line:        "Oct 24 10:23:44 myhost sshd[1235]: Invalid user admin from 192.168.1.5 port 54322",
			wantOK:      true,
			wantIP:      "192.168.1.5",
			wantUser:    "admin",
			wantSuccess: false,
		},
		{
			name:        "syslog accepted password",
			line:        "Oct 24 10:24:00 myhost sshd[1240]: Accepted password for deploy from 192.168.1.9 port 51234 ssh2",
			wantOK:      true,
			wantIP:      "192.168.1.9",
			wantUser:    "deploy",
			wantSuccess: true,
		},
		{
			name:        "syslog accepted publickey with trailing fingerprint",
			line:        "Oct 24 10:24:05 myhost sshd[1241]: Accepted publickey for deploy from 192.168.1.9 port 51235 ssh2: RSA SHA256:abcdef",
			wantOK:      true,
			wantIP:      "192.168.1.9",
			wantUser:    "deploy",
			wantSuccess: true,
		},
		{
			name:        "syslog failed password ipv6",
			line:        "Oct 24 10:25:00 myhost sshd[1242]: Failed password for root from 2001:db8::1 port 54321 ssh2",
			wantOK:      true,
			wantIP:      "2001:db8::1",
			wantUser:    "root",
			wantSuccess: false,
		},
		{
			name:        "journald cat mode failed password invalid user",
			line:        "Failed password for invalid user test from 10.0.0.5 port 22222 ssh2",
			wantOK:      true,
			wantIP:      "10.0.0.5",
			wantUser:    "test",
			wantSuccess: false,
		},
		{
			name:        "journald cat mode accepted publickey",
			line:        "Accepted publickey for ubuntu from 10.0.0.9 port 22223 ssh2: ED25519 SHA256:xyz",
			wantOK:      true,
			wantIP:      "10.0.0.9",
			wantUser:    "ubuntu",
			wantSuccess: true,
		},
		{
			name:   "unrelated sshd disconnect line",
			line:   "Oct 24 10:26:00 myhost sshd[1250]: Received disconnect from 192.168.1.5 port 54321:11: disconnected by user",
			wantOK: false,
		},
		{
			name:   "garbage line",
			line:   "this is not a valid ssh log line at all",
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev, ok := ParseAuthLine(tt.line)
			if ok != tt.wantOK {
				t.Fatalf("ParseAuthLine(%q) ok = %v, want %v", tt.line, ok, tt.wantOK)
			}
			if !tt.wantOK {
				return
			}
			if ev.IP != tt.wantIP {
				t.Errorf("IP = %q, want %q", ev.IP, tt.wantIP)
			}
			if ev.User != tt.wantUser {
				t.Errorf("User = %q, want %q", ev.User, tt.wantUser)
			}
			if ev.Success != tt.wantSuccess {
				t.Errorf("Success = %v, want %v", ev.Success, tt.wantSuccess)
			}
			if ev.Timestamp.IsZero() {
				t.Errorf("Timestamp should not be zero")
			}
		})
	}
}
