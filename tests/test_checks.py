from nexguard import checks


class FakeHost(checks.Host):
    def __init__(self, files=None, modes=None, cmds=None, dirs=None, home="/home/u"):
        self.files, self.modes, self.cmds, self.dirs, self._home = files or {}, modes or {}, cmds or {}, dirs or {}, home

    def read(self, path):
        return self.files.get(path)

    def mode(self, path):
        return self.modes.get(path)

    def listdir(self, path):
        return self.dirs.get(path, [])

    def run(self, argv, timeout=15):
        for key, val in self.cmds.items():
            if argv[: len(key)] == list(key):
                return val
        return -1, ""

    def home(self):
        return self._home


def ids(findings, sev=None):
    return {f.id for f in findings if sev is None or f.severity == sev}


def test_ssh_risky_and_include_first_value_wins():
    h = FakeHost(
        files={"/etc/ssh/sshd_config": "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin yes\nPasswordAuthentication yes\nMaxAuthTries 6\n",
               "/etc/ssh/sshd_config.d/10.conf": "PasswordAuthentication no\n"},
        dirs={"/etc/ssh/sshd_config.d": ["10.conf"]})
    f = checks.check_ssh(h)
    assert "ssh.root" in ids(f, "high")
    assert "ssh.password" in ids(f, "ok")  # include dosyası ilk, parolayı kapatıyor
    assert "ssh.tries" in ids(f, "low")


def test_ssh_ignores_match_block():
    h = FakeHost(files={"/etc/ssh/sshd_config": "PermitRootLogin no\nMatch User bob\n  PermitRootLogin yes\n"})
    assert "ssh.root" in ids(checks.check_ssh(h), "ok")


def test_ssh_unreadable_is_info():
    assert ids(checks.check_ssh(FakeHost()), "info") == {"ssh.unreadable"}


def test_parse_listeners_and_risky_ports():
    ss = ("tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n"
          "tcp LISTEN 0 511 127.0.0.1:6379 0.0.0.0:*\n"
          "tcp LISTEN 0 80 [::]:3306 [::]:*\n"
          "udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:*\n")
    assert (("tcp", "127.0.0.1", 6379)) in checks.parse_listeners(ss)
    f = checks.check_ports(FakeHost(cmds={("ss",): (0, ss)}))
    assert ids(f, "high") == {"ports.risky.3306"}  # redis yalnızca loopback'te


def test_firewall_states():
    assert "fw.nft" in ids(checks.check_firewall(FakeHost(cmds={("nft",): (0, "table inet f { chain input {} }")})), "ok")
    assert "fw.nft" in ids(checks.check_firewall(FakeHost(cmds={("nft",): (0, "")})), "high")
    assert "fw.ufw" in ids(checks.check_firewall(FakeHost(cmds={("ufw",): (0, "Status: inactive")})), "high")
    assert ids(checks.check_firewall(FakeHost()), "info") == {"fw.unknown"}


def test_users_findings():
    h = FakeHost(files={"/etc/passwd": "root:x:0:0::/root:/bin/bash\ntoor:x:0:0::/:/bin/sh\nbob::1000:1000::/h:/bin/sh\n",
                        "/etc/sudoers.d/x": "bob ALL=(ALL) NOPASSWD: ALL\n"},
                 dirs={"/etc/sudoers.d": ["x"]})
    assert {"users.uid0", "users.empty", "users.nopasswd"} <= ids(checks.check_users(h))


def test_permissions():
    h = FakeHost(modes={"/etc/shadow": 0o644, "/home/u": 0o755, "/home/u/.ssh": 0o700, "/home/u/.ssh/id_ed25519": 0o644},
                 dirs={"/home/u/.ssh": ["id_ed25519", "id_ed25519.pub"]})
    f = checks.check_permissions(h)
    assert {"perm.shadow", "perm.key.id_ed25519"} <= ids(f, "high")
    assert "perm.home" in ids(f, "low")


def test_suid_flags_unknown_only():
    out = "/usr/bin/sudo\n/usr/bin/passwd\n/opt/evil/backdoor\n"
    f = checks.check_suid(FakeHost(cmds={("nice",): (0, out)}))
    assert ids(f) == {"suid.unknown"} and "backdoor" in f[0].detail and "sudo" not in f[0].detail


def test_updates_security_is_high():
    apt = "Listing...\nopenssl/stable-security 3.0 amd64 [upgradable from: 2.9]\nvim/stable 9 amd64 [upgradable from: 8]\n"
    f = checks.check_updates(FakeHost(cmds={("apt",): (0, apt), ("dpkg",): (0, "")}))
    assert "upd.security" in ids(f, "high")


def test_sysctl_flags_bad_values():
    h = FakeHost(files={"/proc/sys/net/ipv4/tcp_syncookies": "0\n", "/proc/sys/kernel/randomize_va_space": "2\n"})
    f = checks.check_sysctl(h)
    assert ids(f) == {"sysctl.net.ipv4.tcp_syncookies"}


def test_run_all_scores_and_survives_broken_check(monkeypatch):
    def boom(h):
        raise RuntimeError("x")
    monkeypatch.setattr(checks, "CHECKS", [boom, checks.check_users])
    r = checks.run_all(FakeHost(files={"/etc/passwd": "root:x:0:0::/root:/bin/sh\n"}))
    assert r["score"] == 100 and r["grade"] == "A"
    assert any(f["id"] == "error.boom" for f in r["findings"])


def test_score_weights():
    fs = [checks.Finding("a", "high", "t"), checks.Finding("b", "medium", "t"), checks.Finding("c", "ok", "t")]
    assert checks.score(fs) == 100 - 15 - 7
