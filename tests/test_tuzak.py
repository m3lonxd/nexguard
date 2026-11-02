import json

from nexguard.modules import tuzak

AUTH = [
    "2026-11-02T08:13:24+0000 debian sshd-session[1]: Failed password for invalid user blank from 49.124.150.251 port 35706 ssh2",
    "2026-11-02T08:13:25+0000 debian sshd-session[2]: Failed password for root from 49.124.150.251 port 35707 ssh2",
    # saldırgan kullanıcı adına sahte " from " koyarsa IP yine sondan alınmalı
    "2026-11-02T08:13:26+0000 debian sshd-session[3]: Failed password for invalid user x from 1.2.3.4 port 1 ssh2 from 8.8.8.8 port 22 ssh2",
    "2026-11-02T08:14:00+0000 debian sshd-session[4]: Accepted publickey for root from 9.9.9.9 port 5 ssh2: ED25519 SHA256:abc",
    "2026-11-02T08:14:01+0000 debian sshd-session[5]: Connection closed by 58.247.18.34 port 34501",
]


def cow(**e):
    return json.dumps({"session": "s1", "src_ip": "5.6.7.8", "timestamp": "2026-11-02T08:00:00Z", **e})


def test_parse_auth_counts_and_resists_injection():
    r = tuzak.parse_auth(AUTH)
    assert [f["ip"] for f in r["failed"]] == ["49.124.150.251", "49.124.150.251", "8.8.8.8"]
    assert r["failed"][0]["invalid"] and not r["failed"][1]["invalid"]
    assert r["accepted"] == [{"ts": "2026-11-02T08:14:00+0000", "method": "publickey", "user": "root", "ip": "9.9.9.9"}]


def test_parse_cowrie_session_and_bad_lines():
    lines = ["bozuk json", "[1]", cow(eventid="cowrie.session.connect"),
             cow(eventid="cowrie.login.success", username="root", password="123456"),
             cow(eventid="cowrie.command.input", input="uname -a\x1b[31m\x00"),
             cow(eventid="cowrie.session.file_download", url="http://x/y.sh")]
    r = tuzak.parse_cowrie(lines)
    s = r["sessions"]["s1"]
    assert s["success"] and s["password"] == "123456" and s["downloads"] == ["http://x/y.sh"]
    assert "\x1b" not in s["commands"][0] and "\x00" not in s["commands"][0]
    assert r["passwords"]["123456"] == 1


def test_build_without_trap_and_empty_input():
    d = tuzak.build([], [], False)
    assert d["attempts"] == 0 and d["trap_sessions"] == 0 and not d["installed"]


def test_page_escapes_attacker_html(env, monkeypatch):
    from tests.test_module_routes import do_login
    client, _ = env
    lines = [cow(eventid="cowrie.login.success", username="<script>alert(1)</script>", password="p"),
             cow(eventid="cowrie.command.input", input="<img src=x onerror=alert(1)>")]
    monkeypatch.setattr(tuzak, "_read_journal", lambda: (AUTH, ""))
    monkeypatch.setattr(tuzak, "_read_cowrie", lambda: (lines, True))
    monkeypatch.setattr(tuzak, "service_state", lambda: "on")
    tuzak._cache.update(at=0.0, data=None)
    do_login(client)
    html = client.get("/m/tuzak").text
    assert "<script>alert(1)" not in html and "<img src=x" not in html and "&lt;img src=x" in html
    assert "Tuzağı" in html or "KURULU DEĞİL" in html
    tuzak._cache.update(at=0.0, data=None)


def test_toggle_needs_csrf_validates_and_writes_only_known_values(env, monkeypatch):
    from tests.conftest import csrf_from, do_login
    client, _ = env
    monkeypatch.setattr(tuzak, "service_state", lambda: "off")
    monkeypatch.setattr(tuzak, "_read_journal", lambda: ([], ""))
    monkeypatch.setattr(tuzak, "_read_cowrie", lambda: ([], False))
    tuzak._cache.update(at=0.0, data=None)
    do_login(client)
    assert client.post("/m/tuzak/toggle", data={"want": "on"}).status_code == 400
    assert not tuzak.want_path().exists()
    tok = csrf_from(client, "/m/tuzak")
    client.post("/m/tuzak/toggle", data={"csrf": tok, "want": "rm -rf /"})
    assert not tuzak.want_path().exists()
    assert client.post("/m/tuzak/toggle", data={"csrf": tok, "want": "on"}).status_code == 303
    assert tuzak.want_path().read_text() == "on\n"
    monkeypatch.setattr(tuzak, "service_state", lambda: "absent")
    tuzak.want_path().unlink()
    client.post("/m/tuzak/toggle", data={"csrf": tok, "want": "on"})
    assert not tuzak.want_path().exists()
    tuzak._cache.update(at=0.0, data=None)
