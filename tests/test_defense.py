import importlib.machinery
import importlib.util
import json
import socket
import struct
import time
from pathlib import Path

import pytest

from nexguard import config, db, defense, fleet, sensor
from tests.conftest import csrf_from, do_login


# --- Paket algılayıcı ---------------------------------------------------------

def ipv4(proto: int, src: str, l4: bytes = b"") -> bytes:
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(l4), 0, 0, 64, proto, 0,
                      socket.inet_aton(src), socket.inet_aton("10.0.0.1"))
    return hdr + l4


def tcp_flags(flags: int) -> bytes:
    return struct.pack("!HHIIBBHHH", 1234, 80, 0, 0, 0x50, flags, 0, 0, 0)


def test_parse_ip_protocols_and_syn():
    assert sensor.parse_ip(ipv4(17, "1.2.3.4", b"\0" * 8)) == ("udp", "1.2.3.4", False)
    assert sensor.parse_ip(ipv4(1, "5.6.7.8", b"\0" * 8)) == ("icmp", "5.6.7.8", False)
    assert sensor.parse_ip(ipv4(6, "9.9.9.9", tcp_flags(0x02))) == ("tcp", "9.9.9.9", True)
    assert sensor.parse_ip(ipv4(6, "9.9.9.9", tcp_flags(0x12))) == ("tcp", "9.9.9.9", False)  # SYN-ACK
    assert sensor.parse_ip(ipv4(47, "9.9.9.9")) == ("other", "9.9.9.9", False)
    assert sensor.parse_ip(b"\x45" + b"\0" * 5) is None
    v6 = bytes([0x60, 0, 0, 0, 0, 8, 17, 64]) + socket.inet_pton(socket.AF_INET6, "2001:db8::1") + b"\0" * 16
    assert sensor.parse_ip(v6 + b"\0" * 8) == ("udp", "2001:db8::1", False)


def test_window_scales_to_kernel_counts():
    w = sensor.Window()
    for _ in range(90):
        w.add(ipv4(17, "1.1.1.1", b"\0" * 80))
    for _ in range(10):
        w.add(ipv4(6, "2.2.2.2", tcp_flags(0x02)))
    r = w.result(1.0, real_pkts=1000)
    assert r["scale"] == 10.0
    assert r["proto"]["udp"]["pps"] == 900.0
    assert r["syn_pps"] == 100.0
    assert r["top"]["udp"][0][:2] == ["1.1.1.1", 900.0]
    assert r["top"]["syn"][0][0] == "2.2.2.2"


def test_sensor_read_states(env):
    assert sensor.read()["state"] == "yok"
    data = sensor.Window().result(1.0)
    data["top"]["udp"] = [["1.1.1.1", 5, 1], ["<script>", 9, 9]]
    sensor.write(data)
    r = sensor.read()
    assert r["state"] == "hazır" and r["data"]["top"]["udp"] == [["1.1.1.1", 5.0, 1.0]]
    data["ts"] = time.time() - 100
    sensor.write(data)
    assert sensor.read()["state"] == "eski"


# --- Engelleme ---------------------------------------------------------------

def test_blockable_rejects_private_and_allowlisted():
    import ipaddress
    allow = [ipaddress.ip_network("8.8.8.0/24")]
    assert defense.blockable("1.2.3.4", allow)
    assert not defense.blockable("8.8.8.8", allow)
    for ip in ("10.0.0.1", "127.0.0.1", "192.168.1.1", "::1", "fe80::1", "::ffff:10.0.0.1", "nonsense"):
        assert not defense.blockable(ip, [])


def test_candidates_tcp_and_flood():
    data = {"top": {"udp": [["3.3.3.3", 9000, 5.0], ["4.4.4.4", 10, 0.1]], "syn": [["1.1.1.1", 8000, 0]]}}
    out = dict(defense.candidates([("1.1.1.1", 400), ("2.2.2.2", 3)], 300, data, 5000))
    assert set(out) == {"1.1.1.1", "3.3.3.3"}
    assert "TCP" in out["1.1.1.1"]  # TCP ölçütü öncelikli


def test_block_unblock_and_clear(env):
    assert defense.block([("1.2.3.4", "test"), ("10.0.0.1", "özel")], ttl=600) == ["1.2.3.4"]
    want = json.loads(defense.want_path().read_text())
    assert want["active"] and [e["ip"] for e in want["block"]] == ["1.2.3.4"]
    assert defense.block([("1.2.3.4", "tekrar")]) == []  # yenilenir, yeni değil
    assert set(defense.load_blocks()) == {"1.2.3.4"}
    assert defense.unblock("1.2.3.4") and not defense.unblock("1.2.3.4")
    defense.clear_all()
    assert json.loads(defense.want_path().read_text())["active"] is False
    assert oct(defense.want_path().stat().st_mode & 0o777) == "0o600"


def test_on_attack_respects_switch(env):
    assert defense.on_attack([("1.2.3.4", 999)], 300, None) == []
    db.set_setting("defense.autoblock", "1")
    assert defense.on_attack([("1.2.3.4", 999)], 300, None) == ["1.2.3.4"]
    assert defense.load_blocks()["1.2.3.4"]["auto"] is True


def test_cf_validate():
    good_tok, zone = "a" * 40, "0123456789abcdef0123456789abcdef"
    assert defense.cf_validate(good_tok, zone) == ([zone], None)
    assert defense.cf_validate("kısa", zone)[1]
    assert defense.cf_validate(good_tok, "xyz")[1]
    assert defense.cf_validate("", f"{zone}, {zone.upper()}")[0] == [zone, zone]


def test_cf_set_attack_restores_previous(env, monkeypatch):
    calls = []

    def fake(method, path, token, body=None):
        calls.append((method, body))
        return {"result": {"value": "high"}}

    monkeypatch.setattr(defense, "_cf", fake)
    db.set_setting("cf.token", "a" * 40)
    db.set_setting("cf.zones", "0" * 32)
    defense.cf_set_attack(True)
    assert ("PATCH", {"value": "under_attack"}) in calls and defense.cf_status()["active"]
    defense.cf_set_attack(False)
    assert calls[-1] == ("PATCH", {"value": "high"}) and not defense.cf_status()["active"]


# --- Root yardımcısı (nft betiği) ---------------------------------------------

@pytest.fixture()
def helper(tmp_path, monkeypatch):
    path = Path(__file__).resolve().parent.parent / "deploy" / "nexguard-engel"
    loader = importlib.machinery.SourceFileLoader("nexguard_engel", str(path))
    spec = importlib.util.spec_from_loader("nexguard_engel", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    monkeypatch.setattr(mod, "DATA", str(tmp_path))
    monkeypatch.setattr(mod, "WANT", str(tmp_path / "engel.json"))
    monkeypatch.setattr(mod, "STATE", str(tmp_path / "engel.state"))
    allow = tmp_path / "izinli"
    allow.write_text("# yorum\n5.5.5.0/24\n")
    monkeypatch.setattr(mod, "ALLOW", str(allow))
    monkeypatch.setattr(mod, "ssh_peers", lambda: {__import__("ipaddress").ip_address("6.6.6.6")})
    scripts = []
    monkeypatch.setattr(mod, "nft", scripts.append)
    return mod, tmp_path, scripts


def test_helper_builds_safe_script(helper):
    mod, tmp, scripts = helper
    now = time.time()
    block = [{"ip": ip, "until": now + 600} for ip in
             ("1.2.3.4", "2001:db8::1", "2606:4700::1", "10.0.0.1", "5.5.5.5", "6.6.6.6", "1.1.1.1; drop")]
    block.append({"ip": "9.9.9.9", "until": now + 10**7})
    (tmp / "engel.json").write_text(json.dumps({"active": True, "block": block}))
    assert mod.main() == 0
    script = scripts[0]
    assert script.startswith("table inet nexguard {}\ndelete table inet nexguard\n")
    assert "priority -300" in script
    assert "1.2.3.4 timeout" in script and "2606:4700::1 timeout" in script
    assert "9.9.9.9 timeout 86400s" in script
    for bad in ("10.0.0.1", "5.5.5.5", "6.6.6.6", "drop }", "2001:db8::1"):
        assert bad not in "".join(line for line in script.splitlines() if line.startswith("add element"))
    st = json.loads((tmp / "engel.state").read_text())
    assert st["count"] == 3 and st["skipped"] == 5 and not st["error"]


def test_helper_inactive_deletes_table(helper, monkeypatch):
    mod, tmp, scripts = helper
    ran = []
    monkeypatch.setattr(mod.subprocess, "run", lambda args, **kw: ran.append(args))
    (tmp / "engel.json").write_text(json.dumps({"active": False}))
    assert mod.main() == 0
    assert ran == [["nft", "delete", "table", "inet", "nexguard"]] and not scripts


# --- Savunma sayfası ---------------------------------------------------------

def test_savunma_routes(env):
    client, _ = env
    do_login(client)
    page = client.get("/m/savunma")
    assert page.status_code == 200 and "KURULU DEĞİL" in page.text and 'style="' not in page.text
    tok = csrf_from(client, "/m/savunma")
    r = client.post("/m/savunma/block", data={"csrf": tok, "ip": "10.0.0.1", "minutes": "5"})
    assert r.status_code == 303 and "engellenemez" in client.get("/m/savunma").text
    client.post("/m/savunma/block", data={"csrf": tok, "ip": "1.2.3.4", "minutes": "5"})
    assert "1.2.3.4" in client.get("/m/savunma").text
    client.post("/m/savunma/auto", data={"csrf": tok, "autoblock": "1", "src_pps": "7000", "allow": "8.8.8.8 bad"})
    assert not defense.enabled()  # geçersiz izin listesi kaydedilmez
    client.post("/m/savunma/auto", data={"csrf": tok, "autoblock": "1", "src_pps": "7000", "allow": "8.8.8.8"})
    assert defense.enabled() and defense.src_pps_limit() == 7000
    client.post("/m/savunma/unblock", data={"csrf": tok, "ip": "1.2.3.4"})
    assert defense.load_blocks() == {}
    client.post("/m/savunma/cf", data={"csrf": tok, "token": "x", "zones": ""})
    assert not defense.cf_status()["configured"]
    assert client.post("/m/savunma/block", data={"csrf": "bad", "ip": "1.2.3.4"}).status_code == 400


# --- Filo --------------------------------------------------------------------

def test_api_requires_token_and_rate_limits(env):
    client, limiter = env
    assert client.get("/api/v1/ozet").status_code == 401  # anahtar üretilmedi
    token = fleet.new_api_token()
    assert client.get("/api/v1/ozet", headers={"Authorization": "Bearer yanlis"}).status_code == 401
    ok = client.get("/api/v1/ozet", headers={"Authorization": f"Bearer {token}"})
    assert ok.status_code == 200
    body = ok.json()
    assert body["v"] == 1 and {"mem_pct", "disk_pct", "modules", "events"} <= body.keys()
    assert all("visual" not in m for m in body["modules"])
    assert db.get_setting("api.token_hash") != token
    for _ in range(3):
        client.get("/api/v1/ozet", headers={"Authorization": "Bearer yanlis"})
    assert client.get("/api/v1/ozet", headers={"Authorization": f"Bearer {token}"}).status_code == 429


def test_settings_shows_token_once(env):
    client, _ = env
    do_login(client)
    tok = csrf_from(client, "/settings")
    page = client.post("/settings/api/new", data={"csrf": tok}).text
    assert "ngf_" in page
    assert "ngf_" not in client.get("/settings").text
    client.post("/settings/api/revoke", data={"csrf": tok})
    assert not fleet.api_status()["enabled"]


def test_validate_url():
    assert fleet.validate_url("https://panel.example.com/")[0] == "https://panel.example.com"
    assert fleet.validate_url("http://127.0.0.1:9001")[0] == "http://127.0.0.1:9001"
    for bad in ("http://panel.example.com", "ftp://x", "https://u:p@x.com", "https://x.com/?a=1", "javascript:1"):
        assert fleet.validate_url(bad)[1], bad


def test_sanitize_clips_untrusted_fields():
    data = fleet.sanitize({"name": "x" * 500, "mem_pct": 900, "modules": [
        {"slug": "ddos", "title": "DDoS", "status": "evil\" onclick", "headline": "<b>h</b>"}] * 50,
        "events": [{"level": "boom", "message": "m"}]})
    assert len(data["name"]) == 60 and data["mem_pct"] == 100
    assert len(data["modules"]) == 30 and data["modules"][0]["status"] == "idle"
    assert data["events"][0]["level"] == "info"
    with pytest.raises(ValueError):
        fleet.sanitize([1, 2])


def test_fleet_end_to_end_against_live_api(env, monkeypatch):
    """İki panel: biri diğerinin API'sini TestClient üzerinden okur."""
    client, _ = env
    token = fleet.new_api_token()

    class Resp:
        def __init__(self, r):
            self.status, self._b = r.status_code, r.content

        def read(self, n):
            return self._b[:n]

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_open(req, timeout):
        assert req.full_url == "http://127.0.0.1:9001/api/v1/ozet"
        r = client.get("/api/v1/ozet", headers={"Authorization": req.headers["Authorization"]})
        if r.status_code != 200:
            import urllib.error
            raise urllib.error.HTTPError(req.full_url, r.status_code, "x", {}, None)
        return Resp(r)

    monkeypatch.setattr(fleet._opener, "open", fake_open)
    do_login(client)
    tok = csrf_from(client, "/m/filo")
    client.post("/m/filo/add", data={"csrf": tok, "name": "web-2", "url": "http://127.0.0.1:9001", "token": token})
    page = client.get("/m/filo").text
    assert "web-2" in page and "bağlantı tamam" in page and 'style="' not in page
    sid = fleet.servers()[0]["id"]
    assert fleet.status(sid)["ok"]
    fleet.revoke_api_token()
    fleet.poll_one(fleet.servers()[0])
    assert fleet.status(sid)["error"] == "anahtar reddedildi"
    assert "Erişilemiyor" in client.get("/m/filo").text
    client.post("/m/filo/add", data={"csrf": tok, "name": "kötü", "url": "http://evil.example", "token": token})
    assert len(fleet.servers()) == 1
    client.post("/m/filo/remove", data={"csrf": tok, "sid": sid})
    assert fleet.servers() == []
