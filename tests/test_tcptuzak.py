"""Çok portlu TCP tuzağı: ayar doğrulama, kayıt, servis ve panel bölümü."""
import asyncio
import json
import socket

from nexguard import tcptuzak
from nexguard.modules import tuzak
from tests.conftest import csrf_from, do_login


def test_validate_ports():
    assert tcptuzak.validate_ports("2323, 23 5900 23") == ([23, 2323, 5900], None)
    assert tcptuzak.validate_ports("") == ([], None)
    for bad in ("22", "443", "0", "70000", "abc", "8787"):
        ports, err = tcptuzak.validate_ports(bad)
        assert ports == [] and err, bad
    assert tcptuzak.validate_ports(" ".join(str(p) for p in range(3000, 3017)))[1]


def test_config_roundtrip_and_tamper(env):
    tcptuzak.save_config(True, [2323, 5900])
    assert tcptuzak.load_config() == {"enabled": True, "ports": [2323, 5900]}
    # elle bozulmuş ayar: yasak port içeriyorsa tuzak kapalı sayılır
    tcptuzak.config_path().write_text(json.dumps({"enabled": True, "ports": [22, 2323]}))
    assert tcptuzak.load_config() == {"enabled": False, "ports": []}
    tcptuzak.config_path().write_text("bozuk")
    assert tcptuzak.load_config()["enabled"] is False


def test_escape():
    assert tcptuzak.escape(b"GET /\r\n\x00\xff\\") == "GET /\\r\\n\\x00\\xff\\\\"
    assert tcptuzak.escape(b"a" * 300).endswith("…")


def test_record_throttles_and_counts(env):
    trap = tcptuzak.Trap()
    assert trap.record("198.51.100.4", 2323, b"root", now=1000.0)
    assert not trap.record("198.51.100.4", 2323, b"x", now=1003.0)
    assert not trap.record("198.51.100.4", 2323, b"x", now=1005.0)
    assert trap.record("198.51.100.4", 2323, b"y", now=1011.0)
    assert trap.record("198.51.100.4", 5900, b"RFB", now=1011.5)
    rows = [json.loads(x) for x in tcptuzak.log_path().read_text().splitlines()]
    assert [r["n"] for r in rows] == [1, 3, 1]
    assert rows[0]["payload"] == "root"


def test_service_listens_records_and_closes(env):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()

    async def scenario():
        trap = tcptuzak.Trap(bind="127.0.0.1")
        await trap.apply({"enabled": True, "ports": [port]})
        assert port in trap.servers and not trap.errors
        r, w = await asyncio.open_connection("127.0.0.1", port)
        w.write(b"USER root\r\n")
        await w.drain()
        assert await asyncio.wait_for(r.read(), 7) == b""  # tuzak okuyup kapatır
        w.close()
        await asyncio.sleep(0.05)
        await trap.apply({"enabled": False, "ports": [port]})
        assert not trap.servers
        trap.write_status()

    asyncio.run(scenario())
    hits = tcptuzak.hits_for("127.0.0.1")
    assert hits and hits[0]["port"] == port and hits[0]["payload"] == "USER root\\r\\n"
    st = tcptuzak.service_status()
    assert st["running"] is True and st["listening"] == []


def test_busy_port_reports_error(env):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen()
    port = s.getsockname()[1]

    async def scenario():
        trap = tcptuzak.Trap(bind="127.0.0.1")
        await trap.apply({"enabled": True, "ports": [port]})
        return trap.errors

    try:
        errors = asyncio.run(scenario())
    finally:
        s.close()
    assert port in errors


def test_panel_section_and_save_route(env, monkeypatch):
    client, _ = env
    monkeypatch.setattr(tuzak, "_read_journal", lambda: ([], ""))
    monkeypatch.setattr(tuzak, "_read_cowrie", lambda: ([], False))
    monkeypatch.setattr(tuzak, "service_state", lambda: "absent")
    tuzak._cache.update(at=0, data=None)
    do_login(client)
    trap = tcptuzak.Trap()
    trap.record("198.51.100.7", 2323, b"<img src=x onerror=alert(1)>", now=__import__("time").time())
    html = client.get("/m/tuzak").text
    assert 'id="tcp"' in html and 'data-ip="198.51.100.7"' in html
    assert "<img src=x" not in html  # saldırgan baytı kaçışlanır
    tok = csrf_from(client, "/m/tuzak")
    assert client.post("/m/tuzak/tcp", data={"enabled": "1", "ports": "22", "csrf": tok}).status_code == 303
    assert tcptuzak.load_config()["enabled"] is False
    client.post("/m/tuzak/tcp", data={"enabled": "1", "ports": "2323, 5900", "csrf": tok})
    assert tcptuzak.load_config() == {"enabled": True, "ports": [2323, 5900]}
    assert client.post("/m/tuzak/tcp", data={"enabled": "1", "ports": "2323", "csrf": "yanlis"}).status_code == 400
