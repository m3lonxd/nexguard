"""IP detay çekmecesi: /api/ip ve /api/ip/{işlem} uçları."""
from nexguard import db, defense
from nexguard.modules import tuzak
from tests.conftest import csrf_from, do_login

AUTH = ["2026-11-20T10:00:00+0300 h sshd[1]: Failed password for root from 198.18.0.9 port 1 ssh2",
        "2026-11-20T10:00:01+0300 h sshd[1]: Failed password for invalid user <script>x</script> from 8.8.4.4 port 2 ssh2",
        "2026-11-20T10:00:02+0300 h sshd[1]: Failed password for admin from 8.8.4.4 port 3 ssh2"]


def _quiet(monkeypatch):
    monkeypatch.setattr(tuzak, "_read_journal", lambda: (AUTH, ""))
    monkeypatch.setattr(tuzak, "_read_cowrie", lambda: ([], False))
    monkeypatch.setattr(tuzak, "service_state", lambda: "absent")
    tuzak._cache.update(at=0, data=None)


def test_detail_requires_login(env):
    client, _ = env
    assert client.get("/api/ip?ip=8.8.4.4").status_code == 401


def test_detail_rejects_private_and_garbage(env, monkeypatch):
    client, _ = env
    _quiet(monkeypatch)
    do_login(client)
    for bad in ("10.0.0.1", "127.0.0.1", "kötü", "", "192.168.1.5"):
        r = client.get("/api/ip", params={"ip": bad})
        assert r.status_code == 400, bad
        assert "error" in r.json()


def test_detail_collects_local_evidence(env, monkeypatch):
    client, _ = env
    _quiet(monkeypatch)
    do_login(client)
    d = client.get("/api/ip", params={"ip": "8.8.4.4"}).json()
    assert d["ip"] == "8.8.4.4"
    assert d["ssh"]["n"] == 2
    users = {u["user"] for u in d["ssh"]["users"]}
    assert "admin" in users and "<script>x</script>" in users  # ham veri JSON'da; çekmece textContent ile yazar
    assert d["block"] is None and d["allowed"] is False and d["blockable"] is True
    assert d["tcp_trap"] == [] and d["trap"] == []


def test_actions_need_login_and_csrf(env, monkeypatch):
    client, _ = env
    _quiet(monkeypatch)
    assert client.post("/api/ip/block", data={"ip": "8.8.4.4", "csrf": "x"}).status_code == 401
    do_login(client)
    r = client.post("/api/ip/block", data={"ip": "8.8.4.4", "minutes": "60", "csrf": "yanlis"})
    assert r.status_code == 400 and not r.json()["ok"]
    assert defense.load_blocks() == {}


def test_block_unblock_allow_cycle(env, monkeypatch):
    client, _ = env
    _quiet(monkeypatch)
    do_login(client)
    tok = csrf_from(client, "/m/harita")

    r = client.post("/api/ip/block", data={"ip": "8.8.4.4", "minutes": "60", "csrf": tok})
    assert r.json() == {"ok": True, "message": "8.8.4.4 60 dakika engellendi."}
    assert "8.8.4.4" in defense.load_blocks()
    assert client.get("/api/ip", params={"ip": "8.8.4.4"}).json()["block"]["why"] == "elle"

    # süre ve adres doğrulaması savunma modülüyle aynı
    assert client.post("/api/ip/block", data={"ip": "8.8.4.4", "minutes": "5000", "csrf": tok}).status_code == 400
    assert client.post("/api/ip/block", data={"ip": "10.0.0.1", "minutes": "60", "csrf": tok}).status_code == 400

    # izin listesine almak engeli de kaldırır, sonra engellenemez
    r = client.post("/api/ip/allow", data={"ip": "8.8.4.4", "csrf": tok})
    assert r.json()["ok"]
    assert "8.8.4.4" not in defense.load_blocks()
    assert "8.8.4.4/32" in db.get_setting("defense.allow", "").split()
    assert client.post("/api/ip/block", data={"ip": "8.8.4.4", "minutes": "60", "csrf": tok}).status_code == 400
    d = client.get("/api/ip", params={"ip": "8.8.4.4"}).json()
    assert d["allowed"] is True and d["blockable"] is False

    r = client.post("/api/ip/disallow", data={"ip": "8.8.4.4", "csrf": tok})
    assert r.json()["ok"]
    assert db.get_setting("defense.allow", "") == ""
    assert client.post("/api/ip/unblock", data={"ip": "8.8.4.4", "csrf": tok}).status_code == 400
    assert client.post("/api/ip/sil", data={"ip": "8.8.4.4", "csrf": tok}).status_code == 404


def test_savunma_form_routes_still_work(env, monkeypatch):
    client, _ = env
    _quiet(monkeypatch)
    do_login(client)
    tok = csrf_from(client, "/m/savunma")
    r = client.post("/m/savunma/block", data={"ip": "8.8.4.4", "minutes": "30", "csrf": tok})
    assert r.status_code == 303
    assert "8.8.4.4" in defense.load_blocks()
    client.post("/m/savunma/unblock", data={"ip": "8.8.4.4", "csrf": tok})
    assert defense.load_blocks() == {}


def test_drawer_markup_on_pages(env, monkeypatch):
    client, _ = env
    _quiet(monkeypatch)
    do_login(client)
    html = client.get("/m/harita").text
    assert 'id="drawer"' in html and "/static/detay.js" in html
    assert "/static/kure3b.js" in html and 'data-mv="3d"' in html
    html = client.get("/m/tuzak").text
    assert 'data-ip="198.18.0.9"' in html or 'data-ip="8.8.4.4"' in html
    # saldırgan metni şablonda kaçışlanır
    assert "<script>x</script>" not in html


def test_satellite_cached_other_static_not(env):
    client, _ = env
    r = client.get("/static/uydu/uydu-4096.jpg")
    assert r.status_code == 200 and "max-age" in r.headers["cache-control"]
    assert client.get("/static/style.css").headers["cache-control"] == "no-store"
