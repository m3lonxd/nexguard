from nexguard import db, notify
from tests.conftest import csrf_from, do_login


def test_audit_page_and_run(env, monkeypatch):
    client, _ = env
    from nexguard import checks
    monkeypatch.setattr(checks, "CHECKS", [checks.check_users])
    do_login(client)
    assert "Henüz denetim" in client.get("/m/audit").text
    r = client.post("/m/audit/run", data={"csrf": csrf_from(client, "/m/audit")})
    assert r.status_code == 303
    page = client.get("/m/audit").text
    assert "Son tarama" in page and "Denetim tamamlandı" in page


def test_module_post_requires_login_and_csrf(env):
    client, _ = env
    assert client.post("/m/audit/run", data={"csrf": "x"}).status_code == 303  # girişsiz -> /login
    do_login(client)
    assert client.post("/m/audit/run", data={"csrf": "bad"}).status_code == 400


def test_ddos_page_renders_and_thresholds_validate(env):
    client, _ = env
    do_login(client)
    assert client.get("/m/ddos").status_code == 200
    tok = csrf_from(client, "/m/ddos")
    form = {"csrf": tok}
    for n in ("syn_recv", "conn_per_ip", "rx_pps", "rx_mbps"):
        form[f"{n}_warn"], form[f"{n}_attack"] = "10", "20"
    assert client.post("/m/ddos/thresholds", data=form).status_code == 303
    assert db.get_setting("ddos.syn_recv.attack") == "20"
    form["rx_pps_warn"] = "50"  # uyarı >= saldırı: reddedilmeli
    client.post("/m/ddos/thresholds", data=form)
    assert db.get_setting("ddos.rx_pps.warn") == "10"
    form["rx_pps_warn"] = "abc"
    client.post("/m/ddos/thresholds", data=form)
    assert db.get_setting("ddos.rx_pps.warn") == "10"


def test_notify_settings_validation_and_secret_not_echoed(env):
    client, _ = env
    do_login(client)
    tok = csrf_from(client, "/settings")
    client.post("/settings/notify", data={"csrf": tok, "webhook_url": "javascript:alert(1)"})
    assert not notify.status()["webhook"]
    secret = "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZ_abc"
    client.post("/settings/notify", data={"csrf": tok, "telegram_token": secret, "telegram_chat": "42",
                                          "webhook_url": "https://example.invalid/hook"})
    assert notify.status() == {"telegram": True, "webhook": True, "any": True}
    assert secret not in client.get("/settings").text
    client.post("/settings/notify", data={"csrf": tok, "clear": "1"})
    assert not notify.status()["any"]


def test_notify_send_reports_errors_without_leaking_token(env, monkeypatch):
    client, _ = env
    secret = "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZ_abc"
    db.set_setting("notify.telegram_token", secret)
    db.set_setting("notify.telegram_chat", "42")

    def boom(url, payload):
        raise OSError(f"connect failed {url}")
    monkeypatch.setattr(notify, "_post", boom)
    res = notify.send("x")
    assert res == [("telegram", False, "OSError")] and secret not in repr(res)


def test_geoip_page_and_lookup_validation(env):
    client, _ = env
    do_login(client)
    assert client.get("/m/geoip").status_code == 200
    tok = csrf_from(client, "/m/geoip")
    assert client.post("/m/geoip/lookup", data={"csrf": tok, "ip": "not-an-ip"}).status_code == 303
    assert client.post("/m/geoip/lookup", data={"ip": "1.1.1.1"}).status_code in (400, 403)  # CSRF yok
