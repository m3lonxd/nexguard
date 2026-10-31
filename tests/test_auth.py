import pyotp

from nexguard import db, security
from tests.conftest import csrf_from, do_login


def test_redirects_when_anonymous(env):
    client, _ = env
    assert client.get("/").headers["location"] == "/login"
    assert client.get("/settings").headers["location"] == "/login"
    assert client.get("/m/x").headers["location"] == "/login"


def test_login_success_and_overview(env):
    client, _ = env
    assert do_login(client).status_code == 303
    r = client.get("/")
    assert r.status_code == 200 and "Genel Bakış" in r.text


def test_wrong_password(env):
    client, _ = env
    assert do_login(client, "yanlis-parola-xx").status_code == 401


def test_unknown_user_same_error(env):
    client, _ = env
    r = client.post("/login", data={"username": "nobody", "password": "whatever-long-pw",
                                    "csrf": csrf_from(client)})
    assert r.status_code == 401


def test_csrf_required(env):
    client, _ = env
    client.get("/login")
    r = client.post("/login", data={"username": "admin", "password": "correct horse battery", "csrf": "bad"})
    assert r.status_code == 400


def test_rate_limit_blocks_even_correct_password(env):
    client, _ = env
    for _ in range(3):
        assert do_login(client, "yanlis-parola-xx").status_code == 401
    assert do_login(client).status_code == 429


def test_logout_requires_csrf(env):
    client, _ = env
    do_login(client)
    client.post("/logout", data={"csrf": "bad"})
    assert client.get("/").status_code == 200
    client.post("/logout", data={"csrf": csrf_from(client, "/")})
    assert client.get("/").status_code == 303


def test_security_headers(env):
    client, _ = env
    r = client.get("/login")
    assert r.headers["x-frame-options"] == "DENY"
    assert "default-src 'self'" in r.headers["content-security-policy"]
    assert "httponly" in client.get("/login").headers.get("set-cookie", "httponly").lower()


def test_totp_flow(env):
    client, _ = env
    do_login(client)
    r = client.post("/settings/totp/start", data={"csrf": csrf_from(client, "/settings")})
    secret = r.text.split("<code>", 1)[1].split("</code>", 1)[0]
    bad = client.post("/settings/totp/confirm", data={"code": "000000", "csrf": csrf_from(client, "/settings")})
    assert bad.status_code == 400
    ok = client.post("/settings/totp/confirm",
                     data={"code": pyotp.TOTP(secret).now(), "csrf": csrf_from(client, "/settings")})
    assert ok.status_code == 200 and "etkinleştirildi" in ok.text
    client.post("/logout", data={"csrf": csrf_from(client, "/")})
    assert do_login(client).status_code == 401  # kod yok
    assert do_login(client, code=pyotp.TOTP(secret).now()).status_code == 303


def test_password_policy():
    import pytest
    with pytest.raises(ValueError):
        security.hash_password("kisa")
