import pytest
from fastapi.testclient import TestClient

from nexguard import config, db, security


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "t.db")
    monkeypatch.setattr(config, "SECRET_FILE", tmp_path / "secret.key")
    db.init()
    with db.session() as conn:
        conn.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                     ("admin", security.hash_password("correct horse battery")))
    from nexguard.app import create_app
    limiter = security.LoginLimiter(max_fails=3, window=300)
    return TestClient(create_app(limiter), follow_redirects=False), limiter


def csrf_from(client, path="/login"):
    html = client.get(path).text
    marker = 'name="csrf" value="'
    return html.split(marker, 1)[1].split('"', 1)[0]


def do_login(client, password="correct horse battery", code=""):
    return client.post("/login", data={"username": "admin", "password": password,
                                       "code": code, "csrf": csrf_from(client)})
