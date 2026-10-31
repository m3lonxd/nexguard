import os
import secrets
from pathlib import Path

DATA_DIR = Path(os.environ.get("NEXGUARD_DATA", Path.home() / ".local" / "share" / "nexguard"))
DB_PATH = DATA_DIR / "nexguard.db"
SECRET_FILE = DATA_DIR / "secret.key"
HOST = os.environ.get("NEXGUARD_HOST", "127.0.0.1")
PORT = int(os.environ.get("NEXGUARD_PORT", "8787"))

LOGIN_MAX_FAILS = 5
LOGIN_WINDOW_SECONDS = 300
SESSION_MAX_AGE = 8 * 3600


def get_secret_key() -> str:
    """Oturum imza anahtarı; ilk çalıştırmada üretilir, yalnızca sahibi okuyabilir."""
    DATA_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    if SECRET_FILE.exists():
        return SECRET_FILE.read_text().strip()
    key = secrets.token_urlsafe(48)
    fd = os.open(SECRET_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(key)
    return key
