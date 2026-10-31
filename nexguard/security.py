import hmac
import secrets
import time
from collections import defaultdict, deque

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

from . import config

_hasher = PasswordHasher()
# Zamanlama farkından kullanıcı varlığı sızmasın diye sahte hash ile de doğrulama yapılır.
_DUMMY_HASH = _hasher.hash("nexguard-dummy")

MIN_PASSWORD_LEN = 12


def hash_password(password: str) -> str:
    if len(password) < MIN_PASSWORD_LEN:
        raise ValueError(f"Parola en az {MIN_PASSWORD_LEN} karakter olmalı")
    return _hasher.hash(password)


def verify_password(password_hash: str | None, password: str) -> bool:
    try:
        return _hasher.verify(password_hash or _DUMMY_HASH, password) and password_hash is not None
    except (VerifyMismatchError, InvalidHashError):
        return False


def new_totp_secret() -> str:
    return pyotp.random_base32()


def totp_uri(secret: str, username: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name="NexGuard")


def verify_totp(secret: str, code: str) -> bool:
    return pyotp.TOTP(secret).verify(code.strip().replace(" ", ""), valid_window=1)


def new_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def check_csrf(expected: str | None, given: str | None) -> bool:
    return bool(expected) and bool(given) and hmac.compare_digest(expected, given)


class LoginLimiter:
    """IP başına başarısız giriş sınırı (bellekte, süreç yeniden başlayınca sıfırlanır)."""

    def __init__(self, max_fails: int = config.LOGIN_MAX_FAILS,
                 window: int = config.LOGIN_WINDOW_SECONDS):
        self.max_fails = max_fails
        self.window = window
        self._fails: dict[str, deque[float]] = defaultdict(deque)

    def _prune(self, key: str, now: float) -> deque:
        q = self._fails[key]
        while q and now - q[0] > self.window:
            q.popleft()
        return q

    def blocked(self, key: str, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        return len(self._prune(key, now)) >= self.max_fails

    def fail(self, key: str, now: float | None = None) -> None:
        now = time.monotonic() if now is None else now
        self._prune(key, now).append(now)

    def reset(self, key: str) -> None:
        self._fails.pop(key, None)
