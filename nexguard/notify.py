"""Bildirim kanalları: Telegram botu ve genel webhook (Slack/Discord/özel).

Anahtarlar `settings` tablosunda tutulur (veri dizini 0700). Arayüzde asla geri gösterilmez.
"""
import json
import re
import urllib.error
import urllib.request

from . import db

KEYS = ("notify.telegram_token", "notify.telegram_chat", "notify.webhook_url")
_TOKEN_RE = re.compile(r"^\d{5,}:[\w-]{20,}$")
_CHAT_RE = re.compile(r"^(-?\d+|@\w{4,})$")


def validate(telegram_token: str, telegram_chat: str, webhook_url: str) -> str | None:
    """Hata mesajı döndürür; geçerliyse None."""
    if telegram_token and not _TOKEN_RE.match(telegram_token):
        return "Telegram bot anahtarı biçimi geçersiz."
    if telegram_chat and not _CHAT_RE.match(telegram_chat):
        return "Telegram sohbet kimliği geçersiz (sayı veya @kanal)."
    if webhook_url and not re.match(r"^https?://[^\s]+$", webhook_url):
        return "Webhook adresi http(s):// ile başlamalı."
    return None


def status() -> dict:
    tg = bool(db.get_setting("notify.telegram_token") and db.get_setting("notify.telegram_chat"))
    wh = bool(db.get_setting("notify.webhook_url"))
    return {"telegram": tg, "webhook": wh, "any": tg or wh}


def _post(url: str, payload: dict) -> None:
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310 - şema validate() ile sınırlı
        resp.read(1024)


def send(text: str) -> list[tuple[str, bool, str]]:
    """Ayarlı tüm kanallara gönderir; (kanal, başarılı, hata) listesi döndürür. Anahtar sızdırmaz."""
    results: list[tuple[str, bool, str]] = []
    token, chat = db.get_setting("notify.telegram_token"), db.get_setting("notify.telegram_chat")
    hook = db.get_setting("notify.webhook_url")
    jobs = []
    if token and chat:
        jobs.append(("telegram", f"https://api.telegram.org/bot{token}/sendMessage",
                     {"chat_id": chat, "text": text}))
    if hook:
        jobs.append(("webhook", hook, {"text": text, "content": text, "source": "nexguard"}))
    for name, url, payload in jobs:
        try:
            _post(url, payload)
            results.append((name, True, ""))
        except urllib.error.HTTPError as exc:
            results.append((name, False, f"HTTP {exc.code}"))
        except Exception as exc:  # noqa: BLE001
            results.append((name, False, exc.__class__.__name__))
    return results
