"""E-posta gönderimi (SMTP). Sağlayıcıya süzme isteği ve kötüye kullanım bildirimi için.

Ayarlar `settings` tablosunda durur; parola arayüzde asla geri gösterilmez.
"""
import re
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

from . import db

KEYS = ("smtp.host", "smtp.port", "smtp.user", "smtp.pass", "smtp.from", "smtp.tls")
TLS_MODES = ("starttls", "ssl", "none")
EMAIL_RE = re.compile(r"^[^@\s<>,;\"']{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}$")
_HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")


def parse_emails(text: str, limit: int = 10) -> tuple[list[str], str | None]:
    out = []
    for item in re.split(r"[\s,;]+", text or ""):
        if not item:
            continue
        if not EMAIL_RE.match(item):
            return [], f"{item[:60]!r} geçerli bir e-posta adresi değil."
        if item.lower() not in (o.lower() for o in out):
            out.append(item)
    if len(out) > limit:
        return [], f"En fazla {limit} adres."
    return out, None


def validate(host: str, port: str, sender: str, tls: str) -> str | None:
    if not _HOST_RE.match(host or ""):
        return "SMTP sunucusu geçersiz."
    if not port.isdigit() or not 1 <= int(port) <= 65535:
        return "SMTP portu 1-65535 olmalı."
    if not EMAIL_RE.match(sender or ""):
        return "Gönderen adresi geçersiz."
    if tls not in TLS_MODES:
        return "Şifreleme seçimi geçersiz."
    return None


def status() -> dict:
    host = db.get_setting("smtp.host")
    return {"configured": bool(host and db.get_setting("smtp.from")), "host": host or "",
            "port": db.get_setting("smtp.port", "587"), "user": db.get_setting("smtp.user", ""),
            "sender": db.get_setting("smtp.from", ""), "tls": db.get_setting("smtp.tls", "starttls"),
            "has_pass": bool(db.get_setting("smtp.pass"))}


def send(to: list[str], subject: str, body: str, reply_to: str | None = None) -> None:
    """Gönderir; başarısızlıkta anahtar sızdırmayan kısa bir RuntimeError fırlatır."""
    st = status()
    if not st["configured"]:
        raise RuntimeError("SMTP ayarlı değil")
    if not to:
        raise RuntimeError("alıcı yok")
    msg = EmailMessage()
    msg["From"] = st["sender"]
    msg["To"] = ", ".join(to)
    msg["Subject"] = subject.replace("\r", " ").replace("\n", " ")[:200]
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain=st["sender"].rsplit("@", 1)[1])
    if reply_to:
        msg["Reply-To"] = reply_to
    msg.set_content(body)
    port = int(st["port"] or 587)
    ctx = ssl.create_default_context()
    try:
        if st["tls"] == "ssl":
            server = smtplib.SMTP_SSL(st["host"], port, timeout=20, context=ctx)
        else:
            server = smtplib.SMTP(st["host"], port, timeout=20)
        with server:
            if st["tls"] == "starttls":
                server.starttls(context=ctx)
            password = db.get_setting("smtp.pass")
            if st["user"] and password:
                server.login(st["user"], password)
            server.send_message(msg)
    except smtplib.SMTPAuthenticationError:
        raise RuntimeError("SMTP kimlik doğrulaması reddedildi") from None
    except smtplib.SMTPRecipientsRefused:
        raise RuntimeError("alıcı adres reddedildi") from None
    except (smtplib.SMTPException, OSError) as exc:
        raise RuntimeError(f"SMTP hatası: {exc.__class__.__name__}") from None
