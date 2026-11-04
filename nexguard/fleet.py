"""Filo: birden çok NexGuard sunucusunu tek ekranda toplamak.

Her panel, salt okunur bir özet ucu sunar: GET /api/v1/ozet (Authorization: Bearer <anahtar>).
Anahtar Ayarlar'da üretilir, yalnızca bir kez gösterilir; sunucuda SHA-256 özeti saklanır.
Filo sayfası eklenen sunucuları arka planda yoklar ve sonuçları yerel sunucuyla yan yana gösterir.

Uzak yanıt güvenilmez sayılır: boyut sınırlıdır, alanlar kırpılır, durum değerleri beyaz listeden geçer.
Yönlendirme izlenmez (anahtar başka bir adrese sızmasın).
"""
import hashlib
import hmac
import ipaddress
import json
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from . import __version__, db, sysinfo

TOKEN_PREFIX = "ngf_"
MAX_SERVERS = 50
MAX_BYTES = 256 * 1024
TIMEOUT = 8
POLL_SECONDS = 30
STATUSES = ("ok", "warn", "bad", "idle")
_lock = threading.Lock()
_status: dict[str, dict] = {}


# --- API anahtarı (bu sunucu) ------------------------------------------------

def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def new_api_token() -> str:
    token = TOKEN_PREFIX + secrets.token_urlsafe(32)
    db.set_setting("api.token_hash", _hash(token))
    db.set_setting("api.token_created", time.strftime("%d.%m.%Y %H:%M"))
    return token


def revoke_api_token() -> None:
    db.delete_setting("api.token_hash")
    db.delete_setting("api.token_created")


def api_status() -> dict:
    return {"enabled": bool(db.get_setting("api.token_hash")), "created": db.get_setting("api.token_created", "")}


def check_api_token(header: str | None) -> bool:
    stored = db.get_setting("api.token_hash")
    if not stored or not header or not header.startswith("Bearer "):
        return False
    return hmac.compare_digest(_hash(header[7:].strip()), stored)


def local_summary(modules) -> dict:
    """Bu sunucunun özeti; API'nin ve Filo sayfasındaki yerel kartın kaynağı."""
    mods = []
    for m in modules:
        if not m.summary or m.slug in ("filo", "harita"):
            continue
        try:
            s = m.summary()
        except Exception as exc:  # noqa: BLE001 - tek özet ucu düşürmemeli
            s = {"status": "bad", "headline": "Özet üretilemedi", "detail": exc.__class__.__name__}
        mods.append({"slug": m.slug, "title": m.title, "status": s.get("status", "idle"),
                     "headline": str(s.get("headline", "")), "detail": str(s.get("detail", ""))})
    info = sysinfo.snapshot()
    with db.session() as conn:
        warn24 = conn.execute("SELECT COUNT(*) FROM events WHERE level IN ('warning', 'error') "
                              "AND ts >= datetime('now', '-1 day')").fetchone()[0]
        events = [dict(r) for r in conn.execute(
            "SELECT ts, module, level, message FROM events WHERE level IN ('warning', 'error') "
            "ORDER BY id DESC LIMIT 8").fetchall()]

    def pct(used, total):
        return round(100 * used / total) if total else 0

    return {"v": 1, "name": info.get("hostname", ""), "version": __version__, "ts": int(time.time()),
            "uptime": info["uptime_seconds"], "load1": info["load"][0], "cpus": info["cpus"],
            "mem_pct": pct(info["mem_used"], info["mem_total"]),
            "disk_pct": pct(info["disk_used"], info["disk_total"]),
            "warn24": warn24, "modules": mods, "events": events}


# --- Uzak sunucular ----------------------------------------------------------

def servers() -> list[dict]:
    try:
        data = json.loads(db.get_setting("fleet.servers", "[]") or "[]")
        return [s for s in data if isinstance(s, dict) and {"id", "name", "url", "token"} <= s.keys()]
    except ValueError:
        return []


def _save(items: list[dict]) -> None:
    db.set_setting("fleet.servers", json.dumps(items, ensure_ascii=False))


def validate_url(url: str) -> tuple[str | None, str | None]:
    """https zorunlu; düz http yalnızca yerel tünel (127.0.0.1, ::1, localhost) için."""
    url = url.strip().rstrip("/")
    try:
        p = urllib.parse.urlsplit(url)
    except ValueError:
        return None, "Adres çözümlenemedi."
    if p.scheme not in ("https", "http") or not p.hostname or p.username or p.password or p.query or p.fragment:
        return None, "Adres https://alan-adı[:port][/yol] biçiminde olmalı."
    loopback = p.hostname == "localhost"
    try:
        loopback = loopback or ipaddress.ip_address(p.hostname).is_loopback
    except ValueError:
        pass
    if p.scheme == "http" and not loopback:
        return None, "Anahtar açık metin gitmesin: uzak sunucu için https kullanın (http yalnızca SSH tüneli için)."
    if len(url) > 300:
        return None, "Adres çok uzun."
    return url, None


def add_server(name: str, url: str, token: str) -> str | None:
    name = " ".join(name.split())[:60]
    token = token.strip()
    if not name:
        return "Sunucuya bir ad verin."
    url, err = validate_url(url)
    if err:
        return err
    if not token.startswith(TOKEN_PREFIX) or not 30 <= len(token) <= 100 or not token.isascii():
        return "Anahtar, uzak panelin Ayarlar sayfasında üretilen ngf_ ile başlayan değer olmalı."
    with _lock:
        items = servers()
        if len(items) >= MAX_SERVERS:
            return f"En fazla {MAX_SERVERS} sunucu eklenebilir."
        if any(s["url"] == url for s in items):
            return "Bu adres zaten ekli."
        items.append({"id": secrets.token_hex(6), "name": name, "url": url, "token": token})
        _save(items)
    return None


def remove_server(sid: str) -> bool:
    with _lock:
        items = servers()
        keep = [s for s in items if s["id"] != sid]
        if len(keep) == len(items):
            return False
        _save(keep)
        _status.pop(sid, None)
    return True


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # noqa: ANN002
        return None


_opener = urllib.request.build_opener(_NoRedirect)


def _clip(v, n: int) -> str:
    return str(v)[:n] if v is not None else ""


def sanitize(data) -> dict:
    """Uzak yanıtı yalnızca beklenen, kırpılmış alanlara indirger."""
    if not isinstance(data, dict):
        raise ValueError("yanıt nesne değil")

    def num(v, lo=0, hi=10**9):
        try:
            return min(max(float(v), lo), hi)
        except (TypeError, ValueError):
            return 0

    mods = []
    for m in (data.get("modules") or [])[:30] if isinstance(data.get("modules"), list) else []:
        if isinstance(m, dict):
            st = m.get("status")
            mods.append({"slug": _clip(m.get("slug"), 30), "title": _clip(m.get("title"), 40),
                         "status": st if st in STATUSES else "idle",
                         "headline": _clip(m.get("headline"), 120), "detail": _clip(m.get("detail"), 200)})
    events = []
    for e in (data.get("events") or [])[:8] if isinstance(data.get("events"), list) else []:
        if isinstance(e, dict):
            lv = e.get("level")
            events.append({"ts": _clip(e.get("ts"), 20), "module": _clip(e.get("module"), 30),
                           "level": lv if lv in ("info", "warning", "error") else "info",
                           "message": _clip(e.get("message"), 200)})
    return {"name": _clip(data.get("name"), 60), "version": _clip(data.get("version"), 20),
            "ts": int(num(data.get("ts"), 0, 10**11)), "uptime": int(num(data.get("uptime"))),
            "load1": round(num(data.get("load1"), 0, 10**5), 2), "cpus": int(num(data.get("cpus"), 1, 4096)),
            "mem_pct": int(num(data.get("mem_pct"), 0, 100)), "disk_pct": int(num(data.get("disk_pct"), 0, 100)),
            "warn24": int(num(data.get("warn24"))), "modules": mods, "events": events}


def fetch(server: dict) -> dict:
    req = urllib.request.Request(server["url"] + "/api/v1/ozet", headers={
        "Authorization": f"Bearer {server['token']}", "Accept": "application/json", "User-Agent": "nexguard-filo/1"})
    try:
        with _opener.open(req, timeout=TIMEOUT) as resp:  # noqa: S310 - adres doğrulandı (https/loopback)
            if resp.status != 200:
                raise RuntimeError(f"HTTP {resp.status}")
            raw = resp.read(MAX_BYTES + 1)
    except urllib.error.HTTPError as exc:
        raise RuntimeError({401: "anahtar reddedildi", 404: "API ucu yok (sürüm eski?)",
                            429: "çok fazla hatalı deneme"}.get(exc.code, f"HTTP {exc.code}")) from None
    except urllib.error.URLError as exc:
        raise RuntimeError(f"bağlanılamadı ({_clip(exc.reason, 80)})") from None
    except TimeoutError:
        raise RuntimeError("zaman aşımı") from None
    if len(raw) > MAX_BYTES:
        raise RuntimeError("yanıt çok büyük")
    try:
        return sanitize(json.loads(raw))
    except ValueError as exc:
        raise RuntimeError(f"geçersiz yanıt ({exc})") from None


def poll_one(server: dict) -> dict:
    prev = _status.get(server["id"], {})
    try:
        data = fetch(server)
        st = {"ok": True, "data": data, "checked": time.time(), "seen": time.time(), "error": ""}
    except Exception as exc:  # noqa: BLE001 - bir sunucunun hatası diğerlerini durdurmamalı
        st = {"ok": False, "data": prev.get("data"), "checked": time.time(), "seen": prev.get("seen"),
              "error": str(exc)[:160]}
        if prev.get("ok", True):
            db.log_event("filo", "warning", f"{server['name']}: {st['error']}")
    _status[server["id"]] = st
    return st


def poll_all() -> None:
    threads = [threading.Thread(target=poll_one, args=(s,), daemon=True) for s in servers()]
    for t in threads:
        t.start()
    for t in threads:
        t.join(TIMEOUT + 4)


def status(sid: str) -> dict:
    return _status.get(sid, {})


def _loop() -> None:
    while True:
        try:
            poll_all()
        except Exception as exc:  # noqa: BLE001
            db.log_event("filo", "error", f"Yoklama hatası: {exc.__class__.__name__}")
        time.sleep(POLL_SECONDS)


def start() -> None:
    threading.Thread(target=_loop, name="filo", daemon=True).start()


def worst(mods: list[dict]) -> str:
    order = {"bad": 3, "warn": 2, "ok": 1, "idle": 0}
    return max((m["status"] for m in mods), key=lambda s: order.get(s, 0), default="idle")
