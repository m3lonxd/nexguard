"""SSH saldırıları: gerçek SSH'a yapılan denemeler ve tuzak (Cowrie) oturumları.

Denemeler sistem günlüğünden okunur. Tuzak ayrı bir konteynerde çalışan sahte bir SSH'tır;
saldırganın yazdığı komutlar gerçekten çalışmaz, yalnızca kaydedilir. Bu modül ikisini de sadece okur.
Buradaki tüm metinler saldırgan kontrolündedir: kontrol karakterleri atılır, boyut sınırlanır.
"""
import json
import os
import re
import subprocess
import threading
import time
from collections import Counter
from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, Form, Request
from fastapi.responses import RedirectResponse

from .. import config, db, geoip
from . import Module

router = APIRouter()
UNIT = "tuzak.service"

COWRIE_LOG = Path(os.environ.get("NEXGUARD_COWRIE_LOG", "/var/lib/tuzak/log/cowrie/cowrie.json"))
TAIL_BYTES = 8 * 1024 * 1024
CACHE_SECONDS = 30

_FAILED = re.compile(r"Failed (?:password|publickey) for (invalid user )?(.*) from (\S+) port \d+ ssh2$")
_ACCEPTED = re.compile(r"Accepted (\S+) for (.*) from (\S+) port \d+ ssh2")
_CTRL = re.compile(r"[\x00-\x1f\x7f-\x9f‪-‮⁦-⁩]")

_lock = threading.Lock()
_cache: dict = {"at": 0.0, "data": None}


def clean(text, limit: int = 200) -> str:
    return _CTRL.sub(" ", str(text if text is not None else ""))[:limit]


def _when(value: str) -> str:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone().strftime("%d.%m %H:%M")
    except (ValueError, TypeError, AttributeError):
        return "?"


def parse_auth(lines) -> dict:
    failed, accepted = [], []
    for line in lines:
        ts = line.split(" ", 1)[0]
        m = _FAILED.search(line)
        if m:
            failed.append({"ts": ts, "user": clean(m.group(2), 64), "ip": m.group(3), "invalid": bool(m.group(1))})
            continue
        m = _ACCEPTED.search(line)
        if m:
            accepted.append({"ts": ts, "method": clean(m.group(1), 20), "user": clean(m.group(2), 64), "ip": m.group(3)})
    return {"failed": failed, "accepted": accepted}


def parse_cowrie(lines) -> dict:
    sessions: dict[str, dict] = {}
    passwords, users = Counter(), Counter()
    downloads = 0
    for line in lines:
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if not isinstance(e, dict):
            continue
        sid, kind = str(e.get("session", ""))[:32], e.get("eventid", "")
        if not sid or not kind:
            continue
        s = sessions.setdefault(sid, {"id": sid, "ip": clean(e.get("src_ip"), 45), "ts": str(e.get("timestamp", "")),
                                      "user": "", "password": "", "success": False, "commands": [], "downloads": [],
                                      "client": "", "duration": None})
        if kind in ("cowrie.login.success", "cowrie.login.failed"):
            user, pw = clean(e.get("username"), 64), clean(e.get("password"), 64)
            users[user] += 1
            passwords[pw] += 1
            s["user"], s["password"] = user, pw
            s["success"] = s["success"] or kind == "cowrie.login.success"
        elif kind == "cowrie.command.input" and len(s["commands"]) < 100:
            s["commands"].append(clean(e.get("input"), 500))
        elif kind == "cowrie.session.file_download" and len(s["downloads"]) < 20:
            downloads += 1
            s["downloads"].append(clean(e.get("url"), 300))
        elif kind == "cowrie.client.version":
            s["client"] = clean(e.get("version"), 80)
        elif kind == "cowrie.session.closed":
            s["duration"] = e.get("duration")
    return {"sessions": sessions, "passwords": passwords, "users": users, "downloads": downloads}


def _read_journal() -> tuple[list[str], str]:
    try:
        r = subprocess.run(["journalctl", "-u", "ssh", "-u", "sshd", "--since", "-7d", "-o", "short-iso",
                            "--no-pager", "-n", "60000"], capture_output=True, text=True, errors="replace", timeout=15)
    except (OSError, subprocess.SubprocessError) as exc:
        return [], f"Sistem günlüğü okunamadı ({exc.__class__.__name__})."
    if r.returncode != 0:
        return [], "Sistem günlüğü okunamadı; panel kullanıcısının systemd-journal grubunda olması gerekir."
    return r.stdout.splitlines(), ""


def _read_cowrie() -> tuple[list[str], bool]:
    try:
        with open(COWRIE_LOG, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - TAIL_BYTES))
            raw = f.read()
    except OSError:
        return [], False
    lines = raw.decode("utf-8", "replace").splitlines()
    return (lines[1:] if size > TAIL_BYTES else lines), True


def _country(ips: dict) -> dict:
    names = {}
    for ip in ips:
        info = geoip.lookup(ip)
        names[ip] = (info.cc, info.country)
    return names


def build(journal_lines, cowrie_lines, installed: bool, note: str = "") -> dict:
    auth = parse_auth(journal_lines)
    trap = parse_cowrie(cowrie_lines)
    failed = auth["failed"]
    by_ip = Counter(f["ip"] for f in failed)
    top_ips = by_ip.most_common(300)
    sessions = sorted(trap["sessions"].values(), key=lambda s: s["ts"], reverse=True)
    known = set(dict(top_ips)) | {a["ip"] for a in auth["accepted"][-30:]} | {s["ip"] for s in sessions[:60]} | {f["ip"] for f in failed[-40:]}
    where = _country(known)
    place = lambda ip: where.get(ip, ("ZZ", "Bilinmiyor"))[1]
    countries: dict[str, dict] = {}
    for ip, n in top_ips:
        cc, name = where[ip]
        e = countries.setdefault(cc, {"cc": cc, "country": name, "n": 0, "ips": 0})
        e["n"] += n
        e["ips"] += 1
    hacked = [s for s in sessions if s["success"]]
    with_cmd = [s for s in sessions if s["commands"]]
    shown = (with_cmd + [s for s in hacked if not s["commands"]])[:30]
    shown.sort(key=lambda s: s["ts"], reverse=True)
    return {
        "note": note, "installed": installed,
        "attempts": len(failed), "unique_ips": len(by_ip), "invalid": sum(1 for f in failed if f["invalid"]),
        "countries": sorted(countries.values(), key=lambda e: -e["n"])[:12], "country_count": len(countries),
        "top_users": Counter(f["user"] for f in failed).most_common(8),
        "top_ips": [{"ip": ip, "n": n, "country": place(ip)} for ip, n in by_ip.most_common(10)],
        "recent": [{**f, "when": _when(f["ts"]), "country": place(f["ip"])} for f in reversed(failed[-40:])],
        "accepted": [{**a, "when": _when(a["ts"]), "country": place(a["ip"])} for a in reversed(auth["accepted"][-20:])],
        "trap_sessions": len(sessions), "trap_logins": len(hacked),
        "trap_commands": sum(len(s["commands"]) for s in sessions), "trap_downloads": trap["downloads"],
        "trap_passwords": trap["passwords"].most_common(8), "trap_users": trap["users"].most_common(8),
        "trap_shown": [{**s, "when": _when(s["ts"]), "country": place(s["ip"])} for s in shown],
    }


def service_state() -> str:
    """absent: bu makinede kurulu değil; on / off / changing: tuzak servisinin gerçek durumu."""
    try:
        r = subprocess.run(["systemctl", "show", UNIT, "-p", "LoadState", "-p", "ActiveState"],
                           capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return "absent"
    props = dict(line.split("=", 1) for line in r.stdout.splitlines() if "=" in line)
    if props.get("LoadState") != "loaded":
        return "absent"
    return {"active": "on", "inactive": "off", "failed": "failed"}.get(props.get("ActiveState"), "changing")


def want_path() -> Path:
    return config.DATA_DIR / "tuzak.want"


def request_state(want: str) -> None:
    """Panel yetkisizdir: isteği dosyaya yazar, systemd path birimi yalnızca tuzak servisini açar/kapatır."""
    tmp = want_path().with_suffix(".tmp")
    tmp.write_text(want + "\n", encoding="ascii")
    os.replace(tmp, want_path())


@router.post("/toggle")
def toggle(request: Request, want: str = Form("")):
    if want not in ("on", "off"):
        request.session["flash"] = "Geçersiz istek."
    elif service_state() == "absent":
        request.session["flash"] = "Tuzak bu sunucuda kurulu değil."
    else:
        try:
            request_state(want)
            db.log_event("tuzak", "info", "Tuzak açma isteği" if want == "on" else "Tuzak kapatma isteği")
            request.session["flash"] = "Tuzak açılıyor." if want == "on" else "Tuzak kapatılıyor."
        except OSError as exc:
            request.session["flash"] = f"İstek yazılamadı ({exc.__class__.__name__})."
    return RedirectResponse("/m/tuzak", status_code=303)


def collect() -> dict:
    state = service_state()
    with _lock:
        if _cache["data"] is None or time.time() - _cache["at"] >= CACHE_SECONDS:
            lines, note = _read_journal()
            cow, installed = _read_cowrie()
            _cache.update(at=time.time(), data=build(lines, cow, installed, note))
        return {**_cache["data"], "service": state, "real_ssh": real_ssh()}


def real_ssh() -> dict:
    """Gerçek sshd parola kabul ediyor mu? Etmiyorsa denenen her parola tuzakta görünür."""
    from .. import checks
    cfg = checks.sshd_effective(checks.Host())
    if cfg is None:
        return {"known": False, "password": None, "port": ""}
    return {"known": True, "password": cfg.get("passwordauthentication", "yes") == "yes",
            "port": cfg.get("port", "22")}


def summary() -> dict:
    d = collect()
    base = {"slug": "tuzak", "title": "SSH tuzağı"}
    if d["note"]:
        return {**base, "status": "idle", "headline": "Günlük okunamıyor", "detail": d["note"], "visual": ""}
    detail = f"Son 7 günde {d['attempts']} başarısız giriş, {d['unique_ips']} IP"
    if d["installed"]:
        detail += f" · tuzakta {d['trap_commands']} komut"
    on = d["service"] == "on"
    return {**base, "status": "ok" if on else "idle",
            "headline": {"on": "Tuzak açık", "off": "Tuzak kapalı", "absent": "Tuzak kurulu değil",
                         "failed": "Tuzak hata verdi"}.get(d["service"], "Tuzak geçiş yapıyor"),
            "detail": detail, "visual": ""}


module = Module(
    slug="tuzak", title="SSH tuzağı",
    description="Gerçek SSH'a yapılan giriş denemeleri ve sahte SSH'a düşen saldırganların yazdığı komutlar.",
    collect=collect, order=27, template="tuzak.html", router=router, summary=summary,
)
