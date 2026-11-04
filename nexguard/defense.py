"""Otomatik savunma: kaynak IP engelleme (nftables) ve Cloudflare "Under Attack" modu.

Engelleme: panel ayrıcalıksızdır; engel listesini DATA_DIR/engel.json dosyasına yazar.
Root olarak çalışan `nexguard-engel` yardımcısı (deploy/) dosyayı doğrular ve nftables'a uygular,
sonucu DATA_DIR/engel.state'e yazar. Panel nft'ye asla doğrudan dokunmaz.

Cloudflare: hat doyuran saldırı sunucuya varmadan durdurulmalıdır. Alan adı Cloudflare
üzerinden geçiyorsa saldırı seviyesinde bölgenin güvenlik seviyesi "under_attack" yapılır,
saldırı bitince önceki değere döndürülür.
"""
import ipaddress
import json
import os
import re
import threading
import time
import urllib.error
import urllib.request

from . import config, db, notify

BLOCK_TTL = 1800
MAX_BLOCKS = 2000
SRC_PPS_DEFAULT = 5000

_lock = threading.Lock()
CF_API = "https://api.cloudflare.com/client/v4"
_CF_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{30,80}$")
_ZONE_RE = re.compile(r"^[0-9a-f]{32}$")


# --- Ayarlar -----------------------------------------------------------------

def enabled() -> bool:
    return db.get_setting("defense.autoblock", "0") == "1"


def src_pps_limit() -> int:
    try:
        return max(int(db.get_setting("defense.src_pps", str(SRC_PPS_DEFAULT))), 100)
    except ValueError:
        return SRC_PPS_DEFAULT


def allowlist() -> list[ipaddress._BaseNetwork]:
    out = []
    for item in (db.get_setting("defense.allow", "") or "").split():
        try:
            out.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            continue
    return out


def parse_allowlist(text: str) -> tuple[list[str], str | None]:
    items = []
    for item in text.replace(",", " ").split():
        try:
            items.append(str(ipaddress.ip_network(item, strict=False)))
        except ValueError:
            return [], f"{item!r} geçerli bir IP veya ağ (CIDR) değil."
    return items, None


def blockable(ip: str, allow: list | None = None) -> bool:
    """Yalnızca genel (internetten gelebilen) ve izin listesinde olmayan adresler engellenir."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if a.version == 6 and a.ipv4_mapped:
        a = a.ipv4_mapped
    if not a.is_global or a.is_multicast:
        return False
    return not any(a in net for net in (allowlist() if allow is None else allow) if net.version == a.version)


# --- Engel listesi -----------------------------------------------------------

def want_path():
    return config.DATA_DIR / "engel.json"


def state_path():
    return config.DATA_DIR / "engel.state"


def load_blocks(now: float | None = None) -> dict[str, dict]:
    now = now or time.time()
    try:
        data = json.loads(want_path().read_text())
    except (OSError, ValueError):
        return {}
    out = {}
    for e in data.get("block", []) if isinstance(data, dict) else []:
        try:
            if float(e["until"]) > now and blockable(e["ip"], allow=[]):
                out[str(e["ip"])] = {"ip": str(e["ip"]), "until": float(e["until"]),
                                     "why": str(e.get("why", ""))[:120], "auto": bool(e.get("auto"))}
        except (KeyError, TypeError, ValueError):
            continue
    return out


def _write(blocks: dict[str, dict], active: bool) -> None:
    config.DATA_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    items = sorted(blocks.values(), key=lambda e: -e["until"])[:MAX_BLOCKS]
    payload = {"v": 1, "active": active, "written": int(time.time()),
               "block": [{"ip": e["ip"], "until": int(e["until"]), "why": e["why"], "auto": e["auto"]}
                         for e in items]}
    tmp = want_path().with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(payload, f, ensure_ascii=False)
    os.replace(tmp, want_path())


def block(ips: list[tuple[str, str]], ttl: int = BLOCK_TTL, auto: bool = False) -> list[str]:
    """[(ip, gerekçe)] ekler/yeniler. Yeni eklenen IP'leri döndürür."""
    now = time.time()
    allow = allowlist()
    added = []
    with _lock:
        blocks = load_blocks(now)
        for ip, why in ips:
            if not blockable(ip, allow):
                continue
            if ip not in blocks:
                added.append(ip)
            prev = blocks.get(ip, {})
            blocks[ip] = {"ip": ip, "until": max(now + ttl, prev.get("until", 0)), "why": why[:120],
                          "auto": auto and prev.get("auto", True)}
        if added or ips:
            _write(blocks, active=True)
    return added


def unblock(ip: str) -> bool:
    with _lock:
        blocks = load_blocks()
        if ip not in blocks:
            return False
        blocks.pop(ip)
        _write(blocks, active=True)
    return True


def clear_all() -> None:
    with _lock:
        _write({}, active=False)


def helper_state() -> dict:
    """Yardımcının son uygulaması. Yoksa kurulmamış sayılır."""
    try:
        st = json.loads(state_path().read_text())
        if isinstance(st, dict):
            st["installed"] = True
            return st
    except (OSError, ValueError):
        pass
    return {"installed": False}


def candidates(per_ip: list[tuple[str, int]], conn_limit: int, sensor_data: dict | None,
               pps_limit: int, skipped: list | None = None) -> list[tuple[str, str]]:
    """Saldırı sırasında engellenecek kaynaklar.

    TCP kurulu bağlantı sayısı taklit edilemez (üçlü el sıkışma gerekir), bu yüzden güvenilir ölçüttür.
    Paket hızı ölçütü UDP/ICMP/SYN içindir; bu kaynaklar sahte olabilir. Algılayıcı bir kaynağı sahte
    diye işaretlediyse ya da selin tamamı sahte adresliyse o adres engellenmez: masum birini keser,
    saldırıyı durdurmaz. Atlananlar `skipped` listesine (ip, neden) olarak eklenir.
    """
    out: dict[str, str] = {}
    for ip, n in per_ip:
        if n >= conn_limit:
            out[ip] = f"{n} TCP bağlantısı"
    if sensor_data:
        verdict = (sensor_data.get("spoof") or {}).get("verdict", "")
        for proto in ("udp", "icmp", "syn", "other"):
            for row in (sensor_data.get("top") or {}).get(proto, []):
                ip, pps = row[0], row[1]
                why = row[3] if len(row) > 3 else ""
                if pps < pps_limit or ip in out:
                    continue
                if why or verdict:
                    if skipped is not None:
                        skipped.append((ip, why or "sel sahte adresli"))
                    continue
                out[ip] = f"{proto.upper()} {pps:.0f} paket/sn"
    return list(out.items())


def on_attack(per_ip, conn_limit, sensor_data) -> list[str]:
    if not enabled():
        return []
    skipped: list = []
    found = candidates(per_ip, conn_limit, sensor_data, src_pps_limit(), skipped)
    if skipped:
        _log_skip(skipped)
    if not found:
        return []
    added = block(found, auto=True)
    if added:
        db.log_event("savunma", "warning", f"Otomatik engel: {len(added)} kaynak ({', '.join(added[:5])}"
                     f"{'…' if len(added) > 5 else ''}), {BLOCK_TTL // 60} dk")
    return added


_last_skip = 0.0


def _log_skip(skipped: list) -> None:
    """Sahte kaynak atlamalarını en fazla 5 dakikada bir kaydeder (her örnekte günlüğü doldurmaz)."""
    global _last_skip
    if time.time() - _last_skip < 300:
        return
    _last_skip = time.time()
    db.log_event("savunma", "warning", f"Sahte olabilecek {len(skipped)} kaynak engellenmedi "
                 f"(ör. {skipped[0][0]}: {skipped[0][1]}); kaynakta süzme için sağlayıcıya bildirin")


# --- Cloudflare --------------------------------------------------------------

CF_KEYS = ("cf.token", "cf.zones")


def cf_config() -> tuple[str | None, list[str]]:
    token = db.get_setting("cf.token")
    zones = [z for z in (db.get_setting("cf.zones", "") or "").split(",") if z]
    return token, zones


def cf_status() -> dict:
    token, zones = cf_config()
    return {"configured": bool(token and zones), "zones": len(zones),
            "auto": db.get_setting("cf.auto", "0") == "1",
            "active": db.get_setting("cf.active", "0") == "1",
            "last": db.get_setting("cf.last", "")}


def cf_validate(token: str, zones: str) -> tuple[list[str], str | None]:
    if token and not _CF_TOKEN_RE.match(token):
        return [], "Cloudflare API anahtarı biçimi geçersiz."
    ids = [z.strip().lower() for z in zones.replace(" ", ",").split(",") if z.strip()]
    for z in ids:
        if not _ZONE_RE.match(z):
            return [], f"Bölge kimliği 32 karakterlik onaltılık olmalı: {z[:40]!r}"
    if len(ids) > 20:
        return [], "En fazla 20 bölge."
    return ids, None


def _cf(method: str, path: str, token: str, body: dict | None = None) -> dict:
    req = urllib.request.Request(
        CF_API + path, method=method, data=json.dumps(body).encode() if body is not None else None,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json",
                 "User-Agent": "nexguard/1"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310 - sabit https adresi
            data = json.loads(resp.read(256 * 1024))
    except urllib.error.HTTPError as exc:
        try:
            data = json.loads(exc.read(64 * 1024))
        except ValueError:
            raise RuntimeError(f"HTTP {exc.code}") from None
    if not data.get("success"):
        errs = data.get("errors") or [{}]
        raise RuntimeError(str(errs[0].get("message", "bilinmeyen hata"))[:160])
    return data


def cf_test() -> list[str]:
    token, zones = cf_config()
    if not token or not zones:
        return ["Cloudflare ayarlı değil."]
    out = []
    for z in zones:
        try:
            r = _cf("GET", f"/zones/{z}/settings/security_level", token)
            out.append(f"{z[:8]}…: bağlandı, güvenlik seviyesi {r['result']['value']}")
        except Exception as exc:  # noqa: BLE001
            out.append(f"{z[:8]}…: hata ({exc})")
    return out


def cf_set_attack(on: bool) -> list[str]:
    """Saldırıda under_attack; bitince her bölgeyi önceki değerine döndürür."""
    token, zones = cf_config()
    if not token or not zones:
        return []
    results = []
    prev = json.loads(db.get_setting("cf.prev", "{}") or "{}")
    for z in zones:
        try:
            if on:
                cur = _cf("GET", f"/zones/{z}/settings/security_level", token)["result"]["value"]
                if cur != "under_attack":
                    prev[z] = cur
                    _cf("PATCH", f"/zones/{z}/settings/security_level", token, {"value": "under_attack"})
                results.append(f"{z[:8]}…: under_attack")
            else:
                back = prev.pop(z, "medium")
                _cf("PATCH", f"/zones/{z}/settings/security_level", token, {"value": back})
                results.append(f"{z[:8]}…: {back}")
        except Exception as exc:  # noqa: BLE001
            results.append(f"{z[:8]}…: hata ({exc})")
    db.set_setting("cf.prev", json.dumps(prev))
    db.set_setting("cf.active", "1" if on else "0")
    stamp = time.strftime("%d.%m %H:%M")
    db.set_setting("cf.last", f"{stamp} · " + "; ".join(results))
    level = "warning" if any("hata" in r for r in results) else "info"
    db.log_event("savunma", level, ("Cloudflare saldırı modu açıldı: " if on else "Cloudflare normale döndü: ")
                 + "; ".join(results))
    return results


def on_level_change(level: int) -> None:
    """DDoS izleyicisi seviye değiştirdiğinde çağrılır (ağ işlemi ayrı iş parçacığında)."""
    st = cf_status()
    if not (st["auto"] and st["configured"]):
        return
    if level == 2 and not st["active"]:
        target = True
    elif level == 0 and st["active"]:
        target = False
    else:
        return

    def job():
        res = cf_set_attack(target)
        if notify.status()["any"]:
            notify.send(("NexGuard: Cloudflare saldırı modu açıldı. " if target
                         else "NexGuard: Cloudflare normal moda döndü. ") + "; ".join(res))

    threading.Thread(target=job, name="cf-mode", daemon=True).start()
