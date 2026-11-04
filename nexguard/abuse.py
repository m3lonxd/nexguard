"""Saldırgan kaynağını araştırma ve kötüye kullanım (abuse) bildirimi.

Bir IP'nin "gerçek yeri" sokak adresi değildir; adres, onu dağıtan ağa (ISS, barındırma firması,
üniversite …) kayıtlıdır ve yalnızca o ağ kullanıcıyı bilir. Bu modül bölgesel internet kayıt
kuruluşlarından (RIPE, ARIN, APNIC, LACNIC, AFRINIC) RDAP ile ağın sahibini, adres aralığını,
ülkesini ve kötüye kullanım (abuse) iletişim adresini çeker; ters DNS adını ve yerel coğrafya
veritabanı bilgisini ekler. Paneldeki kanıtlarla (engeller, olay günlüğü, tuzak oturumları) bir
bildirim taslağı hazırlar. Gönderim yalnızca kullanıcı onayıyla, elle yapılır.
"""
import concurrent.futures
import ipaddress
import json
import os
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request

from . import config, db, defense, geoip, mail

RDAP = "https://rdap.org/ip/"
CACHE_TTL = 7 * 86400
CACHE_MAX = 500
_pool = concurrent.futures.ThreadPoolExecutor(max_workers=2, thread_name_prefix="rdns")


def cache_path():
    return config.DATA_DIR / "rdap.json"


def _load_cache() -> dict:
    try:
        data = json.loads(cache_path().read_text())
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_cache(cache: dict) -> None:
    if len(cache) > CACHE_MAX:
        for k in sorted(cache, key=lambda k: cache[k].get("ts", 0))[:len(cache) - CACHE_MAX]:
            cache.pop(k)
    config.DATA_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = cache_path().with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(cache, f, ensure_ascii=False, separators=(",", ":"))
    os.replace(tmp, cache_path())


def normalize(ip: str) -> str | None:
    try:
        a = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        return None
    if a.version == 6 and a.ipv4_mapped:
        a = a.ipv4_mapped
    return str(a) if a.is_global else None


def _vcard(entity: dict) -> tuple[str, list[str]]:
    name, emails = "", []
    card = entity.get("vcardArray")
    if isinstance(card, list) and len(card) > 1 and isinstance(card[1], list):
        for item in card[1]:
            if not isinstance(item, list) or len(item) < 4:
                continue
            if item[0] == "fn" and isinstance(item[3], str):
                name = item[3]
            elif item[0] == "email" and isinstance(item[3], str):
                emails.append(item[3])
    return name, emails


def _kind(entity: dict) -> str:
    card = entity.get("vcardArray")
    if isinstance(card, list) and len(card) > 1 and isinstance(card[1], list):
        for item in card[1]:
            if isinstance(item, list) and len(item) >= 4 and item[0] == "kind" and isinstance(item[3], str):
                return item[3].lower()
    return ""


def parse_rdap(data: dict) -> dict:
    """RDAP ağ nesnesi -> sade özet. Tüm alanlar güvenilmez metin olarak kısaltılır."""
    out = {"network": str(data.get("name") or "")[:120], "handle": str(data.get("handle") or "")[:80],
           "range": "", "country": str(data.get("country") or "")[:4], "org": "", "abuse": [], "registry": ""}
    start, end = data.get("startAddress"), data.get("endAddress")
    if start and end:
        out["range"] = f"{str(start)[:45]} - {str(end)[:45]}"
    cidrs = data.get("cidr0_cidrs")
    if isinstance(cidrs, list) and cidrs and isinstance(cidrs[0], dict):
        c = cidrs[0]
        pre = c.get("v4prefix") or c.get("v6prefix")
        if pre and c.get("length") is not None:
            out["range"] = f"{str(pre)[:45]}/{int(c['length'])}" if str(c["length"]).isdigit() else out["range"]
    port43 = data.get("port43")
    if isinstance(port43, str):
        out["registry"] = port43[:80]

    def walk(entities, depth=0):
        for e in entities if isinstance(entities, list) else []:
            if not isinstance(e, dict):
                continue
            roles = e.get("roles") or []
            name, emails = _vcard(e)
            if "abuse" in roles:
                out["abuse"] += [m for m in emails if mail.EMAIL_RE.match(m)]
            # Yalnızca kurum kaydı: "administrative" çoğu zaman bir kişidir, RIPE'de "registrant" da
            # bazen bakımcı nesnesidir (ör. ORNEK-MNT); ikisi de ağ sahibi değildir.
            if ("registrant" in roles and name and not out["org"] and _kind(e) != "individual"
                    and not name.upper().endswith("-MNT")):
                out["org"] = name[:120]
            if depth < 3:
                walk(e.get("entities"), depth + 1)

    walk(data.get("entities"))
    seen, uniq = set(), []
    for m in out["abuse"]:
        if m.lower() not in seen:
            seen.add(m.lower())
            uniq.append(m[:120])
    out["abuse"] = uniq[:5]
    return out


def _fetch(ip: str) -> dict:
    req = urllib.request.Request(RDAP + urllib.parse.quote(ip),
                                 headers={"Accept": "application/rdap+json", "User-Agent": "nexguard/1"})
    with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310 - sabit https adresi, yönlendirme RIR'lere
        return json.loads(resp.read(512 * 1024))


def rdap(ip: str, fetch=_fetch) -> dict:
    """Önbellekli RDAP özeti. Hata durumunda {"error": ...} döner, asla fırlatmaz."""
    cache = _load_cache()
    hit = cache.get(ip)
    if hit and time.time() - hit.get("ts", 0) < CACHE_TTL:
        return hit["data"]
    try:
        data = parse_rdap(fetch(ip))
    except urllib.error.HTTPError as exc:
        return {"error": f"kayıt sorgusu başarısız (HTTP {exc.code})"}
    except (OSError, ValueError) as exc:
        return {"error": f"kayıt sorgusu başarısız ({exc.__class__.__name__})"}
    cache[ip] = {"ts": time.time(), "data": data}
    try:
        _save_cache(cache)
    except OSError:
        pass
    return data


def rdns(ip: str, timeout: float = 3.0) -> str:
    try:
        return _pool.submit(socket.gethostbyaddr, ip).result(timeout=timeout)[0][:200]
    except (concurrent.futures.TimeoutError, OSError):
        return ""


def evidence(ip: str, sensor_data: dict | None = None, trap_lines: list[str] | None = None) -> dict:
    """Panelin bu IP hakkında bildiği her şey (UTC zaman damgalı)."""
    blk = defense.load_blocks().get(ip)
    with db.session() as conn:
        rows = conn.execute("SELECT ts, module, level, message FROM events WHERE message LIKE ? "
                            "ORDER BY id DESC LIMIT 25", (f"%{ip}%",)).fetchall()
    events = [{"ts": r["ts"], "module": r["module"], "level": r["level"], "message": r["message"][:300]}
              for r in rows if _mentions(r["message"], ip)]
    flood = []
    for proto, items in ((sensor_data or {}).get("top") or {}).items():
        for r in items:
            if r[0] == ip:
                flood.append({"proto": proto, "pps": r[1], "mbps": r[2], "spoof": r[3] if len(r) > 3 else ""})
    trap = []
    if trap_lines:
        from .modules import tuzak
        for s in tuzak.parse_cowrie(trap_lines)["sessions"].values():
            if s["ip"] == ip:
                trap.append({"ts": s["ts"], "user": s["user"], "password": s["password"],
                             "commands": s["commands"][:10], "downloads": s["downloads"][:5], "client": s["client"]})
        trap.sort(key=lambda s: s["ts"], reverse=True)
    return {"block": blk, "events": events, "flood": flood, "trap": trap[:20]}


def _mentions(text: str, ip: str) -> bool:
    """'1.2.3.4' araması '11.2.3.45' satırını saymasın."""
    return re.search(rf"(?<![\w.:]){re.escape(ip)}(?![\w:]|\.\d)", text) is not None


def report(ip: str, info: dict, ev: dict, target: str) -> tuple[str, str]:
    """İngilizce abuse bildirimi taslağı (kayıt kuruluşları ve ISS'ler İngilizce bekler)."""
    lines = ["Hello,", "",
             f"We are reporting abusive traffic from {ip}"
             + (f" ({info['network']}, {info['range']})" if info.get("network") else "")
             + (f" directed at our server {target}." if target else " directed at our server."),
             "Please investigate and stop this activity.", "",
             "Evidence (timestamps UTC unless noted):"]
    for f in ev["flood"]:
        lines.append(f"- {f['proto'].upper()} flood: {f['pps']:.0f} packets/s, {f['mbps']:.2f} Mbit/s (live sample)")
    for t in ev["trap"][:10]:
        extra = f", commands: {' ; '.join(t['commands'][:3])}" if t["commands"] else ""
        lines.append(f"- {t['ts']}: SSH login attempt user={t['user']!r} password={t['password']!r}"
                     f"{', client ' + t['client'] if t['client'] else ''}{extra}")
        for d in t["downloads"][:2]:
            lines.append(f"    downloaded: {d}")
    for e in ev["events"][:10]:
        lines.append(f"- {e['ts']} [{e['module']}] {e['message']}")
    if ev["block"]:
        lines.append(f"- Currently blocked by our firewall: {ev['block']['why']}")
    if len(lines) == 7:
        lines.append("- (add details here)")
    lines += ["", "Log excerpts can be provided on request.", "", "Regards"]
    return f"Abuse report: {ip}", "\n".join(lines)


def research(ip: str, sensor_data: dict | None = None, trap_lines: list[str] | None = None,
             target: str = "") -> dict:
    g = geoip.lookup(ip)
    info = rdap(ip)
    ev = evidence(ip, sensor_data, trap_lines)
    subject, body = report(ip, info if "error" not in info else {}, ev, target)
    return {"ip": ip, "geo": {"cc": g.cc, "country": g.country, "asn": g.asn, "org": g.org, "flags": g.flag_labels},
            "rdap": info, "rdns": rdns(ip), "evidence": ev, "subject": subject, "body": body,
            "to": ", ".join(info.get("abuse", [])) if "error" not in info else "",
            "mail": mail.status()["configured"]}
