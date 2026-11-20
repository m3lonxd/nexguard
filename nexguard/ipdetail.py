"""IP detay çekmecesi: panelin bir kaynak IP hakkında yerelde bildiği her şey ve elle işlemler.

Hiçbir sorgu ağa çıkmaz: ülke/ASN yerel coğrafya veritabanından, bağlantı sayısı DDoS izleyicisinin
son örneğinden, denemeler sistem günlüğünden (tuzak modülünün önbelleği), tuzak oturumları ve paket
seli kanıtı abuse.evidence'tan gelir. RDAP ve ters DNS isteyen tam araştırma /kaynak sayfasında kalır.

Engelleme, engel kaldırma ve izin listesi yalnız kullanıcının açık isteğiyle yapılır; doğrulama
savunma modülüyle aynıdır ve uygulamayı root yetkili engel yardımcısı yapar.
"""
import ipaddress

from . import abuse, db, defense, geoip, sensor

MAX_ALLOW = 200


def _norm(ip: str) -> str | None:
    """Genel (internetten yönlendirilebilir) adresi kanonik biçime çevirir; değilse None."""
    return abuse.normalize((ip or "").strip()[:64])


def _live_connections(ip: str) -> int:
    from .modules import ddos
    with ddos.monitor._lock:
        last = ddos.monitor.history[-1] if ddos.monitor.history else None
    if not last or not last.per_ip:
        return 0
    return next((n for a, n in last.per_ip if a == ip), 0)


def _allowed(ip: str) -> bool:
    a = ipaddress.ip_address(ip)
    return any(a in net for net in defense.allowlist() if net.version == a.version)


def detail(ip_text: str) -> dict:
    ip = _norm(ip_text)
    if not ip:
        return {"error": "Genel (internetten yönlendirilebilir) bir IPv4/IPv6 adresi gerekli."}
    from . import tcptuzak
    from .modules import tuzak
    g = geoip.lookup(ip)
    snap = sensor.read()
    cow, _ = tuzak._read_cowrie()
    ev = abuse.evidence(ip, snap["data"] if snap["state"] == "hazır" else None, cow)
    ssh = tuzak.collect().get("ssh_by_ip", {}).get(ip)
    blk = ev["block"]
    return {
        "ip": ip,
        "geo": {"cc": g.cc, "country": g.country, "asn": g.asn, "org": g.org, "flags": g.flag_labels,
                "installed": geoip.status()["installed"]},
        "live": _live_connections(ip),
        "ssh": {"n": ssh["n"], "users": [{"user": u, "n": n} for u, n in ssh["users"]], "last": ssh["last"]} if ssh else None,
        "trap": ev["trap"][:10],
        "tcp_trap": tcptuzak.hits_for(ip),
        "flood": ev["flood"],
        "events": [{"ts": e["ts"], "module": e["module"], "level": e["level"], "message": e["message"]}
                   for e in ev["events"][:12]],
        "block": {"until": int(blk["until"]), "why": blk["why"], "auto": blk["auto"]} if blk else None,
        "allowed": _allowed(ip),
        "blockable": defense.blockable(ip),
        "helper": defense.helper_state().get("installed", False),
    }


# --- Elle işlemler (savunma modülü de bunları kullanır) ------------------------------------

def block(ip_text: str, minutes: str | int) -> tuple[bool, str]:
    ip = (ip_text or "").strip()
    try:
        ipaddress.ip_address(ip)
        mins = int(minutes)
    except ValueError:
        return False, "Geçerli bir IP adresi ve süre girin."
    if not 1 <= mins <= 1440:
        return False, "Süre 1 ile 1440 dakika arasında olmalı."
    if not defense.blockable(ip):
        return False, f"{ip} engellenemez: yerel/özel adres ya da izin listesinde."
    defense.block([(ip, "elle")], ttl=mins * 60)
    db.log_event("savunma", "info", f"Elle engel: {ip}, {mins} dk")
    return True, f"{ip} {mins} dakika engellendi."


def unblock(ip_text: str) -> tuple[bool, str]:
    ip = (ip_text or "").strip()
    if defense.unblock(ip):
        db.log_event("savunma", "info", f"Engel kaldırıldı: {ip}")
        return True, f"{ip} engeli kaldırıldı."
    return False, "Bu IP engel listesinde değil."


def allow(ip_text: str, on: bool = True) -> tuple[bool, str]:
    """İzin listesine tek adres ekler/çıkarır. Eklenen adresin etkin engeli de kaldırılır."""
    ip = _norm(ip_text)
    if not ip:
        return False, "Genel bir IP adresi gerekli."
    current = (db.get_setting("defense.allow", "") or "").split()
    net = str(ipaddress.ip_network(ip))
    if on:
        if net in current:
            return True, f"{ip} zaten izin listesinde."
        if len(current) >= MAX_ALLOW:
            return False, f"İzin listesinde en fazla {MAX_ALLOW} kayıt olabilir."
        current.append(net)
        db.set_setting("defense.allow", " ".join(current))
        defense.unblock(ip)
        db.log_event("savunma", "info", f"İzin listesine eklendi: {ip}")
        return True, f"{ip} izin listesine eklendi; artık engellenmez."
    if net not in current:
        return False, f"{ip} izin listesinde değil."
    current.remove(net)
    db.set_setting("defense.allow", " ".join(current))
    db.log_event("savunma", "info", f"İzin listesinden çıkarıldı: {ip}")
    return True, f"{ip} izin listesinden çıkarıldı."
