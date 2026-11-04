"""Hat doyuran saldırıda sağlayıcıdan kaynakta süzme istemek.

Sunucunun bağlantısı (ör. 1 Gbit/sn) dolduğunda sunucu içinde alınan hiçbir önlem işe yaramaz:
paketler hattı zaten tıkamıştır. Saldırı ancak üst ağda, sağlayıcının yönlendiricisinde durdurulur
(süzme, hız sınırı, RTBH/kara delik ya da DDoS temizleme hizmeti). Bu modül hat doluluğunu izler ve
eşik aşılınca sağlayıcının NOC/destek adresine kanıtlı bir istek e-postası gönderir, sahibine de
bildirim atar. Otomatik gönderim varsayılan olarak kapalıdır ve 30 dakikada en fazla bir kez yapılır.
"""
import ipaddress
import socket
import threading
import time

from . import db, mail, notify

COOLDOWN = 1800
SATURATION = 0.8
KEYS = ("prov.link_mbps", "prov.email", "prov.auto", "prov.ip", "prov.name")
_lock = threading.Lock()


def server_ip() -> str:
    """Ayarlı genel IP; yoksa varsayılan rotanın kaynak adresi (genelse)."""
    ip = db.get_setting("prov.ip", "")
    if ip:
        return ip
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 9))  # paket gönderilmez, yalnızca rota seçilir
            guess = s.getsockname()[0]
        return guess if ipaddress.ip_address(guess).is_global else ""
    except OSError:
        return ""


def link_mbps() -> int:
    try:
        return max(int(db.get_setting("prov.link_mbps", "0") or 0), 0)
    except ValueError:
        return 0


def status() -> dict:
    to, _ = mail.parse_emails(db.get_setting("prov.email", "") or "")
    return {"link_mbps": link_mbps(), "emails": to, "auto": db.get_setting("prov.auto", "0") == "1",
            "ip": db.get_setting("prov.ip", ""), "detected_ip": server_ip(),
            "name": db.get_setting("prov.name", ""), "last": db.get_setting("prov.last", ""),
            "last_ts": float(db.get_setting("prov.last_ts", "0") or 0),
            "ready": bool(to) and mail.status()["configured"]}


def saturation(rx_mbps: float) -> float | None:
    cap = link_mbps()
    return rx_mbps / cap if cap else None


def should_alert(rx_mbps: float, flood: dict | None) -> str:
    """Sağlayıcıya gidilmesi gerekiyorsa gerekçe; gerekmiyorsa boş metin."""
    sat = saturation(rx_mbps)
    if sat is not None and sat >= SATURATION:
        return f"hat %{sat * 100:.0f} dolu ({rx_mbps:.0f}/{link_mbps()} Mbit/sn)"
    verdict = ((flood or {}).get("spoof") or {}).get("verdict")
    if verdict:
        return f"sahte adresli sel ({verdict.lower()})"
    return ""


def compose(reason: str, rx_mbps: float, rx_pps: float, flood: dict | None) -> tuple[str, str]:
    ip = server_ip() or "(sunucu IP'si ayarlanmadı)"
    now = time.strftime("%d.%m.%Y %H:%M:%S %Z")
    proto = (flood or {}).get("proto") or {}
    lines = [
        "Merhaba,",
        "",
        f"{ip} adresli sunucumuz şu anda DDoS saldırısı altında; {reason}.",
        "Saldırı sunucuya ulaşmadan, ağınızda durdurulmasını rica ediyoruz:",
        "  - hedef IP için üst ağda süzme / hız sınırı (aşağıdaki protokol ve kaynaklara göre),",
        "  - mümkün değilse geçici RTBH (kara delik) ya da DDoS temizleme hizmeti.",
        "",
        f"Zaman: {now}",
        f"Hedef: {ip}",
        f"Gelen trafik: {rx_mbps:.0f} Mbit/sn, {rx_pps:.0f} paket/sn",
    ]
    if link_mbps():
        lines.append(f"Hat kapasitesi: {link_mbps()} Mbit/sn")
    parts = [f"{k.upper()} {v.get('mbps', 0):.0f} Mbit/sn" for k, v in proto.items() if v.get("mbps", 0) >= 1]
    if parts:
        lines.append("Protokol dağılımı: " + ", ".join(parts))
    sp = (flood or {}).get("spoof") or {}
    if sp.get("verdict"):
        lines.append(f"Kaynak analizi: {sp['verdict']} ({int(sp.get('distinct', 0))} farklı kaynak, "
                     f"paketlerin %{sp.get('ttl_share', 0) * 100:.0f}'i aynı TTL={int(sp.get('ttl_top', 0))}).")
        lines.append("Kaynak adresler sahte olduğundan sunucu tarafında adres engellemek etkisiz.")
    rows = []
    for k in ("udp", "icmp", "syn", "other"):
        for r in ((flood or {}).get("top") or {}).get(k, [])[:5]:
            rows.append(f"  {r[0]}  {k.upper()}  {r[1]:.0f} paket/sn" + (f"  ({r[3]})" if len(r) > 3 and r[3] else ""))
    if rows:
        lines += ["", "En yoğun kaynaklar (örnek):", *rows[:15]]
    lines += ["", "Bu mesaj NexGuard izleme panelince otomatik oluşturuldu; sayılar ölçülen gerçek değerlerdir.",
              "Teşekkürler."]
    return f"DDoS: {ip} için üst ağda süzme isteği", "\n".join(lines)


def send_now(reason: str, rx_mbps: float, rx_pps: float, flood: dict | None, manual: bool = False) -> str:
    st = status()
    if not st["ready"]:
        return "Sağlayıcı adresi ve SMTP ayarlı değil."
    subject, body = compose(reason, rx_mbps, rx_pps, flood)
    try:
        mail.send(st["emails"], subject, body, reply_to=mail.status()["sender"])
    except RuntimeError as exc:
        db.log_event("savunma", "error", f"Sağlayıcıya süzme isteği gönderilemedi: {exc}")
        if not manual:  # 5 dakika sonra yeniden dene
            db.set_setting("prov.last_ts", str(time.time() - COOLDOWN + 300))
        return f"Gönderilemedi: {exc}"
    stamp = time.strftime("%d.%m %H:%M")
    db.set_setting("prov.last", f"{stamp} · {', '.join(st['emails'])} · {reason}")
    db.set_setting("prov.last_ts", str(time.time()))
    db.log_event("savunma", "warning", f"Sağlayıcıya süzme isteği gönderildi ({'elle' if manual else 'otomatik'}): "
                 f"{reason} -> {', '.join(st['emails'])}")
    if notify.status()["any"]:
        notify.send(f"NexGuard: sağlayıcıya üst ağ süzme isteği gönderildi. {reason}.")
    return f"İstek gönderildi: {', '.join(st['emails'])}"


def on_attack(rx_mbps: float, rx_pps: float, flood: dict | None) -> bool:
    """DDoS izleyicisi saldırı seviyesindeyken çağırır. Gönderim ayrı iş parçacığında yapılır."""
    if db.get_setting("prov.auto", "0") != "1":
        return False
    reason = should_alert(rx_mbps, flood)
    if not reason:
        return False
    with _lock:
        last = float(db.get_setting("prov.last_ts", "0") or 0)
        if time.time() - last < COOLDOWN:
            return False
        db.set_setting("prov.last_ts", str(time.time()))  # aynı saldırıda yarışan ikinci gönderimi önler
    threading.Thread(target=send_now, args=(reason, rx_mbps, rx_pps, flood), name="prov-alert",
                     daemon=True).start()
    return True
