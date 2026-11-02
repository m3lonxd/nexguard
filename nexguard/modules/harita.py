"""Canlı harita: şu an sunucuya bağlı dış IP'lerin ülkelere göre dağılımı.

Veri DDoS izleyicisinin son örneğinden (/proc/net/tcp) ve yerel coğrafya veritabanından gelir;
harita dosyası pakete gömülüdür, hiçbir IP dışarı gönderilmez. Not: hat doyuran (UDP/ICMP)
saldırıların kaynağı bağlantı tablosunda görünmez; harita yalnızca TCP bağlantılarını gösterir.
"""
import json
import os
import time
from collections import Counter
from functools import lru_cache
from pathlib import Path

from .. import db, geoip, sysinfo
from . import Module
from . import ddos

DATA = Path(__file__).resolve().parent.parent / "data" / "world.json"


@lru_cache(maxsize=1)
def _world() -> dict:
    return json.loads(DATA.read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def _home_cc() -> str | None:
    """Sunucunun ülkesi: saat diliminden (zone.tab). Ağa çıkmaz; bulunamazsa yay çizilmez."""
    try:
        try:
            tz = open("/etc/timezone", encoding="utf-8").read().strip()
        except OSError:
            tz = os.path.realpath("/etc/localtime").split("zoneinfo/")[-1]
        for line in open("/usr/share/zoneinfo/zone.tab", encoding="utf-8"):
            if not line.startswith("#"):
                cols = line.split("\t")
                if len(cols) > 2 and cols[2].strip() == tz:
                    return cols[0]
    except OSError:
        pass
    return None


def _week() -> list[dict]:
    """Son 7 günün uyarı/hata sayısı (yerel gün), bugün sonda."""
    names = ["Pzt", "Sal", "Çar", "Per", "Cum", "Cmt", "Paz"]
    now = time.time()
    days = [time.strftime("%Y-%m-%d", time.localtime(now - 86400 * i)) for i in range(6, -1, -1)]
    with db.session() as conn:
        rows = conn.execute(
            "SELECT date(ts, 'localtime') d, COUNT(*) n FROM events WHERE level IN ('warning', 'error') "
            "AND ts >= datetime('now', '-8 day') GROUP BY d").fetchall()
    counts = {r["d"]: r["n"] for r in rows}
    return [{"label": names[time.strptime(d, "%Y-%m-%d").tm_wday], "n": counts.get(d, 0)} for d in days]


def live_payload() -> dict:
    """/api/live yanıtı: ddos seviyesi, ülke dağılımı ve en çok bağlanan kaynaklar."""
    with ddos.monitor._lock:
        hist = list(ddos.monitor.history)
        last = hist[-1] if hist else None
        level = ddos.monitor.level
        reasons = list(ddos.monitor.reasons)
    running = ddos._started
    label = ddos.LEVELS[level].replace("i", "İ").upper() if running else "BİLİNMİYOR"
    why = (" · ".join(reasons) or "Eşikler aşılmadı.") if running else "İzleyici çalışmıyor; ölçüm yapılamıyor. Paneli yeniden başlatın."
    cent = _world()["centroids"]
    home_cc = _home_cc()
    home_xy = cent.get(home_cc) if home_cc else None
    info = sysinfo.snapshot()
    out = {"ts": time.strftime("%H:%M:%S"), "level": level, "level_name": ddos.LEVELS[level],
           "running": running, "state_label": label, "why": why,
           "installed": geoip.status()["installed"], "total": 0, "anon_pct": 0,
           "countries": [], "sources": [], "verdict": "",
           "pressure": 0, "pressure_text": "Ölçüm yok",
           "home": {"cc": home_cc, "x": home_xy[0], "y": home_xy[1]} if home_xy else None,
           "pps": [round(x.rx_pps, 1) for x in hist[-36:]], "mbps": [round(x.rx_mbps, 2) for x in hist[-14:]],
           "rx_pps": round(last.rx_pps) if last else 0, "rx_mbps": round(last.rx_mbps, 1) if last else 0,
           "syn": last.syn_recv if last else 0, "attack_pps": ddos.load_thresholds()["rx_pps"][1],
           "mem_pct": round(100 * info["mem_used"] / info["mem_total"]) if info["mem_total"] else 0,
           "week": _week()}
    if last:
        th = ddos.load_thresholds()
        values = {"syn_recv": last.syn_recv, "conn_per_ip": last.max_per_ip, "rx_pps": last.rx_pps, "rx_mbps": last.rx_mbps}
        name = max(values, key=lambda n: values[n] / th[n][1])
        out["pressure"] = round(100 * values[name] / th[name][1])
        out["pressure_text"] = f"Saldırı eşiğinin %{out['pressure']}'i · {ddos.LABELS[name]}"
    if not last or not last.per_ip:
        return out
    geo = geoip.summarize(last.per_ip[:50])
    out["total"] = geo["total"]
    out["anon_pct"] = geo["anon_pct"]
    out["verdict"] = geo["verdict"]
    flags: dict[str, Counter] = {}
    for src in geo["sources"]:
        for f in src["flags"]:
            flags.setdefault(src["cc"], Counter())[f] += src["n"]
    for c in geo["countries"]:
        xy = cent.get(c["cc"])
        top_flag = flags[c["cc"]].most_common(1)[0][0] if c["cc"] in flags else ""
        out["countries"].append({"cc": c["cc"], "country": c["country"], "n": c["n"], "ips": c["ips"],
                                 "anon": c["anon"], "flag": top_flag, "x": xy[0] if xy else None, "y": xy[1] if xy else None})
    out["sources"] = [{"ip": s["ip"], "n": s["n"], "cc": s["cc"], "country": s["country"],
                       "org": s["org"], "flags": s["flags"]} for s in geo["sources"][:10]]
    return out


def collect() -> dict:
    w = _world()
    return {"paths": w["paths"], "w": w["w"], "h": w["h"], "live": live_payload()}


def summary() -> dict:
    p = live_payload()
    base = {"slug": "harita", "title": "Canlı harita"}
    if not p["installed"]:
        return {**base, "status": "warn", "headline": "Coğrafya verisi yok",
                "detail": "Ülke dağılımı için Coğrafya veritabanını indirin.", "visual": ""}
    if not p["countries"]:
        return {**base, "status": "ok", "headline": "Dış bağlantı yok", "detail": "Şu an dışarıdan bağlı kaynak görünmüyor.",
                "visual": ""}
    top = p["countries"][0]
    return {**base, "status": "ok" if p["level"] == 0 else ("warn" if p["level"] == 1 else "bad"),
            "headline": f"{len(p['countries'])} ülke", "detail": f"{p['total']} bağlantı · en çok {top['country']}",
            "visual": ""}


module = Module(
    slug="harita", title="Canlı harita",
    description="Sunucuya şu an bağlı dış kaynakların dünya haritasında ülkelere göre dağılımı.",
    collect=collect, order=25, template="harita.html", summary=summary,
)
