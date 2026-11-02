"""Canlı harita: şu an sunucuya bağlı dış IP'lerin ülkelere göre dağılımı.

Veri DDoS izleyicisinin son örneğinden (/proc/net/tcp) ve yerel coğrafya veritabanından gelir;
harita dosyası pakete gömülüdür, hiçbir IP dışarı gönderilmez. Not: hat doyuran (UDP/ICMP)
saldırıların kaynağı bağlantı tablosunda görünmez; harita yalnızca TCP bağlantılarını gösterir.
"""
import json
import time
from functools import lru_cache
from pathlib import Path

from .. import geoip
from . import Module
from . import ddos

DATA = Path(__file__).resolve().parent.parent / "data" / "world.json"


@lru_cache(maxsize=1)
def _world() -> dict:
    return json.loads(DATA.read_text(encoding="utf-8"))


def live_payload() -> dict:
    """/api/live yanıtı: ddos seviyesi, ülke dağılımı ve en çok bağlanan kaynaklar."""
    with ddos.monitor._lock:
        last = ddos.monitor.history[-1] if ddos.monitor.history else None
        level = ddos.monitor.level
        reasons = list(ddos.monitor.reasons)
    running = ddos._started
    label = ddos.LEVELS[level].replace("i", "İ").upper() if running else "BİLİNMİYOR"
    why = (" · ".join(reasons) or "Eşikler aşılmadı.") if running else "İzleyici çalışmıyor; ölçüm yapılamıyor. Paneli yeniden başlatın."
    cent = _world()["centroids"]
    out = {"ts": time.strftime("%H:%M:%S"), "level": level, "level_name": ddos.LEVELS[level],
           "running": running, "state_label": label, "why": why,
           "installed": geoip.status()["installed"], "total": 0, "anon_pct": 0,
           "countries": [], "sources": [], "verdict": ""}
    if not last or not last.per_ip:
        return out
    geo = geoip.summarize(last.per_ip[:50])
    out["total"] = geo["total"]
    out["anon_pct"] = geo["anon_pct"]
    out["verdict"] = geo["verdict"]
    for c in geo["countries"]:
        xy = cent.get(c["cc"])
        out["countries"].append({"cc": c["cc"], "country": c["country"], "n": c["n"], "ips": c["ips"],
                                 "anon": c["anon"], "x": xy[0] if xy else None, "y": xy[1] if xy else None})
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
