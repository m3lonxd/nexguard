"""Coğrafya modülü: yerel IP veritabanının durumu, güncellenmesi ve tek IP sorgusu.

Sorgular yerel SQLite üzerinden yapılır; IP adresleri dışarı gönderilmez.
Veritabanı indirmesi yalnızca kullanıcı düğmeye bastığında, arka planda başlar.
"""
import ipaddress

from fastapi import APIRouter, Form, Request
from fastapi.responses import RedirectResponse

from .. import charts, geoip
from . import Module

router = APIRouter()


def _flash(request: Request, text: str) -> RedirectResponse:
    request.session["flash"] = text
    return RedirectResponse("/m/geoip", status_code=303)


@router.post("/update")
def update(request: Request):
    if geoip.start_update():
        return _flash(request, "İndirme arka planda başladı. Birkaç dakika sürebilir; sayfayı yenileyerek durumu izleyin.")
    return _flash(request, "Güncelleme zaten çalışıyor.")


@router.post("/lookup")
def lookup(request: Request, ip: str = Form("")):
    ip = ip.strip()
    if not ip:
        return _flash(request, "Sorgulamak için bir IP adresi girin.")
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return _flash(request, f"{ip!r} geçerli bir IPv4/IPv6 adresi değil.")
    st = geoip.status()
    if not st["installed"]:
        return _flash(request, "Coğrafya veritabanı kurulu değil; önce güncellemeyi başlatın.")
    info = geoip.lookup(ip)
    parts = [f"{ip} → {info.country} ({info.cc})"]
    if info.asn:
        parts.append(f"AS{info.asn} {info.org}".strip())
    parts.append("aracı işareti: " + (", ".join(info.flag_labels) if info.flags else "yok"))
    return _flash(request, " · ".join(parts))


def collect() -> dict:
    st = geoip.status()
    return {"geo": st, "installed": st["installed"]}


def summary() -> dict:
    st = geoip.status()
    base = {"slug": "geoip", "title": "Coğrafya"}
    if not st["installed"]:
        return {**base, "status": "warn", "headline": "Veritabanı yok",
                "detail": "Kaynak IP'lerin ülkesi ve ağ sağlayıcısı gösterilemiyor.",
                "visual": charts.donut(0, center="–", sub="veri", state="idle", size=92)}
    return {**base, "status": "ok", "headline": "Kurulu",
            "detail": f"{st['tor']} Tor çıkışı · güncelleme {st['updated']}",
            "visual": charts.donut(100, center="✓", sub="hazır", state="ok", size=92)}


module = Module(
    slug="geoip", title="Coğrafya",
    description="Kaynak IP'leri ülke, ağ sağlayıcı (ASN) ve anonimleştirici işaretleriyle eşleştiren yerel veritabanı.",
    collect=collect, order=30, template="geoip.html", router=router, summary=summary,
)
