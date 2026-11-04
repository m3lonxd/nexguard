"""Savunma modülü: otomatik/elle kaynak engelleme ve Cloudflare saldırı modu ayarları."""
import ipaddress
import time

from fastapi import APIRouter, Form, Request
from fastapi.responses import RedirectResponse

from .. import charts, db, defense
from . import Module

router = APIRouter()


def _flash(request: Request, text: str) -> RedirectResponse:
    request.session["flash"] = text
    return RedirectResponse("/m/savunma", status_code=303)


@router.post("/auto")
def save_auto(request: Request, autoblock: str = Form(""), src_pps: str = Form(""), allow: str = Form("")):
    try:
        pps = int(src_pps)
    except ValueError:
        return _flash(request, "Paket hızı eşiği sayı olmalı.")
    if not 100 <= pps <= 10**8:
        return _flash(request, "Paket hızı eşiği 100 ile 100.000.000 arasında olmalı.")
    nets, err = defense.parse_allowlist(allow)
    if err:
        return _flash(request, err)
    if len(nets) > 200:
        return _flash(request, "İzin listesinde en fazla 200 kayıt olabilir.")
    db.set_setting("defense.autoblock", "1" if autoblock else "0")
    db.set_setting("defense.src_pps", str(pps))
    db.set_setting("defense.allow", " ".join(nets))
    db.log_event("savunma", "info", f"Otomatik engel {'açıldı' if autoblock else 'kapatıldı'}")
    return _flash(request, "Savunma ayarları kaydedildi.")


@router.post("/block")
def manual_block(request: Request, ip: str = Form(""), minutes: str = Form("60")):
    ip = ip.strip()
    try:
        ipaddress.ip_address(ip)
        mins = int(minutes)
    except ValueError:
        return _flash(request, "Geçerli bir IP adresi ve süre girin.")
    if not 1 <= mins <= 1440:
        return _flash(request, "Süre 1 ile 1440 dakika arasında olmalı.")
    if not defense.blockable(ip):
        return _flash(request, f"{ip} engellenemez: yerel/özel adres ya da izin listesinde.")
    defense.block([(ip, "elle")], ttl=mins * 60)
    db.log_event("savunma", "info", f"Elle engel: {ip}, {mins} dk")
    return _flash(request, f"{ip} {mins} dakika engellendi.")


@router.post("/unblock")
def manual_unblock(request: Request, ip: str = Form("")):
    if defense.unblock(ip.strip()):
        db.log_event("savunma", "info", f"Engel kaldırıldı: {ip.strip()}")
        return _flash(request, f"{ip.strip()} engeli kaldırıldı.")
    return _flash(request, "Bu IP engel listesinde değil.")


@router.post("/clear")
def clear(request: Request):
    defense.clear_all()
    db.log_event("savunma", "info", "Tüm engeller kaldırıldı")
    return _flash(request, "Tüm engeller kaldırıldı; nftables tablosu silinecek.")


@router.post("/cf")
def cf_save(request: Request, token: str = Form(""), zones: str = Form(""), auto: str = Form(""),
            clear_cf: str = Form("")):
    if clear_cf:
        for key in (*defense.CF_KEYS, "cf.auto", "cf.prev", "cf.active", "cf.last"):
            db.delete_setting(key)
        return _flash(request, "Cloudflare ayarları silindi.")
    token = token.strip()
    ids, err = defense.cf_validate(token, zones)
    if err:
        return _flash(request, err)
    if token:
        db.set_setting("cf.token", token)
    if ids:
        db.set_setting("cf.zones", ",".join(ids))
    db.set_setting("cf.auto", "1" if auto else "0")
    db.log_event("savunma", "info", "Cloudflare ayarları güncellendi")
    return _flash(request, "Cloudflare ayarları kaydedildi. Bağlantıyı test edin.")


@router.post("/cf/test")
def cf_test(request: Request):
    return _flash(request, " · ".join(defense.cf_test()))


@router.post("/cf/mode")
def cf_mode(request: Request, on: str = Form("")):
    if not defense.cf_status()["configured"]:
        return _flash(request, "Önce Cloudflare anahtarı ve bölge kimliği girin.")
    return _flash(request, " · ".join(defense.cf_set_attack(bool(on))) or "Değişiklik yok.")


def collect() -> dict:
    now = time.time()
    blocks = sorted(defense.load_blocks(now).values(), key=lambda e: -e["until"])
    for b in blocks:
        b["left"] = max(int((b["until"] - now) // 60), 0)
    st = defense.helper_state()
    if st.get("applied"):
        st["when"] = time.strftime("%d.%m %H:%M:%S", time.localtime(st["applied"]))
    return {"auto": defense.enabled(), "src_pps": defense.src_pps_limit(),
            "allow": " ".join(str(n) for n in defense.allowlist()), "blocks": blocks, "helper": st,
            "cf": defense.cf_status(), "ttl_min": defense.BLOCK_TTL // 60}


def summary() -> dict:
    d = collect()
    base = {"slug": "savunma", "title": "Savunma"}
    n = len(d["blocks"])
    if not d["helper"]["installed"]:
        return {**base, "status": "idle", "headline": "Yardımcı kurulu değil",
                "detail": "Engelleme için sunucuda deploy/kur.sh çalıştırın.",
                "visual": charts.donut(0, center="–", sub="engel", state="idle", size=92)}
    if d["helper"].get("error"):
        return {**base, "status": "bad", "headline": "Uygulama hatası", "detail": d["helper"]["error"][:120],
                "visual": charts.donut(0, center="!", sub="hata", state="bad", size=92)}
    state = "warn" if n else "ok"
    detail = (f"Otomatik engel {'açık' if d['auto'] else 'kapalı'} · Cloudflare "
              f"{'AÇIK' if d['cf']['active'] else 'hazır' if d['cf']['configured'] and d['cf']['auto'] else 'yok'}")
    return {**base, "status": state, "headline": f"{n} engelli kaynak", "detail": detail,
            "visual": charts.donut(100 if d["auto"] else 0, center=str(n), sub="engel", state=state, size=92)}


module = Module(
    slug="savunma", title="Savunma",
    description="Saldırı kaynaklarını nftables ile engeller; Cloudflare'i saldırı moduna alır.",
    collect=collect, order=25, template="savunma.html", router=router, summary=summary,
)
