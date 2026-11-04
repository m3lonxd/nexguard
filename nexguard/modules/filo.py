"""Filo modülü: eklenen NexGuard sunucularını bu sunucuyla birlikte tek ekranda gösterir."""
import time

from fastapi import APIRouter, Form, Request
from fastapi.responses import RedirectResponse

from .. import charts, db, fleet
from . import Module, load_modules

router = APIRouter()


def _flash(request: Request, text: str) -> RedirectResponse:
    request.session["flash"] = text
    return RedirectResponse("/m/filo", status_code=303)


@router.post("/add")
def add(request: Request, name: str = Form(""), url: str = Form(""), token: str = Form("")):
    err = fleet.add_server(name, url, token)
    if err:
        return _flash(request, err)
    db.log_event("filo", "info", f"Sunucu eklendi: {' '.join(name.split())[:60]}")
    new = next(s for s in reversed(fleet.servers()) if s["url"] == url.strip().rstrip("/"))
    st = fleet.poll_one(new)
    return _flash(request, f"{new['name']} eklendi" + (": bağlantı tamam." if st["ok"] else f", ama yanıt yok: {st['error']}"))


@router.post("/remove")
def remove(request: Request, sid: str = Form("")):
    if fleet.remove_server(sid):
        db.log_event("filo", "info", "Sunucu filodan çıkarıldı")
        return _flash(request, "Sunucu filodan çıkarıldı.")
    return _flash(request, "Sunucu bulunamadı.")


@router.post("/refresh")
def refresh(request: Request):
    fleet.poll_all()
    return _flash(request, "Tüm sunucular yoklandı.")


def _age(ts) -> str:
    if not ts:
        return "hiç"
    s = int(time.time() - ts)
    return f"{s} sn önce" if s < 120 else f"{s // 60} dk önce" if s < 7200 else f"{s // 3600} sa önce"


def _card(name: str, data: dict | None, ok: bool, error: str = "", seen=None, sid=None, url="") -> dict:
    mods = (data or {}).get("modules", [])
    state = fleet.worst(mods) if ok and data else "bad"
    return {"sid": sid, "name": name, "url": url, "ok": ok, "error": error, "data": data, "state": state,
            "seen": _age(seen), "problems": [m for m in mods if m["status"] in ("warn", "bad")]}


def collect() -> dict:
    local = fleet.local_summary(load_modules())
    cards = [_card(local["name"] or "Bu sunucu", local, True, seen=time.time())]
    cards[0]["local"] = True
    for s in fleet.servers():
        st = fleet.status(s["id"])
        if not st:
            c = _card(s["name"], None, False, "henüz yoklanmadı", sid=s["id"], url=s["url"])
            c["state"] = "idle"
        else:
            c = _card(s["name"], st.get("data"), st["ok"], st.get("error", ""), st.get("seen"), s["id"], s["url"])
        cards.append(c)
    return {"cards": cards, "api": fleet.api_status(), "count": len(cards) - 1}


def summary() -> dict:
    items = fleet.servers()
    base = {"slug": "filo", "title": "Filo"}
    if not items:
        return {**base, "status": "idle", "headline": "Yalnızca bu sunucu",
                "detail": "Diğer NexGuard sunucularını ekleyip tek ekranda izleyin.",
                "visual": charts.donut(0, center="1", sub="sunucu", state="idle", size=92)}
    down = bad = 0
    for s in items:
        st = fleet.status(s["id"])
        if st and not st["ok"]:
            down += 1
        elif st and fleet.worst(st["data"]["modules"]) == "bad":
            bad += 1
    state = "bad" if down or bad else "ok"
    detail = f"{down} erişilemiyor · {bad} tehlikede" if down or bad else "Tüm sunucular yanıt veriyor"
    up = len(items) - down
    return {**base, "status": state, "headline": f"{len(items) + 1} sunucu", "detail": detail,
            "visual": charts.donut(round(100 * up / len(items)), center=str(len(items) + 1), sub="sunucu",
                                   state=state, size=92)}


module = Module(
    slug="filo", title="Filo",
    description="Birden çok NexGuard sunucusunu tek ekranda toplar.",
    collect=collect, order=90, template="filo.html", router=router, on_start=fleet.start, summary=summary,
)
