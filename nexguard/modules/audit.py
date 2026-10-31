import json
import time

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse

from .. import checks, db
from . import Module

router = APIRouter()
_KEY = "audit.last"


@router.post("/run")
def run(request: Request):
    result = checks.run_all()
    result["ts"] = time.strftime("%Y-%m-%d %H:%M:%S")
    db.set_setting(_KEY, checks.dumps(result))
    bad = sum(1 for f in result["findings"] if f["severity"] in ("high", "medium"))
    db.log_event("audit", "warning" if bad else "info",
                 f"Denetim tamamlandı: skor {result['score']} ({result['grade']}), {bad} önemli bulgu")
    request.session["flash"] = "Denetim tamamlandı."
    return RedirectResponse("/m/audit", status_code=303)


def collect() -> dict:
    raw = db.get_setting(_KEY)
    result = json.loads(raw) if raw else None
    counts: dict[str, int] = {}
    if result:
        for f in result["findings"]:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    return {"result": result, "counts": counts}


module = Module(
    slug="audit", title="Denetim",
    description="Genel güvenlik ve OPSEC taraması. Yalnızca okur; düzeltme komutlarını gösterir, uygulamaz.",
    collect=collect, order=10, template="audit.html", router=router,
)
