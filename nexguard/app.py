import re
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from . import __version__, config, db, fleet, notify, security, sysinfo
from .modules import load_modules

BASE = Path(__file__).parent
templates = Jinja2Templates(directory=BASE / "templates")
templates.env.filters["hb"] = sysinfo.human_bytes
templates.env.filters["uptime"] = sysinfo.human_uptime

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "same-origin",
    "Content-Security-Policy": (
        "default-src 'self'; style-src 'self'; script-src 'self'; "
        "img-src 'self' data:; frame-ancestors 'none'; form-action 'self'"
    ),
    "Cache-Control": "no-store",
}


def group_events(rows, limit: int = 8) -> list[dict]:
    """Art arda gelen aynı olayları (IP/sayı ayrıntısıyla birlikte) tek satırda toplar; zamanı yerel saate çevirir."""
    out: list[dict] = []
    for r in rows:
        try:
            local = datetime.strptime(r["ts"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc).astimezone()
            when = local.strftime("%d.%m %H:%M")
        except (ValueError, TypeError):
            when = str(r["ts"])
        key = (r["module"], r["level"], re.sub(r"\d+", "#", r["message"]))
        if out and out[-1]["key"] == key:
            out[-1]["count"] += 1
            continue
        out.append({"key": key, "ts": when, "module": r["module"], "level": r["level"],
                    "message": r["message"], "count": 1})
    return out[:limit]


def create_app(limiter: security.LoginLimiter | None = None, background: bool = True) -> FastAPI:
    db.init()
    modules = load_modules()

    @asynccontextmanager
    async def lifespan(_app):
        if background:
            for m in modules:
                if m.on_start:
                    m.on_start()
        yield

    app = FastAPI(title="NexGuard", version=__version__, docs_url=None, redoc_url=None,
                  openapi_url=None, lifespan=lifespan)
    app.add_middleware(
        SessionMiddleware,
        secret_key=config.get_secret_key(),
        max_age=config.SESSION_MAX_AGE,
        same_site="strict",
        https_only=False,  # TLS'i nginx sonlandırır; çerez yine HttpOnly + SameSite=Strict
    )
    app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")
    limiter = limiter or security.LoginLimiter()

    @app.middleware("http")
    async def add_headers(request: Request, call_next):
        response = await call_next(request)
        for k, v in SECURITY_HEADERS.items():
            response.headers.setdefault(k, v)
        return response

    def csrf_token(request: Request) -> str:
        tok = request.session.get("csrf")
        if not tok:
            tok = security.new_csrf_token()
            request.session["csrf"] = tok
        return tok

    def render(request: Request, name: str, status_code: int = 200, **ctx):
        ctx.update(
            request=request, modules=modules, csrf=csrf_token(request),
            user=request.session.get("user"), version=__version__,
            flash=request.session.pop("flash", None),
        )
        return templates.TemplateResponse(request, name, ctx, status_code=status_code)

    def logged_in(request: Request) -> bool:
        return bool(request.session.get("user"))

    def require_user(request: Request) -> None:
        if not logged_in(request):
            raise HTTPException(status_code=303, headers={"Location": "/login"})

    def require_csrf(request: Request, csrf: str = Form("")) -> None:
        if not security.check_csrf(request.session.get("csrf"), csrf):
            raise HTTPException(status_code=400, detail="CSRF doğrulaması başarısız")

    guarded = [Depends(require_user), Depends(require_csrf)]
    for m in modules:
        if m.router:
            app.include_router(m.router, prefix=f"/m/{m.slug}", dependencies=guarded)

    def client_ip(request: Request) -> str:
        return request.client.host if request.client else "unknown"

    @app.get("/login", response_class=HTMLResponse)
    async def login_page(request: Request):
        if logged_in(request):
            return RedirectResponse("/", status_code=303)
        return render(request, "login.html", error=None)

    @app.post("/login", response_class=HTMLResponse)
    async def login(request: Request, username: str = Form(...), password: str = Form(...),
                    code: str = Form(""), csrf: str = Form("")):
        ip = client_ip(request)
        if not security.check_csrf(request.session.get("csrf"), csrf):
            return render(request, "login.html", 400, error="Oturum doğrulanamadı, sayfayı yenileyin.")
        if limiter.blocked(ip):
            db.log_event("core", "warning", f"Giriş sınırı aşıldı: {ip}")
            return render(request, "login.html", 429, error="Çok fazla deneme. Birkaç dakika sonra tekrar deneyin.")
        with db.session() as conn:
            row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        ok = security.verify_password(row["password_hash"] if row else None, password)
        if ok and row["totp_secret"]:
            ok = security.verify_totp(row["totp_secret"], code)
        if not ok:
            limiter.fail(ip)
            db.log_event("core", "warning", f"Başarısız giriş: kullanıcı={username!r} ip={ip}")
            return render(request, "login.html", 401, error="Kullanıcı adı, parola veya kod hatalı.")
        limiter.reset(ip)
        request.session.clear()  # oturum sabitlemeyi önle
        request.session["user"] = row["username"]
        request.session["csrf"] = security.new_csrf_token()
        db.log_event("core", "info", f"Giriş: {username} ip={ip}")
        return RedirectResponse("/", status_code=303)

    @app.post("/logout")
    async def logout(request: Request, csrf: str = Form("")):
        if security.check_csrf(request.session.get("csrf"), csrf):
            request.session.clear()
        return RedirectResponse("/login", status_code=303)

    @app.get("/", response_class=HTMLResponse)
    async def overview(request: Request):
        if not logged_in(request):
            return RedirectResponse("/login", status_code=303)
        with db.session() as conn:
            events = conn.execute("SELECT * FROM events ORDER BY id DESC LIMIT 40").fetchall()
            events = group_events(events)
            warn24 = conn.execute(
                "SELECT COUNT(*) FROM events WHERE level IN ('warning', 'error') "
                "AND ts >= datetime('now', '-1 day')").fetchone()[0]
        info = sysinfo.snapshot()
        mem_pct = round(100 * info["mem_used"] / info["mem_total"]) if info["mem_total"] else 0
        disk_pct = round(100 * info["disk_used"] / info["disk_total"]) if info["disk_total"] else 0


        summaries = []
        for m in modules:
            if not m.summary:
                continue
            try:
                summaries.append(m.summary())
            except Exception as exc:  # noqa: BLE001 - tek özet paneli düşürmemeli
                db.log_event("core", "error", f"Özet üretilemedi: {m.slug}: {exc.__class__.__name__}")
        from .modules import harita
        return render(request, "overview.html", world=harita._world(), live=harita.live_payload(), flush=True, info=info, events=events,
                      page="overview", summaries=summaries, warn24=warn24, mem_pct=mem_pct, disk_pct=disk_pct)

    @app.get("/api/live")
    async def api_live(request: Request):
        if not logged_in(request):
            return JSONResponse({"error": "oturum gerekli"}, status_code=401, headers={"Cache-Control": "no-store"})
        from .modules import harita
        return JSONResponse(harita.live_payload(), headers={"Cache-Control": "no-store"})

    @app.get("/m/{slug}", response_class=HTMLResponse)
    async def module_page(request: Request, slug: str):
        if not logged_in(request):
            return RedirectResponse("/login", status_code=303)
        mod = next((m for m in modules if m.slug == slug), None)
        if mod is None:
            return render(request, "notfound.html", 404, page="")
        from .modules import harita
        return render(request, mod.template, mod=mod, data=mod.collect(), page=slug,
                      flush=slug in ("harita", "ddos", "audit", "geoip", "tuzak"), live=harita.live_payload())

    @app.get("/kaynak", response_class=HTMLResponse)
    def kaynak_page(request: Request, ip: str = ""):
        # Eşzamanlı (def): RDAP ve ters DNS sorguları ağ bekler, iş parçacığı havuzunda çalışır.
        if not logged_in(request):
            return RedirectResponse("/login", status_code=303)
        from . import abuse, sensor, upstream
        from .modules import harita, tuzak
        ctx = {"page": "savunma", "flush": True, "live": harita.live_payload(), "query": ip[:64], "r": None,
               "error": None}
        if ip.strip():
            ip_n = abuse.normalize(ip)
            if not ip_n:
                ctx["error"] = "Genel (internetten yönlendirilebilir) bir IPv4/IPv6 adresi girin."
            else:
                snap = sensor.read()
                lines, _ = tuzak._read_cowrie()
                ctx["r"] = abuse.research(ip_n, snap["data"] if snap["state"] == "hazır" else None, lines,
                                          upstream.server_ip())
        return render(request, "kaynak.html", **ctx)

    @app.get("/settings", response_class=HTMLResponse)
    async def settings(request: Request):
        if not logged_in(request):
            return RedirectResponse("/login", status_code=303)
        return render(request, "settings.html", flush=True, page="settings", **_totp_ctx(request))

    def _totp_ctx(request: Request) -> dict:
        with db.session() as conn:
            row = conn.execute("SELECT totp_secret FROM users WHERE username = ?",
                               (request.session["user"],)).fetchone()
        return {"totp_enabled": bool(row and row["totp_secret"]), "totp_pending": None, "message": None,
                "notify": notify.status(), "api": fleet.api_status(), "api_token": None}

    @app.post("/settings/totp/start", response_class=HTMLResponse)
    async def totp_start(request: Request, csrf: str = Form("")):
        if not logged_in(request):
            return RedirectResponse("/login", status_code=303)
        if not security.check_csrf(request.session.get("csrf"), csrf):
            return render(request, "notfound.html", 400, page="")
        secret = security.new_totp_secret()
        request.session["totp_pending"] = secret
        ctx = _totp_ctx(request)
        ctx["totp_pending"] = {"secret": secret, "uri": security.totp_uri(secret, request.session["user"])}
        return render(request, "settings.html", flush=True, page="settings", **ctx)

    @app.post("/settings/totp/confirm", response_class=HTMLResponse)
    async def totp_confirm(request: Request, code: str = Form(""), csrf: str = Form("")):
        if not logged_in(request):
            return RedirectResponse("/login", status_code=303)
        if not security.check_csrf(request.session.get("csrf"), csrf):
            return render(request, "notfound.html", 400, page="")
        secret = request.session.get("totp_pending")
        ctx = _totp_ctx(request)
        if secret and security.verify_totp(secret, code):
            with db.session() as conn:
                conn.execute("UPDATE users SET totp_secret = ? WHERE username = ?",
                             (secret, request.session["user"]))
            request.session.pop("totp_pending", None)
            db.log_event("core", "info", f"2FA etkinleştirildi: {request.session['user']}")
            ctx.update(totp_enabled=True, message="İki adımlı doğrulama etkinleştirildi.")
            return render(request, "settings.html", flush=True, page="settings", **ctx)
        if secret:
            ctx["totp_pending"] = {"secret": secret, "uri": security.totp_uri(secret, request.session["user"])}
        ctx["message"] = "Kod hatalı, tekrar deneyin."
        return render(request, "settings.html", 400, flush=True, page="settings", **ctx)

    @app.post("/settings/notify", dependencies=guarded)
    async def notify_save(request: Request, telegram_token: str = Form(""), telegram_chat: str = Form(""),
                          webhook_url: str = Form(""), clear: str = Form("")):
        if clear:
            for key in notify.KEYS:
                db.delete_setting(key)
            request.session["flash"] = "Bildirim kanalları temizlendi."
            return RedirectResponse("/settings", status_code=303)
        token, chat, hook = telegram_token.strip(), telegram_chat.strip(), webhook_url.strip()
        err = notify.validate(token, chat, hook)
        if err:
            request.session["flash"] = err
            return RedirectResponse("/settings", status_code=303)
        # Boş bırakılan alan mevcut değeri korur (gizli anahtar geri gösterilmez).
        for key, val in zip(notify.KEYS, (token, chat, hook)):
            if val:
                db.set_setting(key, val)
        db.log_event("core", "info", "Bildirim ayarları güncellendi")
        request.session["flash"] = "Bildirim ayarları kaydedildi."
        return RedirectResponse("/settings", status_code=303)

    @app.post("/settings/notify/test", dependencies=guarded)
    def notify_test(request: Request):
        if not notify.status()["any"]:
            request.session["flash"] = "Önce bir bildirim kanalı ekleyin."
        else:
            res = notify.send("NexGuard test bildirimi.")
            request.session["flash"] = "; ".join(
                f"{n}: {'tamam' if ok else 'hata ' + err}" for n, ok, err in res)
        return RedirectResponse("/settings", status_code=303)

    @app.get("/api/v1/ozet")
    def api_summary(request: Request):
        """Filo için salt okunur özet. Oturum değil, Bearer anahtarı ister."""
        key = "api:" + client_ip(request)
        headers = {"Cache-Control": "no-store"}
        if limiter.blocked(key):
            return JSONResponse({"error": "çok fazla hatalı deneme"}, status_code=429, headers=headers)
        if not fleet.check_api_token(request.headers.get("authorization")):
            limiter.fail(key)
            if fleet.api_status()["enabled"]:
                db.log_event("filo", "warning", f"Filo API: geçersiz anahtar ip={client_ip(request)}")
            return JSONResponse({"error": "geçersiz anahtar"}, status_code=401,
                                headers={**headers, "WWW-Authenticate": "Bearer"})
        limiter.reset(key)
        return JSONResponse(fleet.local_summary(modules), headers=headers)

    @app.post("/settings/api/new", response_class=HTMLResponse, dependencies=guarded)
    def api_new(request: Request):
        token = fleet.new_api_token()
        db.log_event("filo", "info", "Filo API anahtarı üretildi (eskisi geçersiz)")
        # Anahtar çereze (flash) konmaz: oturum çerezi imzalı ama şifreli değil. Yalnızca bu yanıtta görünür.
        ctx = _totp_ctx(request)
        ctx["api_token"] = token
        ctx["api"] = fleet.api_status()
        return render(request, "settings.html", flush=True, page="settings", **ctx)

    @app.post("/settings/api/revoke", dependencies=guarded)
    def api_revoke(request: Request):
        fleet.revoke_api_token()
        db.log_event("filo", "info", "Filo API anahtarı iptal edildi")
        request.session["flash"] = "Filo anahtarı iptal edildi; uzak paneller artık bu sunucuyu okuyamaz."
        return RedirectResponse("/settings", status_code=303)

    return app
