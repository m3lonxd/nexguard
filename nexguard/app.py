from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from . import __version__, config, db, notify, security, sysinfo
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
            events = conn.execute("SELECT * FROM events ORDER BY id DESC LIMIT 10").fetchall()
        return render(request, "overview.html", info=sysinfo.snapshot(), events=events, page="overview")

    @app.get("/m/{slug}", response_class=HTMLResponse)
    async def module_page(request: Request, slug: str):
        if not logged_in(request):
            return RedirectResponse("/login", status_code=303)
        mod = next((m for m in modules if m.slug == slug), None)
        if mod is None:
            return render(request, "notfound.html", 404, page="")
        return render(request, mod.template, mod=mod, data=mod.collect(), page=slug)

    @app.get("/settings", response_class=HTMLResponse)
    async def settings(request: Request):
        if not logged_in(request):
            return RedirectResponse("/login", status_code=303)
        return render(request, "settings.html", page="settings", **_totp_ctx(request))

    def _totp_ctx(request: Request) -> dict:
        with db.session() as conn:
            row = conn.execute("SELECT totp_secret FROM users WHERE username = ?",
                               (request.session["user"],)).fetchone()
        return {"totp_enabled": bool(row and row["totp_secret"]), "totp_pending": None, "message": None,
                "notify": notify.status()}

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
        return render(request, "settings.html", page="settings", **ctx)

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
            return render(request, "settings.html", page="settings", **ctx)
        if secret:
            ctx["totp_pending"] = {"secret": secret, "uri": security.totp_uri(secret, request.session["user"])}
        ctx["message"] = "Kod hatalı, tekrar deneyin."
        return render(request, "settings.html", 400, page="settings", **ctx)

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

    return app
