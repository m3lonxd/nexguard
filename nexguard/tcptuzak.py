"""Çok portlu TCP tuzağı: kimsenin meşru olarak bağlanmadığı portları dinler, bağlananı kaydeder.

İki parça:
- Servis (`python -m nexguard tcptuzak`, nexguard-tcptuzak.service): panelin yazdığı ayarı
  (DATA_DIR/tcptuzak.json) izler, istenen portları açar, bağlantının ilk baytlarını en fazla 5 sn
  okuyup kapatır ve her dokunuşu DATA_DIR/tcptuzak.jsonl dosyasına bir satır olarak ekler.
  1024 altı portlar için yalnızca CAP_NET_BIND_SERVICE gerekir; servis root değildir.
- Panel tarafı (aşağıdaki okuma işlevleri): kaydı okur, özetler, ayarı doğrulayıp yazar.

Tuzak hiçbir şeyi engellemez; panel yalnız gösterir ve öneri sunar. Saldırganın gönderdiği bayt
kaçışlanmış, sınırlı bir metin olarak saklanır. Kaynak tüketimi sınırlıdır: eşzamanlı 64 bağlantı,
IP başına 4 bağlantı; aynı IP ve port için en fazla 10 sn'de bir kayıt (arada gelenler sayılır).
"""
import asyncio
import json
import os
import time
from collections import Counter

from . import config

MAX_CONN = 64
MAX_PER_IP = 4
READ_WAIT = 5.0
MAX_PAYLOAD = 512
LOG_EVERY = 10.0
LOG_MAX_BYTES = 5 * 1024 * 1024
MAX_PORTS = 16
TAIL_BYTES = 2 * 1024 * 1024
# Gerçek bir servisle karışmasın: SSH, panel, web ve DNS portları tuzak olamaz.
RESERVED = {22, 53, 80, 443, config.PORT}
SUGGESTED = [23, 2323, 3389, 5900]


def config_path():
    return config.DATA_DIR / "tcptuzak.json"


def log_path():
    return config.DATA_DIR / "tcptuzak.jsonl"


def status_path():
    return config.DATA_DIR / "tcptuzak.state"


# --- Ayar (panel yazar, servis okur; içerik her iki tarafta da doğrulanır) -------------------

def validate_ports(text: str) -> tuple[list[int], str | None]:
    ports: list[int] = []
    for part in str(text).replace(",", " ").split():
        if not part.isdigit() or not 1 <= int(part) <= 65535:
            return [], f"{part!r} geçerli bir port değil (1-65535)."
        p = int(part)
        if p in RESERVED:
            return [], f"{p} portu tuzak olamaz (SSH, web, DNS ya da panel portu)."
        if p not in ports:
            ports.append(p)
    if len(ports) > MAX_PORTS:
        return [], f"En fazla {MAX_PORTS} port seçilebilir."
    return sorted(ports), None


def load_config() -> dict:
    try:
        data = json.loads(config_path().read_text())
    except (OSError, ValueError):
        return {"enabled": False, "ports": []}
    ports, err = validate_ports(" ".join(str(p) for p in data.get("ports", []) if isinstance(p, int)))
    return {"enabled": bool(data.get("enabled")) and not err and bool(ports), "ports": ports if not err else []}


def save_config(enabled: bool, ports: list[int]) -> None:
    config.DATA_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = config_path().with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({"v": 1, "enabled": bool(enabled), "ports": ports}, f)
    os.replace(tmp, config_path())


# --- Panel: kayıt okuma ----------------------------------------------------------------------

def _tail() -> list[dict]:
    try:
        with open(log_path(), "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - TAIL_BYTES))
            raw = f.read()
    except OSError:
        return []
    lines = raw.decode("utf-8", "replace").splitlines()
    if size > TAIL_BYTES:
        lines = lines[1:]
    out = []
    for line in lines:
        try:
            e = json.loads(line)
            out.append({"ts": float(e["ts"]), "ip": str(e["ip"])[:64], "port": int(e["port"]),
                        "payload": str(e.get("payload", ""))[:200], "n": max(1, int(e.get("n", 1)))})
        except (ValueError, KeyError, TypeError):
            continue
    return out


def service_status() -> dict:
    """Servisin son yazdığı durum: dinlenen portlar ve hatalar. 30 sn'den eskiyse çalışmıyor sayılır."""
    try:
        st = json.loads(status_path().read_text())
        age = time.time() - float(st.get("ts", 0))
    except (OSError, ValueError, TypeError):
        return {"running": False, "listening": [], "errors": {}}
    return {"running": age < 30, "listening": [int(p) for p in st.get("listening", [])][:MAX_PORTS],
            "errors": {str(k): str(v)[:160] for k, v in (st.get("errors") or {}).items()}}


def summary(limit: int = 40) -> dict:
    hits = _tail()
    now = time.time()
    day = [h for h in hits if now - h["ts"] < 86400]
    by_port = Counter()
    by_ip = Counter()
    for h in day:
        by_port[h["port"]] += h["n"]
        by_ip[h["ip"]] += h["n"]
    recent = sorted(hits, key=lambda h: -h["ts"])[:limit]
    return {"config": load_config(), "service": service_status(), "total24": sum(by_port.values()),
            "ips24": len(by_ip), "by_port": by_port.most_common(), "top_ips": by_ip.most_common(10),
            "recent": [{**h, "when": time.strftime("%d.%m %H:%M", time.localtime(h["ts"]))} for h in recent]}


def hits_for(ip: str, limit: int = 10) -> list[dict]:
    rows = [h for h in _tail() if h["ip"] == ip]
    rows.sort(key=lambda h: -h["ts"])
    return [{"when": time.strftime("%d.%m %H:%M", time.localtime(h["ts"])), "port": h["port"],
             "payload": h["payload"], "n": h["n"]} for h in rows[:limit]]


# --- Servis ----------------------------------------------------------------------------------

def escape(b: bytes, limit: int = 160) -> str:
    out = []
    size = 0
    for c in b:
        s = ("\\\\" if c == 92 else chr(c) if 32 <= c < 127 else "\\n" if c == 10 else "\\r" if c == 13
             else f"\\x{c:02x}")
        if size + len(s) > limit:
            out.append("…")
            break
        out.append(s)
        size += len(s)
    return "".join(out)


class Trap:
    def __init__(self, bind: str = "", log=None, status=None):
        self.bind = bind
        self.log = log or log_path()
        self.status = status or status_path()
        self.servers: dict[int, asyncio.base_events.Server] = {}
        self.errors: dict[int, str] = {}
        self.active = 0
        self.per_ip: Counter = Counter()
        self.last_log: dict[tuple[str, int], float] = {}
        self.pending: Counter = Counter()

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, port: int) -> None:
        peer = writer.get_extra_info("peername") or ("?", 0)
        ip = peer[0]
        if ip.startswith("::ffff:"):
            ip = ip[7:]
        if self.active >= MAX_CONN or self.per_ip[ip] >= MAX_PER_IP:
            writer.close()
            return
        self.active += 1
        self.per_ip[ip] += 1
        try:
            try:
                data = await asyncio.wait_for(reader.read(MAX_PAYLOAD), READ_WAIT)
            except (asyncio.TimeoutError, ConnectionError, OSError):
                data = b""
            self.record(ip, port, data)
        finally:
            self.active -= 1
            self.per_ip[ip] -= 1
            if self.per_ip[ip] <= 0:
                del self.per_ip[ip]
            writer.close()

    def record(self, ip: str, port: int, data: bytes, now: float | None = None) -> bool:
        """Kaydı yazar; aynı IP+port için LOG_EVERY içinde gelenleri sayıp bir sonrakine ekler."""
        now = now or time.time()
        key = (ip, port)
        self.pending[key] += 1
        if now - self.last_log.get(key, 0) < LOG_EVERY:
            return False
        n = self.pending.pop(key)
        self.last_log[key] = now
        if len(self.last_log) > 20000:  # bellek sınırı: en eskileri at
            for k, _ in sorted(self.last_log.items(), key=lambda kv: kv[1])[:10000]:
                self.last_log.pop(k, None)
        line = json.dumps({"ts": round(now, 3), "ip": ip, "port": port, "payload": escape(data), "n": n},
                          ensure_ascii=False)
        try:
            if self.log.exists() and self.log.stat().st_size > LOG_MAX_BYTES:
                os.replace(self.log, self.log.with_suffix(".jsonl.1"))
            fd = os.open(self.log, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except OSError:
            return False
        return True

    async def apply(self, cfg: dict) -> None:
        want = set(cfg["ports"]) if cfg["enabled"] else set()
        for p in list(self.servers):
            if p not in want:
                self.servers.pop(p).close()
        self.errors = {p: e for p, e in self.errors.items() if p in want}
        for p in sorted(want - set(self.servers)):
            try:
                self.servers[p] = await asyncio.start_server(
                    lambda r, w, port=p: self.handle(r, w, port), host=self.bind or None, port=p, reuse_address=True)
                self.errors.pop(p, None)
            except PermissionError:
                self.errors[p] = f"{p} portu için yetki yok (1024 altı CAP_NET_BIND_SERVICE ister)."
            except OSError as exc:
                self.errors[p] = f"{p} portu açılamadı: {exc.strerror or exc}"

    def write_status(self) -> None:
        try:
            tmp = self.status.with_suffix(".tmp")
            tmp.write_text(json.dumps({"ts": time.time(), "listening": sorted(self.servers),
                                       "errors": {str(k): v for k, v in self.errors.items()}}))
            os.replace(tmp, self.status)
        except OSError:
            pass


async def _main() -> None:
    trap = Trap()
    seen = None
    while True:
        try:
            mtime = config_path().stat().st_mtime
        except OSError:
            mtime = 0
        if mtime != seen:
            seen = mtime
            await trap.apply(load_config())
        trap.write_status()
        await asyncio.sleep(5)


def run() -> int:
    try:
        asyncio.run(_main())
    except KeyboardInterrupt:
        pass
    return 0
