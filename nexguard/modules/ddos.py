"""DDoS izleme ve bildirim.

Her 5 sn'de /proc'tan ölçer (paket/bant hızı, SYN_RECV, IP başına bağlantı, conntrack),
eşik aşımını 2 ardışık örnekte doğrulayıp olay günlüğüne yazar ve bildirim kanallarına gönderir.
Panel ayrıcalıksız çalıştığı için engelleme uygulamaz; hazır nftables kuralı ve sysctl önerisi sunar.
"""
import ipaddress
import json
import socket
import threading
import time
from collections import Counter, deque
from dataclasses import dataclass, field

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse

from .. import charts, db, geoip, notify
from . import Module

INTERVAL = 5
HISTORY = 120
COOLDOWN = 300  # aynı seviye için bildirimler arası saniye
RECOVER_SAMPLES = 6  # normale dönüş için ardışık sakin örnek
LEVELS = ["normal", "yüksek", "saldırı"]

# ad: (uyarı, saldırı, birim)
DEFAULTS = {
    "syn_recv": (100, 500, "yarı açık bağlantı"),
    "conn_per_ip": (150, 400, "bağlantı / IP"),
    "rx_pps": (50000, 200000, "paket/sn"),
    "rx_mbps": (300, 800, "Mbit/sn"),
}
LABELS = {"syn_recv": "SYN_RECV", "conn_per_ip": "IP başına bağlantı", "rx_pps": "Gelen paket hızı",
          "rx_mbps": "Gelen bant"}


# --- Ayrıştırıcılar (saf fonksiyonlar) ---------------------------------------

def parse_net_dev(text: str) -> tuple[int, int]:
    """Sanal arayüzler hariç toplam (rx_bayt, rx_paket)."""
    rx_b = rx_p = 0
    for line in text.splitlines()[2:]:
        name, _, rest = line.partition(":")
        name = name.strip()
        if not rest or name == "lo" or name.startswith(("veth", "docker", "br-", "virbr")):
            continue
        f = rest.split()
        rx_b += int(f[0])
        rx_p += int(f[1])
    return rx_b, rx_p


def decode_ip(hexaddr: str) -> str:
    raw = bytes.fromhex(hexaddr)
    if len(raw) == 4:
        return socket.inet_ntoa(raw[::-1])
    swapped = b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4))
    return str(ipaddress.IPv6Address(swapped))


def parse_proc_tcp(text: str) -> list[tuple[int, str]]:
    """/proc/net/tcp[6] -> [(durum, uzak_ip)]; yalnızca ESTABLISHED(1) ve SYN_RECV(3)."""
    out = []
    for line in text.splitlines()[1:]:
        f = line.split()
        if len(f) < 4:
            continue
        try:
            state = int(f[3], 16)
            if state not in (1, 3):
                continue
            out.append((state, decode_ip(f[2].split(":")[0])))
        except ValueError:
            continue
    return out


def _external(ip: str) -> bool:
    a = ipaddress.ip_address(ip)
    if a.version == 6 and a.ipv4_mapped:
        a = a.ipv4_mapped
    return not (a.is_loopback or a.is_unspecified)


@dataclass
class Sample:
    ts: float
    rx_pps: float = 0.0
    rx_mbps: float = 0.0
    syn_recv: int = 0
    established: int = 0
    top_ips: list = field(default_factory=list)
    per_ip: list = field(default_factory=list)  # (ip, bağlantı) ilk 100
    conntrack: tuple | None = None

    @property
    def max_per_ip(self) -> int:
        return self.top_ips[0][1] if self.top_ips else 0


def load_thresholds() -> dict[str, tuple[int, int]]:
    th = {}
    for name, (warn, attack, _) in DEFAULTS.items():
        try:
            w = int(db.get_setting(f"ddos.{name}.warn", str(warn)))
            a = int(db.get_setting(f"ddos.{name}.attack", str(attack)))
        except ValueError:
            w, a = warn, attack
        th[name] = (w, a)
    return th


def evaluate(s: Sample, th: dict[str, tuple[int, int]]) -> tuple[int, list[str]]:
    values = {"syn_recv": s.syn_recv, "conn_per_ip": s.max_per_ip,
              "rx_pps": s.rx_pps, "rx_mbps": s.rx_mbps}
    level, reasons = 0, []
    for name, val in values.items():
        warn, attack = th[name]
        if val >= attack:
            level = 2
            reasons.append(f"{LABELS[name]} {val:.0f} (saldırı eşiği {attack})")
        elif val >= warn:
            level = max(level, 1)
            reasons.append(f"{LABELS[name]} {val:.0f} (uyarı eşiği {warn})")
    return level, reasons


class Monitor:
    def __init__(self, notifier=None):
        self.notifier = notifier or self._async_notify
        self.history: deque[Sample] = deque(maxlen=HISTORY)
        self.level = 0
        self.since = time.time()
        self.reasons: list[str] = []
        self._rise = self._calm = 0
        self._prev: tuple[float, int, int] | None = None
        self._last_notify = 0.0
        self._notified_level = 0
        self._lock = threading.Lock()
        self.cur: dict | None = None
        self._ticks = 0

    @staticmethod
    def _async_notify(text: str) -> None:
        if notify.status()["any"]:
            threading.Thread(target=notify.send, args=(text,), daemon=True).start()

    def tick(self, now: float, net_dev: str, tcp_texts: list[str],
             conntrack: tuple[int, int] | None, th: dict | None = None) -> Sample:
        rx_b, rx_p = parse_net_dev(net_dev)
        s = Sample(ts=now, conntrack=conntrack)
        if self._prev:
            dt = max(now - self._prev[0], 0.001)
            s.rx_pps = max(rx_p - self._prev[2], 0) / dt
            s.rx_mbps = max(rx_b - self._prev[1], 0) * 8 / 1e6 / dt
        self._prev = (now, rx_b, rx_p)
        per_ip: Counter = Counter()
        for text in tcp_texts:
            for state, ip in parse_proc_tcp(text):
                if state == 3:
                    s.syn_recv += 1
                else:
                    s.established += 1
                if _external(ip):
                    per_ip[ip] += 1
        s.top_ips = per_ip.most_common(5)
        s.per_ip = per_ip.most_common(100)
        with self._lock:
            self.history.append(s)
            self._transition(s, th or load_thresholds())
            self._track(s)
        return s

    def _transition(self, s: Sample, th: dict) -> None:
        target, reasons = evaluate(s, th)
        if target > self.level:
            self._rise += 1
            self._calm = 0
            if self._rise >= 2:
                self.level, self.reasons, self._rise = target, reasons, 0
                self.since = s.ts
                self._alert(s, rising=True)
        elif target < self.level:
            self._calm += 1
            self._rise = 0
            if self._calm >= RECOVER_SAMPLES:
                was = self.level
                self.level, self.reasons, self._calm = target, reasons, 0
                self.since = s.ts
                if self._notified_level >= 1:
                    self._alert(s, rising=False, was=was)
                if self.level == 0:
                    self._notified_level = 0
        else:
            self._rise = self._calm = 0
            self.reasons = reasons

    def _track(self, s: Sample) -> None:
        """Saldırı kaydı: seviye >0 olduğu sürece tepe değerleri ve kaynak IP'leri biriktirir."""
        if self.level > 0:
            if self.cur is None:
                with db.session() as conn:
                    cur = conn.execute("INSERT INTO attacks (started, peak_level) VALUES (?, ?)",
                                       (time.strftime("%Y-%m-%d %H:%M:%S"), self.level))
                self.cur = {"id": cur.lastrowid, "ips": {}, "pps": 0.0, "mbps": 0.0, "syn": 0, "level": 0}
            c = self.cur
            c.update(pps=max(c["pps"], s.rx_pps), mbps=max(c["mbps"], s.rx_mbps),
                     syn=max(c["syn"], s.syn_recv), level=max(c["level"], self.level))
            for ip, n in s.per_ip:
                c["ips"][ip] = max(c["ips"].get(ip, 0), n)
            if self._ticks % 12 == 0:
                self._save_attack(ended=False)
            self._ticks += 1
        elif self.cur is not None:
            self._save_attack(ended=True)
            self.cur, self._ticks = None, 0

    def _save_attack(self, ended: bool) -> None:
        c = self.cur
        top = sorted(c["ips"].items(), key=lambda kv: -kv[1])[:30]
        summary = json.dumps(geoip.summarize(top), ensure_ascii=False)
        with db.session() as conn:
            conn.execute(
                "UPDATE attacks SET ended = ?, peak_level = ?, peak_pps = ?, peak_mbps = ?, peak_syn = ?, summary = ? WHERE id = ?",
                (time.strftime("%Y-%m-%d %H:%M:%S") if ended else None, c["level"], c["pps"], c["mbps"], c["syn"],
                 summary, c["id"]))

    def _alert(self, s: Sample, rising: bool, was: int = 0) -> None:
        name = LEVELS[self.level]
        if rising:
            top = ", ".join(f"{ip} ({n})" for ip, n in s.top_ips[:3]) or "-"
            geo = geoip.summarize(s.per_ip[:50]) if s.per_ip else None
            msg = f"NexGuard: DDoS seviyesi {name.upper()}. " + "; ".join(self.reasons) + f". En çok bağlanan: {top}"
            if geo:
                cs = ", ".join(f"{e['country']} ({e['n']})" for e in geo["countries"][:3])
                msg += f". Ülkeler: {cs}. {geo['verdict']}"
            db.log_event("ddos", "error" if self.level == 2 else "warning", msg)
            if self.level > self._notified_level or s.ts - self._last_notify >= COOLDOWN:
                self.notifier(msg)
                self._last_notify, self._notified_level = s.ts, self.level
        else:
            msg = f"NexGuard: DDoS seviyesi {LEVELS[was]}'dan {name}'a indi."
            db.log_event("ddos", "info", msg)
            self.notifier(msg)


monitor = Monitor()
_started = False


def _read(path: str) -> str:
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return ""


def _conntrack() -> tuple[int, int] | None:
    c, m = _read("/proc/sys/net/netfilter/nf_conntrack_count"), _read("/proc/sys/net/netfilter/nf_conntrack_max")
    return (int(c), int(m)) if c.strip().isdigit() and m.strip().isdigit() else None


def _loop() -> None:
    failed = False
    while True:
        try:
            monitor.tick(time.time(), _read("/proc/net/dev"),
                         [_read("/proc/net/tcp"), _read("/proc/net/tcp6")], _conntrack())
            failed = False
        except Exception as exc:  # noqa: BLE001 - izleyici ölmemeli
            if not failed:
                db.log_event("ddos", "error", f"Örnekleme hatası: {exc.__class__.__name__}")
            failed = True
        time.sleep(INTERVAL)


def start() -> None:
    global _started
    if not _started:
        _started = True
        threading.Thread(target=_loop, name="ddos-monitor", daemon=True).start()


# --- Arayüz verisi -----------------------------------------------------------

def _points(values: list[float], w: int = 300, h: int = 50) -> str:
    if len(values) < 2:
        return ""
    top = max(max(values), 1)
    step = w / (len(values) - 1)
    return " ".join(f"{i * step:.1f},{h - (v / top) * (h - 4) - 2:.1f}" for i, v in enumerate(values))


SYSCTL_ADVICE = [
    ("net.ipv4.tcp_syncookies", "net/ipv4/tcp_syncookies", "1", "SYN flood'da bağlantı kuyruğunu korur"),
    ("net.ipv4.tcp_max_syn_backlog", "net/ipv4/tcp_max_syn_backlog", "4096", "Yarı açık bağlantı kuyruğu"),
    ("net.ipv4.tcp_synack_retries", "net/ipv4/tcp_synack_retries", "2", "Sahte SYN'lere ayrılan süreyi kısaltır"),
    ("net.core.somaxconn", "net/core/somaxconn", "4096", "Dinleme kuyruğu uzunluğu"),
    ("net.ipv4.conf.all.rp_filter", "net/ipv4/conf/all/rp_filter", "1", "Sahte kaynak IP'leri eler"),
]

NFT_TEMPLATE = """# NexGuard önerisi - ÖNCE test edin: sudo nft -c -f ddos.nft
# Uygulama: sudo nft -f ddos.nft   |   Kaldırma: sudo nft delete table inet nexguard_ddos
table inet nexguard_ddos {
  set blocklist4 { type ipv4_addr; flags timeout; }
  set flood4     { type ipv4_addr; flags dynamic; size 65535; timeout 1m; }
  chain input {
    type filter hook input priority -10; policy accept;
    ip saddr @blocklist4 drop
    # Saniyede 50'den fazla yeni bağlantı açan IP 10 dk engellenir
    ct state new tcp flags syn add @flood4 { ip saddr limit rate over 50/second burst 100 packets } add @blocklist4 { ip saddr timeout 10m } drop
    # Yeni TCP bağlantılarında genel tavan (acil durum; meşru trafiği de etkileyebilir)
    tcp flags syn limit rate over 5000/second burst 10000 packets drop
    # ICMP sel koruması
    ip protocol icmp limit rate over 20/second drop
  }
}
"""


def collect() -> dict:
    with monitor._lock:
        hist = list(monitor.history)
        level, reasons, since = monitor.level, list(monitor.reasons), monitor.since
    last = hist[-1] if hist else None
    th = load_thresholds()
    events = []
    with db.session() as conn:
        events = conn.execute("SELECT * FROM events WHERE module='ddos' ORDER BY id DESC LIMIT 10").fetchall()
    sysctl = []
    for name, path, want, why in SYSCTL_ADVICE:
        cur = _read(f"/proc/sys/{path}").strip() or "?"
        sysctl.append({"name": name, "cur": cur, "want": want, "why": why,
                       "ok": cur == want or (name.endswith("backlog") or name.endswith("somaxconn")) and cur.isdigit() and int(cur) >= int(want)})
    return {
        "level": level, "level_name": LEVELS[level], "reasons": reasons, "since": time.strftime("%H:%M:%S", time.localtime(since)),
        "last": last, "running": _started, "pps_points": _points([s.rx_pps for s in hist]),
        "syn_points": _points([s.syn_recv for s in hist]), "samples": len(hist),
        "thresholds": {n: {"warn": th[n][0], "attack": th[n][1], "label": LABELS[n], "unit": DEFAULTS[n][2]} for n in DEFAULTS},
        "events": events, "sysctl": sysctl, "nft": NFT_TEMPLATE, "notify": notify.status(),
    }


router = APIRouter()


@router.post("/thresholds")
async def save_thresholds(request: Request):
    form = await request.form()
    parsed: dict[str, tuple[int, int]] = {}
    for name in DEFAULTS:
        try:
            warn, attack = int(form.get(f"{name}_warn", "")), int(form.get(f"{name}_attack", ""))
        except ValueError:
            request.session["flash"] = f"{LABELS[name]}: sayı girin."
            return RedirectResponse("/m/ddos", status_code=303)
        if not (0 < warn < attack <= 10**9):
            request.session["flash"] = f"{LABELS[name]}: 0 < uyarı < saldırı olmalı."
            return RedirectResponse("/m/ddos", status_code=303)
        parsed[name] = (warn, attack)
    for name, (warn, attack) in parsed.items():
        db.set_setting(f"ddos.{name}.warn", str(warn))
        db.set_setting(f"ddos.{name}.attack", str(attack))
    db.log_event("ddos", "info", "Eşikler güncellendi")
    request.session["flash"] = "Eşikler kaydedildi."
    return RedirectResponse("/m/ddos", status_code=303)


@router.post("/test")
def test_notification(request: Request):
    if not notify.status()["any"]:
        request.session["flash"] = "Önce Ayarlar'dan bir bildirim kanalı ekleyin."
    else:
        res = notify.send("NexGuard test bildirimi: DDoS izleme çalışıyor.")
        request.session["flash"] = "; ".join(f"{n}: {'tamam' if ok else 'hata ' + err}" for n, ok, err in res)
    return RedirectResponse("/m/ddos", status_code=303)


module = Module(
    slug="ddos", title="DDoS", description="Canlı DDoS izleme, eşik bildirimi ve hazır önlem önerileri.",
    collect=collect, order=20, template="ddos.html", router=router, on_start=start,
)
