"""Yerel IP -> ülke / ağ sağlayıcı (ASN) sorgusu ve anonimleştirici (Tor, VPN, barındırma) işaretleme.

Veri: DB-IP Lite (CC BY 4.0, https://db-ip.com) ve Tor Project çıkış listesi.
Sorgular tamamen yerelde yapılır; IP'ler hiçbir dış servise gönderilmez.
Önemli sınır: bu yalnızca paketlerin GÖRÜNEN kaynağını verir. Proxy/VPN/sunucu zinciri arkasındaki
gerçek saldırgan buradan bilinemez; yalnızca "arkasında bir aracı olabilir" işareti üretilir.
"""
import csv
import gzip
import io
import ipaddress
import json
import re
import sqlite3
import threading
import time
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from . import config

_COUNTRY_NAMES: dict[str, str] = json.loads((Path(__file__).parent / "data" / "countries_tr.json").read_text())
DBIP = "https://download.db-ip.com/free/dbip-{kind}-lite-{ym}.csv.gz"
TOR_URL = "https://check.torproject.org/torbulkexitlist"

_VPN_RE = re.compile(
    r"\b(vpn|proxy|nord|mullvad|proton|expressvpn|surfshark|cyberghost|ipvanish|private internet|"
    r"windscribe|hide\.?me|tunnelbear|privado|m247|datacamp|choopa|zenlayer)\b", re.I)
_HOSTING_RE = re.compile(
    r"(hosting|cloud|vps|server|data ?cent|colo|dedicated|ovh|hetzner|digitalocean|linode|vultr|"
    r"contabo|amazon|aws|google|microsoft|azure|oracle|alibaba|tencent|leaseweb|scaleway|ionos|"
    r"upcloud|hostinger|namecheap|godaddy|psychz|quadranet|frantech|buyvm|colocrossing|serverius|"
    r"online s\.a\.s|cdn77|akamai|fastly|rackspace|softlayer|ibm cloud|kamatera|netcup|aruba|"
    r"selectel|reg\.ru|timeweb|ucloud|huawei|baidu|cogent web|hostwinds|interserver|dreamhost|"
    r"bluehost|hostgator|a2 hosting|liquid web|ramnode|racknerd|virmach|hosthatch)", re.I)

_state_lock = threading.Lock()
_state: dict = {"phase": "idle", "message": "", "started": 0.0}


def db_path() -> Path:
    return config.DATA_DIR / "geo.db"


def country_name(cc: str | None) -> str:
    if not cc or cc == "ZZ":
        return "Bilinmiyor"
    return _COUNTRY_NAMES.get(cc, cc)


@dataclass
class IpInfo:
    ip: str
    cc: str = "ZZ"
    country: str = "Bilinmiyor"
    asn: int | None = None
    org: str = ""
    flags: list[str] = field(default_factory=list)  # tor | vpn | hosting

    @property
    def anonymized(self) -> bool:
        return bool(self.flags)

    @property
    def flag_labels(self) -> list[str]:
        names = {"tor": "Tor çıkışı", "vpn": "VPN/Proxy", "hosting": "Barındırma/Sunucu"}
        return [names[f] for f in self.flags]


def _key(ip: ipaddress._BaseAddress) -> tuple[int, str]:
    return (4, f"{int(ip):08x}") if ip.version == 4 else (6, f"{int(ip):032x}")


def _norm(ip: str):
    a = ipaddress.ip_address(ip)
    if a.version == 6 and a.ipv4_mapped:
        a = a.ipv4_mapped
    return a


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(db_path())
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


SCHEMA = """
CREATE TABLE IF NOT EXISTS country (fam INTEGER, start TEXT, end TEXT, cc TEXT);
CREATE INDEX IF NOT EXISTS country_i ON country (fam, start);
CREATE TABLE IF NOT EXISTS asn (fam INTEGER, start TEXT, end TEXT, asn INTEGER, org TEXT);
CREATE INDEX IF NOT EXISTS asn_i ON asn (fam, start);
CREATE TABLE IF NOT EXISTS tor (ip TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
"""


def status() -> dict:
    with _state_lock:
        st = dict(_state)
    info = {"installed": False, "updated": None, "tor": 0, **st}
    if db_path().exists():
        try:
            with _connect() as c:
                c.executescript(SCHEMA)
                row = c.execute("SELECT value FROM meta WHERE key='updated'").fetchone()
                info["updated"] = row[0] if row else None
                info["installed"] = bool(row)
                info["tor"] = c.execute("SELECT COUNT(*) FROM tor").fetchone()[0]
        except sqlite3.Error:
            pass
    return info


def _lookup_range(c: sqlite3.Connection, table: str, cols: str, ip) -> tuple | None:
    fam, k = _key(ip)
    row = c.execute(f"SELECT end, {cols} FROM {table} WHERE fam=? AND start<=? ORDER BY start DESC LIMIT 1",
                    (fam, k)).fetchone()
    return row[1:] if row and row[0] >= k else None


def lookup(ip_text: str) -> IpInfo:
    """Veritabanı yoksa ya da IP geçersizse boş (Bilinmiyor) bilgi döner; asla hata fırlatmaz."""
    info = IpInfo(ip_text)
    if not db_path().exists():
        return info
    try:
        ip = _norm(ip_text)
        with _connect() as c:
            r = _lookup_range(c, "country", "cc", ip)
            if r:
                info.cc = r[0]
                info.country = country_name(r[0])
            r = _lookup_range(c, "asn", "asn, org", ip)
            if r:
                info.asn, info.org = r[0], r[1] or ""
            if c.execute("SELECT 1 FROM tor WHERE ip=?", (str(ip),)).fetchone():
                info.flags.append("tor")
    except (ValueError, sqlite3.Error):
        return info
    if info.org:
        if _VPN_RE.search(info.org):
            info.flags.append("vpn")
        elif _HOSTING_RE.search(info.org):
            info.flags.append("hosting")
    return info


# --- Güncelleme (arka plan) ---------------------------------------------------

def _open_gz_csv(url: str):
    req = urllib.request.Request(url, headers={"User-Agent": "nexguard-geo/1.0"})
    resp = urllib.request.urlopen(req, timeout=60)  # noqa: S310 - sabit https adresleri
    return io.TextIOWrapper(gzip.GzipFile(fileobj=resp), encoding="utf-8", newline="")


def _import_csv(c: sqlite3.Connection, kind: str, table: str, ncols: int) -> int:
    now = time.gmtime()
    months = [time.strftime("%Y-%m", now)]
    prev = (now.tm_year, now.tm_mon - 1) if now.tm_mon > 1 else (now.tm_year - 1, 12)
    months.append(f"{prev[0]}-{prev[1]:02d}")
    stream = None
    for ym in months:
        try:
            stream = _open_gz_csv(DBIP.format(kind=kind, ym=ym))
            break
        except OSError:
            continue
    if stream is None:
        raise OSError(f"{kind} veritabanı indirilemedi")
    c.execute(f"DELETE FROM {table}")
    batch, total = [], 0
    for row in csv.reader(stream):
        if len(row) < ncols:
            continue
        try:
            a, b = ipaddress.ip_address(row[0]), ipaddress.ip_address(row[1])
        except ValueError:
            continue
        fam, ks = _key(a)
        ke = _key(b)[1]
        if table == "country":
            batch.append((fam, ks, ke, row[2]))
        else:
            batch.append((fam, ks, ke, int(row[2]) if row[2].isdigit() else None, row[3]))
        if len(batch) >= 20000:
            _flush(c, table, batch)
            total += len(batch)
            batch = []
    _flush(c, table, batch)
    return total + len(batch)


def _flush(c: sqlite3.Connection, table: str, batch: list) -> None:
    if batch:
        marks = ",".join("?" * len(batch[0]))
        c.executemany(f"INSERT INTO {table} VALUES ({marks})", batch)


def _update() -> None:
    def setstate(phase: str, msg: str) -> None:
        with _state_lock:
            _state.update(phase=phase, message=msg)

    try:
        config.DATA_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
        with _connect() as c:
            c.executescript(SCHEMA)
            setstate("running", "Ülke veritabanı indiriliyor...")
            n1 = _import_csv(c, "country", "country", 3)
            c.commit()
            setstate("running", "Ağ sağlayıcı (ASN) veritabanı indiriliyor...")
            n2 = _import_csv(c, "asn", "asn", 4)
            c.commit()
            setstate("running", "Tor çıkış listesi indiriliyor...")
            req = urllib.request.Request(TOR_URL, headers={"User-Agent": "nexguard-geo/1.0"})
            with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
                ips = [(l.strip(),) for l in resp.read().decode().splitlines() if l.strip()]
            c.execute("DELETE FROM tor")
            c.executemany("INSERT OR IGNORE INTO tor VALUES (?)", ips)
            c.execute("INSERT OR REPLACE INTO meta VALUES ('updated', ?)", (time.strftime("%Y-%m-%d"),))
            c.commit()
        setstate("done", f"Hazır: {n1} ülke, {n2} ASN aralığı, {len(ips)} Tor çıkışı.")
    except Exception as exc:  # noqa: BLE001
        setstate("error", f"Güncelleme başarısız: {exc.__class__.__name__}")


def start_update() -> bool:
    with _state_lock:
        if _state["phase"] == "running":
            return False
        _state.update(phase="running", message="Başlıyor...", started=time.time())
    threading.Thread(target=_update, name="geo-update", daemon=True).start()
    return True


# --- Özet ---------------------------------------------------------------------

def summarize(conns: list[tuple[str, int]]) -> dict:
    """[(ip, bağlantı sayısı)] -> ülke dağılımı, kaynak listesi ve anonimleştirici oranı."""
    sources, by_country = [], {}
    total = anon = 0
    for ip, n in conns:
        info = lookup(ip)
        sources.append({"ip": ip, "n": n, "cc": info.cc, "country": info.country, "asn": info.asn,
                        "org": info.org, "flags": info.flag_labels, "anon": info.anonymized})
        total += n
        anon += n if info.anonymized else 0
        e = by_country.setdefault(info.cc, {"cc": info.cc, "country": info.country, "n": 0, "ips": 0, "anon": 0})
        e["n"] += n
        e["ips"] += 1
        e["anon"] += n if info.anonymized else 0
    countries = sorted(by_country.values(), key=lambda e: -e["n"])
    pct = round(100 * anon / total) if total else 0
    return {"countries": countries, "sources": sources, "total": total, "anon_pct": pct,
            "verdict": verdict(countries, pct)}


def verdict(countries: list[dict], anon_pct: int) -> str:
    if not countries:
        return "Kaynak verisi yok."
    top = countries[0]
    known = top["cc"] != "ZZ"
    text = f"Görünen ana kaynak: {top['country']}" if known else "Kaynak ülke belirlenemedi (coğrafya veritabanı kurulu olmayabilir)"
    if anon_pct >= 50:
        text += (f". Trafiğin %{anon_pct}'i barındırma/VPN/Tor ağlarından geliyor: saldırgan kendini bir aracı "
                 "sunucu arkasına saklıyor olabilir. Gerçek konumu paketlerden anlaşılamaz.")
    elif anon_pct > 0:
        text += f". Trafiğin %{anon_pct}'i barındırma/VPN/Tor ağlarından; bir kısmı aracı olabilir."
    else:
        text += ". Kaynakların aracı (VPN/proxy/barındırma) işareti yok; yine de botnet ele geçirilmiş ev cihazları da olabilir."
    return text
