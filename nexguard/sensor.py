"""Paket algılayıcı: UDP, ICMP ve TCP SYN sellerinin kaynaklarını örnekler.

/proc yalnızca TCP bağlantı tablosunu verir; bağlantısız trafiğin (UDP, ICMP) ve el sıkışmayı
tamamlamayan SYN'lerin kaynağı orada görünmez. Bu süreç ayrı çalışır ve yalnızca CAP_NET_RAW
yetkisiyle bir AF_PACKET soketi açar (panelin kendisi ayrıcalıksız kalır).

Her INTERVAL saniyede CAPTURE saniyelik bir örnek alır, gelen paketlerin yalnızca IP başlığını
okur (yük okunmaz, kaydedilmez), protokol ve kaynak IP başına sayar. Çekirdeğin o aralıkta
gerçekte aldığı paket sayısı /proc/net/dev'den okunup örnek buna göre ölçeklenir; yoğun selde
Python her paketi yakalayamasa da dağılım doğru kalır.

Sahte (spoofed) kaynak tespiti: UDP/ICMP/SYN paketlerinin kaynak adresi taklit edilebilir, ama
TTL alanı gönderenin gerçek uzaklığını taşır. Aynı adresten gelen paketlerin TTL'i dalgalanıyorsa,
adres ayrılmış (bogon) bir aralıktaysa ya da o adresin gerçek TCP bağlantılarından öğrenilen hop
sayısı ile seldeki hop sayısı uyuşmuyorsa satır "sahte olabilir" diye işaretlenir. Binlerce farklı
adresin aynı TTL ile gelmesi tek bir makinenin adres uydurduğunu gösterir. Öğrenilen hop sayıları
DATA_DIR/sensor-hops.json'da tutulur.

Sonuç DATA_DIR/sensor.json dosyasına atomik yazılır; panel bunu okur.
"""
import ipaddress
import json
import os
import socket
import struct
import time
from collections import Counter

from . import config

INTERVAL = 5.0
CAPTURE = 1.5
MAX_PACKETS = 60000
TOP = 15
MAX_TRACK = 50000
MAX_BASELINE = 20000
FRESH_SECONDS = 20
ETH_P_ALL = 0x0003
PACKET_OUTGOING = 4
_SKIP_IF = ("lo", "veth", "docker", "br-", "virbr")
PROTO_NAMES = {6: "tcp", 17: "udp", 1: "icmp", 58: "icmp"}


def out_path():
    return config.DATA_DIR / "sensor.json"


def skip_iface(name: str) -> bool:
    return name == "lo" or name.startswith(_SKIP_IF[1:])


def parse_hdr(pkt: bytes) -> tuple[str, str, bool, int, bool] | None:
    """Ağ katmanı paketi -> (protokol, kaynak ip, salt SYN mi, TTL/hop limit, ACK'li TCP mi)."""
    if len(pkt) < 20:
        return None
    ver = pkt[0] >> 4
    if ver == 4:
        ihl = (pkt[0] & 0x0F) * 4
        proto = pkt[9]
        ttl = pkt[8]
        src = socket.inet_ntop(socket.AF_INET, pkt[12:16])
        frag_off = struct.unpack_from("!H", pkt, 6)[0] & 0x1FFF
        l4 = ihl if frag_off == 0 else None
    elif ver == 6:
        if len(pkt) < 40:
            return None
        proto = pkt[6]
        ttl = pkt[7]
        src = socket.inet_ntop(socket.AF_INET6, pkt[8:24])
        l4 = 40
    else:
        return None
    name = PROTO_NAMES.get(proto, "other")
    syn = ack = False
    if name == "tcp" and l4 is not None and len(pkt) >= l4 + 14:
        flags = pkt[l4 + 13]
        syn = (flags & 0x12) == 0x02  # SYN var, ACK yok
        ack = bool(flags & 0x10) and not flags & 0x02
    return name, src, syn, ttl, ack


def parse_ip(pkt: bytes) -> tuple[str, str, bool] | None:
    """Ağ katmanı paketi -> (protokol, kaynak ip, salt SYN mi). Tanınmayan paket için None."""
    h = parse_hdr(pkt)
    return None if h is None else h[:3]


def hops(ttl: int) -> int:
    """Gönderenin başlangıç TTL'ini (32/64/128/255) tahmin edip yoldaki yönlendirici sayısını verir."""
    for start in (32, 64, 128, 255):
        if ttl <= start:
            return start - ttl
    return 0


_BOGON_NETS = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "192.0.0.0/24", "192.0.2.0/24",
    "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/3",
    "::/128", "::1/128", "2001:db8::/32", "ff00::/8")]
_LAN_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7",
                                                "fe80::/10")]


def is_bogon(ip: str) -> bool:
    """İnternetten asla gelmemesi gereken (ayrılmış, belgelendirme, çok noktaya yayın) kaynak.

    Yerel ağ aralıkları (10/8, 192.168/16, fc00::/7 …) sahte sayılmaz: sağlayıcı ağ geçidi ya da
    aynı ağdaki makineler bu adreslerden gelebilir.
    """
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return True
    if a.version == 6 and a.ipv4_mapped:
        a = a.ipv4_mapped
    if any(a in n for n in _LAN_NETS if n.version == a.version):
        return False
    return any(a in n for n in _BOGON_NETS if n.version == a.version) or not a.is_global


def _rx_totals() -> tuple[int, int]:
    rx_b = rx_p = 0
    try:
        with open("/proc/net/dev") as f:
            lines = f.read().splitlines()[2:]
    except OSError:
        return 0, 0
    for line in lines:
        name, _, rest = line.partition(":")
        name = name.strip()
        if not rest or skip_iface(name):
            continue
        fields = rest.split()
        rx_b += int(fields[0])
        rx_p += int(fields[1])
    return rx_b, rx_p


class Window:
    """Bir yakalama penceresinin sayaçları (soketten bağımsız, test edilebilir)."""

    def __init__(self):
        self.pkts: Counter = Counter()
        self.bytes: Counter = Counter()
        self.src: dict[str, Counter] = {"tcp": Counter(), "udp": Counter(), "icmp": Counter(),
                                        "other": Counter(), "syn": Counter()}
        self.src_bytes: Counter = Counter()
        self.captured = 0
        self.captured_bytes = 0
        # Sahte adres ipuçları: sel paketlerinde kaynak başına TTL aralığı ve tüm selin TTL dağılımı.
        self.ttl: dict[str, list[int]] = {}
        self.flood_ttl: Counter = Counter()
        # Kurulu TCP (ACK'li) paketler el sıkışma gerektirir, kaynağı gerçektir: hop sayısını öğren.
        self.learn: dict[str, int] = {}

    def add(self, pkt: bytes) -> None:
        parsed = parse_hdr(pkt)
        if parsed is None:
            return
        name, src, syn, ttl, ack = parsed
        n = len(pkt)
        self.captured += 1
        self.captured_bytes += n
        self.pkts[name] += 1
        self.bytes[name] += n
        self.src[name][src] += 1
        self.src_bytes[src] += n
        if syn:
            self.pkts["syn"] += 1
            self.src["syn"][src] += 1
        if ack:
            self.learn[src] = hops(ttl)
        elif syn or name != "tcp":
            self.flood_ttl[ttl] += 1
            t = self.ttl.get(src)
            if t is None:
                if len(self.ttl) < MAX_TRACK:
                    self.ttl[src] = [ttl, ttl, 1]
            else:
                t[0], t[1], t[2] = min(t[0], ttl), max(t[1], ttl), t[2] + 1

    def spoof_reason(self, ip: str, baseline: dict | None = None) -> str:
        """Bu kaynağın sahte olabileceğine dair en güçlü kanıt; yoksa boş metin."""
        if is_bogon(ip):
            return "ayrılmış adres (bogon)"
        t = self.ttl.get(ip)
        if t and t[2] >= 4 and t[1] - t[0] > 3:
            return f"TTL tutarsız ({t[0]}-{t[1]})"
        if t and baseline and ip in baseline:
            seen = hops(t[0])
            if abs(seen - baseline[ip]) > 2:
                return f"hop sayısı uyuşmuyor ({seen}, olağan {baseline[ip]})"
        return ""

    def spoof_verdict(self) -> dict:
        flood_src = set()
        for k in ("udp", "icmp", "other", "syn"):
            flood_src.update(self.src[k])
        distinct = len(flood_src)
        total = sum(self.flood_ttl.values())
        top_ttl, top_n = self.flood_ttl.most_common(1)[0] if total else (0, 0)
        share = top_n / total if total else 0.0
        verdict = ""
        if distinct >= 200 and share >= 0.8:
            verdict = "Binlerce farklı adres aynı TTL ile geliyor: tek noktadan sahte adresli sel"
        elif distinct >= 1000:
            verdict = "Çok sayıda farklı kaynak: adresler büyük olasılıkla sahte"
        return {"verdict": verdict, "distinct": distinct, "ttl_share": round(share, 3), "ttl_top": top_ttl}

    def result(self, seconds: float, real_pkts: int | None = None, real_bytes: int | None = None,
               baseline: dict | None = None) -> dict:
        seconds = max(seconds, 0.001)
        # Çekirdek bu aralıkta daha çok paket aldıysa (yakalayamadıklarımız), oranı koruyarak ölçekle.
        scale = 1.0
        if real_pkts and self.captured and real_pkts > self.captured:
            scale = real_pkts / self.captured
        bscale = 1.0
        if real_bytes and self.captured_bytes and real_bytes > self.captured_bytes:
            bscale = real_bytes / self.captured_bytes

        def pps(v: float) -> float:
            return round(v * scale / seconds, 1)

        def mbps(v: float) -> float:
            return round(v * bscale * 8 / 1e6 / seconds, 3)

        top = {}
        for name, counter in self.src.items():
            top[name] = [[ip, pps(n), mbps(self.src_bytes[ip]) if name != "syn" else 0.0,
                          "" if name == "tcp" else self.spoof_reason(ip, baseline)]
                         for ip, n in counter.most_common(TOP)]
        return {
            "ts": time.time(), "window": round(seconds, 3), "captured": self.captured,
            "scale": round(scale, 3),
            "proto": {k: {"pps": pps(self.pkts[k]), "mbps": mbps(self.bytes[k])}
                      for k in ("tcp", "udp", "icmp", "other")},
            "syn_pps": pps(self.pkts["syn"]),
            "sources": {k: len(v) for k, v in self.src.items()},
            "spoof": self.spoof_verdict(),
            "top": top,
        }


def baseline_path():
    return config.DATA_DIR / "sensor-hops.json"


def load_baseline() -> dict[str, int]:
    try:
        data = json.loads(baseline_path().read_text())
        return {str(k): int(v) for k, v in data.items()} if isinstance(data, dict) else {}
    except (OSError, ValueError, TypeError):
        return {}


def learn(baseline: dict[str, int], seen: dict[str, int]) -> None:
    """Gerçek bağlantılardan öğrenilen hop sayılarını ekler; en eskiler atılarak sınırda tutulur."""
    for ip, h in seen.items():
        baseline.pop(ip, None)
        baseline[ip] = h
    while len(baseline) > MAX_BASELINE:
        baseline.pop(next(iter(baseline)))


def save_baseline(baseline: dict[str, int]) -> None:
    config.DATA_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = baseline_path().with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(baseline, f, separators=(",", ":"))
    os.replace(tmp, baseline_path())


def capture_once(seconds: float = CAPTURE, limit: int = MAX_PACKETS, baseline: dict | None = None) -> dict:
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(ETH_P_ALL))
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
        w = Window()
        b0, p0 = _rx_totals()
        start = time.monotonic()
        end = start + seconds
        while w.captured < limit:
            left = end - time.monotonic()
            if left <= 0:
                break
            sock.settimeout(left)
            try:
                pkt, addr = sock.recvfrom(128)  # yalnızca başlık; yük okunmaz
            except socket.timeout:
                break
            if addr[2] == PACKET_OUTGOING or skip_iface(addr[0]):
                continue
            w.add(pkt)
        elapsed = time.monotonic() - start
        b1, p1 = _rx_totals()
        result = w.result(elapsed, real_pkts=p1 - p0, real_bytes=b1 - b0, baseline=baseline)
        if baseline is not None:
            learn(baseline, w.learn)
        return result
    finally:
        sock.close()


def write(result: dict) -> None:
    config.DATA_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = out_path().with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(result, f, separators=(",", ":"))
    os.replace(tmp, out_path())


def read() -> dict:
    """Panel tarafı. {"state": yok|eski|hazır, "data": ...}; asla hata fırlatmaz."""
    try:
        data = json.loads(out_path().read_text())
    except (OSError, ValueError):
        return {"state": "yok", "data": None}
    if not isinstance(data, dict) or not isinstance(data.get("ts"), (int, float)):
        return {"state": "yok", "data": None}
    age = max(time.time() - data["ts"], 0)
    if age > FRESH_SECONDS:
        return {"state": "eski", "data": data, "age": int(age)}
    for name, rows in (data.get("top") or {}).items():
        clean = []
        for row in rows if isinstance(rows, list) else []:
            try:
                why = str(row[3])[:80] if len(row) > 3 and isinstance(row[3], str) else ""
                clean.append([str(ipaddress.ip_address(row[0])), float(row[1]), float(row[2]), why])
            except (ValueError, TypeError, IndexError):
                continue
        data["top"][name] = clean
    sp = data.get("spoof") if isinstance(data.get("spoof"), dict) else {}
    data["spoof"] = {"verdict": str(sp.get("verdict", ""))[:160], "distinct": _num(sp.get("distinct")),
                     "ttl_share": _num(sp.get("ttl_share")), "ttl_top": _num(sp.get("ttl_top"))}
    return {"state": "hazır", "data": data, "age": int(age)}


def _num(v) -> float:
    return float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else 0.0


def run() -> int:
    failed = False
    baseline = load_baseline()
    rounds = 0
    while True:
        started = time.monotonic()
        try:
            write(capture_once(baseline=baseline))
            rounds += 1
            if rounds % 12 == 0:  # dakikada bir
                save_baseline(baseline)
            failed = False
        except PermissionError:
            print("sensor: CAP_NET_RAW yetkisi yok (systemd AmbientCapabilities=CAP_NET_RAW gerekir)", flush=True)
            return 1
        except Exception as exc:  # noqa: BLE001 - algılayıcı ölmemeli
            if not failed:
                print(f"sensor: örnekleme hatası: {exc.__class__.__name__}: {exc}", flush=True)
            failed = True
        time.sleep(max(INTERVAL - (time.monotonic() - started), 0.5))
