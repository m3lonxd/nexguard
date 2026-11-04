"""Paket algılayıcı: UDP, ICMP ve TCP SYN sellerinin kaynaklarını örnekler.

/proc yalnızca TCP bağlantı tablosunu verir; bağlantısız trafiğin (UDP, ICMP) ve el sıkışmayı
tamamlamayan SYN'lerin kaynağı orada görünmez. Bu süreç ayrı çalışır ve yalnızca CAP_NET_RAW
yetkisiyle bir AF_PACKET soketi açar (panelin kendisi ayrıcalıksız kalır).

Her INTERVAL saniyede CAPTURE saniyelik bir örnek alır, gelen paketlerin yalnızca IP başlığını
okur (yük okunmaz, kaydedilmez), protokol ve kaynak IP başına sayar. Çekirdeğin o aralıkta
gerçekte aldığı paket sayısı /proc/net/dev'den okunup örnek buna göre ölçeklenir; yoğun selde
Python her paketi yakalayamasa da dağılım doğru kalır.

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
FRESH_SECONDS = 20
ETH_P_ALL = 0x0003
PACKET_OUTGOING = 4
_SKIP_IF = ("lo", "veth", "docker", "br-", "virbr")
PROTO_NAMES = {6: "tcp", 17: "udp", 1: "icmp", 58: "icmp"}


def out_path():
    return config.DATA_DIR / "sensor.json"


def skip_iface(name: str) -> bool:
    return name == "lo" or name.startswith(_SKIP_IF[1:])


def parse_ip(pkt: bytes) -> tuple[str, str, bool] | None:
    """Ağ katmanı paketi -> (protokol, kaynak ip, salt SYN mi). Tanınmayan paket için None."""
    if len(pkt) < 20:
        return None
    ver = pkt[0] >> 4
    if ver == 4:
        ihl = (pkt[0] & 0x0F) * 4
        proto = pkt[9]
        src = socket.inet_ntop(socket.AF_INET, pkt[12:16])
        frag_off = struct.unpack_from("!H", pkt, 6)[0] & 0x1FFF
        l4 = ihl if frag_off == 0 else None
    elif ver == 6:
        if len(pkt) < 40:
            return None
        proto = pkt[6]
        src = socket.inet_ntop(socket.AF_INET6, pkt[8:24])
        l4 = 40
    else:
        return None
    name = PROTO_NAMES.get(proto, "other")
    syn = False
    if name == "tcp" and l4 is not None and len(pkt) >= l4 + 14:
        syn = (pkt[l4 + 13] & 0x12) == 0x02  # SYN var, ACK yok
    return name, src, syn


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

    def add(self, pkt: bytes) -> None:
        parsed = parse_ip(pkt)
        if parsed is None:
            return
        name, src, syn = parsed
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

    def result(self, seconds: float, real_pkts: int | None = None, real_bytes: int | None = None) -> dict:
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
            top[name] = [[ip, pps(n), mbps(self.src_bytes[ip]) if name != "syn" else 0.0]
                         for ip, n in counter.most_common(TOP)]
        return {
            "ts": time.time(), "window": round(seconds, 3), "captured": self.captured,
            "scale": round(scale, 3),
            "proto": {k: {"pps": pps(self.pkts[k]), "mbps": mbps(self.bytes[k])}
                      for k in ("tcp", "udp", "icmp", "other")},
            "syn_pps": pps(self.pkts["syn"]),
            "sources": {k: len(v) for k, v in self.src.items()},
            "top": top,
        }


def capture_once(seconds: float = CAPTURE, limit: int = MAX_PACKETS) -> dict:
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
        return w.result(elapsed, real_pkts=p1 - p0, real_bytes=b1 - b0)
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
                clean.append([str(ipaddress.ip_address(row[0])), float(row[1]), float(row[2])])
            except (ValueError, TypeError, IndexError):
                continue
        data["top"][name] = clean
    return {"state": "hazır", "data": data, "age": int(age)}


def run() -> int:
    failed = False
    while True:
        started = time.monotonic()
        try:
            write(capture_once())
            failed = False
        except PermissionError:
            print("sensor: CAP_NET_RAW yetkisi yok (systemd AmbientCapabilities=CAP_NET_RAW gerekir)", flush=True)
            return 1
        except Exception as exc:  # noqa: BLE001 - algılayıcı ölmemeli
            if not failed:
                print(f"sensor: örnekleme hatası: {exc.__class__.__name__}: {exc}", flush=True)
            failed = True
        time.sleep(max(INTERVAL - (time.monotonic() - started), 0.5))
