"""Genel Bakış için /proc tabanlı, bağımlılıksız sistem bilgisi."""
import os
import platform
import shutil
from pathlib import Path


def _meminfo() -> dict[str, int]:
    out: dict[str, int] = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        key, _, rest = line.partition(":")
        out[key] = int(rest.split()[0]) * 1024
    return out


def snapshot() -> dict:
    mem = _meminfo()
    total, avail = mem.get("MemTotal", 0), mem.get("MemAvailable", 0)
    disk = shutil.disk_usage("/")
    uptime = float(Path("/proc/uptime").read_text().split()[0])
    load1, load5, load15 = os.getloadavg()
    return {
        "hostname": platform.node(),
        "kernel": platform.release(),
        "uptime_seconds": int(uptime),
        "load": (round(load1, 2), round(load5, 2), round(load15, 2)),
        "cpus": os.cpu_count() or 1,
        "mem_total": total,
        "mem_used": total - avail,
        "disk_total": disk.total,
        "disk_used": disk.used,
    }


def human_bytes(n: int) -> str:
    size = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{n} B"


def human_uptime(seconds: int) -> str:
    d, rem = divmod(seconds, 86400)
    h, rem = divmod(rem, 3600)
    m = rem // 60
    return f"{d} g {h} sa {m} dk" if d else f"{h} sa {m} dk"
