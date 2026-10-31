"""Genel güvenlik / OPSEC denetim kontrolleri (yalnızca okur, hiçbir şeyi değiştirmez).

Her kontrol bir `Host` alır ve `Finding` listesi döndürür; testlerde `Host` sahte olanla değişir.
Düzeltme önerileri yalnızca metindir, panel komut çalıştırmaz.
"""
import json
import os
import re
import stat
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path

from . import config

SEVERITY_WEIGHT = {"high": 15, "medium": 7, "low": 2}
SEVERITY_ORDER = ["high", "medium", "low", "info", "ok"]


@dataclass
class Finding:
    id: str
    severity: str  # high | medium | low | info | ok
    title: str
    detail: str = ""
    fix: str = ""


class Host:
    """Sistem erişimi; tek noktada toplanır ki testler sahteleyebilsin."""

    def read(self, path: str) -> str | None:
        try:
            return Path(path).read_text(errors="replace")
        except OSError:
            return None

    def mode(self, path: str) -> int | None:
        try:
            return stat.S_IMODE(os.stat(path).st_mode)
        except OSError:
            return None

    def listdir(self, path: str) -> list[str]:
        try:
            return sorted(os.listdir(path))
        except OSError:
            return []

    def run(self, argv: list[str], timeout: int = 15) -> tuple[int, str]:
        try:
            p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
            return p.returncode, p.stdout
        except (OSError, subprocess.TimeoutExpired):
            return -1, ""

    def home(self) -> str:
        return str(Path.home())


# --- SSH -----------------------------------------------------------------

def sshd_effective(h: Host) -> dict[str, str] | None:
    """sshd'nin 'ilk değer kazanır' kuralına göre Match öncesi etkin ayarlar."""
    main = h.read("/etc/ssh/sshd_config")
    if main is None:
        return None
    cfg: dict[str, str] = {}

    def parse(text: str, depth: int = 0) -> None:
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            key = parts[0].lower()
            val = parts[1].strip() if len(parts) > 1 else ""
            if key == "match":
                return
            if key == "include" and depth < 3:
                pat = val.split()[0]
                d = os.path.dirname(pat)
                for name in h.listdir(d):
                    if re.fullmatch(re.escape(os.path.basename(pat)).replace(r"\*", ".*"), name):
                        sub = h.read(os.path.join(d, name))
                        if sub:
                            parse(sub, depth + 1)
                continue
            cfg.setdefault(key, val.lower())

    parse(main)
    return cfg


def check_ssh(h: Host) -> list[Finding]:
    cfg = sshd_effective(h)
    if cfg is None:
        return [Finding("ssh.unreadable", "info", "sshd_config okunamadı",
                        "SSH sunucusu kurulu olmayabilir ya da dosya okunamıyor.")]
    out: list[Finding] = []
    root = cfg.get("permitrootlogin", "prohibit-password")
    if root == "yes":
        out.append(Finding("ssh.root", "high", "SSH ile root girişi açık",
                           "Parola sızarsa doğrudan tam yetki.",
                           "PermitRootLogin no  (sonra: sudo systemctl reload ssh)"))
    else:
        out.append(Finding("ssh.root", "ok", f"SSH root girişi kısıtlı ({root})"))
    if cfg.get("passwordauthentication", "yes") == "yes":
        out.append(Finding("ssh.password", "medium", "SSH parola ile girişe açık",
                           "Brute-force hedefi olur; anahtar tabanlı giriş önerilir.",
                           "Önce anahtarınızı ekleyip test edin, sonra: PasswordAuthentication no"))
    else:
        out.append(Finding("ssh.password", "ok", "SSH parola girişi kapalı"))
    if cfg.get("permitemptypasswords", "no") == "yes":
        out.append(Finding("ssh.empty", "high", "SSH boş parolaya izin veriyor", "", "PermitEmptyPasswords no"))
    tries = cfg.get("maxauthtries", "6")
    if tries.isdigit() and int(tries) > 4:
        out.append(Finding("ssh.tries", "low", f"MaxAuthTries yüksek ({tries})", "", "MaxAuthTries 3"))
    if cfg.get("x11forwarding", "no") == "yes":
        out.append(Finding("ssh.x11", "low", "X11 yönlendirme açık", "Gerekmiyorsa saldırı yüzeyini büyütür.",
                           "X11Forwarding no"))
    if cfg.get("port", "22") == "22":
        out.append(Finding("ssh.port", "info", "SSH varsayılan portta (22)",
                           "Güvenlik sağlamaz ama otomatik tarama gürültüsünü azaltır; asıl önlem anahtar + engelleme."))
    return out


# --- Portlar ---------------------------------------------------------------

RISKY_PORTS = {
    21: ("medium", "FTP"), 23: ("high", "Telnet"), 111: ("medium", "rpcbind"),
    139: ("medium", "NetBIOS"), 445: ("medium", "SMB"), 2375: ("high", "Docker API (şifresiz)"),
    3306: ("high", "MySQL"), 5432: ("high", "PostgreSQL"), 5900: ("high", "VNC"),
    6379: ("high", "Redis"), 9200: ("high", "Elasticsearch"), 11211: ("high", "Memcached"),
    27017: ("high", "MongoDB"),
}
_PUBLIC_ADDRS = {"0.0.0.0", "*", "[::]", "::"}


def parse_listeners(ss_output: str) -> list[tuple[str, str, int]]:
    """`ss -H -tuln` çıktısından (proto, adres, port); benzersiz."""
    seen: set[tuple[str, str, int]] = set()
    for line in ss_output.splitlines():
        cols = line.split()
        if len(cols) < 5:
            continue
        addr, _, port = cols[4].rpartition(":")
        if not port.isdigit():
            continue
        seen.add((cols[0], addr.split("%")[0], int(port)))
    return sorted(seen, key=lambda t: (t[2], t[0]))


def check_ports(h: Host) -> list[Finding]:
    rc, out = h.run(["ss", "-H", "-tuln"])
    if rc != 0:
        return [Finding("ports.unavailable", "info", "Açık portlar listelenemedi", "`ss` komutu çalışmadı.")]
    listeners = parse_listeners(out)
    public = [(p, a, port) for p, a, port in listeners if a in _PUBLIC_ADDRS]
    findings: list[Finding] = []
    for port in sorted({port for _, _, port in public if port in RISKY_PORTS}):
        sev, name = RISKY_PORTS[port]
        findings.append(Finding(f"ports.risky.{port}", sev, f"{name} dışarıya açık (port {port})",
                                "Bu servis internete açık olmamalı.",
                                f"Servisi 127.0.0.1'e bağlayın veya firewall'dan {port} portunu kapatın."))
    ports_txt = ", ".join(sorted({f"{port}/{p[:3]}" for p, _, port in public}, key=lambda x: int(x.split("/")[0])))
    findings.append(Finding("ports.public", "info", f"Dışarıya dinleyen {len({(p, port) for p, _, port in public})} port",
                            ports_txt or "Yok"))
    if not any(f.severity in ("high", "medium") for f in findings):
        findings.append(Finding("ports.ok", "ok", "Riskli bilinen servis dışarıya açık değil"))
    return findings


# --- Firewall ---------------------------------------------------------------

def check_firewall(h: Host) -> list[Finding]:
    rc, out = h.run(["nft", "list", "ruleset"])
    if rc == 0:
        return ([Finding("fw.nft", "ok", "nftables kuralları var")] if "chain" in out else
                [Finding("fw.nft", "high", "nftables kural kümesi boş", "Hiçbir paket filtrelenmiyor.",
                         "Temel bir input zinciri tanımlayın (ssh + gerekli portlar, gerisi drop).")])
    rc, out = h.run(["ufw", "status"])
    if rc == 0:
        low = out.lower()
        if "inactive" in low or "etkin değil" in low:
            return [Finding("fw.ufw", "high", "UFW kurulu ama kapalı", "", "sudo ufw allow ssh && sudo ufw enable")]
        return [Finding("fw.ufw", "ok", "UFW etkin")]
    rc, out = h.run(["iptables", "-S"])
    if rc == 0:
        rules = [l for l in out.splitlines() if not l.startswith("-P")]
        policy_drop = any(l.startswith("-P INPUT DROP") for l in out.splitlines())
        if not rules and not policy_drop:
            return [Finding("fw.ipt", "medium", "iptables'ta kural yok, INPUT politikası ACCEPT", "",
                            "Firewall kurun (ufw/nftables).")]
        return [Finding("fw.ipt", "ok", "iptables kuralları var")]
    for svc in ("ufw", "firewalld", "nftables"):
        if h.run(["systemctl", "is-active", svc])[1].strip() == "active":
            return [Finding("fw.svc", "info", f"{svc} servisi etkin", "Kural içeriği root olmadan doğrulanamadı.")]
    return [Finding("fw.unknown", "info", "Firewall durumu doğrulanamadı",
                    "Kural listesini okumak için root gerekir; panel ayrıcalıksız çalışır. "
                    "Elle kontrol: sudo nft list ruleset  /  sudo ufw status")]


# --- Kullanıcılar ve yetkiler -------------------------------------------------

def check_users(h: Host) -> list[Finding]:
    out: list[Finding] = []
    passwd = h.read("/etc/passwd") or ""
    extra_root, empty = [], []
    for line in passwd.splitlines():
        f = line.split(":")
        if len(f) < 7:
            continue
        if f[2] == "0" and f[0] != "root":
            extra_root.append(f[0])
        if f[1] == "":
            empty.append(f[0])
    if extra_root:
        out.append(Finding("users.uid0", "high", "root dışında UID 0 hesabı var", ", ".join(extra_root),
                           "Hesabı inceleyin; gerekmiyorsa kaldırın."))
    if empty:
        out.append(Finding("users.empty", "high", "Parolası boş hesap", ", ".join(empty), "sudo passwd -l <hesap>"))
    shadow = h.read("/etc/shadow")
    if shadow is not None:
        blank = [l.split(":")[0] for l in shadow.splitlines() if len(l.split(":")) > 1 and l.split(":")[1] == ""]
        if blank:
            out.append(Finding("users.shadow_empty", "high", "shadow'da boş parola alanı", ", ".join(blank),
                               "sudo passwd -l <hesap>"))
    nopass: list[str] = []
    for path in ["/etc/sudoers"] + [f"/etc/sudoers.d/{n}" for n in h.listdir("/etc/sudoers.d")]:
        for line in (h.read(path) or "").splitlines():
            if "NOPASSWD" in line and not line.strip().startswith("#"):
                nopass.append(f"{os.path.basename(path)}: {line.strip()}")
    if nopass:
        out.append(Finding("users.nopasswd", "medium", "Parolasız sudo kuralı", "; ".join(nopass[:5]),
                           "Gerekmiyorsa NOPASSWD'yi kaldırın (visudo)."))
    if not out:
        out.append(Finding("users.ok", "ok", "Kullanıcı hesaplarında belirgin sorun yok"))
    return out


# --- Dosya izinleri ------------------------------------------------------------

def check_permissions(h: Host) -> list[Finding]:
    out: list[Finding] = []
    m = h.mode("/etc/shadow")
    if m is not None and m & 0o007:
        out.append(Finding("perm.shadow", "high", f"/etc/shadow herkese okunabilir ({m:o})", "",
                           "sudo chmod 640 /etc/shadow"))
    for path in ("/etc/passwd", "/etc/ssh/sshd_config", "/etc/sudoers"):
        m = h.mode(path)
        if m is not None and m & 0o002:
            out.append(Finding(f"perm.ww.{path}", "high", f"{path} herkese yazılabilir ({m:o})", "",
                               f"sudo chmod go-w {path}"))
    home = h.home()
    m = h.mode(home)
    if m is not None and m & 0o007:
        out.append(Finding("perm.home", "low", f"Ev dizini diğer kullanıcılara açık ({m:o})",
                           "Paylaşımlı sunucuda dosyalar okunabilir.", "chmod 750 ~"))
    ssh_dir = os.path.join(home, ".ssh")
    m = h.mode(ssh_dir)
    if m is not None and m & 0o077:
        out.append(Finding("perm.sshdir", "medium", f"~/.ssh izinleri gevşek ({m:o})", "", "chmod 700 ~/.ssh"))
    for name in h.listdir(ssh_dir):
        if name.startswith("id_") and not name.endswith(".pub"):
            km = h.mode(os.path.join(ssh_dir, name))
            if km is not None and km & 0o077:
                out.append(Finding(f"perm.key.{name}", "high", f"Özel anahtar gevşek izinli: {name} ({km:o})",
                                   "", f"chmod 600 ~/.ssh/{name}"))
    sock = h.mode("/var/run/docker.sock")
    if sock is not None and sock & 0o002:
        out.append(Finding("perm.docker", "high", "docker.sock herkese yazılabilir",
                           "Docker erişimi = root eşdeğeri.", "sudo chmod 660 /var/run/docker.sock"))
    if not out:
        out.append(Finding("perm.ok", "ok", "Kritik dosya izinleri uygun"))
    return out


SUID_COMMON = {
    "passwd", "su", "sudo", "mount", "umount", "chsh", "chfn", "gpasswd", "newgrp", "pkexec",
    "fusermount", "fusermount3", "ssh-keysign", "polkit-agent-helper-1", "dbus-daemon-launch-helper",
    "chage", "expiry", "unix_chkpwd", "crontab", "at", "ping", "ping6", "newuidmap", "newgidmap",
    "mount.nfs", "mount.cifs", "pam_timestamp_check", "Xorg.wrap", "ntfs-3g", "bwrap", "sudoedit",
    "vmware-user-suid-wrapper", "ksu", "ssh-agent", "chrome-sandbox", "pppd", "mount.fuse", "fusermount-glusterfs",
}


def check_suid(h: Host) -> list[Finding]:
    rc, out = h.run(["nice", "-n", "19", "find", "/usr", "/bin", "/sbin", "/opt", "-xdev",
                     "-perm", "-4000", "-type", "f"], timeout=60)
    if rc not in (0, 1):  # find erişilemeyen dizinlerde 1 döner, çıktı yine geçerli
        return [Finding("suid.unavailable", "info", "SUID taraması yapılamadı")]
    unknown = sorted(p for p in out.splitlines() if p and os.path.basename(p) not in SUID_COMMON)
    if unknown:
        return [Finding("suid.unknown", "low", f"Alışılmadık {len(unknown)} SUID dosyası",
                        "; ".join(unknown[:8]) + (" ..." if len(unknown) > 8 else ""),
                        "Her birini inceleyin: dpkg -S <yol>; gerekmiyorsa sudo chmod u-s <yol>")]
    return [Finding("suid.ok", "ok", "SUID dosyaları bilinen/standart olanlardan oluşuyor")]


# --- Güncellemeler -----------------------------------------------------------

def check_updates(h: Host) -> list[Finding]:
    rc, out = h.run(["apt", "list", "--upgradable"], timeout=30)
    out_findings: list[Finding] = []
    if rc == 0:
        lines = [l for l in out.splitlines() if "upgradable" in l]
        sec = [l for l in lines if "-security" in l]
        n = len(lines)
        if sec:
            out_findings.append(Finding("upd.security", "high", f"{len(sec)} güvenlik güncellemesi bekliyor",
                                        "; ".join(l.split("/")[0] for l in sec[:8]),
                                        "sudo apt update && sudo apt upgrade"))
        elif n > 20:
            out_findings.append(Finding("upd.many", "medium", f"{n} güncelleme bekliyor", "", "sudo apt upgrade"))
        elif n:
            out_findings.append(Finding("upd.some", "low", f"{n} güncelleme bekliyor", "", "sudo apt upgrade"))
        else:
            out_findings.append(Finding("upd.ok", "ok", "Bekleyen güncelleme yok (önbelleğe göre)"))
        if h.run(["dpkg", "-s", "unattended-upgrades"])[0] != 0:
            out_findings.append(Finding("upd.auto", "low", "Otomatik güvenlik güncellemesi kurulu değil", "",
                                        "sudo apt install unattended-upgrades"))
        return out_findings
    rc, out = h.run(["dnf", "-q", "check-update", "--security"], timeout=60)
    if rc == 100:
        return [Finding("upd.security", "high", "Güvenlik güncellemesi bekliyor", "", "sudo dnf upgrade --security")]
    if rc == 0:
        return [Finding("upd.ok", "ok", "Bekleyen güvenlik güncellemesi yok")]
    return [Finding("upd.unknown", "info", "Güncelleme durumu belirlenemedi", "apt/dnf bulunamadı ya da çalışmadı.")]


# --- Çekirdek sertleştirme -----------------------------------------------------

# (anahtar, kabul eden fonksiyon, öneri değeri, önem, açıklama)
SYSCTL_RULES = [
    ("net/ipv4/tcp_syncookies", lambda v: v == "1", "1", "medium", "SYN flood'a karşı syncookies kapalı"),
    ("net/ipv4/conf/all/accept_redirects", lambda v: v == "0", "0", "medium", "ICMP redirect kabul ediliyor"),
    ("net/ipv4/conf/all/send_redirects", lambda v: v == "0", "0", "low", "ICMP redirect gönderiliyor"),
    ("net/ipv4/conf/all/accept_source_route", lambda v: v == "0", "0", "medium", "Source routing kabul ediliyor"),
    ("net/ipv4/conf/all/rp_filter", lambda v: v in ("1", "2"), "1", "low", "Ters yol filtresi (IP spoofing) kapalı"),
    ("net/ipv4/icmp_echo_ignore_broadcasts", lambda v: v == "1", "1", "low", "Broadcast ping yanıtlanıyor (smurf)"),
    ("kernel/randomize_va_space", lambda v: v == "2", "2", "medium", "ASLR tam etkin değil"),
    ("kernel/kptr_restrict", lambda v: v in ("1", "2"), "2", "low", "Çekirdek adresleri sızabilir"),
    ("kernel/dmesg_restrict", lambda v: v == "1", "1", "low", "dmesg herkese açık"),
    ("kernel/yama/ptrace_scope", lambda v: v in ("1", "2", "3"), "1", "low", "ptrace kısıtlı değil"),
    ("fs/protected_symlinks", lambda v: v == "1", "1", "low", "Symlink koruması kapalı"),
    ("fs/suid_dumpable", lambda v: v == "0", "0", "low", "SUID süreçlerin core dump'ı açık"),
]


def check_sysctl(h: Host) -> list[Finding]:
    bad: list[Finding] = []
    seen = 0
    for key, ok, want, sev, why in SYSCTL_RULES:
        val = h.read(f"/proc/sys/{key}")
        if val is None:
            continue
        seen += 1
        if not ok(val.strip()):
            name = key.replace("/", ".")
            bad.append(Finding(f"sysctl.{name}", sev, f"{why} ({name}={val.strip()})", "",
                               f"echo '{name} = {want}' | sudo tee /etc/sysctl.d/99-nexguard.conf -a && sudo sysctl --system"))
    if seen and not bad:
        return [Finding("sysctl.ok", "ok", "Çekirdek ağ/bellek sertleştirmeleri uygun")]
    return bad


# --- Servisler, panel kendisi ----------------------------------------------------

def check_services(h: Host) -> list[Finding]:
    out: list[Finding] = []
    guards = [s for s in ("fail2ban", "crowdsec") if h.run(["systemctl", "is-active", s])[1].strip() == "active"]
    if guards:
        out.append(Finding("svc.guard", "ok", f"Brute-force koruması etkin ({', '.join(guards)})"))
    else:
        out.append(Finding("svc.guard", "medium", "Brute-force koruması (fail2ban/crowdsec) çalışmıyor",
                           "Tekrarlayan başarısız girişler engellenmiyor.", "sudo apt install fail2ban"))
    rc, val = h.run(["timedatectl", "show", "-p", "NTPSynchronized", "--value"])
    if rc == 0 and val.strip() == "no":
        out.append(Finding("svc.ntp", "low", "Saat senkronize değil", "Log zamanları ve TLS doğrulaması bozulur.",
                           "sudo timedatectl set-ntp true"))
    return out


def check_panel(h: Host) -> list[Finding]:
    out: list[Finding] = []
    if config.HOST not in ("127.0.0.1", "::1", "localhost"):
        out.append(Finding("panel.bind", "high", f"Panel yerel adres dışında dinliyor ({config.HOST})",
                           "Yönetim arayüzü internete açık olmamalı.",
                           "NEXGUARD_HOST=127.0.0.1; erişimi nginx (TLS + IP kısıtı) veya SSH tüneliyle verin."))
    m = h.mode(str(config.DATA_DIR))
    if m is not None and m & 0o077:
        out.append(Finding("panel.datadir", "medium", f"Panel veri dizini gevşek izinli ({m:o})",
                           "Oturum anahtarı ve bildirim token'ları burada.", f"chmod 700 {config.DATA_DIR}"))
    if not out:
        out.append(Finding("panel.ok", "ok", "Panel yerel adrese bağlı, veri dizini korumalı"))
    return out


CHECKS = [check_ssh, check_ports, check_firewall, check_users, check_permissions, check_suid,
          check_updates, check_sysctl, check_services, check_panel]


def score(findings: list[Finding]) -> int:
    return max(0, 100 - sum(SEVERITY_WEIGHT.get(f.severity, 0) for f in findings))


def grade(s: int) -> str:
    return "A" if s >= 90 else "B" if s >= 75 else "C" if s >= 60 else "D" if s >= 40 else "F"


def run_all(h: Host | None = None) -> dict:
    h = h or Host()
    findings: list[Finding] = []
    for fn in CHECKS:
        try:
            findings.extend(fn(h))
        except Exception as exc:  # noqa: BLE001 - tek kontrol hatası denetimi durdurmasın
            findings.append(Finding(f"error.{fn.__name__}", "info", f"{fn.__name__} çalışmadı", exc.__class__.__name__))
    findings.sort(key=lambda f: SEVERITY_ORDER.index(f.severity))
    s = score(findings)
    return {"score": s, "grade": grade(s), "findings": [asdict(f) for f in findings]}


def dumps(result: dict) -> str:
    return json.dumps(result, ensure_ascii=False)
