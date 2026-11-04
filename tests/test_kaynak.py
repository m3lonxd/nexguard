"""Sağlayıcıya süzme isteği, SMTP, RDAP kaynak araştırma ve abuse bildirimi."""
import json

from nexguard import abuse, db, mail, upstream
from tests.conftest import csrf_from, do_login

RDAP_SAMPLE = {
    "objectClassName": "ip network", "handle": "NET-198-51-100-0-1", "name": "EXAMPLE-NET",
    "startAddress": "198.51.100.0", "endAddress": "198.51.100.255", "country": "NL", "port43": "whois.ripe.net",
    "cidr0_cidrs": [{"v4prefix": "198.51.100.0", "length": 24}],
    "entities": [
        {"roles": ["registrant"], "vcardArray": ["vcard", [["version", {}, "text", "4.0"],
                                                            ["fn", {}, "text", "Example Hosting BV"]]],
         "entities": [{"roles": ["abuse"], "vcardArray": ["vcard", [
             ["fn", {}, "text", "Abuse desk"], ["email", {}, "text", "abuse@example.net"],
             ["email", {}, "text", "ABUSE@example.net"], ["email", {}, "text", "not an email"]]]}]},
    ],
}


def flood_sample(verdict=""):
    return {"proto": {"udp": {"mbps": 900.0, "pps": 80000}},
            "top": {"udp": [["198.51.100.7", 40000.0, 450.0, ""]], "icmp": [], "syn": [], "other": []},
            "spoof": {"verdict": verdict, "distinct": 3000, "ttl_share": 0.95, "ttl_top": 52}}


# --- mail ----------------------------------------------------------------------

def test_parse_emails_and_validate():
    assert mail.parse_emails("a@b.com, A@b.com; c@d.org") == (["a@b.com", "c@d.org"], None)
    assert mail.parse_emails("a@b.com nope")[1]
    assert mail.parse_emails(" ".join(f"u{i}@x.com" for i in range(4)), limit=3)[1]
    assert mail.parse_emails("") == ([], None)
    assert mail.validate("smtp.x.com", "587", "me@x.com", "starttls") is None
    assert mail.validate("bad host", "587", "me@x.com", "starttls")
    assert mail.validate("smtp.x.com", "70000", "me@x.com", "starttls")
    assert mail.validate("smtp.x.com", "587", "me", "starttls")
    assert mail.validate("smtp.x.com", "587", "me@x.com", "tls9")


def test_mail_send_unconfigured(env):
    try:
        mail.send(["a@b.com"], "s", "b")
    except RuntimeError as exc:
        assert "ayarlı değil" in str(exc)
    else:
        raise AssertionError("fırlatmalıydı")


# --- upstream --------------------------------------------------------------------

def test_should_alert_and_compose(env):
    assert upstream.should_alert(900, flood_sample()) == ""  # kapasite bilinmiyor, sahte değil
    db.set_setting("prov.link_mbps", "1000")
    assert "hat %90" in upstream.should_alert(900, flood_sample())
    assert upstream.should_alert(100, flood_sample()) == ""
    assert "sahte adresli" in upstream.should_alert(100, flood_sample("Binlerce farklı adres"))
    db.set_setting("prov.ip", "203.0.113.10")
    subject, body = upstream.compose("hat %90 dolu", 900, 80000, flood_sample("Binlerce farklı adres"))
    assert "203.0.113.10" in subject and "UDP 900 Mbit/sn" in body and "198.51.100.7" in body
    assert "RTBH" in body and "TTL=52" in body


def test_on_attack_opt_in_and_cooldown(env, monkeypatch):
    sent = []
    monkeypatch.setattr(upstream.threading, "Thread",
                        lambda target, args, **kw: type("T", (), {"start": lambda self: sent.append(args)})())
    db.set_setting("prov.link_mbps", "1000")
    assert not upstream.on_attack(950, 1, flood_sample())  # otomatik kapalı
    db.set_setting("prov.auto", "1")
    assert upstream.on_attack(950, 1, flood_sample())
    assert not upstream.on_attack(950, 1, flood_sample())  # 30 dk bekleme
    assert len(sent) == 1 and "hat %95" in sent[0][0]
    db.set_setting("prov.last_ts", "0")
    assert not upstream.on_attack(100, 1, flood_sample())  # gerekçe yok


def test_send_now_failure_retries_soon(env, monkeypatch):
    db.set_setting("prov.email", "noc@prov.net")
    for k, v in (("smtp.host", "smtp.x.com"), ("smtp.from", "me@x.com")):
        db.set_setting(k, v)

    def boom(*a, **kw):
        raise RuntimeError("SMTP hatası: X")
    monkeypatch.setattr(mail, "send", boom)
    out = upstream.send_now("test", 1, 1, None)
    assert out.startswith("Gönderilemedi")
    last = float(db.get_setting("prov.last_ts"))
    import time
    assert time.time() - last > upstream.COOLDOWN - 400  # ~5 dk sonra tekrar denenebilir
    monkeypatch.setattr(mail, "send", lambda *a, **kw: None)
    assert "gönderildi" in upstream.send_now("test", 1, 1, None, manual=True)
    assert "noc@prov.net" in db.get_setting("prov.last")


# --- abuse -----------------------------------------------------------------------

def test_parse_rdap():
    info = abuse.parse_rdap(RDAP_SAMPLE)
    assert info["network"] == "EXAMPLE-NET" and info["org"] == "Example Hosting BV"
    assert info["range"] == "198.51.100.0/24" and info["country"] == "NL"
    assert info["abuse"] == ["abuse@example.net"]  # tekrar ve geçersiz atıldı
    assert abuse.parse_rdap({})["abuse"] == []
    mnt = {"name": "X", "entities": [{"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "X-MNT"]]]}]}
    assert abuse.parse_rdap(mnt)["org"] == ""
    person = {"entities": [{"roles": ["registrant"], "vcardArray": ["vcard", [["kind", {}, "text", "individual"],
                                                                            ["fn", {}, "text", "Ad Soyad"]]]},
                           {"roles": ["administrative"], "vcardArray": ["vcard", [["fn", {}, "text", "Kişi"]]]}]}
    assert abuse.parse_rdap(person)["org"] == ""


def test_rdap_cache_and_errors(env):
    calls = []

    def fake(ip):
        calls.append(ip)
        return RDAP_SAMPLE
    assert abuse.rdap("8.8.8.8", fetch=fake)["network"] == "EXAMPLE-NET"
    assert abuse.rdap("8.8.8.8", fetch=fake)["network"] == "EXAMPLE-NET"
    assert calls == ["8.8.8.8"]
    assert json.loads(abuse.cache_path().read_text())["8.8.8.8"]["data"]["org"] == "Example Hosting BV"

    def broken(ip):
        raise OSError("ağ yok")
    assert "error" in abuse.rdap("9.9.9.9", fetch=broken)


def test_normalize_and_mentions():
    assert abuse.normalize("8.8.8.8") == "8.8.8.8"
    assert abuse.normalize("::ffff:8.8.8.8") == "8.8.8.8"
    assert abuse.normalize("10.0.0.1") is None and abuse.normalize("x") is None
    assert abuse._mentions("engel 1.2.3.4 (SYN)", "1.2.3.4")
    assert not abuse._mentions("engel 11.2.3.45", "1.2.3.4")
    assert not abuse._mentions("engel 1.2.3.45", "1.2.3.4")
    assert abuse._mentions("1.2.3.4.", "1.2.3.4")


def test_evidence_and_report(env):
    db.log_event("savunma", "warning", "Otomatik engel: 198.51.100.7 (UDP seli)")
    db.log_event("savunma", "warning", "Otomatik engel: 198.51.100.70 (UDP seli)")
    trap = [json.dumps({"eventid": "cowrie.login.failed", "src_ip": "198.51.100.7", "session": "s1",
                        "username": "root", "password": "123456", "timestamp": "2026-11-04T10:00:00Z"})]
    ev = abuse.evidence("198.51.100.7", flood_sample(), trap)
    assert len(ev["events"]) == 1 and ev["flood"][0]["pps"] == 40000.0
    assert ev["trap"] and ev["trap"][0]["password"] == "123456"
    subject, body = abuse.report("198.51.100.7", abuse.parse_rdap(RDAP_SAMPLE), ev, "203.0.113.10")
    assert "198.51.100.7" in subject and "EXAMPLE-NET" in body and "UDP flood" in body
    assert "password='123456'" in body and "203.0.113.10" in body


# --- rotalar ---------------------------------------------------------------------

def test_prov_and_smtp_routes(env):
    client, _ = env
    do_login(client)
    page = client.get("/m/savunma")
    assert page.status_code == 200 and "Hat doyuran saldırı" in page.text and 'style="' not in page.text
    tok = csrf_from(client, "/m/savunma")
    client.post("/m/savunma/prov", data={"csrf": tok, "link_mbps": "1000", "email": "noc@prov.net", "auto": "1"})
    assert db.get_setting("prov.auto") == "1" and db.get_setting("prov.email") == "noc@prov.net"
    client.post("/m/savunma/prov", data={"csrf": tok, "link_mbps": "1000", "email": "", "auto": "1"})
    assert "gerekir" in client.get("/m/savunma").text and db.get_setting("prov.email") == "noc@prov.net"
    client.post("/m/savunma/prov", data={"csrf": tok, "link_mbps": "x"})
    client.post("/m/savunma/prov", data={"csrf": tok, "link_mbps": "10", "ip": "10.0.0.1"})
    assert db.get_setting("prov.link_mbps") == "1000"
    client.post("/m/savunma/smtp", data={"csrf": tok, "host": "smtp.x.com", "port": "587", "user": "me",
                                         "password": "gizli-parola", "sender": "me@x.com", "tls": "starttls"})
    page = client.get("/m/savunma").text
    assert mail.status()["configured"] and "gizli-parola" not in page
    client.post("/m/savunma/smtp", data={"csrf": tok, "host": "smtp.x.com", "port": "587", "sender": "me@x.com",
                                         "tls": "starttls"})
    assert db.get_setting("smtp.pass") == "gizli-parola"  # boş parola eskisini silmez
    client.post("/m/savunma/smtp", data={"csrf": tok, "clear_smtp": "1"})
    assert not mail.status()["configured"] and db.get_setting("smtp.pass") is None


def test_kaynak_page_and_send(env, monkeypatch):
    client, _ = env
    assert client.get("/kaynak?ip=8.8.8.8").status_code == 303  # giriş zorunlu
    do_login(client)
    monkeypatch.setattr(abuse, "_fetch", lambda ip: RDAP_SAMPLE)
    monkeypatch.setattr(abuse, "rdns", lambda ip: "host.example.net")
    monkeypatch.setattr(abuse.rdap, "__defaults__", (lambda ip: RDAP_SAMPLE,))
    assert client.get("/kaynak").status_code == 200
    bad = client.get("/kaynak?ip=10.0.0.1").text
    assert "Genel" in bad
    page = client.get("/kaynak?ip=8.8.4.4")
    assert page.status_code == 200 and 'style="' not in page.text
    assert "Example Hosting BV" in page.text and "abuse@example.net" in page.text and "host.example.net" in page.text
    assert "SMTP" in page.text  # gönderim ayarlı değil uyarısı
    tok = csrf_from(client, "/kaynak?ip=8.8.4.4")
    got = []
    monkeypatch.setattr(mail, "send", lambda to, s, b, reply_to=None: got.append((to, s)))
    r = client.post("/m/savunma/kaynak/send", data={"csrf": tok, "ip": "8.8.4.4", "to": "abuse@example.net",
                                                    "subject": "Abuse report", "body": "text"})
    assert r.status_code == 303 and r.headers["location"] == "/kaynak?ip=8.8.4.4"
    assert got == [(["abuse@example.net"], "Abuse report")]
    client.post("/m/savunma/kaynak/send", data={"csrf": tok, "ip": "8.8.4.4", "to": "x", "subject": "s",
                                                "body": "b"})
    assert len(got) == 1


def test_tuzak_real_ssh(env, monkeypatch):
    from nexguard import checks
    from nexguard.modules import tuzak
    monkeypatch.setattr(checks, "sshd_effective", lambda h: {"passwordauthentication": "no", "port": "2200"})
    assert tuzak.real_ssh() == {"known": True, "password": False, "port": "2200"}
    monkeypatch.setattr(checks, "sshd_effective", lambda h: None)
    assert tuzak.real_ssh()["known"] is False
