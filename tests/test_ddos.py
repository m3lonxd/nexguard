from nexguard.modules import ddos

NET1 = "h1\nh2\n  eth0: 1000000 1000 0 0 0 0 0 0 500 5 0 0 0 0 0 0\n    lo: 999 9 0 0 0 0 0 0 999 9 0 0 0 0 0 0\n"
NET2 = "h1\nh2\n  eth0: 26000000 51000 0 0 0 0 0 0 500 5 0 0 0 0 0 0\n    lo: 999 9 0 0 0 0 0 0 999 9 0 0 0 0 0 0\n"
HDR = "  sl  local_address rem_address   st\n"


def tcp(entries):
    # entries: (remote_hex_ip_le, state)
    return HDR + "".join(f"   0: 0100007F:0050 {ip}:C350 {st:02X} 0:0 00:0 0 0 0\n" for ip, st in entries)


def test_decode_ip():
    assert ddos.decode_ip("0100007F") == "127.0.0.1"
    assert ddos.decode_ip("0A00A8C0") == "192.168.0.10"
    assert ddos.decode_ip("00000000000000000000000001000000") == "::1"


def test_parse_net_dev_skips_loopback():
    assert ddos.parse_net_dev(NET1) == (1000000, 1000)


def test_parse_proc_tcp_only_states_1_and_3():
    rows = ddos.parse_proc_tcp(tcp([("0A00A8C0", 1), ("0A00A8C0", 3), ("0A00A8C0", 10)]))
    assert rows == [(1, "192.168.0.10"), (3, "192.168.0.10")]


def test_evaluate_levels():
    th = {"syn_recv": (100, 500), "conn_per_ip": (150, 400), "rx_pps": (50000, 200000), "rx_mbps": (300, 800)}
    assert ddos.evaluate(ddos.Sample(0), th)[0] == 0
    assert ddos.evaluate(ddos.Sample(0, syn_recv=150), th)[0] == 1
    assert ddos.evaluate(ddos.Sample(0, rx_pps=300000), th)[0] == 2


def make_monitor(env):
    msgs = []
    return ddos.Monitor(notifier=msgs.append), msgs


TH = {"syn_recv": (100, 500), "conn_per_ip": (150, 400), "rx_pps": (50000, 200000), "rx_mbps": (300, 800)}


def test_rates_and_attack_needs_two_samples_then_recovers(env):
    mon, msgs = make_monitor(env)
    mon.tick(100.0, NET1, [HDR, HDR], None, TH)
    s = mon.tick(105.0, NET2, [HDR, HDR], None, TH)  # 50000 paket / 5 sn = 10000 pps; 25 MB*8/5 = 40 Mbit
    assert round(s.rx_pps) == 10000 and round(s.rx_mbps) == 40
    flood = tcp([("0A00A8C0", 3)] * 600)
    mon.tick(110.0, NET2, [flood, HDR], None, TH)
    assert mon.level == 0 and not msgs  # tek örnek yetmez
    mon.tick(115.0, NET2, [flood, HDR], None, TH)
    assert mon.level == 2 and len(msgs) == 1 and "SALDIRI" in msgs[0] and "192.168.0.10" in msgs[0]
    mon.tick(120.0, NET2, [flood, HDR], None, TH)
    assert len(msgs) == 1  # tekrar bildirim yok
    for i in range(ddos.RECOVER_SAMPLES):
        mon.tick(125.0 + i, NET2, [HDR, HDR], None, TH)
    assert mon.level == 0 and len(msgs) == 2 and "indi" in msgs[1]


def test_counter_reset_does_not_go_negative(env):
    mon, _ = make_monitor(env)
    mon.tick(0.0, NET2, [HDR, HDR], None, TH)
    s = mon.tick(5.0, NET1, [HDR, HDR], None, TH)
    assert s.rx_pps == 0 and s.rx_mbps == 0


def test_loopback_clients_not_counted(env):
    mon, _ = make_monitor(env)
    s = mon.tick(0.0, NET1, [tcp([("0100007F", 1)] * 5), HDR], None, TH)
    assert s.top_ips == [] and s.established == 5
