import importlib
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def load_app(tmp_path, monkeypatch):
    monkeypatch.setenv("AWG_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("AWG_ENABLE_POLLER", "0")
    import app
    return importlib.reload(app)


def test_parse_wg_dump_marks_recent_peer_online(tmp_path, monkeypatch):
    app = load_app(tmp_path, monkeypatch)
    now = int(time.time())
    dump = "server_private\tserver_public\t8727\toff\n" + \
        f"peer_pub\tpsk\t1.2.3.4:5555\t10.8.0.2/32\t{now-30}\t1024\t2048\t25\n"

    peers = app.parse_wg_dump(dump, now_ts=now, online_threshold=180)

    assert peers == [{
        "public_key": "peer_pub",
        "endpoint": "1.2.3.4:5555",
        "allowed_ips": "10.8.0.2/32",
        "latest_handshake": now - 30,
        "transfer_rx": 1024,
        "transfer_tx": 2048,
        "online": True,
        "last_seen_at": app.datetime.fromtimestamp(now - 30).isoformat(timespec="seconds"),
    }]


def test_parse_wg_dump_marks_old_or_missing_handshake_offline(tmp_path, monkeypatch):
    app = load_app(tmp_path, monkeypatch)
    now = 1000
    dump = "server_private\tserver_public\t8727\toff\npeer_old\tpsk\t(none)\t10.8.0.3/32\t700\t1\t2\t25\npeer_new\tpsk\t(none)\t10.8.0.4/32\t0\t3\t4\t25\n"

    peers = app.parse_wg_dump(dump, now_ts=now, online_threshold=180)

    assert [p["online"] for p in peers] == [False, False]
    assert peers[0]["endpoint"] == ""


def test_compute_counter_delta_handles_reset(tmp_path, monkeypatch):
    app = load_app(tmp_path, monkeypatch)
    assert app.compute_counter_delta(100, 150) == 50
    assert app.compute_counter_delta(100, 20) == 20


def test_update_client_stat_accumulates_totals_and_handles_counter_reset(tmp_path, monkeypatch):
    app = load_app(tmp_path, monkeypatch)
    server = {"id": "s1", "created_at": app.now(), "updated_at": app.now()}
    client = {"id": "c1", "server_id": "s1", "pubkey": "p", "created_at": app.now(), "updated_at": app.now()}
    app.SERVERS["s1"] = server
    app.CLIENTS.append(client)
    app.persist()
    first = {"public_key": "p", "endpoint": "e", "allowed_ips": "10.0.0.2/32", "latest_handshake": 10, "transfer_rx": 100, "transfer_tx": 200, "online": True, "last_seen_at": "t1"}
    second = dict(first, transfer_rx=150, transfer_tx=250, last_seen_at="t2")
    reset = dict(first, transfer_rx=10, transfer_tx=20, last_seen_at="t3")

    app.update_client_stat(server, client, first)
    app.update_client_stat(server, client, second)
    row = app.update_client_stat(server, client, reset)

    assert row["total_rx"] == 160
    assert row["total_tx"] == 270
    assert row["last_rx"] == 10
    assert row["last_tx"] == 20


def test_resolve_root_ssh_key_to_mounted_ssh_dir(tmp_path, monkeypatch):
    app = load_app(tmp_path, monkeypatch)
    monkeypatch.setattr(app.os.path, "exists", lambda path: path == "/ssh/id_ed25519")
    assert app.resolve_ssh_key_path("/root/.ssh/id_ed25519") == "/ssh/id_ed25519"


def test_public_from_private_matches_generated_keypair(tmp_path, monkeypatch):
    app = load_app(tmp_path, monkeypatch)
    priv, pub = app.generate_keypair()
    assert app.public_from_private(priv) == pub



def test_detected_server_from_conf_uses_address_and_listen_port(tmp_path, monkeypatch):
    app = load_app(tmp_path, monkeypatch)
    base = {
        "name": "admrus",
        "host": "138.16.227.27",
        "ssh_user": "root",
        "ssh_port": 22,
        "ssh_key": "/ssh/id_ed25519",
        "endpoint": "",
    }
    conf = """[Interface]
PrivateKey = x
Address = 10.9.5.0/24
ListenPort = 9727
DNS = 9.9.9.9
"""

    detected = app.build_detected_server(base, "2.0", conf)

    assert detected["version"] == "2.0"
    assert detected["container"] == "amnezia-awg2"
    assert detected["interface"] == "awg0"
    assert detected["wg_port"] == 9727
    assert detected["subnet"] == "10.9.5.0/24"
    assert detected["dns"] == "9.9.9.9"
    assert detected["endpoint"] == "138.16.227.27"


def test_detected_server_without_dns_keeps_safe_default(tmp_path, monkeypatch):
    app = load_app(tmp_path, monkeypatch)
    base = {"name": "admrus", "host": "1.2.3.4"}
    conf = "[Interface]\nAddress = 10.8.7.1/24\nListenPort = 8727\n"

    detected = app.build_detected_server(base, "1.5", conf)

    assert detected["subnet"] == "10.8.7.0/24"
    assert detected["wg_port"] == 8727
    assert detected["dns"] == "1.1.1.1,8.8.8.8"

