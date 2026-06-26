import importlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def load_app(tmp_path, monkeypatch):
    monkeypatch.setenv("WG_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("WG_ENABLE_POLLER", "0")
    import app
    return importlib.reload(app)


def test_default_server_is_vanilla_wireguard_wg_easy(tmp_path, monkeypatch):
    app = load_app(tmp_path, monkeypatch)

    server = app.normalize_server({"name": "msk", "host": "1.2.3.4"})

    assert server["version"] == "wireguard"
    assert server["container"] == "wg-easy"
    assert server["interface"] == "wg0"
    assert server["config_path"] == "/etc/wireguard/wg0.conf"
    assert server["wg_port"] == 51820


def test_detect_wireguard_server_uses_wg_easy_config(tmp_path, monkeypatch):
    app = load_app(tmp_path, monkeypatch)
    conf = """[Interface]
PrivateKey = SERVER_PRIVATE
Address = 10.8.0.1/24
ListenPort = 51820
DNS = 1.1.1.1
"""
    calls = []

    def fake_cexec(server, command, timeout=25):
        calls.append((server, command))
        if server["container"] == "wg-easy" and "/etc/wireguard/wg0.conf" in command:
            return {"ok": True, "out": conf, "err": "", "code": 0}
        return {"ok": False, "out": "", "err": "missing", "code": 1}

    monkeypatch.setattr(app, "cexec", fake_cexec)

    detected = app.detect_wireguard_servers({"name": "msk", "host": "1.2.3.4"})

    assert len(detected) == 1
    assert detected[0]["version"] == "wireguard"
    assert detected[0]["container"] == "wg-easy"
    assert detected[0]["interface"] == "wg0"
    assert detected[0]["config_path"] == "/etc/wireguard/wg0.conf"
    assert detected[0]["subnet"] == "10.8.0.0/24"
    assert detected[0]["wg_port"] == 51820


def test_client_config_does_not_include_awg_obfuscation_params(tmp_path, monkeypatch):
    app = load_app(tmp_path, monkeypatch)
    server = app.normalize_server({"name": "s", "host": "vpn.example.com", "dns": "1.1.1.1"})
    client = {"privkey": "CLIENT_PRIVATE", "address": "10.8.0.2/24", "preshared_key": "PSK", "allowed_ips": "0.0.0.0/0"}
    sp = {"pubkey": "SERVER_PUBLIC", "params": {"Jc": "4", "S1": "128"}}

    cfg = app.build_client_conf(server, client, sp)

    assert "Jc =" not in cfg
    assert "S1 =" not in cfg
    assert "Endpoint = vpn.example.com:51820" in cfg
    assert "PublicKey = SERVER_PUBLIC" in cfg
