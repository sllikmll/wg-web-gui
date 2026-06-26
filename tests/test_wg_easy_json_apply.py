import importlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def load_app(tmp_path, monkeypatch):
    monkeypatch.setenv("WG_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("WG_ENABLE_POLLER", "0")
    import app
    return importlib.reload(app)


def test_apply_client_to_wg_easy_updates_wg0_json_not_conf(tmp_path, monkeypatch):
    app = load_app(tmp_path, monkeypatch)
    server = app.normalize_server({"id": "admger", "name": "admger", "host": "1.2.3.4"})
    client = {
        "id": "client1",
        "name": "phone",
        "privkey": "CLIENT_PRIV",
        "pubkey": "CLIENT_PUB",
        "preshared_key": "CLIENT_PSK",
        "address": "10.88.0.3/32",
    }
    wg_json = {"server": {"address": "10.88.0.1", "privateKey": "S", "publicKey": "SP"}, "clients": {}}
    calls = []

    def fake_cexec(s, command, timeout=25):
        calls.append(("cexec", command))
        if "cat /etc/wireguard/wg0.json" in command:
            return {"ok": True, "out": json.dumps(wg_json), "err": "", "code": 0}
        if "cat /etc/wireguard/wg0.conf" in command:
            return {"ok": True, "out": "[Interface]\nAddress = 10.88.0.1/24\n", "err": "", "code": 0}
        if "test -f /etc/wireguard/wg0.conf" in command:
            return {"ok": True, "out": "", "err": "", "code": 0}
        return {"ok": True, "out": "", "err": "", "code": 0}

    def fake_ssh_run(s, command, timeout=25):
        calls.append(("ssh", command))
        out = "true\n" if "docker inspect" in command else ""
        return {"ok": True, "out": out, "err": "", "code": 0}

    monkeypatch.setattr(app, "cexec", fake_cexec)
    monkeypatch.setattr(app, "ssh_run", fake_ssh_run)
    monkeypatch.setattr(app, "wait_for_peer", lambda s, pub, remove=False, timeout=25, delay=1.0: {"ok": True, "stage": "verify_add"})

    result = app.apply_client_to_server(server, client)

    assert result["ok"] is True
    assert result["stage"] == "verify_add"
    write_commands = [cmd for kind, cmd in calls if kind == "ssh" and "wg0.json" in cmd]
    assert write_commands, calls
    assert not any("base64 -d > /etc/wireguard/wg0.conf" in cmd for kind, cmd in calls if kind == "ssh")
    assert client["wg_easy_id"]


def test_remove_client_from_wg_easy_json_by_public_key(tmp_path, monkeypatch):
    app = load_app(tmp_path, monkeypatch)
    server = app.normalize_server({"id": "admger", "name": "admger", "host": "1.2.3.4"})
    client = {"id": "client1", "name": "phone", "pubkey": "CLIENT_PUB"}
    wg_json = {
        "server": {"address": "10.88.0.1", "privateKey": "S", "publicKey": "SP"},
        "clients": {
            "uuid1": {"id": "uuid1", "name": "phone", "privateKey": "P", "publicKey": "CLIENT_PUB", "preSharedKey": "PSK", "address": "10.88.0.3", "enabled": True},
            "uuid2": {"id": "uuid2", "name": "other", "privateKey": "P2", "publicKey": "OTHER", "preSharedKey": "PSK2", "address": "10.88.0.4", "enabled": True},
        },
    }
    written = {}

    def fake_cexec(s, command, timeout=25):
        if "cat /etc/wireguard/wg0.json" in command:
            return {"ok": True, "out": json.dumps(wg_json), "err": "", "code": 0}
        if "cat /etc/wireguard/wg0.conf" in command:
            return {"ok": True, "out": "[Interface]\nAddress = 10.88.0.1/24\n", "err": "", "code": 0}
        return {"ok": True, "out": "", "err": "", "code": 0}

    def fake_write_json(s, data):
        written.update(data)
        return {"ok": True, "out": "", "err": "", "code": 0}

    monkeypatch.setattr(app, "cexec", fake_cexec)
    monkeypatch.setattr(app, "write_wg_easy_json", fake_write_json)
    monkeypatch.setattr(app, "ssh_run", lambda s, command, timeout=25: {"ok": True, "out": "true\n" if "docker inspect" in command else "", "err": "", "code": 0})
    monkeypatch.setattr(app, "wait_for_peer", lambda s, pub, remove=False, timeout=25, delay=1.0: {"ok": True, "stage": "verify_remove"})

    result = app.apply_client_to_server(server, client, remove=True)

    assert result["ok"] is True
    assert "uuid1" not in written["clients"]
    assert "uuid2" in written["clients"]
