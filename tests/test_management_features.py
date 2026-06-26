import importlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def load_app(tmp_path, monkeypatch):
    monkeypatch.setenv("WG_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("WG_ENABLE_POLLER", "0")
    import app
    return importlib.reload(app)


def test_password_hash_supports_secure_and_legacy_hashes(tmp_path, monkeypatch):
    app = load_app(tmp_path, monkeypatch)
    secure = app.make_password_hash("secret")
    assert secure.startswith("scrypt:") or secure.startswith("pbkdf2:")
    assert app.verify_password_hash(secure, "secret") is True
    assert app.verify_password_hash(secure, "wrong") is False
    assert app.verify_password_hash(app.hashlib.sha256(b"admin").hexdigest(), "admin") is True


def test_public_server_masks_ssh_password(tmp_path, monkeypatch):
    app = load_app(tmp_path, monkeypatch)
    server = app.normalize_server({"name": "s", "host": "1.2.3.4", "ssh_password": "supersecret"})
    public = app.public_server(server)
    assert public["has_ssh_password"] is True
    assert "ssh_password" not in public


def test_public_client_hides_private_key_but_keeps_status(tmp_path, monkeypatch):
    app = load_app(tmp_path, monkeypatch)
    client = {"id": "c", "name": "phone", "privkey": "PRIVATE", "pubkey": "PUBLIC", "preshared_key": "PSK"}
    public = app.public_client(client)
    assert public["has_privkey"] is True
    assert public["has_preshared_key"] is True
    assert "privkey" not in public
    assert "preshared_key" not in public
    assert public["pubkey"] == "PUBLIC"


def test_parse_client_conf_extracts_keys_and_public_from_private(tmp_path, monkeypatch):
    app = load_app(tmp_path, monkeypatch)
    priv, pub = app.generate_keypair()
    conf = f"""[Interface]
PrivateKey = {priv}
Address = 10.0.0.2/32
DNS = 1.1.1.1

[Peer]
PublicKey = SERVERPUB
PresharedKey = PSKVALUE
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = example.com:1234
"""
    parsed = app.parse_client_conf(conf)
    assert parsed["privkey"] == priv
    assert parsed["pubkey"] == pub
    assert parsed["address"] == "10.0.0.2/32"
    assert parsed["allowed_ips"] == "0.0.0.0/0, ::/0"
    assert parsed["preshared_key"] == "PSKVALUE"


def test_metadata_refresh_due_uses_timestamp_not_random(tmp_path, monkeypatch):
    app = load_app(tmp_path, monkeypatch)
    assert app.metadata_refresh_due({}) is True
    assert app.metadata_refresh_due({"last_metadata_refresh_at": app.now()}) is False
