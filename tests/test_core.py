import ipaddress

import pytest

from llaverito.audit import verify_chain
from llaverito.credtypes import ValidationFailure, validate_meta, validate_secret
from llaverito.crypto import Cipher
from llaverito.policy import Redactor, command_auto_allowed, host_allowed, ip_block_reason


def test_envelope_roundtrip_and_aad_binding():
    c = Cipher(b"k" * 32)
    wrapped, blob = c.encrypt(b"top secret", b"cred:1")
    assert b"top secret" not in blob
    assert c.decrypt(wrapped, blob, b"cred:1") == b"top secret"
    with pytest.raises(Exception):
        c.decrypt(wrapped, blob, b"cred:2")  # blob copiado a otra credencial
    with pytest.raises(Exception):
        Cipher(b"x" * 32).decrypt(wrapped, blob, b"cred:1")  # otra KEK


def test_same_plaintext_gives_different_ciphertext():
    c = Cipher(b"k" * 32)
    assert c.encrypt(b"a", b"x")[1] != c.encrypt(b"a", b"x")[1]


def test_host_allowlist():
    assert host_allowed("api.example.com", ["api.example.com"])
    assert host_allowed("API.example.com.", ["api.example.com"])
    assert host_allowed("a.example.com", ["*.example.com"])
    assert not host_allowed("example.com", ["*.example.com"])
    assert not host_allowed("evil-example.com", ["*.example.com"])
    assert not host_allowed("api.example.com.evil.io", ["api.example.com"])
    assert not host_allowed("anything", [])


@pytest.mark.parametrize(
    "ip,allow_private,dev,blocked",
    [
        ("127.0.0.1", True, False, True),
        ("169.254.169.254", True, False, True),
        ("::1", False, False, True),
        ("::ffff:127.0.0.1", True, False, True),
        ("10.1.2.3", False, False, True),
        ("10.1.2.3", True, False, False),
        ("8.8.8.8", False, False, False),
        ("127.0.0.1", False, True, False),
    ],
)
def test_ip_block(ip, allow_private, dev, blocked):
    reason = ip_block_reason(ipaddress.ip_address(ip), allow_private=allow_private, dev_override=dev)
    assert (reason is not None) == blocked


def test_command_allowlist_blocks_shell_injection():
    pats = ["uptime", "systemctl status *"]
    assert command_auto_allowed("uptime", pats)
    assert command_auto_allowed("systemctl status nginx", pats)
    assert not command_auto_allowed("systemctl status nginx; rm -rf /", pats)
    assert not command_auto_allowed("systemctl status $(reboot)", pats)
    assert not command_auto_allowed("whoami", pats)
    assert not command_auto_allowed("anything", [])
    assert command_auto_allowed("cat /etc/hosts | wc -l", ["*"])


def test_redactor_covers_encoded_variants():
    import base64
    from urllib.parse import quote

    secret = "s3cr3t/Tok+en=value"
    r = Redactor([secret])
    for variant in (
        secret,
        quote(secret, safe=""),
        base64.b64encode(secret.encode()).decode(),
        base64.urlsafe_b64encode(secret.encode()).decode().rstrip("="),
        secret.encode().hex(),
    ):
        assert secret not in r.text(f"x {variant} y") and variant not in r.text(f"x {variant} y")
    assert r.obj({"a": [f"pre{secret}post"]}) == {"a": ["pre[REDACTED]post"]}


def test_redactor_private_key_lines():
    key = "-----BEGIN KEY-----\nAAAAAAAAAAAAAAAAAAAAAAAA\n-----END KEY-----"
    out = Redactor([key]).text("leak: AAAAAAAAAAAAAAAAAAAAAAAA")
    assert "AAAA" not in out


def test_validation():
    assert validate_meta("bearer_token", {"allowed_hosts": ["API.example.com"]})["allowed_hosts"] == ["api.example.com"]
    with pytest.raises(ValidationFailure):
        validate_meta("bearer_token", {"allowed_hosts": ["https://x.com/path"]})
    with pytest.raises(ValidationFailure):
        validate_meta("bearer_token", {"unknown_field": 1})
    with pytest.raises(ValidationFailure):
        validate_meta("ssh_key", {"host": "h"})  # falta username
    with pytest.raises(ValidationFailure):
        validate_secret("api_key", {"secret": "abc"})  # muy corto
    with pytest.raises(ValidationFailure):
        validate_secret("ssh_key", {})
    assert validate_secret("ssh_key", {"private_key": "k"})["private_key"] == "k"


def test_audit_chain_detects_tampering(env, admin, folder):
    admin.post("/api/folders", json={"name": "otra"})
    assert admin.get("/api/audit/verify").json()["ok"] is True
    from sqlalchemy import text

    with env.rt.session() as s:
        s.execute(text("UPDATE audit_log SET outcome='denied' WHERE id = 2"))
    res = admin.get("/api/audit/verify").json()
    assert res["ok"] is False and res["broken_at"] == 2
    with env.rt.session() as s:
        assert verify_chain(s)["ok"] is False
