import asyncio
import json
import threading

import asyncssh
import pytest

from test_mcp import new_agent

PASSWORD = "ssh-pass-9988776655"
USER_KEY = asyncssh.generate_private_key("ssh-ed25519")


class _Server(asyncssh.SSHServer):
    def begin_auth(self, username):
        return True

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        return username == "deploy" and password == PASSWORD

    def public_key_auth_supported(self):
        return True

    def validate_public_key(self, username, key):
        return username == "deploy" and key.export_public_key() == USER_KEY.export_public_key()


async def _handle(process):
    # Un servidor "malo": devuelve la contraseña en la salida para probar la redacción.
    process.stdout.write(f"ran:{process.command} pw={PASSWORD}\n")
    process.exit(0)


@pytest.fixture
def ssh_server():
    host_key = asyncssh.generate_private_key("ssh-ed25519")
    loop = asyncio.new_event_loop()
    started = threading.Event()
    box = {}

    async def start():
        srv = await asyncssh.create_server(
            _Server, "127.0.0.1", 0, server_host_keys=[host_key], process_factory=_handle
        )
        box["port"] = srv.sockets[0].getsockname()[1]
        box["srv"] = srv
        started.set()

    def run():
        asyncio.set_event_loop(loop)
        loop.run_until_complete(start())
        loop.run_forever()

    t = threading.Thread(target=run, daemon=True)
    t.start()
    assert started.wait(10)
    yield box["port"], host_key
    loop.call_soon_threadsafe(box["srv"].close)
    loop.call_soon_threadsafe(loop.stop)


def make_ssh_cred(admin, folder, port, *, ctype="ssh_password", name="srv", allowed=("uptime", "echo *"), sensitive=False):
    secret = {"password": PASSWORD} if ctype == "ssh_password" else {"private_key": USER_KEY.export_private_key().decode()}
    r = admin.post(
        "/api/credentials",
        json={
            "folder_id": folder["id"],
            "name": name,
            "type": ctype,
            "meta": {"host": "127.0.0.1", "port": port, "username": "deploy", "allowed_commands": list(allowed)},
            "secret": secret,
            "sensitive": sensitive,
        },
    )
    assert r.status_code == 201, r.text
    return r.json()


def pin(admin, cred_id):
    scan = admin.post(f"/api/credentials/{cred_id}/scan-host-key")
    assert scan.status_code == 200, scan.text
    assert scan.json()["fingerprint"].startswith("SHA256:")
    r = admin.post(f"/api/credentials/{cred_id}/pin-host-key", json={"host_key": scan.json()["host_key"]})
    assert r.status_code == 200, r.text


def test_ssh_refuses_until_host_key_is_pinned(env, admin, folder, ssh_server):
    port, _ = ssh_server
    make_ssh_cred(admin, folder, port)
    token = new_agent(admin, [{"folder_id": folder["id"]}])
    err = env.mcp(token, "ssh_exec", {"credential": "cred://infra/srv", "command": "uptime"}, expect_error=True)
    assert "clave de host" in err


@pytest.mark.parametrize("ctype", ["ssh_password", "ssh_key"])
def test_ssh_exec_allowed_command_redacts_output(env, admin, folder, ssh_server, ctype):
    port, _ = ssh_server
    cred = make_ssh_cred(admin, folder, port, ctype=ctype)
    pin(admin, cred["id"])
    token = new_agent(admin, [{"folder_id": folder["id"]}])
    out = env.mcp(token, "ssh_exec", {"credential": "cred://infra/srv", "command": "echo hola"})
    assert out["exit_status"] == 0
    assert out["stdout"].startswith("ran:echo hola")
    if ctype == "ssh_password":  # con clave privada, la contraseña del servidor no es un secreto guardado
        assert PASSWORD not in json.dumps(out)
        assert "[REDACTED]" in out["stdout"]


def test_ssh_unlisted_command_needs_approval(env, admin, folder, ssh_server):
    port, _ = ssh_server
    cred = make_ssh_cred(admin, folder, port)
    pin(admin, cred["id"])
    token = new_agent(admin, [{"folder_id": folder["id"]}])
    args = {"credential": "cred://infra/srv", "command": "echo hola; rm -rf /"}  # el comodín no cubre metacaracteres
    pending = env.mcp(token, "ssh_exec", args)
    assert pending["status"] == "approval_required"
    admin.post(f"/api/approvals/{pending['approval_id']}/decide", json={"approve": True})
    out = env.mcp(token, "ssh_exec", {**args, "approval_id": pending["approval_id"]})
    assert out["exit_status"] == 0


def test_ssh_wrong_host_key_is_rejected_before_sending_credentials(env, admin, folder, ssh_server):
    port, _ = ssh_server
    cred = make_ssh_cred(admin, folder, port)
    impostor = asyncssh.generate_private_key("ssh-ed25519").export_public_key().decode().split()
    admin.post(f"/api/credentials/{cred['id']}/pin-host-key", json={"host_key": f"{impostor[0]} {impostor[1]}"})
    token = new_agent(admin, [{"folder_id": folder["id"]}])
    err = env.mcp(token, "ssh_exec", {"credential": "cred://infra/srv", "command": "uptime"}, expect_error=True)
    assert "Falló la ejecución SSH" in err
    assert PASSWORD not in err
    entries = admin.get("/api/audit").json()
    assert any(e["action"] == "ssh_exec" and e["outcome"] == "error" for e in entries)


def test_changing_ssh_target_unpins_host_key(admin, folder, ssh_server):
    port, _ = ssh_server
    cred = make_ssh_cred(admin, folder, port)
    pin(admin, cred["id"])
    meta = {**cred["meta"], "host": "10.0.0.5"}
    r = admin.patch(f"/api/credentials/{cred['id']}", json={"meta": meta})
    assert r.json()["meta"]["host_key"] == ""
