import base64
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from fastapi.testclient import TestClient

from llaverito.app import create_app
from llaverito.config import Settings
from llaverito.models import User
from llaverito.security import hash_password

ADMIN_EMAIL = "admin@vicentelopez.gov.ar"
ADMIN_PASSWORD = "correct horse battery"
CSRF = {"X-Requested-With": "llaverito"}


def make_settings(tmp_path, **overrides) -> Settings:
    return Settings(
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        master_key=base64.urlsafe_b64encode(os.urandom(32)).decode(),
        public_hosts="testserver",
        _env_file=None,
        **overrides,
    )


class Env:
    def __init__(self, app):
        self.app = app
        self.rt = app.state.rt
        self.client = TestClient(app, base_url="http://testserver", headers=CSRF)

    def add_user(self, email, role, password="another long password"):
        with self.rt.session() as s:
            s.add(User(email=email, name=email, password_hash=hash_password(password), role=role))
        return password

    def login(self, email=ADMIN_EMAIL, password=ADMIN_PASSWORD) -> TestClient:
        c = TestClient(self.app, base_url="http://testserver", headers=CSRF)
        r = c.post("/api/auth/login", json={"email": email, "password": password})
        assert r.status_code == 200, r.text
        return c

    def mcp(self, token, tool, arguments=None, expect_error=False):
        """Llama a una tool MCP por HTTP (modo stateless con respuestas JSON)."""
        r = self.client.post(
            "/mcp",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json, text/event-stream",
                "Content-Type": "application/json",
            },
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": tool, "arguments": arguments or {}},
            },
        )
        assert r.status_code == 200, r.text
        result = r.json()["result"]
        text = "".join(c["text"] for c in result["content"] if c["type"] == "text")
        if expect_error:
            assert result.get("isError"), result
            return text
        assert not result.get("isError"), text
        return result.get("structuredContent") or json.loads(text)


@pytest.fixture
def env(tmp_path):
    app = create_app(make_settings(tmp_path, allow_private_networks=True))
    with TestClient(app):  # ejecuta el lifespan (session manager de MCP)
        e = Env(app)
        with e.rt.session() as s:
            s.add(User(email=ADMIN_EMAIL, name="Admin", password_hash=hash_password(ADMIN_PASSWORD), role="admin"))
        yield e


@pytest.fixture
def strict_env(tmp_path):
    """Igual que env pero sin el atajo de desarrollo: loopback bloqueado."""
    app = create_app(make_settings(tmp_path, allow_private_networks=False))
    with TestClient(app):
        e = Env(app)
        with e.rt.session() as s:
            s.add(User(email=ADMIN_EMAIL, name="Admin", password_hash=hash_password(ADMIN_PASSWORD), role="admin"))
        yield e


class _Echo(BaseHTTPRequestHandler):
    def _reply(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode() if length else ""
        if self.path.startswith("/redirect"):
            self.send_response(302)
            self.send_header("Location", "http://evil.example/steal")
            self.end_headers()
            return
        payload = json.dumps(
            {"method": self.command, "path": self.path, "headers": {k.lower(): v for k, v in self.headers.items()}, "body": body}
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = do_POST = do_PUT = do_DELETE = _reply

    def log_message(self, *args):
        pass


@pytest.fixture
def echo_server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Echo)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


@pytest.fixture
def admin(env):
    return env.login()


@pytest.fixture
def folder(admin):
    r = admin.post("/api/folders", json={"name": "infra", "description": "Servidores"})
    assert r.status_code == 201, r.text
    return r.json()
