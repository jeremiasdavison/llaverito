"""Simula la API AD municipal: v1 (POST /login, POST /gruposUser, JWT HS256) y v2 (GET /empleados/{usuario})."""

import base64
import hashlib
import hmac
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

JWT_KEY = b"clave-compartida-de-prueba"
V2_KEY = "v2-key-de-prueba"


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def make_jwt(payload_text: str, key: bytes = JWT_KEY, alg: str = "HS256") -> str:
    """Como jsonwebtoken con un string: el payload es el texto JSON tal cual."""
    head = b64(json.dumps({"alg": alg}).encode())
    body = b64(payload_text.encode())
    sig = b"" if alg == "none" else hmac.new(key, f"{head}.{body}".encode(), hashlib.sha256).digest()
    return f"{head}.{body}.{b64(sig)}"


class FakeAd:
    def __init__(self):
        self.users: dict[str, dict] = {}
        self.active: set[str] = set()  # sAMAccountName que la v2 considera activos
        self.calls: list[tuple[str, str]] = []
        self.sign_key = JWT_KEY
        self.alg = "HS256"
        self.fail_groups = False
        self.login_status = 200
        self.v2_down = False
        self.impersonate: str | None = None  # devuelve la identidad de otro usuario
        self.server: ThreadingHTTPServer | None = None

    def add(self, email, password, cn, groups=(), department="MODERNIZACION"):
        sam = email.split("@")[0]
        self.users[email] = {"password": password, "sam": sam, "cn": cn, "groups": list(groups), "department": department}
        self.active.add(sam)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}"

    def start(self):
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def _send(self, status, text, ctype="text/html"):
                body = text.encode()
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _body(self):
                n = int(self.headers.get("Content-Length") or 0)
                return json.loads(self.rfile.read(n) or b"{}")

            def do_POST(self):
                data = self._body()
                usuario, clave = data.get("usuario", ""), data.get("clave", "")
                outer.calls.append((self.path, usuario))
                u = outer.users.get(usuario)
                ok = bool(u) and u["password"] == clave
                if self.path == "/login":
                    if outer.login_status != 200:
                        return self._send(outer.login_status, "")
                    if not ok:
                        text = '{"login": false}'
                    else:
                        who = outer.users.get(outer.impersonate, u) if outer.impersonate else u
                        email = outer.impersonate or usuario
                        text = json.dumps(
                            {"dn": "CN=X,DC=vicentelopez", "userPrincipalName": email, "sAMAccountName": who["sam"],
                             "employeeID": "1", "cn": who["cn"], "department": who["department"],
                             "physicalDeliveryOfficeName": "SUBSEC.INNOVACION"}
                        )
                    return self._send(200, make_jwt(text, outer.sign_key, outer.alg))
                if self.path == "/gruposUser":
                    if outer.fail_groups:
                        return self._send(500, "")
                    text = json.dumps(u["groups"]) if ok else json.dumps({"error": "bad credentials"})
                    return self._send(200, make_jwt(text, outer.sign_key, outer.alg))
                self._send(404, "")

            def do_GET(self):
                outer.calls.append((self.path, ""))
                if not self.path.startswith("/empleados/"):
                    return self._send(404, "")
                if self.headers.get("x-api-key") != V2_KEY:
                    return self._send(401, "{}", "application/json")
                if outer.v2_down:
                    return self._send(503, "{}", "application/json")
                sam = self.path.rsplit("/", 1)[1]
                if sam in outer.active:
                    return self._send(200, json.dumps({"sAMAccountName": sam}), "application/json")
                self._send(404, "{}", "application/json")

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self

    def stop(self):
        self.server.shutdown()
