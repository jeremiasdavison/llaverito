import json
from contextlib import asynccontextmanager
from pathlib import Path

import anyio.to_thread
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from .api import router
from .broker import Broker, Unauthorized
from .config import Settings, get_settings
from .mcp_server import build_mcp
from .runtime import build_runtime

STATIC_DIR = Path(__file__).parent / "static"

CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
)


class SecurityMiddleware:
    """Cabeceras de seguridad y autenticación temprana (401) del endpoint MCP."""

    def __init__(self, app, broker: Broker):
        self.app = app
        self.broker = broker

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        if scope["path"].rstrip("/") == "/mcp":
            headers = {k.decode().lower(): v.decode() for k, v in scope["headers"]}
            auth = headers.get("authorization", "")
            token = auth[7:].strip() if auth.lower().startswith("bearer ") else None
            try:
                await anyio.to_thread.run_sync(lambda: self._check(token))
            except Unauthorized as exc:
                body = json.dumps({"error": "unauthorized", "message": str(exc)}).encode()
                await send(
                    {
                        "type": "http.response.start",
                        "status": 401,
                        "headers": [
                            (b"content-type", b"application/json"),
                            (b"www-authenticate", b'Bearer realm="llaverito"'),
                            (b"content-length", str(len(body)).encode()),
                        ],
                    }
                )
                await send({"type": "http.response.body", "body": body})
                return

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                hdrs = list(message.get("headers", []))
                hdrs += [
                    (b"content-security-policy", CSP.encode()),
                    (b"x-content-type-options", b"nosniff"),
                    (b"referrer-policy", b"no-referrer"),
                ]
                if self.broker.rt.settings.cookie_secure:
                    hdrs.append((b"strict-transport-security", b"max-age=63072000; includeSubDomains"))
                if scope["path"].startswith(("/api", "/mcp")):
                    hdrs.append((b"cache-control", b"no-store"))
                message = {**message, "headers": hdrs}
            await send(message)

        await self.app(scope, receive, send_with_headers)

    def _check(self, token: str | None) -> None:
        with self.broker.rt.session() as s:
            self.broker.authenticate(s, token)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    rt = build_runtime(settings)
    broker = Broker(rt)
    mcp = build_mcp(broker, settings)
    mcp_asgi = mcp.streamable_http_app()

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        async with mcp.session_manager.run():
            yield

    app = FastAPI(
        title="Llaverito",
        version="0.1.0",
        lifespan=lifespan,
        docs_url=None,  # la CSP bloquea Swagger y no hay motivo para exponer el esquema sin login
        redoc_url=None,
        openapi_url=None,
    )
    app.state.rt = rt
    app.state.broker = broker
    app.include_router(router)
    app.router.routes.extend(mcp_asgi.routes)  # expone POST /mcp
    app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="ui")
    app.add_middleware(SecurityMiddleware, broker=broker)
    return app
