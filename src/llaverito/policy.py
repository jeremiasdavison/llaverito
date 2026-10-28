"""Políticas del broker: hosts permitidos, protección SSRF, comandos SSH y redacción de salida."""

import asyncio
import base64
import fnmatch
import ipaddress
import json
import re
import socket
from typing import Any, Iterable
from urllib.parse import quote

import httpcore
import httpx


class PolicyDenied(Exception):
    """El broker rechaza la acción; el mensaje es seguro de mostrar al agente."""


# ---------------------------------------------------------------- hosts y SSRF


def host_allowed(host: str, patterns: Iterable[str]) -> bool:
    host = host.lower().rstrip(".")
    for p in patterns:
        if p.startswith("*."):
            suffix = p[1:]  # ".example.com"
            if host.endswith(suffix) and len(host) > len(suffix):
                return True
        elif host == p:
            return True
    return False


def ip_block_reason(ip: ipaddress._BaseAddress, *, allow_private: bool, dev_override: bool) -> str | None:
    """Devuelve el motivo por el que la IP está prohibida, o None si se puede usar."""
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
        return None if dev_override else f"dirección no permitida ({ip})"
    if ip.is_private and not allow_private:
        return f"red privada no habilitada para esta credencial ({ip})"
    return None


class _SafeBackend(httpcore.AsyncNetworkBackend):
    """Resuelve el nombre, valida cada IP y recién entonces conecta (evita DNS rebinding)."""

    def __init__(self, *, allow_private: bool, dev_override: bool):
        self._inner = httpcore.AnyIOBackend()
        self._allow_private = allow_private
        self._dev = dev_override

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        infos = await _resolve(host, port)
        last_error: Exception | None = None
        for ip_text in infos:
            ip = ipaddress.ip_address(ip_text)
            reason = ip_block_reason(ip, allow_private=self._allow_private, dev_override=self._dev)
            if reason:
                last_error = PolicyDenied(f"Destino bloqueado: {reason}")
                continue
            try:
                return await self._inner.connect_tcp(
                    ip_text, port, timeout=timeout, local_address=local_address, socket_options=socket_options
                )
            except Exception as exc:  # intenta con la siguiente IP
                last_error = exc
        raise last_error or PolicyDenied("No se pudo resolver el destino")

    async def connect_unix_socket(self, path, timeout=None, socket_options=None):
        raise PolicyDenied("Sockets unix no permitidos")

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


async def _resolve(host: str, port: int) -> list[str]:
    try:
        ipaddress.ip_address(host)
        return [host]
    except ValueError:
        pass
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    seen: list[str] = []
    for info in infos:
        addr = info[4][0]
        if addr not in seen:
            seen.append(addr)
    return seen


class _Stream(httpx.AsyncByteStream):
    def __init__(self, stream):
        self._stream = stream

    async def __aiter__(self):
        async for chunk in self._stream:
            yield chunk

    async def aclose(self) -> None:
        await self._stream.aclose()


class SafeTransport(httpx.AsyncBaseTransport):
    def __init__(self, *, allow_private: bool, dev_override: bool):
        self._pool = httpcore.AsyncConnectionPool(
            network_backend=_SafeBackend(allow_private=allow_private, dev_override=dev_override),
            max_connections=4,
        )

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        req = httpcore.Request(
            method=request.method,
            url=httpcore.URL(
                scheme=request.url.raw_scheme,
                host=request.url.raw_host,
                port=request.url.port,
                target=request.url.raw_path,
            ),
            headers=request.headers.raw,
            content=request.stream,
            extensions=request.extensions,
        )
        resp = await self._pool.handle_async_request(req)
        return httpx.Response(
            status_code=resp.status,
            headers=resp.headers,
            stream=_Stream(resp.stream),
            extensions=resp.extensions,
        )

    async def aclose(self) -> None:
        await self._pool.aclose()


# ---------------------------------------------------------------- comandos SSH

_SHELL_META = set(";&|`$<>\n\r(){}\\")


def command_auto_allowed(command: str, patterns: list[str]) -> bool:
    """¿Se puede ejecutar sin aprobación humana?

    - Coincidencia exacta con un patrón: sí.
    - Patrón con comodines: solo si el comando no contiene metacaracteres de shell
      (evita `ls *` => `ls; rm -rf /`).
    - El patrón `*` solo (opt-in explícito del admin) permite todo.
    """
    for p in patterns:
        if p == "*" or p == command:
            return True
        if any(c in _SHELL_META for c in command):
            continue
        if fnmatch.fnmatchcase(command, p):
            return True
    return False


# ---------------------------------------------------------------- redacción


class Redactor:
    """Reemplaza valores secretos (y sus variantes codificadas) por [REDACTED]."""

    MIN_LEN = 4

    def __init__(self, values: Iterable[str]):
        variants: set[str] = set()
        for v in values:
            if not v or len(v) < self.MIN_LEN:
                continue
            b = v.encode()
            variants.update(
                {
                    v,
                    quote(v, safe=""),
                    quote(v, safe="/"),
                    json.dumps(v)[1:-1],
                    b.hex(),
                    b.hex().upper(),
                    base64.b64encode(b).decode(),
                    base64.b64encode(b).decode().rstrip("="),
                    base64.urlsafe_b64encode(b).decode(),
                    base64.urlsafe_b64encode(b).decode().rstrip("="),
                }
            )
            if "\n" in v:  # claves privadas: también por líneas
                variants.update(line.strip() for line in v.splitlines() if len(line.strip()) >= 16)
        self._variants = sorted((x for x in variants if len(x) >= self.MIN_LEN), key=len, reverse=True)
        self._regex = (
            re.compile("|".join(re.escape(x) for x in self._variants)) if self._variants else None
        )

    def text(self, value: str) -> str:
        if not self._regex:
            return value
        return self._regex.sub("[REDACTED]", value)

    def obj(self, value: Any) -> Any:
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, dict):
            return {self.text(str(k)): self.obj(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self.obj(v) for v in value]
        return value


def basic_auth_value(username: str, password: str) -> str:
    return base64.b64encode(f"{username}:{password}".encode()).decode()

