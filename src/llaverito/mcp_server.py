"""Servidor MCP (Streamable HTTP, sin estado). Ninguna tool devuelve secretos."""

from typing import Any

import anyio.to_thread
from mcp.server.fastmcp import Context, FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from mcp.server.transport_security import TransportSecuritySettings

from .broker import Broker, Unauthorized
from .config import Settings
from .policy import PolicyDenied

INSTRUCTIONS = """\
Llaverito es la bóveda de credenciales de la Municipalidad. Vos NUNCA ves los secretos: \
referenciás una credencial (cred://carpeta/nombre) y Llaverito ejecuta la acción por vos, \
inyectando la autenticación del lado servidor.

1. list_credentials para ver qué credenciales tenés disponibles y para qué sirven.
2. http_request para APIs (la autenticación se agrega sola; si necesitás ponerla en otro lugar \
usá el placeholder {{secret}}, {{password}} o {{username}}).
3. ssh_exec para ejecutar comandos en servidores.
Si una acción devuelve status="approval_required", un humano debe aprobarla en Llaverito; \
luego repetí la llamada idéntica agregando approval_id (podés consultar get_approval_status).
"""


def _token(ctx: Context) -> str | None:
    req = ctx.request_context.request
    auth = req.headers.get("authorization", "") if req is not None else ""
    return auth[7:].strip() if auth.lower().startswith("bearer ") else None


def build_mcp(broker: Broker, settings: Settings) -> FastMCP:
    mcp = FastMCP(
        "llaverito",
        instructions=INSTRUCTIONS,
        stateless_http=True,
        json_response=True,
        streamable_http_path="/mcp",
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=settings.mcp_allowed_hosts(),
            allowed_origins=[],
        ),
    )

    async def guarded(coro_factory):
        try:
            return await coro_factory()
        except Unauthorized as exc:
            raise ToolError(f"No autorizado: {exc}") from None
        except PolicyDenied as exc:
            raise ToolError(str(exc)) from None

    @mcp.tool()
    async def list_credentials(ctx: Context, query: str | None = None) -> list[dict]:
        """Lista las credenciales a las que este agente tiene acceso (solo metadatos, nunca secretos).

        Cada item indica su ref (cred://carpeta/nombre), el tipo, para qué tool sirve
        (http_request o ssh_exec), los hosts permitidos y si requiere aprobación humana.
        `query` filtra por texto en el nombre o la descripción.
        """
        return await guarded(
            lambda: anyio.to_thread.run_sync(lambda: broker.list_credentials(_token(ctx), query))
        )

    @mcp.tool()
    async def http_request(
        ctx: Context,
        credential: str,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        query: dict[str, str] | None = None,
        body: str | None = None,
        json_body: Any = None,
        approval_id: str | None = None,
    ) -> dict:
        """Hace una solicitud HTTP autenticada con una credencial de la bóveda.

        Llaverito agrega la autenticación configurada en la credencial (Bearer, cabecera, Basic o query)
        sin mostrártela. Si necesitás ubicar el secreto en otro lado, usá {{secret}}, {{password}} o
        {{username}} en url, headers, query, body o json_body. Solo se puede llamar a los hosts que la
        credencial permite. No se siguen redirecciones (la respuesta 3xx incluye Location).
        Devuelve status_code, headers y body (con cualquier secreto redactado).
        Si devuelve status="approval_required", pedí aprobación humana y repetí con approval_id.
        """
        return await guarded(
            lambda: broker.http_request(
                _token(ctx),
                ref=credential,
                method=method,
                url=url,
                headers=headers,
                query=query,
                body=body,
                json_body=json_body,
                approval_id=approval_id,
            )
        )

    @mcp.tool()
    async def ssh_exec(
        ctx: Context,
        credential: str,
        command: str,
        timeout: int | None = None,
        approval_id: str | None = None,
    ) -> dict:
        """Ejecuta un comando por SSH usando una credencial de la bóveda (no ves la clave ni la contraseña).

        Los comandos fuera de la lista permitida de la credencial requieren aprobación humana: la tool
        devuelve status="approval_required" y debés repetir la misma llamada con approval_id cuando
        un humano la apruebe. Devuelve exit_status, stdout y stderr (con secretos redactados).
        """
        return await guarded(
            lambda: broker.ssh_exec(
                _token(ctx), ref=credential, command=command, timeout=timeout, approval_id=approval_id
            )
        )

    @mcp.tool()
    async def get_approval_status(ctx: Context, approval_id: str) -> dict:
        """Consulta el estado de una aprobación: pending, approved, denied, consumed o expired."""
        return await guarded(
            lambda: anyio.to_thread.run_sync(lambda: broker.approval_status(_token(ctx), approval_id))
        )

    return mcp
