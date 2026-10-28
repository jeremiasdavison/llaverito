"""Broker: ejecuta acciones con credenciales del lado servidor sin devolver nunca el secreto.

Flujo de cada acción:
  1. `prepare_*` (síncrono, con DB): autentica al agente, verifica permisos y políticas,
     decide si hace falta aprobación humana y descifra el secreto en memoria.
  2. `_run_*` (asíncrono, sin DB): hace la llamada de red.
  3. `_finish` (síncrono): registra el resultado en la auditoría.
La salida pasa por `Redactor` antes de volver al agente.
"""

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import anyio.to_thread
import asyncssh
import httpx
from sqlalchemy import select, update
from sqlalchemy.orm import Session, joinedload

from . import audit
from .credtypes import HTTP_TYPES, SSH_TYPES, HttpMeta, SshMeta, primary_secret
from .models import Agent, ApprovalRequest, Credential, User, utcnow
from .policy import (
    PolicyDenied,
    Redactor,
    SafeTransport,
    basic_auth_value,
    command_auto_allowed,
    host_allowed,
)
from .runtime import Runtime
from .security import RateLimiter, hash_agent_token
from .vault import credential_access, open_secret, resolve_ref

HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
FORBIDDEN_REQUEST_HEADERS = {"host", "content-length", "transfer-encoding", "connection", "upgrade", "te"}
DROPPED_RESPONSE_HEADERS = {"set-cookie", "authorization", "proxy-authenticate"}
PLACEHOLDER_RE = re.compile(r"\{\{\s*(\w+)\s*\}\}")
HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")


class Unauthorized(Exception):
    pass


@dataclass
class AgentInfo:
    id: str
    name: str
    owner_id: str


@dataclass
class PreparedHttp:
    agent: AgentInfo
    cred_id: str
    cred_ref: str
    method: str
    url: str
    log_target: str
    headers: dict[str, str]
    content: bytes | None
    allow_private: bool
    redactor: Redactor


@dataclass
class PreparedSsh:
    agent: AgentInfo
    cred_id: str
    cred_ref: str
    host: str
    port: int
    username: str
    password: str | None
    private_key: str | None
    passphrase: str | None
    known_hosts: str
    command: str
    timeout: int
    redactor: Redactor


@dataclass
class _Ctx:
    """Contexto de una acción en `prepare_*`."""

    session: Session
    agent: Agent
    cred: Credential
    action: str
    approval_id: str | None
    extra: dict[str, Any] = field(default_factory=dict)


class Broker:
    def __init__(self, rt: Runtime):
        self.rt = rt
        self.limiter = RateLimiter(rt.settings.agent_rate_limit_per_minute)

    # ------------------------------------------------------------ autenticación y permisos

    def authenticate(self, session: Session, token: str | None) -> Agent:
        if not token:
            raise Unauthorized("Falta el token del agente")
        agent = session.scalar(
            select(Agent).options(joinedload(Agent.grants)).where(Agent.token_hash == hash_agent_token(token))
        )
        now = utcnow()
        if agent is None or agent.revoked or (agent.expires_at and agent.expires_at <= now):
            raise Unauthorized("Token inválido, revocado o vencido")
        # Un agente actúa con los permisos de su dueño: si el dueño se desactiva o pasa a lector, se corta.
        owner = session.get(User, agent.owner_id)
        if owner is None or not owner.active or owner.role == "viewer":
            raise Unauthorized("El dueño del agente ya no tiene permisos")
        if owner.auth_source == "ad" and not self.rt.directory.is_active(owner.ad_sam, owner.last_login_at):
            raise Unauthorized("El dueño del agente ya no figura como empleado activo en AD")
        agent.last_used_at = now
        return agent

    def _granted(self, session: Session, agent: Agent, cred: Credential) -> bool:
        owner = session.get(User, agent.owner_id)
        # El permiso del agente nunca excede el acceso vigente de su dueño a la carpeta.
        if owner is None or credential_access(session, owner, cred)[0] is None:
            return False
        now = utcnow()
        for g in agent.grants:
            if g.expires_at and g.expires_at <= now:
                continue
            if g.credential_id == cred.id or (g.folder_id and g.folder_id == cred.folder_id):
                return True
        return False

    def _audit(
        self,
        session: Session,
        agent: Agent,
        action: str,
        outcome: str,
        cred: Credential | None = None,
        target: str | None = None,
        detail: dict | None = None,
    ) -> None:
        audit.record(
            session,
            actor_type="agent",
            actor_id=agent.id,
            actor_name=agent.name,
            action=action,
            outcome=outcome,
            credential=cred,
            target=target,
            detail=detail,
        )

    def _deny(
        self,
        session: Session,
        agent: Agent,
        action: str,
        message: str,
        cred: Credential | None = None,
        target: str | None = None,
    ) -> PolicyDenied:
        self._audit(session, agent, action, "denied", cred, target, {"reason": message})
        session.commit()  # la auditoría debe persistir aunque la acción falle
        return PolicyDenied(message)

    def _find(self, session: Session, agent: Agent, ref: str, action: str, types: set[str]) -> Credential:
        if not self.limiter.allow(agent.id):
            raise self._deny(session, agent, action, "Límite de solicitudes por minuto excedido")
        cred = resolve_ref(session, ref)
        if cred is None or not self._granted(session, agent, cred):
            # Mismo mensaje para "no existe" y "sin permiso": no revela qué credenciales existen.
            raise self._deny(session, agent, action, "Credencial no encontrada o sin acceso", target=ref[:200])
        if cred.type not in types:
            raise self._deny(
                session, agent, action, f"Esta credencial (tipo {cred.type}) no sirve para {action}", cred
            )
        return cred

    def _open(self, session: Session, agent: Agent, cred: Credential, action: str, target: str) -> dict:
        try:
            return open_secret(self.rt.cipher, cred)
        except Exception:  # InvalidTag: blob alterado o KEK equivocada; no filtrar detalles
            raise self._deny(session, agent, action, "Error de integridad al descifrar la credencial", cred, target) from None

    # ------------------------------------------------------------ aprobaciones

    @staticmethod
    def _action_hash(agent_id: str, cred_id: str, action: str, params: dict) -> str:
        canon = json.dumps([agent_id, cred_id, action, params], sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(canon.encode()).hexdigest()

    def _gate(self, c: _Ctx, params: dict, summary: str, reason: str | None) -> dict | None:
        """Devuelve None si se puede ejecutar, o el dict 'approval_required'. Lanza PolicyDenied si no."""
        if reason is None:
            return None
        s, now = c.session, utcnow()
        h = self._action_hash(c.agent.id, c.cred.id, c.action, params)
        if c.approval_id:
            ap = s.get(ApprovalRequest, c.approval_id)
            if (
                ap is None
                or ap.agent_id != c.agent.id
                or ap.credential_id != c.cred.id
                or ap.action != c.action
                or ap.action_hash != h
            ):
                raise self._deny(s, c.agent, c.action, "La aprobación no corresponde a esta acción", c.cred)
            if ap.status == "pending":
                raise self._deny(s, c.agent, c.action, "La aprobación sigue pendiente", c.cred)
            if ap.status == "denied":
                raise self._deny(s, c.agent, c.action, "La aprobación fue rechazada", c.cred)
            if ap.status == "consumed":
                raise self._deny(s, c.agent, c.action, "La aprobación ya fue utilizada", c.cred)
            if ap.expires_at <= now:
                raise self._deny(s, c.agent, c.action, "La aprobación venció", c.cred)
            res = s.execute(
                update(ApprovalRequest)
                .where(ApprovalRequest.id == ap.id, ApprovalRequest.status == "approved")
                .values(status="consumed")
            )
            if res.rowcount != 1:
                raise self._deny(s, c.agent, c.action, "La aprobación ya fue utilizada", c.cred)
            return None
        ap = ApprovalRequest(
            agent_id=c.agent.id,
            credential_id=c.cred.id,
            action=c.action,
            action_hash=h,
            summary=summary[:1000],
            reason=reason,
            expires_at=now + timedelta(seconds=self.rt.settings.approval_ttl_seconds),
        )
        s.add(ap)
        s.flush()
        self._audit(s, c.agent, "approval_requested", "pending", c.cred, summary[:500], {"approval_id": ap.id, "reason": reason})
        s.commit()
        return {
            "status": "approval_required",
            "approval_id": ap.id,
            "reason": reason,
            "message": (
                "Un humano debe aprobar esta acción en Llaverito. Cuando la apruebe, repetí la misma "
                f"llamada con approval_id={ap.id} (parámetros idénticos). Vence en "
                f"{self.rt.settings.approval_ttl_seconds // 60} min."
            ),
        }

    def approval_status(self, token: str | None, approval_id: str) -> dict:
        with self.rt.session() as s:
            agent = self.authenticate(s, token)
            ap = s.get(ApprovalRequest, approval_id)
            if ap is None or ap.agent_id != agent.id:
                raise PolicyDenied("Aprobación no encontrada")
            status = ap.status
            if status in ("pending", "approved") and ap.expires_at <= utcnow():
                status = "expired"
            return {"approval_id": ap.id, "status": status, "summary": ap.summary}

    # ------------------------------------------------------------ listado

    def list_credentials(self, token: str | None, query: str | None) -> list[dict]:
        with self.rt.session() as s:
            agent = self.authenticate(s, token)
            creds = s.scalars(
                select(Credential).options(joinedload(Credential.folder)).order_by(Credential.name)
            ).all()
            out = []
            q = (query or "").strip().lower()
            for cred in creds:
                if not self._granted(s, agent, cred):
                    continue
                meta = cred.meta
                text = f"{cred.ref} {meta.get('description', '')}".lower()
                if q and q not in text:
                    continue
                item: dict[str, Any] = {
                    "ref": cred.ref,
                    "type": cred.type,
                    "description": meta.get("description", ""),
                    "requires_approval": cred.sensitive,
                }
                if cred.type in HTTP_TYPES:
                    item["use_with"] = "http_request"
                    item["allowed_hosts"] = meta.get("allowed_hosts", [])
                    item["auth_injected_as"] = meta.get("inject_mode")
                else:
                    item["use_with"] = "ssh_exec"
                    item["ssh_target"] = f"{meta.get('username')}@{meta.get('host')}:{meta.get('port')}"
                    item["auto_approved_commands"] = meta.get("allowed_commands", [])
                out.append(item)
            self._audit(s, agent, "list_credentials", "ok", detail={"returned": len(out), "query": q})
            return out

    # ------------------------------------------------------------ HTTP

    def prepare_http(
        self,
        token: str | None,
        ref: str,
        method: str,
        url: str,
        headers: dict[str, str] | None,
        query: dict[str, str] | None,
        body: str | None,
        json_body: Any,
        approval_id: str | None,
    ) -> PreparedHttp | dict:
        action = "http_request"
        with self.rt.session() as s:
            agent = self.authenticate(s, token)
            cred = self._find(s, agent, ref, action, HTTP_TYPES)
            meta = HttpMeta(**cred.meta)
            method = method.upper()
            target = f"{method} {url}"

            def deny(msg: str) -> PolicyDenied:
                return self._deny(s, agent, action, msg, cred, target)

            if method not in HTTP_METHODS:
                raise deny(f"Método no permitido: {method}")
            if body is not None and json_body is not None:
                raise deny("Usá 'body' o 'json', no ambos")
            parts = urlsplit(url)
            if parts.scheme not in ("https", "http") or not parts.hostname:
                raise deny("URL inválida (se requiere http(s)://host/...)")
            if parts.scheme == "http" and not meta.allow_http:
                raise deny("Esta credencial solo se puede usar sobre HTTPS")
            if parts.username or parts.password or "{{" in parts.netloc:
                raise deny("La URL no puede incluir credenciales ni placeholders en el host")
            if not host_allowed(parts.hostname, meta.allowed_hosts):
                raise deny(f"Host no permitido para esta credencial: {parts.hostname}")

            secret = self._open(s, agent, cred, action, target)
            main = primary_secret(cred.type, secret) or ""
            values = {"secret": main, "password": secret.get("password", main), "username": meta.username}

            def fill(text: str) -> str:
                def sub(m: re.Match) -> str:
                    key = m.group(1)
                    if key not in values:
                        raise deny(f"Placeholder desconocido: {{{{{key}}}}} (válidos: secret, password, username)")
                    return values[key]

                return PLACEHOLDER_RE.sub(sub, text)

            def fill_obj(o: Any) -> Any:
                if isinstance(o, str):
                    return fill(o)
                if isinstance(o, dict):
                    return {fill(str(k)): fill_obj(v) for k, v in o.items()}
                if isinstance(o, list):
                    return [fill_obj(v) for v in o]
                return o

            out_headers: dict[str, str] = {}
            for name, value in (headers or {}).items():
                if not HEADER_NAME_RE.fullmatch(name):
                    raise deny(f"Nombre de cabecera inválido: {name!r}")
                if name.lower() in FORBIDDEN_REQUEST_HEADERS:
                    raise deny(f"Cabecera no permitida: {name}")
                out_headers[name] = fill(str(value))

            query_items = {k: fill(str(v)) for k, v in (query or {}).items()}
            path_url = urlunsplit(("", "", parts.path, parts.query, ""))  # relativo, para rellenar placeholders
            final_path = fill(path_url)
            final_url = f"{parts.scheme}://{parts.netloc}{final_path}"

            mode = meta.inject_mode
            if mode == "bearer":
                _set_header(out_headers, "Authorization", f"Bearer {main}")
            elif mode == "header":
                _set_header(out_headers, meta.header_name, main)
            elif mode == "basic":
                if not meta.username:
                    raise deny("La credencial basic_auth no tiene usuario configurado")
                _set_header(out_headers, "Authorization", f"Basic {basic_auth_value(meta.username, secret.get('password', ''))}")
            elif mode == "query":
                query_items[meta.query_param] = main

            content: bytes | None = None
            if json_body is not None:
                content = json.dumps(fill_obj(json_body)).encode()
                if not any(k.lower() == "content-type" for k in out_headers):
                    out_headers["Content-Type"] = "application/json"
            elif body is not None:
                content = fill(body).encode()
            if query_items:
                final_url = str(httpx.URL(final_url).copy_merge_params(query_items))

            approval_params = {"m": method, "u": url, "h": headers or {}, "q": query or {}, "b": body, "j": json_body}
            reason = "Credencial marcada como sensible" if cred.sensitive else None
            pending = self._gate(_Ctx(s, agent, cred, action, approval_id), approval_params, target, reason)
            if pending:
                return pending

            redact_values = [v for v in secret.values()]
            if mode == "basic":
                redact_values.append(basic_auth_value(meta.username, secret.get("password", "")))
            return PreparedHttp(
                agent=AgentInfo(agent.id, agent.name, agent.owner_id),
                cred_id=cred.id,
                cred_ref=cred.ref,
                method=method,
                url=final_url,
                log_target=target,
                headers=out_headers,
                content=content,
                allow_private=meta.allow_private_network,
                redactor=Redactor(redact_values),
            )

    async def http_request(self, token: str | None, **params: Any) -> dict:
        prep = await anyio.to_thread.run_sync(lambda: self.prepare_http(token, **params))
        if isinstance(prep, dict):
            return prep
        try:
            result = await self._run_http(prep)
            outcome, detail = "ok", {"status_code": result["status_code"]}
        except PolicyDenied as exc:
            outcome, detail = "denied", {"reason": str(exc)}
            await self._finish(prep.agent, prep.cred_id, "http_request", outcome, prep.log_target, detail)
            raise
        except Exception as exc:
            msg = prep.redactor.text(f"{type(exc).__name__}: {exc}")
            await self._finish(prep.agent, prep.cred_id, "http_request", "error", prep.log_target, {"error": msg})
            raise PolicyDenied(f"Falló la solicitud: {msg}") from None
        await self._finish(prep.agent, prep.cred_id, "http_request", outcome, prep.log_target, detail)
        return result

    async def _run_http(self, p: PreparedHttp) -> dict:
        st = self.rt.settings
        transport = SafeTransport(allow_private=p.allow_private, dev_override=st.allow_private_networks)
        async with httpx.AsyncClient(transport=transport, timeout=st.http_timeout_seconds, follow_redirects=False) as client:
            async with client.stream(p.method, p.url, headers=p.headers, content=p.content) as resp:
                buf = bytearray()
                truncated = False
                async for chunk in resp.aiter_bytes():
                    buf += chunk
                    if len(buf) > st.http_max_response_bytes:
                        del buf[st.http_max_response_bytes :]
                        truncated = True
                        break
                headers = {k.lower(): v for k, v in resp.headers.items() if k.lower() not in DROPPED_RESPONSE_HEADERS}
                return {
                    "status_code": resp.status_code,
                    "headers": p.redactor.obj(headers),
                    "body": p.redactor.text(buf.decode("utf-8", errors="replace")),
                    "truncated": truncated,
                }

    # ------------------------------------------------------------ SSH

    def prepare_ssh(
        self, token: str | None, ref: str, command: str, timeout: int | None, approval_id: str | None
    ) -> PreparedSsh | dict:
        action = "ssh_exec"
        st = self.rt.settings
        with self.rt.session() as s:
            agent = self.authenticate(s, token)
            cred = self._find(s, agent, ref, action, SSH_TYPES)
            meta = SshMeta(**cred.meta)
            target = f"{meta.username}@{meta.host}:{meta.port} $ {command[:500]}"

            def deny(msg: str) -> PolicyDenied:
                return self._deny(s, agent, action, msg, cred, target)

            if not command.strip() or len(command) > 4000 or "\x00" in command:
                raise deny("Comando inválido")
            if not meta.host_key:
                raise deny("La clave de host SSH no está fijada; un administrador debe fijarla en Llaverito")
            timeout = max(1, min(timeout or st.ssh_default_timeout, st.ssh_max_timeout))

            reason = None
            if cred.sensitive:
                reason = "Credencial marcada como sensible"
            elif not command_auto_allowed(command, meta.allowed_commands):
                reason = "Comando fuera de la lista de comandos permitidos"
            pending = self._gate(
                _Ctx(s, agent, cred, action, approval_id), {"c": command}, target, reason
            )
            if pending:
                return pending

            secret = self._open(s, agent, cred, action, target)
            hostspec = meta.host if meta.port == 22 else f"[{meta.host}]:{meta.port}"
            return PreparedSsh(
                agent=AgentInfo(agent.id, agent.name, agent.owner_id),
                cred_id=cred.id,
                cred_ref=cred.ref,
                host=meta.host,
                port=meta.port,
                username=meta.username,
                password=secret.get("password"),
                private_key=secret.get("private_key"),
                passphrase=secret.get("passphrase"),
                known_hosts=f"{hostspec} {meta.host_key}\n",
                command=command,
                timeout=timeout,
                redactor=Redactor(secret.values()),
            )

    async def ssh_exec(self, token: str | None, **params: Any) -> dict:
        prep = await anyio.to_thread.run_sync(lambda: self.prepare_ssh(token, **params))
        if isinstance(prep, dict):
            return prep
        target = prep.redactor.text(f"{prep.username}@{prep.host}:{prep.port} $ {prep.command[:500]}")
        try:
            result = await self._run_ssh(prep)
        except Exception as exc:
            msg = prep.redactor.text(f"{type(exc).__name__}: {exc}")
            await self._finish(prep.agent, prep.cred_id, "ssh_exec", "error", target, {"error": msg})
            raise PolicyDenied(f"Falló la ejecución SSH: {msg}") from None
        await self._finish(prep.agent, prep.cred_id, "ssh_exec", "ok", target, {"exit_status": result["exit_status"]})
        return result

    async def _run_ssh(self, p: PreparedSsh) -> dict:
        cap = self.rt.settings.ssh_max_output_bytes
        key_args: dict[str, Any] = {"client_keys": None, "password": p.password}
        if p.private_key:
            key_args = {"client_keys": [asyncssh.import_private_key(p.private_key, p.passphrase)], "password": None}
        async with asyncssh.connect(
            p.host,
            p.port,
            username=p.username,
            known_hosts=asyncssh.import_known_hosts(p.known_hosts),
            connect_timeout=15,
            agent_path=None,
            config=[],
            **key_args,
        ) as conn:
            result = await conn.run(p.command, check=False, timeout=p.timeout)

        def clip(v: Any) -> tuple[str, bool]:
            text = v.decode("utf-8", "replace") if isinstance(v, bytes) else (v or "")
            if len(text) > cap:
                return text[:cap], True
            return text, False

        out, t1 = clip(result.stdout)
        err, t2 = clip(result.stderr)
        return {
            "exit_status": result.exit_status,
            "stdout": p.redactor.text(out),
            "stderr": p.redactor.text(err),
            "truncated": t1 or t2,
        }

    # ------------------------------------------------------------ auditoría posterior

    async def _finish(self, agent: AgentInfo, cred_id: str, action: str, outcome: str, target: str, detail: dict) -> None:
        def write() -> None:
            with self.rt.session() as s:
                cred = s.scalar(select(Credential).options(joinedload(Credential.folder)).where(Credential.id == cred_id))
                audit.record(
                    s,
                    actor_type="agent",
                    actor_id=agent.id,
                    actor_name=agent.name,
                    action=action,
                    outcome=outcome,
                    credential=cred,
                    target=target,
                    detail=detail,
                )

        await anyio.to_thread.run_sync(write)


def _set_header(headers: dict[str, str], name: str, value: str) -> None:
    """Fija una cabecera pisando cualquier variante de mayúsculas que haya puesto el agente."""
    for k in [k for k in headers if k.lower() == name.lower()]:
        del headers[k]
    headers[name] = value


async def scan_host_key(host: str, port: int) -> tuple[str, str]:
    """Devuelve (clave pública OpenSSH, huella SHA256) del servidor. No envía credenciales."""
    key = await asyncssh.get_server_host_key(host, port)
    if key is None:
        raise PolicyDenied("No se pudo obtener la clave del host")
    line = key.export_public_key("openssh").decode().strip()
    parts = line.split()
    return " ".join(parts[:2]), key.get_fingerprint("sha256")
