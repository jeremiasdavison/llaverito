"""Login con Active Directory a través de la API AD municipal.

- API AD v1 (`POST /login`, `POST /gruposUser`): valida usuario y contraseña contra AD y devuelve un JWT HS256.
- API AD v2 (`GET /empleados/{usuario}`, con `x-api-key`): solo lista cuentas activas; se usa para saber si
  alguien sigue siendo empleado (si no, se cortan sus sesiones y sus agentes).

Decisiones de seguridad (ver README):
- Solo se acepta identidad `usuario@dominio` con caracteres seguros. Nunca un número: la v1 trata los números como
  legajo y consulta otra base con una ruta distinta.
- Las contraseñas se mandan únicamente por HTTPS (salvo `ad_allow_insecure`, para desarrollo).
- La respuesta se tolera solo si es HS256 (nunca `alg=none`), y si hay clave configurada, con firma válida.
  La clave de la v1 es compartida, así que la firma es una verificación de integridad, no de autenticidad:
  la protección real es TLS hacia la API AD y que Llaverito sea quien la llama (el navegador nunca aporta un JWT).
- La identidad devuelta debe coincidir con la pedida.
"""

import base64
import hashlib
import hmac
import json
import re
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import quote

import httpx

from .config import Settings
from .models import utcnow

MAX_PASSWORD_LEN = 256


class AdAuthFailed(Exception):
    """Credenciales rechazadas por AD."""


class AdUnavailable(Exception):
    """La API AD no respondió bien: no se puede decidir (se falla cerrado)."""


@dataclass
class AdIdentity:
    upn: str
    sam: str
    name: str
    department: str | None
    office: str | None


def normalize_identity(raw: str, domain: str) -> str | None:
    """Devuelve `usuario@dominio` en minúsculas, o None si no es una identidad aceptable."""
    value = raw.strip().lower()
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}@" + re.escape(domain.lower()), value):
        return None
    return value


def _b64d(part: str) -> bytes:
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


def decode_jwt(token: str, key: bytes | None):
    """Decodifica el JWT de la API AD. El payload puede ser objeto, lista o texto JSON (la API firma strings)."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise AdUnavailable("Respuesta inválida de la API AD")
    try:
        header = json.loads(_b64d(parts[0]))
        if not isinstance(header, dict) or header.get("alg") != "HS256":
            raise AdUnavailable("Algoritmo de firma no aceptado")
        if key:
            expected = hmac.new(key, f"{parts[0]}.{parts[1]}".encode(), hashlib.sha256).digest()
            if not hmac.compare_digest(expected, _b64d(parts[2])):
                raise AdUnavailable("Firma inválida en la respuesta de la API AD")
        payload = json.loads(_b64d(parts[1]))
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except ValueError:
                pass
        return payload
    except AdUnavailable:
        raise
    except Exception as exc:
        raise AdUnavailable("Respuesta ilegible de la API AD") from exc


class AdClient:
    def __init__(self, settings: Settings):
        self.s = settings
        self._key = settings.ad_jwt_key.get_secret_value().encode() if settings.ad_jwt_key else None

    def _post(self, path: str, body: dict):
        verify = str(self.s.ad_ca_file) if self.s.ad_ca_file else True
        try:
            with httpx.Client(timeout=self.s.ad_timeout_seconds, verify=verify, follow_redirects=False) as c:
                r = c.post(self.s.ad_api_url.rstrip("/") + path, json=body)
        except httpx.HTTPError as exc:
            raise AdUnavailable(f"No se pudo contactar a la API AD ({type(exc).__name__})") from None
        if r.status_code != 200:
            raise AdUnavailable(f"La API AD respondió {r.status_code}")
        return decode_jwt(r.text, self._key)

    def login(self, identity: str, password: str) -> AdIdentity:
        """`identity` ya debe estar normalizada con `normalize_identity`."""
        if not password or len(password) > MAX_PASSWORD_LEN:
            raise AdAuthFailed("Contraseña vacía o demasiado larga")
        data = self._post("/login", {"usuario": identity, "clave": password})
        if not isinstance(data, dict) or data.get("login") is False or not data.get("sAMAccountName"):
            raise AdAuthFailed("AD rechazó las credenciales")
        sam = str(data["sAMAccountName"]).lower()
        upn = str(data.get("userPrincipalName") or "").lower()
        if identity != upn and identity.split("@")[0] != sam:
            raise AdAuthFailed("La identidad devuelta no coincide con la pedida")
        return AdIdentity(
            upn=upn or identity,
            sam=sam,
            name=str(data.get("cn") or sam).strip().title(),
            department=(data.get("department") or None),
            office=(data.get("physicalDeliveryOfficeName") or None),
        )

    def groups(self, identity: str, password: str) -> set[str]:
        """Nombres (cn) de los grupos del usuario, en minúsculas. Falla cerrado ante cualquier anomalía."""
        data = self._post("/gruposUser", {"usuario": identity, "clave": password})
        if not isinstance(data, list):
            raise AdUnavailable("No se pudieron obtener los grupos de AD")
        return {str(g).strip().lower() for g in data}


class AdDirectory:
    """Consulta a la API AD v2 (cuentas activas) con caché y tolerancia acotada a caídas."""

    def __init__(self, settings: Settings):
        self.s = settings
        self._cache: dict[str, tuple[bool, float]] = {}
        self._lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        return bool(self.s.ad_v2_url and self.s.ad_v2_api_key)

    def check_at_login(self, sam: str) -> bool:
        """Consulta fresca al iniciar sesión. Si la v2 no responde se acepta: AD acaba de autenticar a la persona."""
        if not self.enabled:
            return True
        try:
            active = self._query(sam.lower())
        except AdUnavailable:
            active = True
        with self._lock:
            self._cache[sam.lower()] = (active, time.monotonic())
        return active

    def _query(self, sam: str) -> bool:
        verify = str(self.s.ad_ca_file) if self.s.ad_ca_file else True
        try:
            with httpx.Client(timeout=self.s.ad_timeout_seconds, verify=verify, follow_redirects=False) as c:
                r = c.get(
                    f"{self.s.ad_v2_url.rstrip('/')}/empleados/{quote(sam, safe='')}",
                    headers={"x-api-key": self.s.ad_v2_api_key.get_secret_value()},
                )
        except httpx.HTTPError as exc:
            raise AdUnavailable(type(exc).__name__) from None
        if r.status_code == 200:
            return True
        if r.status_code == 404:
            return False
        raise AdUnavailable(f"API AD v2 respondió {r.status_code}")

    def is_active(self, sam: str | None, last_login_at: datetime | None = None) -> bool:
        """True si la cuenta de AD sigue activa. Sin v2 configurada no se puede saber y se asume que sí."""
        if not self.enabled or not sam:
            return True
        sam = sam.lower()
        now = time.monotonic()
        with self._lock:
            hit = self._cache.get(sam)
        if hit and now - hit[1] < self.s.ad_v2_cache_seconds:
            return hit[0]
        try:
            active = self._query(sam)
        except AdUnavailable:
            stale = self.s.ad_v2_stale_seconds
            if hit and now - hit[1] < stale:
                return hit[0]
            if not hit and last_login_at and (utcnow() - last_login_at).total_seconds() < stale:
                return True
            return False  # sin dato reciente y la v2 no responde: se falla cerrado
        with self._lock:
            self._cache[sam] = (active, now)
        return active
