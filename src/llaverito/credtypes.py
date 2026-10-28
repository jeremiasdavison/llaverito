"""Tipos de credencial: qué campos son secretos y qué metadatos (no secretos) admiten."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

HTTP_TYPES = {"api_key", "bearer_token", "basic_auth", "password"}
SSH_TYPES = {"ssh_key", "ssh_password"}
ALL_TYPES = HTTP_TYPES | SSH_TYPES

# campo -> obligatorio
SECRET_FIELDS: dict[str, dict[str, bool]] = {
    "api_key": {"secret": True},
    "bearer_token": {"secret": True},
    "basic_auth": {"password": True},
    "password": {"password": True},
    "ssh_key": {"private_key": True, "passphrase": False},
    "ssh_password": {"password": True},
}

MIN_SECRET_LEN = 6


class ValidationFailure(ValueError):
    pass


class _MetaBase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    description: str = Field(default="", max_length=1000)
    url: str = Field(default="", max_length=500)


class HttpMeta(_MetaBase):
    allowed_hosts: list[str] = Field(default_factory=list)
    inject_mode: Literal["bearer", "header", "basic", "query", "none"] = "bearer"
    header_name: str = "X-API-Key"
    query_param: str = "api_key"
    username: str = ""
    allow_http: bool = False
    allow_private_network: bool = False

    @field_validator("allowed_hosts")
    @classmethod
    def _hosts(cls, v: list[str]) -> list[str]:
        out = []
        for h in v:
            h = h.strip().lower()
            if not h or "/" in h or " " in h or "://" in h:
                raise ValueError(f"Host inválido: {h!r} (usar solo nombre de host, ej. api.example.com o *.example.com)")
            out.append(h)
        return out


class SshMeta(_MetaBase):
    host: str = Field(min_length=1, max_length=255)
    port: int = Field(default=22, ge=1, le=65535)
    username: str = Field(min_length=1, max_length=128)
    allowed_commands: list[str] = Field(default_factory=list)
    host_key: str = ""  # clave pública OpenSSH fijada (ver /scan-host-key y /pin-host-key)


_DEFAULT_MODE = {
    "api_key": "header",
    "bearer_token": "bearer",
    "basic_auth": "basic",
    "password": "none",
}


def validate_meta(ctype: str, meta: dict) -> dict:
    if ctype not in ALL_TYPES:
        raise ValidationFailure(f"Tipo desconocido: {ctype}")
    try:
        if ctype in HTTP_TYPES:
            meta = {"inject_mode": _DEFAULT_MODE[ctype], **meta}
            return HttpMeta(**meta).model_dump()
        return SshMeta(**meta).model_dump()
    except ValueError as exc:
        raise ValidationFailure(str(exc)) from exc


def validate_secret(ctype: str, secret: dict, *, partial: bool = False) -> dict:
    fields = SECRET_FIELDS.get(ctype)
    if fields is None:
        raise ValidationFailure(f"Tipo desconocido: {ctype}")
    unknown = set(secret) - set(fields)
    if unknown:
        raise ValidationFailure(f"Campos secretos no válidos para {ctype}: {sorted(unknown)}")
    out = {}
    for name, required in fields.items():
        value = secret.get(name)
        if not value:
            if required and not partial:
                raise ValidationFailure(f"Falta el campo secreto '{name}'")
            continue
        if not isinstance(value, str):
            raise ValidationFailure(f"El campo '{name}' debe ser texto")
        if name != "passphrase" and name != "private_key" and len(value) < MIN_SECRET_LEN:
            raise ValidationFailure(f"El secreto '{name}' es demasiado corto (mínimo {MIN_SECRET_LEN})")
        out[name] = value
    return out


def primary_secret(ctype: str, secret: dict) -> str | None:
    for name in ("secret", "password", "private_key"):
        if name in secret:
            return secret[name]
    return None
