"""Operaciones sobre la bóveda: creación, lectura y acceso a credenciales."""

import json
import re

from sqlalchemy import or_, select
from sqlalchemy.orm import Session, joinedload

from .credtypes import validate_meta, validate_secret
from .crypto import Cipher
from .models import Credential, CredentialShare, Folder, FolderAccess, User, utcnow

NAME_RE = re.compile(r"^[^/\x00-\x1f]{1,120}$")


class VaultError(ValueError):
    pass


def check_name(name: str, what: str = "nombre") -> str:
    name = name.strip()
    if not NAME_RE.match(name):
        raise VaultError(f"{what.capitalize()} inválido (no puede contener '/' ni caracteres de control)")
    return name


def _aad(credential_id: str) -> bytes:
    return f"cred:{credential_id}".encode()


def seal(cipher: Cipher, credential: Credential, secret: dict) -> None:
    payload = json.dumps(secret, separators=(",", ":")).encode()
    credential.wrapped_dek, credential.blob = cipher.encrypt(payload, _aad(credential.id))


def open_secret(cipher: Cipher, credential: Credential) -> dict:
    raw = cipher.decrypt(credential.wrapped_dek, credential.blob, _aad(credential.id))
    return json.loads(raw)


def create_credential(
    session: Session,
    cipher: Cipher,
    *,
    folder: Folder,
    name: str,
    ctype: str,
    meta: dict,
    secret: dict,
    sensitive: bool,
    allow_reveal: bool,
    user: User,
) -> Credential:
    name = check_name(name)
    meta = validate_meta(ctype, meta)
    secret = validate_secret(ctype, secret)
    exists = session.scalar(
        select(Credential.id).where(Credential.folder_id == folder.id, Credential.name == name)
    )
    if exists:
        raise VaultError("Ya existe una credencial con ese nombre en la carpeta")
    cred = Credential(
        folder_id=folder.id,
        name=name,
        type=ctype,
        meta=meta,
        sensitive=sensitive,
        allow_reveal=allow_reveal,
        created_by=user.id,
        wrapped_dek=b"",
        blob=b"",
    )
    cred.folder = folder
    session.add(cred)
    session.flush()  # asigna id, que forma parte del AAD
    seal(cipher, cred, secret)
    return cred


def update_secret(cipher: Cipher, credential: Credential, changes: dict) -> None:
    """Cambia campos secretos (rotación). Los campos ausentes se conservan."""
    current = open_secret(cipher, credential)
    merged = {**current, **validate_secret(credential.type, changes, partial=True)}
    validate_secret(credential.type, merged)
    seal(cipher, credential, merged)
    credential.version += 1


def resolve_ref(session: Session, ref: str) -> Credential | None:
    """Acepta `cred://carpeta/nombre`, `carpeta/nombre` o el id de la credencial."""
    ref = ref.strip()
    if ref.startswith("cred://"):
        ref = ref[len("cred://") :]
    stmt = select(Credential).options(joinedload(Credential.folder))
    if "/" in ref:
        folder_name, _, name = ref.partition("/")
        stmt = stmt.join(Folder).where(Folder.name == folder_name, Credential.name == name)
    else:
        stmt = stmt.where(Credential.id == ref)
    return session.scalars(stmt).first()


def folder_level(session: Session, user: User, folder_id: str) -> str | None:
    """Nivel efectivo de un usuario sobre una carpeta: None | 'read' | 'write'."""
    if not user.active:
        return None
    if user.role == "admin":
        return "write"
    level = session.scalar(
        select(FolderAccess.level).where(
            FolderAccess.user_id == user.id, FolderAccess.folder_id == folder_id
        )
    )
    if level == "write" and user.role != "editor":
        return "read"
    return level


def _active(stmt):
    return stmt.where(or_(CredentialShare.expires_at.is_(None), CredentialShare.expires_at > utcnow()))


def active_shares(session: Session, user_id: str) -> list[CredentialShare]:
    return list(session.scalars(_active(select(CredentialShare).where(CredentialShare.user_id == user_id))))


def credential_access(session: Session, user: User, cred: Credential) -> tuple[str | None, CredentialShare | None]:
    """Acceso efectivo a una credencial: ('write'|'read', None) por carpeta, ('shared', share) por compartido vigente.

    El vencimiento se evalúa en cada consulta: no hay tareas que "quiten" accesos, simplemente dejan de valer.
    """
    if not user.active:
        return None, None
    level = folder_level(session, user, cred.folder_id)
    if level:
        return level, None
    share = session.scalar(
        _active(select(CredentialShare).where(CredentialShare.user_id == user.id, CredentialShare.credential_id == cred.id))
    )
    return ("shared", share) if share else (None, None)


def reveal_allowed(user: User, cred: Credential, level: str | None, share: CredentialShare | None) -> bool:
    if not cred.allow_reveal or level is None:
        return False
    if level == "shared":
        return share is not None and share.level == "reveal"
    return user.role != "viewer"
