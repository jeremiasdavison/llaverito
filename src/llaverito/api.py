"""API REST para la interfaz web (personas). Los agentes usan el endpoint MCP, no esta API."""

import re
from datetime import timedelta
from typing import Annotated, Any, Iterator, Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, EmailStr, Field
from sqlalchemy import delete, select
from sqlalchemy.orm import Session, joinedload

from . import audit
from .adauth import AdAuthFailed, AdUnavailable, normalize_identity
from .broker import scan_host_key
from .credtypes import ALL_TYPES, SshMeta, ValidationFailure, validate_meta
from .models import (
    Agent,
    AgentGrant,
    ApprovalRequest,
    AuditLog,
    Credential,
    CredentialShare,
    Folder,
    FolderAccess,
    User,
    utcnow,
)
from .runtime import Runtime
from .security import (
    DUMMY_HASH,
    UNUSABLE_HASH,
    LoginThrottle,
    decode_session_token,
    generate_agent_token,
    hash_agent_token,
    hash_password,
    make_session_token,
    verify_password,
)
from .vault import (
    VaultError,
    check_name,
    active_shares,
    create_credential,
    credential_access,
    folder_level,
    open_secret,
    reveal_allowed,
    update_secret,
)

router = APIRouter(prefix="/api")
throttle = LoginThrottle()
email_throttle = LoginThrottle(max_failures=20, window_seconds=900)  # ataques distribuidos contra una cuenta
COOKIE = "llv_session"
CSRF_HEADER = "x-requested-with"
CSRF_VALUE = "llaverito"


# ------------------------------------------------------------------ dependencias


def get_rt(request: Request) -> Runtime:
    return request.app.state.rt


def get_db(rt: Annotated[Runtime, Depends(get_rt)]) -> Iterator[Session]:
    # Los endpoints que modifican datos llaman a db.commit() explícitamente antes de responder.
    s = rt.sessionmaker()
    try:
        yield s
    finally:
        s.rollback()
        s.close()


DB = Annotated[Session, Depends(get_db)]
RT = Annotated[Runtime, Depends(get_rt)]


def csrf_check(request: Request) -> None:
    if request.method not in ("GET", "HEAD", "OPTIONS") and request.headers.get(CSRF_HEADER) != CSRF_VALUE:
        raise HTTPException(403, "Falta la cabecera anti-CSRF")


def current_user(request: Request, rt: RT, db: DB) -> User:
    csrf_check(request)
    token = request.cookies.get(COOKIE)
    claims = decode_session_token(token, rt.jwt_secret) if token else None
    if not claims:
        raise HTTPException(401, "No autenticado")
    user = db.get(User, claims["sub"])
    if user is None or not user.active or user.session_version != claims.get("sv"):
        raise HTTPException(401, "Sesión inválida")
    if user.auth_source == "ad" and not rt.directory.is_active(user.ad_sam, user.last_login_at):
        raise HTTPException(401, "Tu cuenta ya no figura como activa en Active Directory")
    return user


CurrentUser = Annotated[User, Depends(current_user)]


def require_admin(user: CurrentUser) -> User:
    if user.role != "admin":
        raise HTTPException(403, "Requiere rol de administrador")
    return user


Admin = Annotated[User, Depends(require_admin)]


def ip_of(request: Request) -> str | None:
    return request.client.host if request.client else None


def log(db: Session, user: User | None, request: Request, action: str, outcome: str = "ok", **kw: Any) -> None:
    audit.record(
        db,
        actor_type="user" if user else "system",
        actor_id=user.id if user else None,
        actor_name=user.email if user else None,
        action=action,
        outcome=outcome,
        ip=ip_of(request),
        **kw,
    )


# ------------------------------------------------------------------ esquemas


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    email: str
    name: str
    role: str
    active: bool
    auth_source: str = "local"
    department: str | None = None


class LoginIn(BaseModel):
    email: str
    password: str


class UserCreate(BaseModel):
    email: EmailStr
    name: str = Field(min_length=1, max_length=255)
    password: str
    role: Literal["admin", "editor", "viewer"] = "viewer"


class UserPatch(BaseModel):
    name: str | None = None
    role: Literal["admin", "editor", "viewer"] | None = None
    active: bool | None = None
    password: str | None = None


class FolderIn(BaseModel):
    name: str
    description: str = ""


class FolderOut(BaseModel):
    id: str
    name: str
    description: str
    level: str


class AccessItem(BaseModel):
    user_id: str
    level: Literal["read", "write"]


class CredentialIn(BaseModel):
    folder_id: str
    name: str
    type: str
    meta: dict = Field(default_factory=dict)
    secret: dict
    sensitive: bool = False
    allow_reveal: bool = True


class CredentialPatch(BaseModel):
    name: str | None = None
    meta: dict | None = None
    secret: dict | None = None
    sensitive: bool | None = None
    allow_reveal: bool | None = None


class RevealIn(BaseModel):
    password: str


class PinIn(BaseModel):
    host_key: str


class GrantIn(BaseModel):
    folder_id: str | None = None
    credential_id: str | None = None


class AgentIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    expires_in_days: int | None = Field(default=None, ge=1, le=3650)
    grants: list[GrantIn] = Field(default_factory=list)


class DecideIn(BaseModel):
    approve: bool


# ------------------------------------------------------------------ auth


def user_out(u: User) -> dict:
    return UserOut.model_validate(u).model_dump()


def _login_fail(db: Session, request: Request, key: str, email: str, reason: str) -> HTTPException:
    throttle.fail(key)
    email_throttle.fail(email)
    log(db, None, request, "login", "denied", detail={"email": email[:254], "reason": reason})
    db.commit()
    return HTTPException(401, "Credenciales inválidas")


def _login_ad(db: Session, rt: Runtime, request: Request, email: str, password: str, existing: User | None, key: str) -> User:
    st = rt.settings
    identity = normalize_identity(email, st.ad_email_domain)
    if identity is None:
        raise _login_fail(db, request, key, email, "bad_identity")
    try:
        ident = rt.ad.login(identity, password)
        groups = rt.ad.groups(identity, password) if st.login_groups else set()
    except AdAuthFailed:
        raise _login_fail(db, request, key, email, "ad_rejected") from None
    except AdUnavailable as exc:
        log(db, None, request, "login", "error", detail={"email": email[:254], "reason": "ad_unavailable", "error": str(exc)[:200]})
        db.commit()
        raise HTTPException(503, "El servicio de autenticación institucional no está disponible") from None
    if not re.fullmatch(r"[a-z0-9._-]{1,64}", ident.sam):
        raise _login_fail(db, request, key, email, "bad_account_name")
    if st.login_groups and not (groups & st.login_groups):
        log(db, None, request, "login", "denied", detail={"email": email[:254], "reason": "not_in_allowed_group"})
        db.commit()
        raise HTTPException(403, "Tu cuenta no está habilitada para usar Llaverito")

    role = existing.role if existing else st.ad_default_role
    if st.admin_groups or st.editor_groups:  # con grupos configurados, AD manda sobre el rol
        role = "admin" if groups & st.admin_groups else "editor" if groups & st.editor_groups else st.ad_default_role
    user = existing
    if user is None:
        user = User(email=identity, name=ident.name, password_hash=UNUSABLE_HASH, role=role, auth_source="ad",
                    ad_sam=ident.sam, department=ident.department)
        db.add(user)
        db.flush()
        log(db, user, request, "user_provision", detail={"source": "ad", "role": role})
    else:
        user.name, user.department, user.ad_sam = ident.name, ident.department, ident.sam
        if role != user.role:
            log(db, user, request, "user_role_sync", detail={"from": user.role, "to": role})
            user.role = role
            user.session_version += 1  # los permisos cambiaron: las sesiones viejas dejan de valer
    if not user.active:
        raise _login_fail(db, request, key, email, "inactive")
    if not rt.directory.check_at_login(ident.sam):
        raise _login_fail(db, request, key, email, "inactive_in_directory")
    return user


@router.get("/auth/config")
def auth_config(rt: RT) -> dict:
    return {"ad_enabled": rt.ad is not None, "ad_domain": rt.settings.ad_email_domain}


def check_password(rt: Runtime, user: User, password: str) -> bool:
    """Verifica la contraseña actual: localmente, o contra AD para cuentas de AD."""
    if user.auth_source != "ad":
        return verify_password(user.password_hash, password)
    if rt.ad is None:
        return False
    try:
        rt.ad.login(user.email, password)
        return True
    except AdAuthFailed:
        return False
    except AdUnavailable:
        raise HTTPException(503, "El servicio de autenticación institucional no está disponible") from None


@router.post("/auth/login")
def login(body: LoginIn, request: Request, response: Response, rt: RT, db: DB) -> dict:
    csrf_check(request)
    email = body.email.strip().lower()
    key = f"{email}|{ip_of(request)}"
    if throttle.blocked(key) or email_throttle.blocked(email):
        raise HTTPException(429, "Demasiados intentos fallidos. Probá de nuevo en unos minutos.")
    user = db.scalar(select(User).where(User.email == email))
    use_ad = rt.ad is not None and (
        user.auth_source == "ad" if user else normalize_identity(email, rt.settings.ad_email_domain) is not None
    )
    if use_ad:
        user = _login_ad(db, rt, request, email, body.password, user, key)
    else:
        ok = verify_password(user.password_hash if user else DUMMY_HASH, body.password)
        if not (user and ok and user.active and user.auth_source == "local"):
            raise _login_fail(db, request, key, email, "bad_credentials")
    throttle.reset(key)
    email_throttle.reset(email)
    user.last_login_at = utcnow()
    token = make_session_token(user, rt.jwt_secret, rt.settings.session_ttl_minutes)
    response.set_cookie(
        COOKIE,
        token,
        max_age=rt.settings.session_ttl_minutes * 60,
        httponly=True,
        samesite="strict",
        secure=rt.settings.cookie_secure,
        path="/",
    )
    log(db, user, request, "login", detail={"source": user.auth_source})
    db.commit()
    return user_out(user)


@router.post("/auth/logout")
def logout(request: Request, response: Response, rt: RT, db: DB) -> dict:
    csrf_check(request)
    token = request.cookies.get(COOKIE)
    claims = decode_session_token(token, rt.jwt_secret) if token else None
    user = db.get(User, claims["sub"]) if claims else None
    if user and user.session_version == claims.get("sv"):
        user.session_version += 1  # invalida este token (y cualquier otra sesión) también en el servidor
        log(db, user, request, "logout")
        db.commit()
    response.delete_cookie(COOKIE, path="/")
    return {"ok": True}


@router.get("/auth/me")
def me(user: CurrentUser) -> dict:
    return user_out(user)


@router.get("/health")
def health() -> dict:
    return {"status": "ok"}


# ------------------------------------------------------------------ usuarios (admin)


@router.get("/users")
def list_users(_: Admin, db: DB) -> list[dict]:
    return [user_out(u) for u in db.scalars(select(User).order_by(User.email))]


@router.post("/users", status_code=201)
def create_user(body: UserCreate, admin: Admin, request: Request, db: DB) -> dict:
    email = str(body.email).lower()
    if db.scalar(select(User.id).where(User.email == email)):
        raise HTTPException(409, "Ya existe un usuario con ese email")
    try:
        pw = hash_password(body.password)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    user = User(email=email, name=body.name, password_hash=pw, role=body.role)
    db.add(user)
    db.flush()
    log(db, admin, request, "user_create", target=email, detail={"role": body.role})
    db.commit()
    return user_out(user)


@router.patch("/users/{user_id}")
def patch_user(user_id: str, body: UserPatch, admin: Admin, request: Request, db: DB, rt: RT) -> dict:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(404, "Usuario no encontrado")
    if user.auth_source == "ad":
        if body.password:
            raise HTTPException(422, "Las cuentas de AD se autentican contra Active Directory: no tienen contraseña local")
        if body.role is not None and body.role != user.role and (rt.settings.admin_groups or rt.settings.editor_groups):
            raise HTTPException(409, "El rol de las cuentas de AD lo define su pertenencia a grupos de AD")
    changed = []
    if body.name is not None:
        user.name = body.name
    if body.role is not None and body.role != user.role:
        user.role = body.role
        user.session_version += 1
        changed.append("role")
    if body.active is not None and body.active != user.active:
        if user.id == admin.id and not body.active:
            raise HTTPException(422, "No podés desactivarte a vos mismo")
        user.active = body.active
        user.session_version += 1
        changed.append("active")
    if body.password:
        try:
            user.password_hash = hash_password(body.password)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        user.session_version += 1
        changed.append("password")
    log(db, admin, request, "user_update", target=user.email, detail={"changed": changed})
    db.commit()
    return user_out(user)


# ------------------------------------------------------------------ carpetas


@router.get("/folders")
def list_folders(user: CurrentUser, db: DB) -> list[dict]:
    out = []
    for f in db.scalars(select(Folder).order_by(Folder.name)):
        level = folder_level(db, user, f.id)
        if level:
            out.append(FolderOut(id=f.id, name=f.name, description=f.description, level=level).model_dump())
    return out


@router.post("/folders", status_code=201)
def create_folder(body: FolderIn, admin: Admin, request: Request, db: DB) -> dict:
    try:
        name = check_name(body.name)
    except VaultError as exc:
        raise HTTPException(422, str(exc)) from exc
    if db.scalar(select(Folder.id).where(Folder.name == name)):
        raise HTTPException(409, "Ya existe una carpeta con ese nombre")
    f = Folder(name=name, description=body.description)
    db.add(f)
    db.flush()
    log(db, admin, request, "folder_create", target=name)
    db.commit()
    return FolderOut(id=f.id, name=f.name, description=f.description, level="write").model_dump()


@router.delete("/folders/{folder_id}", status_code=204)
def delete_folder(folder_id: str, admin: Admin, request: Request, db: DB) -> Response:
    f = db.get(Folder, folder_id)
    if f is None:
        raise HTTPException(404, "Carpeta no encontrada")
    if db.scalar(select(Credential.id).where(Credential.folder_id == f.id).limit(1)):
        raise HTTPException(409, "La carpeta tiene credenciales; vaciala primero")
    db.execute(delete(AgentGrant).where(AgentGrant.folder_id == f.id))
    db.delete(f)
    log(db, admin, request, "folder_delete", target=f.name)
    db.commit()
    return Response(status_code=204)


@router.get("/folders/{folder_id}/access")
def get_access(folder_id: str, _: Admin, db: DB) -> list[dict]:
    rows = db.scalars(select(FolderAccess).where(FolderAccess.folder_id == folder_id))
    return [{"user_id": r.user_id, "level": r.level} for r in rows]


@router.put("/folders/{folder_id}/access")
def set_access(folder_id: str, items: list[AccessItem], admin: Admin, request: Request, db: DB) -> dict:
    f = db.get(Folder, folder_id)
    if f is None:
        raise HTTPException(404, "Carpeta no encontrada")
    db.execute(delete(FolderAccess).where(FolderAccess.folder_id == f.id))
    for it in items:
        if db.get(User, it.user_id) is None:
            raise HTTPException(422, f"Usuario inexistente: {it.user_id}")
        db.add(FolderAccess(user_id=it.user_id, folder_id=f.id, level=it.level))
    log(db, admin, request, "folder_access_set", target=f.name, detail={"entries": len(items)})
    db.commit()
    return {"ok": True}


# ------------------------------------------------------------------ credenciales


def cred_out(c: Credential, level: str, share: CredentialShare | None = None) -> dict:
    out = {
        "id": c.id,
        "ref": c.ref,
        "folder_id": c.folder_id,
        "folder": c.folder.name,
        "name": c.name,
        "type": c.type,
        "meta": c.meta,
        "sensitive": c.sensitive,
        "allow_reveal": c.allow_reveal,
        "version": c.version,
        "can_write": level == "write",
        "access": "shared" if level == "shared" else "folder",
        "created_at": c.created_at.isoformat(),
        "updated_at": c.updated_at.isoformat(),
    }
    if share is not None:
        out.update(
            share_level=share.level,
            shared_until=share.expires_at.isoformat() if share.expires_at else None,
            shared_permanent=share.expires_at is None,
        )
    return out


def load_cred(db: Session, user: User, cred_id: str, need: str = "read") -> tuple[Credential, str, CredentialShare | None]:
    cred = db.scalar(select(Credential).options(joinedload(Credential.folder)).where(Credential.id == cred_id))
    level, share = credential_access(db, user, cred) if cred else (None, None)
    # 404 tanto si no existe como si no tiene acceso, para no filtrar existencia.
    if cred is None or level is None:
        raise HTTPException(404, "Credencial no encontrada")
    if need == "write" and level != "write":
        raise HTTPException(403, "Sin permiso de escritura en la carpeta")
    return cred, level, share


@router.get("/credential-types")
def credential_types(_: CurrentUser) -> list[str]:
    return sorted(ALL_TYPES)


@router.get("/credentials")
def list_credentials(
    user: CurrentUser, db: DB, folder_id: str | None = None, q: str | None = None, shared: bool = False
) -> list[dict]:
    stmt = select(Credential).options(joinedload(Credential.folder)).order_by(Credential.name)
    if folder_id:
        stmt = stmt.where(Credential.folder_id == folder_id)
    shares = {sh.credential_id: sh for sh in active_shares(db, user.id)} if user.active else {}
    levels: dict[str, str | None] = {}
    out = []
    needle = (q or "").lower()
    for c in db.scalars(stmt):
        if c.folder_id not in levels:
            levels[c.folder_id] = folder_level(db, user, c.folder_id)
        level, share = levels[c.folder_id], None
        if not level:
            share = shares.get(c.id)
            if share is None:
                continue
            level = "shared"
        if shared and level != "shared":
            continue
        if needle and needle not in f"{c.ref} {c.meta.get('description', '')}".lower():
            continue
        out.append(cred_out(c, level, share))
    return out


@router.post("/credentials", status_code=201)
def create_cred(body: CredentialIn, user: CurrentUser, request: Request, db: DB, rt: RT) -> dict:
    folder = db.get(Folder, body.folder_id)
    if folder is None or folder_level(db, user, folder.id) != "write":
        raise HTTPException(403, "Sin permiso de escritura en esa carpeta")
    try:
        cred = create_credential(
            db,
            rt.cipher,
            folder=folder,
            name=body.name,
            ctype=body.type,
            meta=body.meta,
            secret=body.secret,
            sensitive=body.sensitive,
            allow_reveal=body.allow_reveal,
            user=user,
        )
    except (VaultError, ValidationFailure) as exc:
        raise HTTPException(422, str(exc)) from exc
    log(db, user, request, "credential_create", credential=cred)
    db.commit()
    return cred_out(cred, "write")


@router.get("/credentials/{cred_id}")
def get_cred(cred_id: str, user: CurrentUser, db: DB) -> dict:
    cred, level, share = load_cred(db, user, cred_id)
    return cred_out(cred, level, share)


@router.patch("/credentials/{cred_id}")
def patch_cred(cred_id: str, body: CredentialPatch, user: CurrentUser, request: Request, db: DB, rt: RT) -> dict:
    cred, level, _ = load_cred(db, user, cred_id, "write")
    changed = []
    try:
        if body.name is not None:
            new = check_name(body.name)
            clash = db.scalar(
                select(Credential.id).where(
                    Credential.folder_id == cred.folder_id, Credential.name == new, Credential.id != cred.id
                )
            )
            if clash:
                raise VaultError("Ya existe una credencial con ese nombre en la carpeta")
            cred.name = new
            changed.append("name")
        if body.meta is not None:
            meta = validate_meta(cred.type, body.meta)
            if cred.type in ("ssh_key", "ssh_password"):
                old = cred.meta
                if (meta["host"], meta["port"]) != (old.get("host"), old.get("port")):
                    meta["host_key"] = ""  # cambió el destino: hay que volver a fijar la clave del host
                elif not meta.get("host_key"):
                    meta["host_key"] = old.get("host_key", "")
            cred.meta = meta
            changed.append("meta")
        if body.sensitive is not None:
            cred.sensitive = body.sensitive
            changed.append("sensitive")
        if body.allow_reveal is not None:
            cred.allow_reveal = body.allow_reveal
            changed.append("allow_reveal")
        if body.secret:
            update_secret(rt.cipher, cred, body.secret)
            changed.append("secret")
    except (VaultError, ValidationFailure) as exc:
        raise HTTPException(422, str(exc)) from exc
    log(db, user, request, "credential_update", credential=cred, detail={"changed": changed})
    db.commit()
    return cred_out(cred, level)


@router.delete("/credentials/{cred_id}", status_code=204)
def delete_cred(cred_id: str, user: CurrentUser, request: Request, db: DB) -> Response:
    cred, _, _ = load_cred(db, user, cred_id, "write")
    db.execute(delete(AgentGrant).where(AgentGrant.credential_id == cred.id))
    db.execute(delete(CredentialShare).where(CredentialShare.credential_id == cred.id))
    log(db, user, request, "credential_delete", credential=cred)
    db.delete(cred)
    db.commit()
    return Response(status_code=204)


@router.post("/credentials/{cred_id}/reveal")
def reveal(cred_id: str, body: RevealIn, user: CurrentUser, request: Request, db: DB, rt: RT) -> dict:
    cred, level, share = load_cred(db, user, cred_id)
    if not reveal_allowed(user, cred, level, share):
        log(db, user, request, "credential_reveal", "denied", credential=cred, detail={"reason": "not_allowed"})
        db.commit()
        raise HTTPException(403, "Esta credencial no se puede revelar con tu rol")
    key = f"reveal|{user.id}"
    if throttle.blocked(key):
        raise HTTPException(429, "Demasiados intentos. Probá de nuevo en unos minutos.")
    if not check_password(rt, user, body.password):
        throttle.fail(key)
        log(db, user, request, "credential_reveal", "denied", credential=cred, detail={"reason": "bad_password"})
        db.commit()
        raise HTTPException(401, "Contraseña incorrecta")
    throttle.reset(key)
    try:
        secret = open_secret(rt.cipher, cred)
    except Exception:  # blob alterado o KEK equivocada
        log(db, user, request, "credential_reveal", "error", credential=cred, detail={"reason": "integrity"})
        db.commit()
        raise HTTPException(500, "Error de integridad al descifrar la credencial") from None
    log(db, user, request, "credential_reveal", credential=cred, detail={"via": "share" if share else "folder"})
    db.commit()
    return {"secret": secret}


@router.post("/credentials/{cred_id}/scan-host-key")
async def scan_key(cred_id: str, user: CurrentUser, db: DB) -> dict:
    cred, _, _ = load_cred(db, user, cred_id, "write")
    if cred.type not in ("ssh_key", "ssh_password"):
        raise HTTPException(422, "Solo aplica a credenciales SSH")
    meta = SshMeta(**cred.meta)
    try:
        key, fingerprint = await scan_host_key(meta.host, meta.port)
    except Exception as exc:
        raise HTTPException(502, f"No se pudo contactar al host: {type(exc).__name__}") from exc
    return {"host_key": key, "fingerprint": fingerprint, "current": meta.host_key}


@router.post("/credentials/{cred_id}/pin-host-key")
def pin_key(cred_id: str, body: PinIn, user: CurrentUser, request: Request, db: DB) -> dict:
    cred, level, _ = load_cred(db, user, cred_id, "write")
    if cred.type not in ("ssh_key", "ssh_password"):
        raise HTTPException(422, "Solo aplica a credenciales SSH")
    parts = body.host_key.split()
    if len(parts) < 2 or not parts[0].startswith(("ssh-", "ecdsa-", "sk-")):
        raise HTTPException(422, "Clave pública OpenSSH inválida")
    cred.meta = {**cred.meta, "host_key": f"{parts[0]} {parts[1]}"}
    log(db, user, request, "credential_pin_host_key", credential=cred)
    db.commit()
    return cred_out(cred, level)


# ------------------------------------------------------------------ compartir credenciales


class ShareIn(BaseModel):
    user_id: str
    level: Literal["use", "reveal"] = "use"  # use: la usa por sus agentes; reveal: además puede ver el valor
    expires_in_minutes: int | None = Field(default=None, ge=5, le=525600)  # None = permanente (máx. 1 año si vence)


def share_out(sh: CredentialShare, u: User) -> dict:
    return {
        "id": sh.id,
        "user_id": u.id,
        "email": u.email,
        "name": u.name,
        "level": sh.level,
        "permanent": sh.expires_at is None,
        "expires_at": sh.expires_at.isoformat() if sh.expires_at else None,
        "expired": bool(sh.expires_at and sh.expires_at <= utcnow()),
        "created_at": sh.created_at.isoformat(),
    }


@router.get("/users/directory")
def users_directory(user: CurrentUser, db: DB) -> list[dict]:
    """Personas activas con las que se puede compartir (no incluye hashes ni datos de sesión)."""
    if user.role == "viewer":
        raise HTTPException(403, "Los lectores no pueden compartir credenciales")
    rows = db.scalars(select(User).where(User.active.is_(True), User.id != user.id).order_by(User.name))
    return [{"id": u.id, "name": u.name, "email": u.email, "role": u.role, "department": u.department} for u in rows]


@router.get("/credentials/{cred_id}/shares")
def list_shares(cred_id: str, user: CurrentUser, db: DB) -> list[dict]:
    cred, _, _ = load_cred(db, user, cred_id, "write")
    rows = db.execute(
        select(CredentialShare, User)
        .join(User, User.id == CredentialShare.user_id)
        .where(CredentialShare.credential_id == cred.id)
        .order_by(CredentialShare.created_at.desc())
    ).all()
    return [share_out(sh, u) for sh, u in rows]


@router.post("/credentials/{cred_id}/shares", status_code=201)
def share_credential(cred_id: str, body: ShareIn, user: CurrentUser, request: Request, db: DB) -> dict:
    cred, _, _ = load_cred(db, user, cred_id, "write")
    target = db.get(User, body.user_id)
    if target is None or not target.active:
        raise HTTPException(404, "Persona no encontrada o inactiva (tiene que haber ingresado a Llaverito al menos una vez)")
    if target.id == user.id:
        raise HTTPException(422, "No tiene sentido compartirla con vos mismo")
    if folder_level(db, target, cred.folder_id):
        raise HTTPException(409, "Esa persona ya tiene acceso por la carpeta")
    if target.role == "viewer" and body.level == "use":
        raise HTTPException(422, "Los lectores no pueden crear agentes: compartí con nivel 'reveal' o cambiá su rol")
    expires = utcnow() + timedelta(minutes=body.expires_in_minutes) if body.expires_in_minutes else None
    share = db.scalar(
        select(CredentialShare).where(CredentialShare.credential_id == cred.id, CredentialShare.user_id == target.id)
    )
    action = "credential_share_update" if share else "credential_share"
    if share is None:
        share = CredentialShare(credential_id=cred.id, user_id=target.id, level=body.level, expires_at=expires, created_by=user.id)
        db.add(share)
    else:
        share.level, share.expires_at, share.created_by = body.level, expires, user.id
    db.flush()
    log(db, user, request, action, credential=cred, target=target.email,
        detail={"level": body.level, "permanent": expires is None, "expires_at": expires.isoformat() if expires else None})
    db.commit()
    return share_out(share, target)


@router.delete("/credentials/{cred_id}/shares/{share_id}", status_code=204)
def unshare_credential(cred_id: str, share_id: int, user: CurrentUser, request: Request, db: DB) -> Response:
    cred, _, _ = load_cred(db, user, cred_id, "write")
    share = db.get(CredentialShare, share_id)
    if share is None or share.credential_id != cred.id:
        raise HTTPException(404, "Compartido no encontrado")
    target = db.get(User, share.user_id)
    log(db, user, request, "credential_unshare", credential=cred, target=target.email if target else share.user_id)
    db.delete(share)
    db.commit()
    return Response(status_code=204)


# ------------------------------------------------------------------ agentes


def agent_out(a: Agent) -> dict:
    return {
        "id": a.id,
        "name": a.name,
        "owner_id": a.owner_id,
        "token_prefix": a.token_prefix,
        "revoked": a.revoked,
        "expires_at": a.expires_at.isoformat() if a.expires_at else None,
        "last_used_at": a.last_used_at.isoformat() if a.last_used_at else None,
        "created_at": a.created_at.isoformat(),
        "grants": [
            {
                "folder_id": g.folder_id,
                "credential_id": g.credential_id,
                "expires_at": g.expires_at.isoformat() if g.expires_at else None,
            }
            for g in a.grants
        ],
    }


def own_agent(db: Session, user: User, agent_id: str) -> Agent:
    a = db.scalar(select(Agent).options(joinedload(Agent.grants)).where(Agent.id == agent_id))
    if a is None or (user.role != "admin" and a.owner_id != user.id):
        raise HTTPException(404, "Agente no encontrado")
    return a


def apply_grants(db: Session, user: User, agent: Agent, grants: list[GrantIn]) -> None:
    new: list[AgentGrant] = []
    for g in grants:
        if bool(g.folder_id) == bool(g.credential_id):
            raise HTTPException(422, "Cada permiso debe indicar folder_id o credential_id (uno solo)")
        if g.credential_id:
            cred = db.get(Credential, g.credential_id)
            allowed = cred is not None and credential_access(db, user, cred)[0] is not None
        else:
            allowed = bool(g.folder_id) and folder_level(db, user, g.folder_id) is not None
        if not allowed:
            raise HTTPException(403, "No podés otorgar acceso a algo que vos no podés ver")
        new.append(AgentGrant(folder_id=g.folder_id, credential_id=g.credential_id))
    agent.grants.clear()
    db.flush()
    agent.grants.extend(new)


@router.get("/agents")
def list_agents(user: CurrentUser, db: DB) -> list[dict]:
    stmt = select(Agent).options(joinedload(Agent.grants)).order_by(Agent.created_at.desc())
    if user.role != "admin":
        stmt = stmt.where(Agent.owner_id == user.id)
    return [agent_out(a) for a in db.scalars(stmt).unique()]


@router.post("/agents", status_code=201)
def create_agent(body: AgentIn, user: CurrentUser, request: Request, db: DB) -> dict:
    if user.role == "viewer":
        raise HTTPException(403, "Los lectores no pueden crear agentes")
    token = generate_agent_token()
    agent = Agent(
        name=body.name,
        owner_id=user.id,
        token_prefix=token[:10],
        token_hash=hash_agent_token(token),
        expires_at=utcnow() + timedelta(days=body.expires_in_days) if body.expires_in_days else None,
    )
    db.add(agent)
    db.flush()
    apply_grants(db, user, agent, body.grants)
    log(db, user, request, "agent_create", target=agent.name, detail={"grants": len(body.grants)})
    db.commit()
    return {**agent_out(agent), "token": token}  # el token solo se muestra ahora


@router.put("/agents/{agent_id}/grants")
def set_grants(agent_id: str, grants: list[GrantIn], user: CurrentUser, request: Request, db: DB) -> dict:
    agent = own_agent(db, user, agent_id)
    apply_grants(db, user, agent, grants)
    log(db, user, request, "agent_grants_set", target=agent.name, detail={"grants": len(grants)})
    db.commit()
    return agent_out(agent)


@router.delete("/agents/{agent_id}", status_code=204)
def revoke_agent(agent_id: str, user: CurrentUser, request: Request, db: DB) -> Response:
    agent = own_agent(db, user, agent_id)
    agent.revoked = True
    log(db, user, request, "agent_revoke", target=agent.name)
    db.commit()
    return Response(status_code=204)


# ------------------------------------------------------------------ aprobaciones


def approval_out(a: ApprovalRequest) -> dict:
    status = a.status
    if status in ("pending", "approved") and a.expires_at <= utcnow():
        status = "expired"
    return {
        "id": a.id,
        "agent": a.agent.name,
        "credential": a.credential.ref,
        "action": a.action,
        "summary": a.summary,
        "reason": a.reason,
        "status": status,
        "requested_at": a.requested_at.isoformat(),
        "expires_at": a.expires_at.isoformat(),
    }


@router.get("/approvals")
def list_approvals(user: CurrentUser, db: DB, status: str | None = None) -> list[dict]:
    stmt = (
        select(ApprovalRequest)
        .options(joinedload(ApprovalRequest.agent), joinedload(ApprovalRequest.credential).joinedload(Credential.folder))
        .order_by(ApprovalRequest.requested_at.desc())
        .limit(200)
    )
    if user.role != "admin":
        stmt = stmt.join(Agent, ApprovalRequest.agent_id == Agent.id).where(Agent.owner_id == user.id)
    out = [approval_out(a) for a in db.scalars(stmt).unique()]
    return [a for a in out if status is None or a["status"] == status]


@router.post("/approvals/{approval_id}/decide")
def decide(approval_id: str, body: DecideIn, user: CurrentUser, request: Request, db: DB) -> dict:
    ap = db.scalar(
        select(ApprovalRequest)
        .options(joinedload(ApprovalRequest.agent), joinedload(ApprovalRequest.credential).joinedload(Credential.folder))
        .where(ApprovalRequest.id == approval_id)
    )
    if ap is None or (user.role != "admin" and ap.agent.owner_id != user.id):
        raise HTTPException(404, "Solicitud no encontrada")
    if user.role == "viewer":
        raise HTTPException(403, "Los lectores no pueden decidir aprobaciones")
    if user.role != "admin" and credential_access(db, user, ap.credential)[0] is None:
        raise HTTPException(404, "Solicitud no encontrada")  # perdió el acceso a la carpeta
    if ap.status != "pending" or ap.expires_at <= utcnow():
        raise HTTPException(409, "La solicitud ya no está pendiente")
    ap.status = "approved" if body.approve else "denied"
    ap.decided_by = user.id
    ap.decided_at = utcnow()
    log(
        db,
        user,
        request,
        "approval_approve" if body.approve else "approval_deny",
        credential=ap.credential,
        target=ap.summary[:500],
        detail={"approval_id": ap.id, "agent": ap.agent.name},
    )
    db.commit()
    return approval_out(ap)


# ------------------------------------------------------------------ auditoría


@router.get("/audit")
def list_audit(
    _: Admin,
    db: DB,
    limit: int = 100,
    before_id: int | None = None,
    action: str | None = None,
    credential_id: str | None = None,
) -> list[dict]:
    stmt = select(AuditLog).order_by(AuditLog.id.desc()).limit(max(1, min(limit, 500)))
    if before_id:
        stmt = stmt.where(AuditLog.id < before_id)
    if action:
        stmt = stmt.where(AuditLog.action == action)
    if credential_id:
        stmt = stmt.where(AuditLog.credential_id == credential_id)
    return [
        {
            "id": e.id,
            "ts": e.ts.isoformat(),
            "actor_type": e.actor_type,
            "actor": e.actor_name,
            "action": e.action,
            "outcome": e.outcome,
            "credential": e.credential_name,
            "target": e.target,
            "detail": e.detail,
            "ip": e.ip,
        }
        for e in db.scalars(stmt)
    ]


@router.get("/audit/verify")
def verify_audit(_: Admin, db: DB) -> dict:
    return audit.verify_chain(db)

