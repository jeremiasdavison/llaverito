import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Text,
    TypeDecorator,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(UTC)


def new_id() -> str:
    return uuid.uuid4().hex


class UTCDateTime(TypeDecorator):
    """Guarda siempre UTC y devuelve datetimes con zona horaria (SQLite pierde el tzinfo)."""

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Any) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    def process_result_value(self, value: datetime | None, dialect: Any) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(255))
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16), default="viewer")  # admin | editor | viewer
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    session_version: Mapped[int] = mapped_column(Integer, default=1)
    auth_source: Mapped[str] = mapped_column(String(8), default="local")  # local | ad
    ad_sam: Mapped[str | None] = mapped_column(String(128), nullable=True)
    department: Mapped[str | None] = mapped_column(String(255), nullable=True)
    last_login_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class Folder(Base):
    __tablename__ = "folders"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    description: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)

    credentials: Mapped[list["Credential"]] = relationship(back_populates="folder")


class FolderAccess(Base):
    __tablename__ = "folder_access"
    __table_args__ = (UniqueConstraint("user_id", "folder_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    folder_id: Mapped[str] = mapped_column(ForeignKey("folders.id", ondelete="CASCADE"), index=True)
    level: Mapped[str] = mapped_column(String(8))  # read | write


class Credential(Base):
    __tablename__ = "credentials"
    __table_args__ = (UniqueConstraint("folder_id", "name"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    folder_id: Mapped[str] = mapped_column(ForeignKey("folders.id"), index=True)
    name: Mapped[str] = mapped_column(String(120))
    type: Mapped[str] = mapped_column(String(24))
    meta: Mapped[dict] = mapped_column(JSON, default=dict)
    sensitive: Mapped[bool] = mapped_column(Boolean, default=False)
    allow_reveal: Mapped[bool] = mapped_column(Boolean, default=True)
    wrapped_dek: Mapped[bytes] = mapped_column(LargeBinary)
    blob: Mapped[bytes] = mapped_column(LargeBinary)
    version: Mapped[int] = mapped_column(Integer, default=1)
    created_by: Mapped[str | None] = mapped_column(String(32), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, onupdate=utcnow)

    folder: Mapped[Folder] = relationship(back_populates="credentials")

    @property
    def ref(self) -> str:
        return f"cred://{self.folder.name}/{self.name}"


class CredentialShare(Base):
    """Acceso a una credencial concreta para una persona, permanente (expires_at NULL) o con vencimiento."""

    __tablename__ = "credential_shares"
    __table_args__ = (UniqueConstraint("credential_id", "user_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    credential_id: Mapped[str] = mapped_column(ForeignKey("credentials.id"), index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    level: Mapped[str] = mapped_column(String(8))  # use | reveal
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(32), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class Agent(Base):
    __tablename__ = "agents"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(120))
    owner_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    token_prefix: Mapped[str] = mapped_column(String(12))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)

    grants: Mapped[list["AgentGrant"]] = relationship(
        back_populates="agent", cascade="all, delete-orphan"
    )


class AgentGrant(Base):
    __tablename__ = "agent_grants"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    agent_id: Mapped[str] = mapped_column(ForeignKey("agents.id", ondelete="CASCADE"), index=True)
    folder_id: Mapped[str | None] = mapped_column(ForeignKey("folders.id"), nullable=True)
    credential_id: Mapped[str | None] = mapped_column(ForeignKey("credentials.id"), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)

    agent: Mapped[Agent] = relationship(back_populates="grants")


class ApprovalRequest(Base):
    __tablename__ = "approval_requests"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    agent_id: Mapped[str] = mapped_column(ForeignKey("agents.id"), index=True)
    credential_id: Mapped[str] = mapped_column(ForeignKey("credentials.id"))
    action: Mapped[str] = mapped_column(String(24))
    action_hash: Mapped[str] = mapped_column(String(64))
    summary: Mapped[str] = mapped_column(Text)
    reason: Mapped[str] = mapped_column(String(255), default="")
    status: Mapped[str] = mapped_column(String(12), default="pending")
    # pending | approved | denied | consumed
    requested_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)
    decided_by: Mapped[str | None] = mapped_column(String(32), nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)

    agent: Mapped[Agent] = relationship()
    credential: Mapped[Credential] = relationship()


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    actor_type: Mapped[str] = mapped_column(String(8))  # user | agent | system
    actor_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    actor_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    action: Mapped[str] = mapped_column(String(48), index=True)
    outcome: Mapped[str] = mapped_column(String(16))  # ok | denied | error | pending
    credential_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    credential_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    target: Mapped[str | None] = mapped_column(Text, nullable=True)
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64))
