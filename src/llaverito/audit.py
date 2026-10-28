"""Auditoría append-only con cadena de hashes (cada fila incluye el hash de la anterior).

La cadena no impide que alguien con acceso a la base borre filas, pero `verify_chain`
detecta cualquier modificación o eliminación en el medio. Nunca se registran valores secretos.
"""

import hashlib
import json
import threading
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from .models import AuditLog, Credential, utcnow

GENESIS = "0" * 64
_lock = threading.Lock()


def _digest(prev: str, e: AuditLog) -> str:
    payload = json.dumps(
        [
            e.ts.isoformat(),
            e.actor_type,
            e.actor_id,
            e.actor_name,
            e.action,
            e.outcome,
            e.credential_id,
            e.credential_name,
            e.target,
            e.detail,
            e.ip,
        ],
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )
    return hashlib.sha256((prev + payload).encode()).hexdigest()


def record(
    session: Session,
    *,
    actor_type: str,
    actor_id: str | None,
    actor_name: str | None,
    action: str,
    outcome: str,
    credential: Credential | None = None,
    target: str | None = None,
    detail: dict[str, Any] | None = None,
    ip: str | None = None,
) -> AuditLog:
    with _lock:
        if session.bind is not None and session.bind.dialect.name == "postgresql":
            session.execute(text("SELECT pg_advisory_xact_lock(727274)"))
        prev = session.scalar(select(AuditLog.hash).order_by(AuditLog.id.desc()).limit(1)) or GENESIS
        entry = AuditLog(
            ts=utcnow(),
            actor_type=actor_type,
            actor_id=actor_id,
            actor_name=actor_name,
            action=action,
            outcome=outcome,
            credential_id=credential.id if credential else None,
            credential_name=credential.ref if credential else None,
            target=target[:2000] if target else None,
            detail=detail or {},
            ip=ip,
            prev_hash=prev,
            hash="",
        )
        entry.hash = _digest(prev, entry)
        session.add(entry)
        session.flush()
        return entry


def verify_chain(session: Session) -> dict:
    prev = GENESIS
    count = 0
    for entry in session.scalars(select(AuditLog).order_by(AuditLog.id)):
        if entry.prev_hash != prev or entry.hash != _digest(prev, entry):
            return {"ok": False, "checked": count, "broken_at": entry.id}
        prev = entry.hash
        count += 1
    return {"ok": True, "checked": count, "broken_at": None}
