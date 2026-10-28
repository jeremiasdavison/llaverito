import hashlib
import secrets
import threading
import time
from datetime import timedelta

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

from .models import User, utcnow

_hasher = PasswordHasher()

MIN_PASSWORD_LEN = 12
# Hash que nunca verifica: las cuentas de AD no tienen contraseña local.
UNUSABLE_HASH = "!active-directory"
AGENT_TOKEN_PREFIX = "llv_"


def hash_password(password: str) -> str:
    if len(password) < MIN_PASSWORD_LEN:
        raise ValueError(f"La contraseña debe tener al menos {MIN_PASSWORD_LEN} caracteres")
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except (VerificationError, InvalidHashError):
        return False


# Hash ficticio para igualar tiempos cuando el usuario no existe.
DUMMY_HASH = _hasher.hash("llaverito-dummy-password")


def make_session_token(user: User, secret: bytes, ttl_minutes: int) -> str:
    now = utcnow()
    return jwt.encode(
        {
            "sub": user.id,
            "sv": user.session_version,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=ttl_minutes)).timestamp()),
        },
        secret,
        algorithm="HS256",
    )


def decode_session_token(token: str, secret: bytes) -> dict | None:
    try:
        return jwt.decode(token, secret, algorithms=["HS256"], options={"require": ["exp", "sub"]})
    except jwt.PyJWTError:
        return None


def generate_agent_token() -> str:
    return AGENT_TOKEN_PREFIX + secrets.token_urlsafe(32)


def hash_agent_token(token: str) -> str:
    # El token ya tiene 256 bits de entropía: SHA-256 alcanza (no hace falta KDF lento).
    return hashlib.sha256(token.encode()).hexdigest()


class LoginThrottle:
    """Bloqueo temporal tras fallos repetidos (en memoria, por proceso)."""

    def __init__(self, max_failures: int = 5, window_seconds: int = 300):
        self.max_failures = max_failures
        self.window = window_seconds
        self._failures: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def _recent(self, key: str) -> list[float]:
        cutoff = time.monotonic() - self.window
        items = [t for t in self._failures.get(key, []) if t > cutoff]
        self._failures[key] = items
        return items

    def blocked(self, key: str) -> bool:
        with self._lock:
            return len(self._recent(key)) >= self.max_failures

    def fail(self, key: str) -> None:
        with self._lock:
            self._recent(key).append(time.monotonic())

    def reset(self, key: str) -> None:
        with self._lock:
            self._failures.pop(key, None)


class RateLimiter:
    """Ventana deslizante de 60 s por clave."""

    def __init__(self, per_minute: int):
        self.per_minute = per_minute
        self._hits: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            hits = [t for t in self._hits.get(key, []) if t > now - 60]
            if len(hits) >= self.per_minute:
                self._hits[key] = hits
                return False
            hits.append(now)
            self._hits[key] = hits
            return True
