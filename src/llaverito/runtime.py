from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterator

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from .config import Settings
from .crypto import Cipher
from .adauth import AdClient, AdDirectory
from .models import Base


@dataclass
class Runtime:
    settings: Settings
    engine: Engine
    sessionmaker: sessionmaker
    cipher: Cipher
    jwt_secret: bytes
    ad: AdClient | None = None
    directory: AdDirectory | None = None

    @contextmanager
    def session(self) -> Iterator[Session]:
        """Sesión con commit al salir sin error, rollback si hay excepción."""
        s = self.sessionmaker()
        try:
            yield s
            s.commit()
        except BaseException:
            s.rollback()
            raise
        finally:
            s.close()


def build_runtime(settings: Settings) -> Runtime:
    settings.validate_ad()
    url = settings.database_url
    kwargs: dict = {"future": True, "pool_pre_ping": True}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
        if ":memory:" in url or url in ("sqlite://", "sqlite:///"):
            kwargs["poolclass"] = StaticPool
    elif url.startswith("postgresql://"):
        url = url.replace("postgresql://", "postgresql+psycopg://", 1)
    engine = create_engine(url, **kwargs)
    Base.metadata.create_all(engine)
    cipher = Cipher(settings.load_kek())
    return Runtime(
        settings=settings,
        engine=engine,
        sessionmaker=sessionmaker(engine, expire_on_commit=False),
        cipher=cipher,
        jwt_secret=cipher.derive_subkey(b"jwt"),
        ad=AdClient(settings) if settings.ad_api_url else None,
        directory=AdDirectory(settings),
    )
