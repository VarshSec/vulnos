"""Database session lifecycle and engine management for VulnOS.

Provides connection pooling with pool pre-ping, session factory, and a FastAPI
request-scoped session dependency with automatic transaction commit/rollback.
"""

from collections.abc import Generator

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from backend.app.core.config import Settings, get_settings


def create_db_engine(settings: Settings | None = None) -> Engine:
    """Create a configured SQLAlchemy engine."""
    if settings is None:
        settings = get_settings()

    kwargs: dict[str, object] = {
        "pool_pre_ping": True,
        "echo": settings.DATABASE_ECHO,
    }
    if not settings.DATABASE_URL.startswith("sqlite"):
        kwargs["pool_size"] = settings.DATABASE_POOL_SIZE
        kwargs["max_overflow"] = settings.DATABASE_MAX_OVERFLOW

    eng = create_engine(settings.DATABASE_URL, **kwargs)
    from backend.app.db.tenant import attach_tenant_pool_listeners

    attach_tenant_pool_listeners(eng)
    return eng


# Default process engine and session factory
_settings = get_settings()
engine = create_db_engine(_settings)

SessionLocal = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,
)


def get_db() -> Generator[Session]:
    """FastAPI request-scoped database session dependency.

    Ensures rollback on exceptions, commit on clean exit, and connection release.
    """
    session: Session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
