"""SQLAlchemy Declarative Base with architectural naming conventions."""

from sqlalchemy import MetaData
from sqlalchemy.orm import DeclarativeBase

# Standard PostgreSQL constraint naming convention per DATABASE_DESIGN.md Section 2
POSTGRESQL_NAMING_CONVENTION: dict[str, str] = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

metadata = MetaData(naming_convention=POSTGRESQL_NAMING_CONVENTION)


class Base(DeclarativeBase):
    """Shared declarative base for all VulnOS database models."""

    metadata = metadata

    def __repr__(self) -> str:
        attrs: list[str] = []
        for col in self.__table__.columns:
            val = getattr(self, col.name, None)
            attrs.append(f"{col.name}={val!r}")
        return f"<{self.__class__.__name__}({', '.join(attrs)})>"
