"""Tests for database session lifecycle and engine creation.

Tests engine configuration parameters and session dependency commit/rollback behavior.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy.orm import Session

from backend.app.core.config import Settings
from backend.app.db.session import create_db_engine, get_db


class TestEngineConfiguration:
    """Verify engine creation uses application settings correctly."""

    def test_engine_pool_pre_ping_enabled(self) -> None:
        custom_settings = Settings(
            DATABASE_URL="sqlite:///:memory:",
            DATABASE_POOL_SIZE=5,
            DATABASE_MAX_OVERFLOW=10,
            DATABASE_ECHO=False,
        )
        engine = create_db_engine(custom_settings)
        assert engine.pool._pre_ping is True

    def test_engine_echo_configuration(self) -> None:
        custom_settings = Settings(
            DATABASE_URL="sqlite:///:memory:",
            DATABASE_ECHO=True,
        )
        engine = create_db_engine(custom_settings)
        assert engine.echo is True


class TestGetDBSessionDependency:
    """Verify get_db transaction lifecycle."""

    @patch("backend.app.db.session.SessionLocal")
    def test_get_db_commits_on_success(self, mock_session_factory: MagicMock) -> None:
        mock_session = MagicMock(spec=Session)
        mock_session_factory.return_value = mock_session

        gen = get_db()
        session = next(gen)
        assert session is mock_session
        assert mock_session.commit.call_count == 0

        # Simulate clean completion of FastAPI request
        with pytest.raises(StopIteration):
            next(gen)

        mock_session.commit.assert_called_once()
        mock_session.rollback.assert_not_called()
        mock_session.close.assert_called_once()

    @patch("backend.app.db.session.SessionLocal")
    def test_get_db_rolls_back_on_exception(self, mock_session_factory: MagicMock) -> None:
        mock_session = MagicMock(spec=Session)
        mock_session_factory.return_value = mock_session

        gen = get_db()
        session = next(gen)
        assert session is mock_session

        # Simulate an exception raised during request handling
        test_exception = RuntimeError("Simulated DB handler failure")
        with pytest.raises(RuntimeError, match="Simulated DB handler failure"):
            gen.throw(test_exception)

        mock_session.commit.assert_not_called()
        mock_session.rollback.assert_called_once()
        mock_session.close.assert_called_once()
