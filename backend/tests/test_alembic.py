"""Tests for Alembic configuration, migration scripts, and metadata alignment."""

from __future__ import annotations

import configparser
import importlib
from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory

import backend.app.db.models  # noqa: F401
from backend.app.db.base import Base


class TestAlembicConfiguration:
    """Verify alembic.ini and script directory structure."""

    def test_alembic_ini_exists(self) -> None:
        ini_path = Path("alembic.ini")
        assert ini_path.is_file()

        parser = configparser.ConfigParser()
        parser.read(ini_path)
        assert parser.has_section("alembic")
        assert parser.get("alembic", "script_location") == "backend/alembic"

    def test_alembic_script_directory_loads(self) -> None:
        config = Config("alembic.ini")
        script = ScriptDirectory.from_config(config)
        heads = script.get_heads()
        assert len(heads) == 1
        assert heads[0] == "0004"

    def test_baseline_revision_metadata(self) -> None:
        baseline_module = importlib.import_module("backend.alembic.versions.0001_phase2_baseline")
        assert baseline_module.revision == "0001"
        assert baseline_module.down_revision is None
        assert callable(baseline_module.upgrade)
        assert callable(baseline_module.downgrade)

    def test_rls_revision_metadata(self) -> None:
        rls_module = importlib.import_module("backend.alembic.versions.0002_phase2_rls")
        assert rls_module.revision == "0002"
        assert rls_module.down_revision == "0001"
        assert callable(rls_module.upgrade)
        assert callable(rls_module.downgrade)

    def test_authorization_records_revision_metadata(self) -> None:
        rev_name = "backend.alembic.versions.0003_phase2_authorization_records"
        auth_module = importlib.import_module(rev_name)
        assert auth_module.revision == "0003"
        assert auth_module.down_revision == "0002"
        assert callable(auth_module.upgrade)
        assert callable(auth_module.downgrade)

    def test_scope_rules_revision_metadata(self) -> None:
        rev_name = "backend.alembic.versions.0004_phase2_scope_rules"
        rules_module = importlib.import_module(rev_name)
        assert rules_module.revision == "0004"
        assert rules_module.down_revision == "0003"
        assert callable(rules_module.upgrade)
        assert callable(rules_module.downgrade)

    def test_all_50_tables_in_baseline_migration(self) -> None:
        """Inspect the migration file to confirm all 50 tables are mentioned in upgrade."""
        migration_source = Path("backend/alembic/versions/0001_phase2_baseline.py").read_text(
            encoding="utf-8"
        )
        for table_name in Base.metadata.tables:
            assert (
                f'"{table_name}"' in migration_source
                or f"'{table_name}'" in migration_source
                or f" {table_name} " in migration_source
            ), f"Table {table_name} not found in 0001_phase2_baseline.py migration script"
