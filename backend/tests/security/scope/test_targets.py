"""Unit and security tests for VulnOS Target Management Service (P2.5.3).

Validates:
- Deterministic normalization during target creation.
- Project isolation and cross-project target access denial.
- Duplicate target prevention within the same project.
- Retrieval, listing, filtering, pagination, metadata updates, and archiving.
- Append-only audit log recording.
- Critical architectural invariant: Targets are discovery seeds, never authorization permits.
"""

from __future__ import annotations

from collections.abc import Generator

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from backend.app.db.base import Base
from backend.app.db.models.audit import AuditLog
from backend.app.db.models.identity import (
    AuthorizationRecord,
    Project,
    ProjectMember,
    ScopeRule,
    ScopeVersion,
    Target,
    User,
)
from backend.app.db.types import uuid7
from backend.app.scope.exceptions import DuplicateTargetError, TargetNotFoundError
from backend.app.scope.normalization import MalformedTargetError, TargetType
from backend.app.scope.schemas import TargetCreateRequest, TargetUpdateRequest
from backend.app.scope.targets import (
    archive_target,
    create_target,
    get_target,
    list_targets,
    update_target,
)


@pytest.fixture
def target_db() -> Generator[Session]:
    """In-memory SQLite session with schema required for targets, projects, and audit logs."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    tables = [
        User.__table__,
        Project.__table__,
        ProjectMember.__table__,
        Target.__table__,
        AuditLog.__table__,
        AuthorizationRecord.__table__,
        ScopeVersion.__table__,
        ScopeRule.__table__,
    ]
    Base.metadata.create_all(engine, tables=tables)  # type: ignore[arg-type]
    session = Session(bind=engine)
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


@pytest.fixture
def test_user(target_db: Session) -> User:
    """Create test operator user."""
    user = User(
        id=uuid7(),
        email="operator@vulnos.test",
        display_name="Test Operator",
        password_hash="test_argon2id_hash",
        is_active=True,
    )
    target_db.add(user)
    target_db.commit()
    target_db.refresh(user)
    return user


@pytest.fixture
def test_project(target_db: Session, test_user: User) -> Project:
    """Create test project."""
    project = Project(
        id=uuid7(),
        name="Project Alpha",
        slug="project-alpha",
        owner_id=test_user.id,
        status="active",
    )
    target_db.add(project)
    target_db.commit()
    target_db.refresh(project)
    return project


@pytest.fixture
def other_project(target_db: Session, test_user: User) -> Project:
    """Create secondary project for cross-project isolation tests."""
    project = Project(
        id=uuid7(),
        name="Project Beta",
        slug="project-beta",
        owner_id=test_user.id,
        status="active",
    )
    target_db.add(project)
    target_db.commit()
    target_db.refresh(project)
    return project


# -----------------------------------------------------------------------------
# Target Creation & Normalization Tests
# -----------------------------------------------------------------------------


def test_create_target_domain_normalized(
    target_db: Session, test_project: Project, test_user: User
) -> None:
    """Target creation normalizes domain names to lowercase, stripping trailing dots."""
    req = TargetCreateRequest(
        name="Primary Domain",
        seed_type=TargetType.DOMAIN,
        seed_value="EXAMPLE.COM.",
        description="Production domain",
    )
    target = create_target(
        db=target_db,
        project_id=test_project.id,
        user_id=test_user.id,
        data=req,
    )
    target_db.commit()

    assert target.seed_value == "example.com"
    assert target.seed_type == "domain"
    assert target.status == "active"
    assert target.created_by == test_user.id
    assert target.project_id == test_project.id


def test_create_target_url_normalized(
    target_db: Session, test_project: Project, test_user: User
) -> None:
    """Target creation strips default ports and removes dot-segments from URLs."""
    req = TargetCreateRequest(
        name="API Gateway",
        seed_type=TargetType.URL,
        seed_value="HTTPS://EXAMPLE.COM:443/api/./v1/?b=2&a=1#frag",
    )
    target = create_target(
        db=target_db,
        project_id=test_project.id,
        user_id=test_user.id,
        data=req,
    )
    target_db.commit()

    assert target.seed_value == "https://example.com/api/v1/?a=1&b=2"


def test_create_target_ip_canonicalized(
    target_db: Session, test_project: Project, test_user: User
) -> None:
    """Target creation unpacks IPv4-mapped IPv6 addresses to native IPv4."""
    req = TargetCreateRequest(
        name="Internal Server",
        seed_type=TargetType.IP,
        seed_value="::ffff:192.0.2.1",
    )
    target = create_target(
        db=target_db,
        project_id=test_project.id,
        user_id=test_user.id,
        data=req,
    )
    target_db.commit()

    assert target.seed_value == "192.0.2.1"


def test_create_target_repository_normalized(
    target_db: Session, test_project: Project, test_user: User
) -> None:
    """Target creation transcodes SSH git format into canonical HTTPS URL."""
    req = TargetCreateRequest(
        name="Source Code",
        seed_type=TargetType.REPOSITORY,
        seed_value="git@github.com:VarshSec/vulnos.git",
    )
    target = create_target(
        db=target_db,
        project_id=test_project.id,
        user_id=test_user.id,
        data=req,
    )
    target_db.commit()

    assert target.seed_value == "https://github.com/VarshSec/vulnos"


def test_create_target_invalid_syntax_rejected(
    target_db: Session, test_project: Project, test_user: User
) -> None:
    """Target creation fails with normalization exception on invalid input."""
    req = TargetCreateRequest(
        name="Bad Domain",
        seed_type=TargetType.DOMAIN,
        seed_value="in valid domain",
    )
    with pytest.raises(MalformedTargetError):
        create_target(
            db=target_db,
            project_id=test_project.id,
            user_id=test_user.id,
            data=req,
        )


# -----------------------------------------------------------------------------
# Duplicate Prevention & Project Isolation Tests
# -----------------------------------------------------------------------------


def test_create_duplicate_target_same_project_rejected(
    target_db: Session, test_project: Project, test_user: User
) -> None:
    """Duplicate normalized target seeds within the same project are rejected."""
    req1 = TargetCreateRequest(
        name="First Target",
        seed_type=TargetType.DOMAIN,
        seed_value="example.com",
    )
    create_target(target_db, test_project.id, test_user.id, req1)
    target_db.commit()

    req2 = TargetCreateRequest(
        name="Duplicate Target",
        seed_type=TargetType.DOMAIN,
        seed_value="EXAMPLE.COM.",  # Normalizes to identical string
    )
    with pytest.raises(DuplicateTargetError, match="already exists"):
        create_target(target_db, test_project.id, test_user.id, req2)


def test_create_same_target_different_projects_allowed(
    target_db: Session, test_project: Project, other_project: Project, test_user: User
) -> None:
    """Identical targets can exist independently in different projects."""
    req = TargetCreateRequest(
        name="Common Domain",
        seed_type=TargetType.DOMAIN,
        seed_value="example.com",
    )
    t1 = create_target(target_db, test_project.id, test_user.id, req)
    t2 = create_target(target_db, other_project.id, test_user.id, req)
    target_db.commit()

    assert t1.id != t2.id
    assert t1.project_id == test_project.id
    assert t2.project_id == other_project.id


# -----------------------------------------------------------------------------
# Retrieval, Project Scoping & Listing Tests
# -----------------------------------------------------------------------------


def test_get_target_success(target_db: Session, test_project: Project, test_user: User) -> None:
    """Target can be retrieved by ID within its project."""
    req = TargetCreateRequest(
        name="API",
        seed_type=TargetType.DOMAIN,
        seed_value="api.example.com",
    )
    created = create_target(target_db, test_project.id, test_user.id, req)
    target_db.commit()

    fetched = get_target(target_db, test_project.id, created.id)
    assert fetched.id == created.id
    assert fetched.seed_value == "api.example.com"


def test_get_target_cross_project_isolation(
    target_db: Session, test_project: Project, other_project: Project, test_user: User
) -> None:
    """Attempting to access Project A's target under Project B raises TargetNotFoundError."""
    req = TargetCreateRequest(
        name="Project A Secret Target",
        seed_type=TargetType.DOMAIN,
        seed_value="secret.corp.internal",
    )
    t_a = create_target(target_db, test_project.id, test_user.id, req)
    target_db.commit()

    with pytest.raises(TargetNotFoundError):
        get_target(target_db, other_project.id, t_a.id)


def test_get_nonexistent_target_raises(target_db: Session, test_project: Project) -> None:
    """Querying a non-existent UUID raises TargetNotFoundError."""
    with pytest.raises(TargetNotFoundError):
        get_target(target_db, test_project.id, uuid7())


def test_list_targets_project_isolation_and_filters(
    target_db: Session, test_project: Project, other_project: Project, test_user: User
) -> None:
    """Listing targets respects project scoping, pagination, and status filters."""
    # Create 3 targets in test_project
    create_target(
        target_db,
        test_project.id,
        test_user.id,
        TargetCreateRequest(name="T1", seed_type=TargetType.DOMAIN, seed_value="t1.example.com"),
    )
    create_target(
        target_db,
        test_project.id,
        test_user.id,
        TargetCreateRequest(name="T2", seed_type=TargetType.IP, seed_value="198.51.100.1"),
    )
    t3 = create_target(
        target_db,
        test_project.id,
        test_user.id,
        TargetCreateRequest(
            name="T3", seed_type=TargetType.URL, seed_value="https://t3.example.com/"
        ),
    )
    # Archive t3
    archive_target(target_db, test_project.id, t3.id, test_user.id)

    # Create 1 target in other_project
    create_target(
        target_db,
        other_project.id,
        test_user.id,
        TargetCreateRequest(
            name="Other", seed_type=TargetType.DOMAIN, seed_value="other.example.com"
        ),
    )
    target_db.commit()

    # List all in test_project
    items, total = list_targets(target_db, test_project.id)
    assert total == 3
    assert len(items) == 3

    # Filter by status="active"
    active_items, active_total = list_targets(target_db, test_project.id, status="active")
    assert active_total == 2
    assert len(active_items) == 2

    # Filter by status="archived"
    arch_items, arch_total = list_targets(target_db, test_project.id, status="archived")
    assert arch_total == 1
    assert len(arch_items) == 1
    assert arch_items[0].id == t3.id

    # Filter by seed_type="ip"
    ip_items, ip_total = list_targets(target_db, test_project.id, seed_type="ip")
    assert ip_total == 1
    assert ip_items[0].seed_type == "ip"

    # Pagination: limit=1, offset=1
    paged_items, paged_total = list_targets(target_db, test_project.id, limit=1, offset=1)
    assert paged_total == 3
    assert len(paged_items) == 1


# -----------------------------------------------------------------------------
# Metadata Updates & Archiving Tests
# -----------------------------------------------------------------------------


def test_update_target_metadata(target_db: Session, test_project: Project, test_user: User) -> None:
    """Target name and description can be updated."""
    target = create_target(
        target_db,
        test_project.id,
        test_user.id,
        TargetCreateRequest(
            name="Initial Name",
            seed_type=TargetType.DOMAIN,
            seed_value="example.com",
            description="Old description",
        ),
    )
    target_db.commit()

    updated = update_target(
        target_db,
        test_project.id,
        target.id,
        test_user.id,
        TargetUpdateRequest(
            name="Updated Name",
            description="New description",
        ),
    )
    target_db.commit()

    assert updated.name == "Updated Name"
    assert updated.description == "New description"
    assert updated.seed_value == "example.com"  # Seed value unmodified


def test_update_target_status_and_timestamps(
    target_db: Session, test_project: Project, test_user: User
) -> None:
    """Updating status to archived sets archived_at; reactivating clears it."""
    target = create_target(
        target_db,
        test_project.id,
        test_user.id,
        TargetCreateRequest(
            name="Status Test",
            seed_type=TargetType.DOMAIN,
            seed_value="status.example.com",
        ),
    )
    target_db.commit()
    assert target.archived_at is None

    # Archive via update
    updated = update_target(
        target_db,
        test_project.id,
        target.id,
        test_user.id,
        TargetUpdateRequest(status="archived"),
    )
    target_db.commit()
    assert updated.status == "archived"
    assert updated.archived_at is not None

    # Reactivate via update
    reactivated = update_target(
        target_db,
        test_project.id,
        target.id,
        test_user.id,
        TargetUpdateRequest(status="active"),
    )
    target_db.commit()
    assert reactivated.status == "active"
    assert reactivated.archived_at is None


def test_archive_target_idempotent(
    target_db: Session, test_project: Project, test_user: User
) -> None:
    """archive_target soft-deletes the target and repeated calls are no-ops."""
    target = create_target(
        target_db,
        test_project.id,
        test_user.id,
        TargetCreateRequest(
            name="Decommission Test",
            seed_type=TargetType.DOMAIN,
            seed_value="decom.example.com",
        ),
    )
    target_db.commit()

    archived = archive_target(target_db, test_project.id, target.id, test_user.id)
    target_db.commit()
    assert archived.status == "archived"
    assert archived.archived_at is not None
    archived_time = archived.archived_at

    # Idempotent call
    archived_again = archive_target(target_db, test_project.id, target.id, test_user.id)
    target_db.commit()
    assert archived_again.status == "archived"
    assert archived_again.archived_at == archived_time


# -----------------------------------------------------------------------------
# Audit Logging & Critical Architectural Invariant Tests
# -----------------------------------------------------------------------------


def test_audit_logs_recorded_for_all_mutations(
    target_db: Session, test_project: Project, test_user: User
) -> None:
    """Append-only audit logs are created for target create, update, and archive operations."""
    target = create_target(
        target_db,
        test_project.id,
        test_user.id,
        TargetCreateRequest(
            name="Audit Target",
            seed_type=TargetType.DOMAIN,
            seed_value="audit.example.com",
        ),
        ip_address="192.0.2.10",
        request_id="req-123",
    )
    target_db.commit()

    update_target(
        target_db,
        test_project.id,
        target.id,
        test_user.id,
        TargetUpdateRequest(name="Audit Target Renamed"),
        ip_address="192.0.2.10",
        request_id="req-124",
    )
    target_db.commit()

    archive_target(
        target_db,
        test_project.id,
        target.id,
        test_user.id,
        ip_address="192.0.2.10",
        request_id="req-125",
    )
    target_db.commit()

    # Fetch audit logs
    stmt = (
        select(AuditLog)
        .where(
            AuditLog.project_id == test_project.id,
            AuditLog.entity_type == "target",
            AuditLog.entity_id == str(target.id),
        )
        .order_by(AuditLog.id.asc())
    )
    logs = list(target_db.scalars(stmt).all())
    assert len(logs) == 3

    assert logs[0].action == "target.create"
    assert logs[0].metadata_["raw_input"] == "audit.example.com"
    assert logs[0].request_id == "req-123"

    assert logs[1].action == "target.update"
    assert "name" in logs[1].metadata_["changes"]
    assert logs[1].request_id == "req-124"

    assert logs[2].action == "target.archive"
    assert logs[2].metadata_["previous_status"] == "active"
    assert logs[2].request_id == "req-125"


def test_critical_invariant_never_authorizes_or_creates_scope(
    target_db: Session, test_project: Project, test_user: User
) -> None:
    """CRITICAL INVARIANT TEST:

    A target is a discovery seed, not an authorization permit.
    Creating, updating, and archiving targets must NEVER create or touch:
    - AuthorizationRecord
    - ScopeVersion
    - ScopeRule
    """
    # Record initial counts
    auth_count_before = target_db.scalar(select(func.count(AuthorizationRecord.id))) or 0
    version_count_before = target_db.scalar(select(func.count(ScopeVersion.id))) or 0
    rule_count_before = target_db.scalar(select(func.count(ScopeRule.id))) or 0

    assert auth_count_before == 0
    assert version_count_before == 0
    assert rule_count_before == 0

    # Perform all target lifecycle actions
    target = create_target(
        target_db,
        test_project.id,
        test_user.id,
        TargetCreateRequest(
            name="Invariant Target",
            seed_type=TargetType.DOMAIN,
            seed_value="invariant.example.com",
        ),
    )
    update_target(
        target_db,
        test_project.id,
        target.id,
        test_user.id,
        TargetUpdateRequest(description="New Notes"),
    )
    archive_target(target_db, test_project.id, target.id, test_user.id)
    target_db.commit()

    # Assert invariant: Counts must remain strictly zero
    auth_count_after = target_db.scalar(select(func.count(AuthorizationRecord.id))) or 0
    version_count_after = target_db.scalar(select(func.count(ScopeVersion.id))) or 0
    rule_count_after = target_db.scalar(select(func.count(ScopeRule.id))) or 0

    assert auth_count_after == 0, "Invariant violation: Target created AuthorizationRecord!"
    assert version_count_after == 0, "Invariant violation: Target created ScopeVersion!"
    assert rule_count_after == 0, "Invariant violation: Target created ScopeRule!"
