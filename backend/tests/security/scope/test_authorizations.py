"""Unit and security tests for VulnOS Authorization Management Service (P2.5.4).

Validates:
- Creation of immutable authorization records and validation constraints.
- Project isolation and cross-project access prevention.
- Duplicate active reference detection within the same project.
- Retrieval, paginated listing, and active-only temporal filtering.
- Idempotent revocation with append-only audit logging.
- Deterministic evaluation engine precedence:
    1. Existence (NOT_FOUND)
    2. Project match (PROJECT_MISMATCH)
    3. Revocation status (REVOKED)
    4. Time window bounds (NOT_YET_VALID vs VALID vs EXPIRED)
    5. Action allowlist (ACTION_NOT_ALLOWED)
    6. Destructive permission (DESTRUCTIVE_NOT_ALLOWED)
    7. Private range permission (PRIVATE_RANGE_NOT_ALLOWED)
- Exact time boundaries:
    - now == valid_from -> VALID
    - now == valid_to -> VALID
    - now > valid_to -> EXPIRED
"""

from __future__ import annotations

from collections.abc import Generator
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine, select
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
from backend.app.db.types import utc_now, uuid7
from backend.app.scope.authorizations import (
    _ensure_utc,
    create_authorization,
    evaluate_authorization,
    evaluate_authorization_record,
    get_authorization,
    list_authorizations,
    revoke_authorization,
)
from backend.app.scope.exceptions import (
    AuthorizationNotFoundError,
    DuplicateAuthorizationError,
)
from backend.app.scope.schemas import (
    AuthorizationCreateRequest,
    AuthorizationReasonCode,
)


@pytest.fixture
def auth_db() -> Generator[Session]:
    """In-memory SQLite session configured for authorization testing."""
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
def test_user(auth_db: Session) -> User:
    """Create test operator user."""
    user = User(
        id=uuid7(),
        email="operator@vulnos.test",
        display_name="Test Operator",
        password_hash="test_argon2id_hash",
        is_active=True,
    )
    auth_db.add(user)
    auth_db.commit()
    auth_db.refresh(user)
    return user


@pytest.fixture
def test_projects(auth_db: Session, test_user: User) -> tuple[Project, Project]:
    """Create Project Alpha and Project Beta for multi-tenant isolation testing."""
    proj_alpha = Project(
        id=uuid7(),
        name="Project Alpha",
        slug="proj-alpha",
        owner_id=test_user.id,
        status="active",
    )
    proj_beta = Project(
        id=uuid7(),
        name="Project Beta",
        slug="proj-beta",
        owner_id=test_user.id,
        status="active",
    )
    auth_db.add_all([proj_alpha, proj_beta])
    auth_db.commit()
    auth_db.refresh(proj_alpha)
    auth_db.refresh(proj_beta)
    return proj_alpha, proj_beta


# -----------------------------------------------------------------------------
# Creation & Validation Tests
# -----------------------------------------------------------------------------


def test_create_authorization_minimal(
    auth_db: Session, test_user: User, test_projects: tuple[Project, Project]
) -> None:
    """Creating an authorization with minimal required fields succeeds."""
    proj_alpha, _ = test_projects
    now = utc_now()

    req = AuthorizationCreateRequest(
        reference="ENG-2026-001",
        authorized_by_name="Jane Doe",
        authorized_by_contact="jane@example.com",
        valid_from=now,
        valid_to=now + timedelta(days=30),
        allowed_actions=["scan", "validate"],
    )

    record = create_authorization(
        db=auth_db,
        project_id=proj_alpha.id,
        user_id=test_user.id,
        data=req,
    )
    auth_db.commit()

    assert record.id is not None
    assert record.project_id == proj_alpha.id
    assert record.reference == "ENG-2026-001"
    assert record.authorized_by_name == "Jane Doe"
    assert record.authorized_by_contact == "jane@example.com"
    assert record.allowed_actions == ["scan", "validate"]
    assert record.destructive_allowed is False
    assert record.allow_private_ranges is False
    assert record.max_requests_per_scan is None
    assert record.notes is None
    assert record.document_evidence_id is None
    assert record.revoked_at is None
    assert record.created_by == test_user.id


def test_create_authorization_full(
    auth_db: Session, test_user: User, test_projects: tuple[Project, Project]
) -> None:
    """Creating an authorization with all optional fields persists correctly."""
    proj_alpha, _ = test_projects
    now = utc_now()
    evidence_id = uuid7()

    req = AuthorizationCreateRequest(
        reference="ENG-2026-FULL",
        authorized_by_name="Chief CISO",
        authorized_by_contact="ciso@enterprise.corp",
        valid_from=now,
        valid_to=now + timedelta(days=90),
        allowed_actions=["scan", "validate", "agent_run", "fuzz"],
        destructive_allowed=True,
        allow_private_ranges=True,
        max_requests_per_scan=100000,
        notes="Red team assessment with explicit fuzzing authorization",
        document_evidence_id=evidence_id,
    )

    record = create_authorization(
        db=auth_db,
        project_id=proj_alpha.id,
        user_id=test_user.id,
        data=req,
        ip_address="192.168.1.50",
        request_id="req-auth-001",
        user_agent="SecurityAgent/1.0",
    )
    auth_db.commit()

    assert record.destructive_allowed is True
    assert record.allow_private_ranges is True
    assert record.max_requests_per_scan == 100000
    assert record.notes == "Red team assessment with explicit fuzzing authorization"
    assert record.document_evidence_id == evidence_id


def test_create_authorization_appends_audit_log(
    auth_db: Session, test_user: User, test_projects: tuple[Project, Project]
) -> None:
    """Authorization creation appends an immutable audit log entry."""
    proj_alpha, _ = test_projects
    now = utc_now()

    req = AuthorizationCreateRequest(
        reference="ENG-AUDIT-TEST",
        authorized_by_name="Audit Lead",
        authorized_by_contact="audit@example.com",
        valid_from=now,
        valid_to=now + timedelta(days=14),
        allowed_actions=["reconnaissance"],
    )

    record = create_authorization(
        db=auth_db,
        project_id=proj_alpha.id,
        user_id=test_user.id,
        data=req,
        ip_address="10.0.0.1",
        request_id="req-12345",
        user_agent="VulnOS-CLI",
    )
    auth_db.commit()

    audit_entry = auth_db.scalar(
        select(AuditLog).where(
            AuditLog.entity_id == str(record.id),
            AuditLog.action == "authorization.create",
        )
    )
    assert audit_entry is not None
    assert audit_entry.actor_id == str(test_user.id)
    assert audit_entry.project_id == proj_alpha.id
    assert audit_entry.ip == "10.0.0.1"
    assert audit_entry.request_id == "req-12345"
    assert audit_entry.user_agent == "VulnOS-CLI"
    assert audit_entry.metadata_["reference"] == "ENG-AUDIT-TEST"


def test_create_authorization_duplicate_reference_rejected(
    auth_db: Session, test_user: User, test_projects: tuple[Project, Project]
) -> None:
    """Attempting to create duplicate active authorization in same project fails."""
    proj_alpha, _ = test_projects
    now = utc_now()

    req = AuthorizationCreateRequest(
        reference="ENG-DUP-01",
        authorized_by_name="Alice",
        authorized_by_contact="alice@example.com",
        valid_from=now,
        valid_to=now + timedelta(days=10),
        allowed_actions=["scan"],
    )

    create_authorization(db=auth_db, project_id=proj_alpha.id, user_id=test_user.id, data=req)
    auth_db.commit()

    with pytest.raises(DuplicateAuthorizationError, match="already exists"):
        create_authorization(db=auth_db, project_id=proj_alpha.id, user_id=test_user.id, data=req)


def test_create_authorization_same_reference_allowed_after_revocation(
    auth_db: Session, test_user: User, test_projects: tuple[Project, Project]
) -> None:
    """A superseded/revoked authorization reference can be re-issued cleanly."""
    proj_alpha, _ = test_projects
    now = utc_now()

    req = AuthorizationCreateRequest(
        reference="ENG-REISSUE",
        authorized_by_name="Bob",
        authorized_by_contact="bob@example.com",
        valid_from=now,
        valid_to=now + timedelta(days=10),
        allowed_actions=["scan"],
    )

    record = create_authorization(
        db=auth_db, project_id=proj_alpha.id, user_id=test_user.id, data=req
    )
    auth_db.commit()

    # Revoke old record
    revoke_authorization(
        db=auth_db,
        project_id=proj_alpha.id,
        authorization_id=record.id,
        user_id=test_user.id,
    )
    auth_db.commit()

    # Creating with same reference now succeeds
    record2 = create_authorization(
        db=auth_db, project_id=proj_alpha.id, user_id=test_user.id, data=req
    )
    auth_db.commit()
    assert record2.id != record.id
    assert record2.revoked_at is None


# -----------------------------------------------------------------------------
# Retrieval & Listing Tests
# -----------------------------------------------------------------------------


def test_get_authorization_success_and_cross_project_isolation(
    auth_db: Session, test_user: User, test_projects: tuple[Project, Project]
) -> None:
    """Authorization retrieval respects strict project boundaries."""
    proj_alpha, proj_beta = test_projects
    now = utc_now()

    req = AuthorizationCreateRequest(
        reference="ENG-ISO-ALPHA",
        authorized_by_name="Alpha Officer",
        authorized_by_contact="officer@alpha.test",
        valid_from=now,
        valid_to=now + timedelta(days=10),
        allowed_actions=["scan"],
    )

    record = create_authorization(
        db=auth_db, project_id=proj_alpha.id, user_id=test_user.id, data=req
    )
    auth_db.commit()

    # Success when querying under Alpha
    fetched = get_authorization(db=auth_db, project_id=proj_alpha.id, authorization_id=record.id)
    assert fetched.id == record.id

    # Cross-project access fails under Beta
    with pytest.raises(AuthorizationNotFoundError):
        get_authorization(db=auth_db, project_id=proj_beta.id, authorization_id=record.id)


def test_get_authorization_not_found(
    auth_db: Session, test_projects: tuple[Project, Project]
) -> None:
    """Non-existent authorization ID raises AuthorizationNotFoundError."""
    proj_alpha, _ = test_projects
    with pytest.raises(AuthorizationNotFoundError):
        get_authorization(db=auth_db, project_id=proj_alpha.id, authorization_id=uuid7())


def test_list_authorizations_pagination_and_active_filter(
    auth_db: Session, test_user: User, test_projects: tuple[Project, Project]
) -> None:
    """list_authorizations correctly supports pagination and active-only temporal filtering."""
    proj_alpha, _ = test_projects
    now = utc_now()

    # 1. Active record
    rec_active = create_authorization(
        db=auth_db,
        project_id=proj_alpha.id,
        user_id=test_user.id,
        data=AuthorizationCreateRequest(
            reference="ENG-ACTIVE",
            authorized_by_name="A",
            authorized_by_contact="a@test.com",
            valid_from=now - timedelta(days=1),
            valid_to=now + timedelta(days=10),
            allowed_actions=["scan"],
        ),
    )

    # 2. Future record (not yet valid)
    create_authorization(
        db=auth_db,
        project_id=proj_alpha.id,
        user_id=test_user.id,
        data=AuthorizationCreateRequest(
            reference="ENG-FUTURE",
            authorized_by_name="B",
            authorized_by_contact="b@test.com",
            valid_from=now + timedelta(days=5),
            valid_to=now + timedelta(days=15),
            allowed_actions=["scan"],
        ),
    )

    # 3. Expired record
    create_authorization(
        db=auth_db,
        project_id=proj_alpha.id,
        user_id=test_user.id,
        data=AuthorizationCreateRequest(
            reference="ENG-EXPIRED",
            authorized_by_name="C",
            authorized_by_contact="c@test.com",
            valid_from=now - timedelta(days=20),
            valid_to=now - timedelta(days=5),
            allowed_actions=["scan"],
        ),
    )

    # 4. Revoked record
    rec_revoked = create_authorization(
        db=auth_db,
        project_id=proj_alpha.id,
        user_id=test_user.id,
        data=AuthorizationCreateRequest(
            reference="ENG-REVOKED",
            authorized_by_name="D",
            authorized_by_contact="d@test.com",
            valid_from=now - timedelta(days=1),
            valid_to=now + timedelta(days=10),
            allowed_actions=["scan"],
        ),
    )
    revoke_authorization(
        db=auth_db,
        project_id=proj_alpha.id,
        authorization_id=rec_revoked.id,
        user_id=test_user.id,
    )
    auth_db.commit()

    # List all (unfiltered)
    all_items, total = list_authorizations(db=auth_db, project_id=proj_alpha.id)
    assert total == 4
    assert len(all_items) == 4

    # Pagination test
    page1, total1 = list_authorizations(db=auth_db, project_id=proj_alpha.id, limit=2, offset=0)
    assert total1 == 4
    assert len(page1) == 2

    # Active only filter: should ONLY return rec_active
    active_items, active_total = list_authorizations(
        db=auth_db, project_id=proj_alpha.id, active_only=True, now=now
    )
    assert active_total == 1
    assert len(active_items) == 1
    assert active_items[0].id == rec_active.id


# -----------------------------------------------------------------------------
# Revocation & Idempotency Tests
# -----------------------------------------------------------------------------


def test_revoke_authorization_idempotence_and_audit(
    auth_db: Session, test_user: User, test_projects: tuple[Project, Project]
) -> None:
    """Revocation sets revoked_at, is idempotent, and preserves original timestamp."""
    proj_alpha, _ = test_projects
    now = utc_now()

    record = create_authorization(
        db=auth_db,
        project_id=proj_alpha.id,
        user_id=test_user.id,
        data=AuthorizationCreateRequest(
            reference="ENG-REV-IDEMP",
            authorized_by_name="Tester",
            authorized_by_contact="tester@example.com",
            valid_from=now,
            valid_to=now + timedelta(days=30),
            allowed_actions=["scan"],
        ),
    )
    auth_db.commit()

    # First revocation
    first_time = now + timedelta(minutes=5)
    revoked1 = revoke_authorization(
        db=auth_db,
        project_id=proj_alpha.id,
        authorization_id=record.id,
        user_id=test_user.id,
        ip_address="192.168.1.100",
        request_id="req-rev-1",
        revocation_time=first_time,
    )
    auth_db.commit()
    assert revoked1.revoked_at is not None
    assert _ensure_utc(revoked1.revoked_at) == first_time

    # Verify audit log
    audit_entry = auth_db.scalar(
        select(AuditLog).where(
            AuditLog.entity_id == str(record.id),
            AuditLog.action == "authorization.revoke",
        )
    )
    assert audit_entry is not None
    assert audit_entry.metadata_["revoked_at"] == first_time.isoformat()

    # Second revocation attempt (idempotent, must not change original timestamp)
    second_time = now + timedelta(hours=1)
    revoked2 = revoke_authorization(
        db=auth_db,
        project_id=proj_alpha.id,
        authorization_id=record.id,
        user_id=test_user.id,
        revocation_time=second_time,
    )
    auth_db.commit()
    assert revoked2.revoked_at is not None
    assert _ensure_utc(revoked2.revoked_at) == first_time  # Unchanged!


# -----------------------------------------------------------------------------
# Evaluation Engine Tests
# -----------------------------------------------------------------------------


def test_evaluate_authorization_not_found_and_project_mismatch() -> None:
    """Evaluation handles missing records and project mismatch deterministically."""
    proj_a = uuid7()
    proj_b = uuid7()

    # None record
    res_none = evaluate_authorization_record(
        record=None,
        project_id=proj_a,
        action="scan",
    )
    assert res_none.allowed is False
    assert res_none.reason_code == AuthorizationReasonCode.NOT_FOUND

    # Project mismatch
    record = AuthorizationRecord(
        id=uuid7(),
        project_id=proj_a,
        reference="ENG-MISMATCH",
        authorized_by_name="Jane",
        authorized_by_contact="jane@test.com",
        valid_from=datetime(2026, 1, 1, tzinfo=UTC),
        valid_to=datetime(2026, 12, 31, tzinfo=UTC),
        allowed_actions=["scan"],
        destructive_allowed=False,
        allow_private_ranges=False,
        created_by=uuid7(),
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
    )

    res_mismatch = evaluate_authorization_record(
        record=record,
        project_id=proj_b,  # Evaluated under Project B instead of Project A
        action="scan",
    )
    assert res_mismatch.allowed is False
    assert res_mismatch.reason_code == AuthorizationReasonCode.PROJECT_MISMATCH


def test_evaluate_authorization_revoked_takes_precedence() -> None:
    """Revocation takes precedence over action validity and temporal windows."""
    proj_id = uuid7()
    valid_from = datetime(2026, 6, 1, 0, 0, 0, tzinfo=UTC)
    valid_to = datetime(2026, 6, 30, 0, 0, 0, tzinfo=UTC)

    record = AuthorizationRecord(
        id=uuid7(),
        project_id=proj_id,
        reference="ENG-REVOKED-TEST",
        authorized_by_name="Officer",
        authorized_by_contact="officer@test.com",
        valid_from=valid_from,
        valid_to=valid_to,
        allowed_actions=["scan"],
        destructive_allowed=False,
        allow_private_ranges=False,
        created_by=uuid7(),
        created_at=valid_from,
        revoked_at=datetime(2026, 6, 10, 0, 0, 0, tzinfo=UTC),
    )

    # During validity window, but revoked
    res = evaluate_authorization_record(
        record=record,
        project_id=proj_id,
        action="scan",
        now=datetime(2026, 6, 15, 0, 0, 0, tzinfo=UTC),
    )
    assert res.allowed is False
    assert res.reason_code == AuthorizationReasonCode.REVOKED

    # After expiration, but revoked takes precedence
    res_after = evaluate_authorization_record(
        record=record,
        project_id=proj_id,
        action="scan",
        now=datetime(2026, 7, 1, 0, 0, 0, tzinfo=UTC),
    )
    assert res_after.allowed is False
    assert res_after.reason_code == AuthorizationReasonCode.REVOKED


def test_evaluate_authorization_temporal_boundaries() -> None:
    """Validates exact temporal boundaries: valid_from <= now <= valid_to."""
    proj_id = uuid7()
    valid_from = datetime(2026, 6, 1, 0, 0, 0, tzinfo=UTC)
    valid_to = datetime(2026, 6, 30, 23, 59, 59, tzinfo=UTC)

    record = AuthorizationRecord(
        id=uuid7(),
        project_id=proj_id,
        reference="ENG-BOUNDARY",
        authorized_by_name="Officer",
        authorized_by_contact="officer@test.com",
        valid_from=valid_from,
        valid_to=valid_to,
        allowed_actions=["scan"],
        destructive_allowed=False,
        allow_private_ranges=False,
        created_by=uuid7(),
        created_at=valid_from,
        revoked_at=None,
    )

    # 1. One second before start -> NOT_YET_VALID
    r1 = evaluate_authorization_record(
        record=record,
        project_id=proj_id,
        action="scan",
        now=valid_from - timedelta(seconds=1),
    )
    assert r1.allowed is False
    assert r1.reason_code == AuthorizationReasonCode.NOT_YET_VALID

    # 2. Exact start instant -> VALID
    r2 = evaluate_authorization_record(
        record=record,
        project_id=proj_id,
        action="scan",
        now=valid_from,
    )
    assert r2.allowed is True
    assert r2.reason_code == AuthorizationReasonCode.VALID

    # 3. Inside window -> VALID
    r3 = evaluate_authorization_record(
        record=record,
        project_id=proj_id,
        action="scan",
        now=datetime(2026, 6, 15, 12, 0, 0, tzinfo=UTC),
    )
    assert r3.allowed is True
    assert r3.reason_code == AuthorizationReasonCode.VALID

    # 4. Exact valid_to instant -> VALID (inclusive final second)
    r4 = evaluate_authorization_record(
        record=record,
        project_id=proj_id,
        action="scan",
        now=valid_to,
    )
    assert r4.allowed is True
    assert r4.reason_code == AuthorizationReasonCode.VALID

    # 5. One second after valid_to -> EXPIRED
    r5 = evaluate_authorization_record(
        record=record,
        project_id=proj_id,
        action="scan",
        now=valid_to + timedelta(seconds=1),
    )
    assert r5.allowed is False
    assert r5.reason_code == AuthorizationReasonCode.EXPIRED


def test_evaluate_authorization_action_allowlist() -> None:
    """Action check enforces action allowlist and handles casing/whitespace cleanly."""
    proj_id = uuid7()
    valid_from = datetime(2026, 1, 1, tzinfo=UTC)
    valid_to = datetime(2026, 12, 31, tzinfo=UTC)

    record = AuthorizationRecord(
        id=uuid7(),
        project_id=proj_id,
        reference="ENG-ACTIONS",
        authorized_by_name="Officer",
        authorized_by_contact="officer@test.com",
        valid_from=valid_from,
        valid_to=valid_to,
        allowed_actions=["scan", "validate"],
        destructive_allowed=False,
        allow_private_ranges=False,
        created_by=uuid7(),
        created_at=valid_from,
        revoked_at=None,
    )
    now = datetime(2026, 6, 1, tzinfo=UTC)

    # Allowed action
    assert evaluate_authorization_record(record, proj_id, "scan", now=now).allowed is True

    # Case folding & whitespace
    assert evaluate_authorization_record(record, proj_id, " SCAN  ", now=now).allowed is True
    assert evaluate_authorization_record(record, proj_id, "Validate", now=now).allowed is True

    # Disallowed action
    disallowed = evaluate_authorization_record(record, proj_id, "fuzz", now=now)
    assert disallowed.allowed is False
    assert disallowed.reason_code == AuthorizationReasonCode.ACTION_NOT_ALLOWED


def test_evaluate_authorization_destructive_and_private_range_permissions() -> None:
    """Destructive and private-range testing require explicit permission booleans."""
    proj_id = uuid7()
    valid_from = datetime(2026, 1, 1, tzinfo=UTC)
    valid_to = datetime(2026, 12, 31, tzinfo=UTC)
    now = datetime(2026, 6, 1, tzinfo=UTC)

    # Record without destructive or private permissions
    record_restrictive = AuthorizationRecord(
        id=uuid7(),
        project_id=proj_id,
        reference="ENG-RESTRICTIVE",
        authorized_by_name="Officer",
        authorized_by_contact="officer@test.com",
        valid_from=valid_from,
        valid_to=valid_to,
        allowed_actions=["scan"],
        destructive_allowed=False,
        allow_private_ranges=False,
        created_by=uuid7(),
        created_at=valid_from,
        revoked_at=None,
    )

    # Destructive test denied
    dest_denied = evaluate_authorization_record(
        record_restrictive, proj_id, "scan", is_destructive=True, now=now
    )
    assert dest_denied.allowed is False
    assert dest_denied.reason_code == AuthorizationReasonCode.DESTRUCTIVE_NOT_ALLOWED

    # Private range test denied
    priv_denied = evaluate_authorization_record(
        record_restrictive, proj_id, "scan", is_private_range=True, now=now
    )
    assert priv_denied.allowed is False
    assert priv_denied.reason_code == AuthorizationReasonCode.PRIVATE_RANGE_NOT_ALLOWED

    # Record WITH destructive and private permissions
    record_permissive = AuthorizationRecord(
        id=uuid7(),
        project_id=proj_id,
        reference="ENG-PERMISSIVE",
        authorized_by_name="Officer",
        authorized_by_contact="officer@test.com",
        valid_from=valid_from,
        valid_to=valid_to,
        allowed_actions=["scan"],
        destructive_allowed=True,
        allow_private_ranges=True,
        created_by=uuid7(),
        created_at=valid_from,
        revoked_at=None,
    )

    # Both succeed
    dest_allowed = evaluate_authorization_record(
        record_permissive, proj_id, "scan", is_destructive=True, now=now
    )
    assert dest_allowed.allowed is True
    assert dest_allowed.reason_code == AuthorizationReasonCode.VALID

    priv_allowed = evaluate_authorization_record(
        record_permissive, proj_id, "scan", is_private_range=True, now=now
    )
    assert priv_allowed.allowed is True
    assert priv_allowed.reason_code == AuthorizationReasonCode.VALID


def test_evaluate_authorization_db_lookup(
    auth_db: Session, test_user: User, test_projects: tuple[Project, Project]
) -> None:
    """evaluate_authorization performs end-to-end database lookup and evaluation."""
    proj_alpha, _ = test_projects
    now = utc_now()

    record = create_authorization(
        db=auth_db,
        project_id=proj_alpha.id,
        user_id=test_user.id,
        data=AuthorizationCreateRequest(
            reference="ENG-EVAL-DB",
            authorized_by_name="Security Officer",
            authorized_by_contact="officer@test.com",
            valid_from=now,
            valid_to=now + timedelta(days=7),
            allowed_actions=["scan", "crawl"],
        ),
    )
    auth_db.commit()

    # Evaluated successfully through DB query
    result = evaluate_authorization(
        db=auth_db,
        project_id=proj_alpha.id,
        authorization_id=record.id,
        action="scan",
        now=now + timedelta(days=1),
    )
    assert result.allowed is True
    assert result.reason_code == AuthorizationReasonCode.VALID
    assert result.authorization_id == record.id
