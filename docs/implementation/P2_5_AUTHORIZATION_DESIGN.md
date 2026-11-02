# VulnOS Phase 2.5.4 — Authorization Record Management & Legal Consent Design

## 1. Architectural Purpose & Security Boundaries

The **Authorization Management Service** (`backend/app/scope/authorizations.py`) and its associated HTTP API (`backend/app/api/v1/authorizations.py`) govern the registration, retrieval, lifecycle tracking, revocation, and deterministic policy evaluation of legal and contractual authorization records in VulnOS.

### Critical Invariants

1. **Non-Authorization Invariant:**
   > **An authorization record is a legal prerequisite, NOT an independent permit to execute scans.**
   
   Registering an authorization record verifies that an authorized client representative has consented to security testing within specified boundaries and dates. It does **NOT**:
   - Automatically permit network scanning or crawling.
   - Activate or generate scope rules.
   - Supersede the requirement for an active, authorized `ScopeVersion`.
   - Bypass the deterministic scope evaluation engine.

2. **Strict Immutability Invariant:**
   > **Legal terms are strictly immutable: NO UPDATE OR PATCH ENDPOINTS exist.**
   
   A legal agreement cannot be altered after the fact. If engagement terms, testing dates, or rules of engagement change, the operator must:
   - Create a new authorization record with the updated parameters.
   - Revoke the previous/superseded authorization record.
   - Any attempt to issue `PATCH`, `PUT`, or `DELETE` on authorization endpoints returns `405 Method Not Allowed`.

3. **Strict Multi-Tenant Isolation:**
   - Authorizations belong strictly to a single project via foreign key `project_id`.
   - Requests from non-members return `404 Not Found` (via `require_project_context`), completely preventing cross-tenant project existence and authorization enumeration.
   - Row-Level Security (RLS) enforces database-level tenant isolation in PostgreSQL via `authorization_records_project_isolation`.

---

## 2. Multi-Tenant Architecture & RBAC Matrix

VulnOS enforces defense-in-depth authorization across all authorization endpoints:

```
[ Incoming HTTP Request ]
           │
           ▼
[ AuthenticatedPrincipal ] (Bearer JWT or API Key)
           │
           ▼
[ require_project_context() ]
   ├── Verifies project exists and status == 'active'
   ├── Verifies user is active ProjectMember (Non-members -> 404)
   ├── Enforces Role Hierarchy (Admin required for write/revoke; Viewer for read)
   ├── Enforces API Key Scopes ('admin' scope for write/revoke; 'read' for read)
   └── Establishes transaction-local RLS tenant context (SET LOCAL app.current_project_id)
           │
           ▼
[ Authorization Service & DB Engine ]
   ├── RLS Policy: authorization_records.project_id = current_project_id()
   ├── CheckConstraint: valid_to > valid_from
   └── Append-only AuditLog persistence
```

### Role & Scope Permissions Matrix

| Operation | HTTP Route | Min Role | API Key Scope | Status Codes |
| :--- | :--- | :--- | :--- | :--- |
| **Create Record** | `POST /projects/{id}/authorizations` | `admin` | `admin` | `201`, `400`, `403`, `404`, `409`, `422` |
| **List Records** | `GET /projects/{id}/authorizations` | `viewer` | `read` | `200`, `403`, `404` |
| **Get Record** | `GET /projects/{id}/authorizations/{auth_id}` | `viewer` | `read` | `200`, `403`, `404` |
| **Revoke Record** | `POST /projects/{id}/authorizations/{auth_id}/revoke` | `admin` | `admin` | `200`, `403`, `404` |
| **Update Terms** | `PATCH /projects/{id}/authorizations/{auth_id}` | N/A | N/A | `405 Method Not Allowed` |
| **Delete Record** | `DELETE /projects/{id}/authorizations/{auth_id}` | N/A | N/A | `405 Method Not Allowed` |

---

## 3. Schema & Database Representation

The canonical model is defined in `backend/app/db/models/identity.py`:

```python
class AuthorizationRecord(Base):
    __tablename__ = "authorization_records"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid7)
    project_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    reference: Mapped[str] = mapped_column(Text, nullable=False)
    document_evidence_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    authorized_by_name: Mapped[str] = mapped_column(Text, nullable=False)
    authorized_by_contact: Mapped[str] = mapped_column(Text, nullable=False)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    valid_to: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    allowed_actions: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False)
    destructive_allowed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    allow_private_ranges: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    max_requests_per_scan: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        CheckConstraint("valid_to > valid_from", name="ck_authorization_records_validity_window"),
    )
```

### Migration Reconciliation Gate
Alembic migration `backend/alembic/versions/0003_phase2_authorization_records.py` cleanly reconciles the draft prototype columns from baseline `0001` with the canonical model specification in `DATABASE_DESIGN.md` §4.3, adding the validity window check constraint and project index.

---

## 4. Deterministic Evaluation Engine

The evaluation engine (`evaluate_authorization` and `evaluate_authorization_record`) evaluates whether a specific operation is permitted under an authorization record without side-effects.

### Evaluation Precedence Order

```
[ Evaluate Action Request ]
            │
            ▼
    [ Record Exists? ] ─────────────────────────► NO ──► NOT_FOUND (allowed=False)
            │ YES
            ▼
   [ Project Matches? ] ────────────────────────► NO ──► PROJECT_MISMATCH (allowed=False)
            │ YES
            ▼
  [ revoked_at IS NOT NULL? ] ──────────────────► YES ─► REVOKED (allowed=False)
            │ NO
            ▼
     [ now < valid_from? ] ─────────────────────► YES ─► NOT_YET_VALID (allowed=False)
            │ NO
            ▼
     [ now > valid_to? ] ───────────────────────► YES ─► EXPIRED (allowed=False)
            │ NO
            ▼
  [ action IN allowed_actions? ] ───────────────► NO ──► ACTION_NOT_ALLOWED (allowed=False)
            │ YES
            ▼
 [ is_destructive AND NOT destructive_allowed ] ─► YES ─► DESTRUCTIVE_NOT_ALLOWED (allowed=False)
            │ NO
            ▼
 [ is_private_range AND NOT allow_private_ranges ]► YES ─► PRIVATE_RANGE_NOT_ALLOWED (allowed=False)
            │ NO
            ▼
          VALID (allowed=True)
```

### Exact Boundary Rules

1. **`now == valid_from`:** Valid (inclusive beginning).
2. **`valid_from < now < valid_to`:** Valid.
3. **`now == valid_to`:** Valid (inclusive final second of authorized window).
4. **`now > valid_to`:** Strictly expired (`AUTHORIZATION_EXPIRED`).
5. **Revocation Precedence:** If `revoked_at` is set, `AUTHORIZATION_REVOKED` is returned regardless of time window or actions.

---

## 5. Idempotent Revocation & Audit Logging

- **Revocation:** Invoking `revoke_authorization` sets `revoked_at = utc_now()`. If already revoked, the function is strictly idempotent, preserving the original timestamp and returning the unchanged record.
- **Audit Logging:** Every authorization creation (`authorization.create`) and revocation (`authorization.revoke`) writes an immutable record to `audit_logs` capturing actor identity, project ID, IP address, user agent, request ID, and metadata.
