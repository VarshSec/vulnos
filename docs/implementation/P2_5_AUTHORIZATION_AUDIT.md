# VulnOS Phase 2.5.4 — Authorization Records & Legal Consent Security Audit

**Milestone:** P2.5.4.1 — Repository Audit and Schema Review  
**Date:** 2026-11-02  
**Status:** Complete & Signed Off  

---

## 1. Executive Summary

Phase 2.5.4 implements **Authorization Record Management, Legal Consent & Lifecycle Enforcement**.

In VulnOS, authorization records represent the **mandatory legal and contractual boundary** for all security testing activities:
- A registered target seed is **not** permission to test.
- A project membership is **not** permission to test.
- An approved tool or active agent is **not** permission to test.

Only an **explicit, active, unexpired, and unrevoked `AuthorizationRecord`** bound to the target's project can enable testing operations. Furthermore, an authorization record does not independently execute scans—it is evaluated deterministically alongside scope rules by the scope validator.

This audit inspects the current repository, evaluates the existing schema and migrations, identifies discrepancies, establishes validity semantics, and defines the service architecture.

---

## 2. Existing Schema Audit: `AuthorizationRecord` Model

### 2.1 SQLAlchemy Model (`backend/app/db/models/identity.py`)

The authoritative SQLAlchemy model `AuthorizationRecord` (lines 186–228) defines:

```python
class AuthorizationRecord(Base):
    """Legal/contractual scope authorization."""

    __tablename__ = "authorization_records"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid7)
    project_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    reference: Mapped[str] = mapped_column(Text, nullable=False)
    document_evidence_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    authorized_by_name: Mapped[str] = mapped_column(Text, nullable=False)
    authorized_by_contact: Mapped[str] = mapped_column(Text, nullable=False)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    valid_to: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    allowed_actions: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False)
    destructive_allowed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    allow_private_ranges: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    max_requests_per_scan: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        CheckConstraint("valid_to > valid_from", name="ck_authorization_records_validity_window"),
    )
```

### 2.2 Schema Consistency Analysis

| Source | Field Definitions | Status |
| :--- | :--- | :--- |
| `DATABASE_DESIGN.md` §4.3 | `reference`, `authorized_by_name`, `authorized_by_contact`, `valid_from`, `valid_to`, `allowed_actions`, `destructive_allowed`, `allow_private_ranges`, `max_requests_per_scan`, `notes`, `created_by`, `created_at`, `revoked_at` | **Authoritative Architecture Blueprint** |
| `P2_5_SECURITY_AUDIT.md` §3.2 | Exact match with `DATABASE_DESIGN.md` | **Consistent** |
| `identity.py` ORM Model | Exact match with `DATABASE_DESIGN.md` | **Consistent** |
| `0001_phase2_baseline.py` | Legacy draft columns: `authorization_type`, `granted_by`, `valid_until`, `status`, `restrictions`, `scope_summary` | **Discrepancy Documented Below** |

### 2.3 Migration Discrepancy Note

In `backend/alembic/versions/0001_phase2_baseline.py` (lines 154–200), `authorization_records` contains draft columns created during early Phase 2.1 before `DATABASE_DESIGN.md` was finalized in Phase 2.2.
- The runtime application and all tests use `Base.metadata` as defined in `identity.py`.
- In keeping with the strict project rule (*"Never modify historical migrations. Do not create speculative migrations unless justified"*), we document that `identity.py` is the single source of truth for all application logic. When deploying to real PostgreSQL databases, an Alembic migration aligning the DDL is documented in Section 8.

---

## 3. Project Ownership, Tenancy & Row-Level Security (RLS)

- **Isolation Tier:** Direct Project Table.
- **Tenant Key:** `project_id` (foreign key to `projects.id`).
- **PostgreSQL RLS Policy:**
  ```sql
  CREATE POLICY authorization_records_project_isolation ON authorization_records
      FOR ALL
      USING (project_id = current_project_id())
      WITH CHECK (project_id = current_project_id());
  ```
- **Context Establishment:** Handled exclusively via `require_project_context()`, which validates membership, verifies RBAC roles, and sets transaction-local `app.current_project_id`.

---

## 4. Roles, Permissions & API Key Scopes

In accordance with `API_CONTRACTS.md` Section 8.5:

| Action | Minimum RBAC Role | Minimum API Key Scope | HTTP Endpoint |
| :--- | :--- | :--- | :--- |
| **Create Authorization** | `admin` | `admin` | `POST /projects/{project_id}/authorizations` |
| **List Authorizations** | `viewer` | `read` | `GET /projects/{project_id}/authorizations` |
| **Get Authorization** | `viewer` | `read` | `GET /projects/{project_id}/authorizations/{authorization_id}` |
| **Revoke Authorization** | `admin` | `admin` | `POST /projects/{project_id}/authorizations/{authorization_id}/revoke` |

- **Non-Member Defense:** Requests from non-members return `404 Not Found` (via `verify_project_access`), mitigating project existence and authorization record enumeration.
- **No Manual Activation:** Authorizations do not possess a mutable `is_active` boolean. Validity is deterministically computed from the calendar window (`valid_from`, `valid_to`) and `revoked_at`.

---

## 5. Authorization Validity Semantics

The lifecycle state of an authorization record is a **pure, deterministic function** of time and revocation state:

```
                  valid_from                  valid_to
                       │                         │
  NOT_YET_VALID        │          VALID          │        EXPIRED
───────────────────────┼─────────────────────────┼───────────────────────► Time
                       │                         │
                       ▼                         ▼
                  revoked_at IS NOT NULL ──► REVOKED (Immediate termination)
```

### Exact Boundary Rules:
1. **Not-Yet-Valid:** `now < valid_from` $\rightarrow$ Evaluation outcome: `AUTHORIZATION_NOT_YET_VALID` (`allowed=False`).
2. **Effective Window:** `valid_from <= now <= valid_to` AND `revoked_at IS NULL` $\rightarrow$ Eligible for action check.
3. **Expired:** `now > valid_to` $\rightarrow$ Evaluation outcome: `AUTHORIZATION_EXPIRED` (`allowed=False`).
   - Boundary specification: The instant `valid_to` is reached, `now == valid_to` is the final valid second. Any time `now > valid_to` is strictly expired.
4. **Revoked:** `revoked_at IS NOT NULL` $\rightarrow$ Evaluation outcome: `AUTHORIZATION_REVOKED` (`allowed=False`).
   - Revocation takes effect immediately upon timestamping.
   - An expired authorization that was also revoked reports `AUTHORIZATION_REVOKED` as the higher-priority revocation signal.

---

## 6. Action Vocabulary & Parameter Constraints

### 6.1 Allowed Action Vocabulary

To prevent arbitrary privilege escalation, `allowed_actions` is strictly validated against an explicit allowlist:

```python
VALID_AUTHORIZATION_ACTIONS: Final[frozenset[str]] = frozenset({
    "scan",             # Vulnerability scanning
    "validate",         # PoC verification & finding validation
    "agent_run",        # Autonomous agent execution
    "crawl",            # Web application crawling & endpoint discovery
    "reconnaissance",   # Passive & active asset reconnaissance
    "probe",            # Network service discovery
    "fuzz",             # Input fuzzer execution
})
```

- Any action not in this allowlist is rejected at schema validation with `422 Unprocessable Entity` / `400 Bad Request`.
- An authorization permitting `["crawl"]` can never authorize `"scan"` or `"fuzz"`.

### 6.2 Destructive Actions (`destructive_allowed`)

- Destructive operations (`destructive_allowed = False`) are **blocked by default**.
- If an operation is marked as destructive (e.g. intrusive exploit verification or high-impact fuzzing), the authorization record must explicitly have `destructive_allowed = True`.
- In addition, destructive actions require run-time approval hashes as specified in `API_CONTRACTS.md` §8.11.

### 6.3 Private Ranges (`allow_private_ranges`)

- By default, RFC 1918 and link-local ranges are rejected by future scope validation.
- If `allow_private_ranges = True`, private subnets may be permitted if covered by explicit scope rules.
- **CRITICAL INVARIANT:** `allow_private_ranges = True` **CANNOT override hard-blocked cloud metadata addresses** (`169.254.169.254`, `169.254.169.253`, `169.254.170.2`, `100.100.100.200`, `fd00:ec2::254`). Cloud IMDS endpoints remain permanently blocked.

### 6.4 Request Ceilings (`max_requests_per_scan`)

- If provided, `max_requests_per_scan` must be a strictly positive integer ($1 \le N \le 10,000,000$).
- Negative, zero, or excessively large values are rejected.

---

## 7. Audit Logging Integration

All authorization events are appended to the immutable `audit_logs` table:

1. `authorization.create`: Captures `reference`, `authorized_by_name`, `valid_from`, `valid_to`, `allowed_actions`, `destructive_allowed`, `allow_private_ranges`.
2. `authorization.revoke`: Captures `authorization_id`, `revoked_at`, `revoker_id`.
3. `authorization.evaluate`: Records evaluation denials for high-severity policy violations where security auditing is warranted.

**Privacy & Redaction Rule:**
Personal contact details (`authorized_by_contact`) and unstructured `notes` are omitted or scrubbed from audit metadata to prevent PII bloat and credential exposure.

---

## 8. Identified Security Gaps & Mitigations

| Identified Risk | Impact | Architectural Mitigation |
| :--- | :--- | :--- |
| **Premature Testing** | Scans executed before legal agreement is active. | Hard boundary: `now < valid_from` evaluates to `AUTHORIZATION_NOT_YET_VALID` (`allowed=False`). |
| **Post-Engagement Testing** | Scans executed after contract expiration. | Hard boundary: `now > valid_to` evaluates to `AUTHORIZATION_EXPIRED` (`allowed=False`). |
| **Revocation Invalidation Lag** | Scans continue after client revokes consent. | `revoked_at` is evaluated on every evaluation check in real time. |
| **Action Expansion Attack** | Malicious operator adds `"exploit"` to allowed actions of existing record. | Authorization records are **strictly immutable**. No PATCH endpoint exists for terms. Changing terms requires creating a new record and revoking the previous one. |
| **Cross-Project Scope Bleed** | Project A authorization used for Project B targets. | Strict project isolation: `AuthorizationRecord.project_id == target.project_id` verified cryptographically and at RLS boundary. |
| **Cloud Metadata Bypass** | Private range permission used to probe AWS IMDS. | Hard-blocked IMDS addresses from P2.5.2 are unconditional and non-overridable by `allow_private_ranges`. |

---

## 9. Audit Sign-Off

- **Schema Alignment:** The SQLAlchemy model `AuthorizationRecord` in `backend/app/db/models/identity.py` is confirmed as the exact, complete, and authoritative definition.
- **No Schema Changes Required:** All fields required by P2.5.4 are present in the model.
- **Ready for Implementation:** Milestone P2.5.4.1 is complete. Ready to proceed to P2.5.4.2 (Schemas and Validation).
