# VulnOS Phase 2.5.4.2 — Authorization Schema Design & Migration Reconciliation

**Milestone:** P2.5.4.2 — Authorization Schemas, Validation & Database Migration Reconciliation  
**Date:** 2026-11-02  
**Status:** Complete & Verified  

---

## 1. Migration Reconciliation Gate Resolution

### 1.1 Discrepancy Identified
In early Phase 2.1, `backend/alembic/versions/0001_phase2_baseline.py` created the `authorization_records` table with provisional draft columns (`authorization_type`, `granted_by`, `valid_until`, `status`, `scope_summary`, `restrictions`, `reviewed_by`, `reviewed_at`, `updated_at`). 
In Phase 2.2, `DATABASE_DESIGN.md` §4.3 and `backend/app/db/models/identity.py` established the canonical legal-consent authorization schema.

### 1.2 Reconciliation Strategy
In strict adherence to repository invariants (*"Never modify historical migrations. Propose a new reversible migration"*):
- Created **Alembic Migration 0003**: [`backend/alembic/versions/0003_phase2_authorization_records.py`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/alembic/versions/0003_phase2_authorization_records.py).
- **`upgrade()` Operations:**
  1. Drops legacy check constraints (`ck_authorization_records_authorization_type`, `ck_authorization_records_status`, `ck_authorization_records_validity_range`).
  2. Drops legacy draft columns (`authorization_type`, `granted_by`, `status`, `scope_summary`, `restrictions`, `reviewed_by`, `reviewed_at`, `updated_at`).
  3. Renames `valid_until` $\rightarrow$ `valid_to`.
  4. Adds canonical columns: `reference`, `authorized_by_name`, `authorized_by_contact`, `allowed_actions` (ARRAY(Text)), `destructive_allowed` (Boolean), `allow_private_ranges` (Boolean), `max_requests_per_scan` (BigInteger), `notes` (Text), `revoked_at` (timestamptz).
  5. Creates canonical check constraint `ck_authorization_records_validity_window` (`valid_to > valid_from`).
  6. Creates project index `ix_authorization_records_project_id`.
  7. Preserves Row-Level Security (RLS) policies and all foreign keys.
- **`downgrade()` Operations:** Symmetrically reverses all column additions, renames, and constraint drops.
- **Integration Environment Status:** PostgreSQL daemon is not running on `localhost:5432` (`TcpTestSucceeded: False`), so live PostgreSQL execution is recorded as blocked. Offline migration lineage and script directory validation verified via `test_alembic.py` (heads: `0003`).

---

## 2. Canonical Schema & Field Specifications

The Pydantic schemas in [`backend/app/scope/schemas.py`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/app/scope/schemas.py) mirror the canonical database columns:

| Field | Python Type | Constraints & Validation Rules |
| :--- | :--- | :--- |
| `reference` | `str` | Min length 1, max length 255. Cannot be empty or whitespace-only. |
| `document_evidence_id` | `UUID \| None` | Valid UUID format. References encrypted legal agreement in `evidence_objects`. |
| `authorized_by_name` | `str` | Min length 1, max length 255. Authorizing officer's full name. Non-empty. |
| `authorized_by_contact` | `str` | Min length 3, max length 255. Non-empty email or phone. |
| `valid_from` | `datetime` | Must be **timezone-aware**. Normalized to UTC upon ingestion. |
| `valid_to` | `datetime` | Must be **timezone-aware**. Normalized to UTC. Must be **strictly after** `valid_from`. |
| `allowed_actions` | `list[str]` | Non-empty list. Must strictly belong to `VALID_AUTHORIZATION_ACTIONS`. Folded to lowercase and deduplicated deterministically. |
| `destructive_allowed` | `bool` | Default: `False`. Opt-in permission for intrusive security testing. |
| `allow_private_ranges` | `bool` | Default: `False`. Opt-in permission for RFC 1918 / intranet ranges. Cannot override cloud IMDS blocks. |
| `max_requests_per_scan` | `int \| None` | Optional ceiling. If provided, must be strictly positive ($1 \le N \le 10,000,000$). `None` represents no volume ceiling. |
| `notes` | `str \| None` | Optional rules of engagement / caveats (max 4,000 chars). |

---

## 3. Allowed Actions Vocabulary

Validated against an explicit compile-time set:

```python
VALID_AUTHORIZATION_ACTIONS: Final[frozenset[str]] = frozenset(
    {"scan", "validate", "agent_run", "crawl", "reconnaissance", "probe", "fuzz"}
)
```

- Any attempt to register an unrecognized action (e.g. arbitrary strings or `"exploit"`) raises a validation error.
- Case folding (`"SCAN"` $\rightarrow$ `"scan"`) and deduplication (`["scan", "scan"]` $\rightarrow$ `["scan"]`) ensure canonical representation.

---

## 4. Immutability Contract

In accordance with legal compliance and security boundary invariants:
- **No Authorization PATCH Endpoint:** Legal authorization terms (authorizer, contact, validity period, permitted actions, destructive/private flags, request limits) **cannot be mutated after creation**.
- **Material Changes:** Modifying authorization terms requires registering a **new** `AuthorizationRecord` and revoking the previous one.
- **Revocation:** Only `revoked_at` is timestamped to terminate authorization immediately.

---

## 5. Evaluation Decision Codes

The `AuthorizationReasonCode` enum defines standard decision codes for downstream evaluation (Milestone P2.5.4.4):

- `AUTHORIZATION_VALID`
- `AUTHORIZATION_NOT_FOUND`
- `AUTHORIZATION_NOT_YET_VALID`
- `AUTHORIZATION_EXPIRED`
- `AUTHORIZATION_REVOKED`
- `AUTHORIZATION_ACTION_NOT_ALLOWED`
- `AUTHORIZATION_DESTRUCTIVE_NOT_ALLOWED`
- `AUTHORIZATION_PRIVATE_RANGE_NOT_ALLOWED`
- `AUTHORIZATION_INVALID`
- `AUTHORIZATION_PROJECT_MISMATCH`
