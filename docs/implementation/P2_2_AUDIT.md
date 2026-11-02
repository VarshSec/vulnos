# VulnOS — Phase 2.2 Audit & Implementation Plan

**Date:** 2026-11-01  
**Milestone:** P2.2 (PostgreSQL Database Foundation, SQLAlchemy Models & Alembic)  
**Baseline Git HEAD:** `c2e8bb72298e2a5f03716cf70da4d837a1a9ace8`  
**Database Source of Truth:** `docs/architecture/DATABASE_DESIGN.md`  

---

## 1. Existing Database Infrastructure

- **Configuration:** `Settings` in `backend/app/core/config.py` defines:
  - `DATABASE_URL`: `postgresql+psycopg://vulnos:change-me@localhost:5432/vulnos`
  - `DATABASE_POOL_SIZE`: 10
  - `DATABASE_MAX_OVERFLOW`: 20
  - `DATABASE_ECHO`: False
  - Fail-fast production check rejecting `"change-me"` placeholder in `DATABASE_URL`.
  - Endpoint parser `parsed_db_host_port` extracting host/port safely for TCP probes.
- **Readiness Probes:** `backend/app/core/readiness.py` implements bounded TCP reachability probes (`/ready`) against PostgreSQL (5432), Redis (6379), and S3 (9000).
- **Docker Compose:** `compose.yaml` defines `postgres` service with `postgres:16-alpine@sha256:0cefaabd882e42bcb2a2f3dc56d3ce4770560ba62fd7f197f1a2e008fd5731ab` and persistent volume `vulnos_postgres_data`.
- **Runtime Docker Availability:** Docker is not installed on the host environment's PATH. Live container execution is blocked; all models, constraints, types, migrations, and static schema comparisons must be rigorously verified in code.

---

## 2. Existing Dependencies

The Python 3.13 virtual environment (`.venv`) is managed via `uv`:
- **SQLAlchemy:** `2.1.6` (SQLAlchemy 2.x declarative mapped columns, typed relationships)
- **Alembic:** `1.20.1` (database migration engine)
- **Psycopg:** `3.3.6` (psycopg 3 binary driver for PostgreSQL)
- **UUIDv7:** `uuid6` (v2025.0.1) installed to provide RFC 9562 UUIDv7 support since Python 3.13 stdlib `uuid` does not yet ship `uuid.uuid7()`.
- **Pydantic:** `2.14.2`
- **Pytest:** `8.4.2` with `pytest-asyncio` and `pytest-cov`

---

## 3. Existing Project Structure

```text
vulnos/
├── backend/
│   ├── app/
│   │   ├── api/v1/          # Versioned API routes
│   │   ├── core/            # Settings, logging, redaction, errors, middleware, readiness
│   │   ├── schemas/         # Pydantic schemas (transport)
│   │   ├── repositories/    # Data access layer
│   │   ├── services/        # Business logic use cases
│   │   ├── auth/            # Auth domain
│   │   └── main.py          # App factory
│   ├── alembic/             # Migrations
│   └── tests/               # Unit and integration test suites
├── engine/                  # Core domain logic
├── workers/                 # Background workers
├── infra/                   # Container configs
├── tests/                   # Cross-package config tests
└── docs/                    # Architecture blueprints & progress tracking
```

---

## 4. Exact Phase 2 Database Tables

`DATABASE_DESIGN.md` Section 3.4 establishes:
> "The initial model contains **50 tables**."

Every table has a distinct lifecycle, foreign keys, and indexes. The full table catalog is:

| Category | Tables | Count |
|---|---|---|
| **Identity & Tenancy** | `users`, `api_keys`, `projects`, `project_members`, `authorization_records`, `scope_versions`, `scope_rules`, `scope_decisions`, `targets` | 9 |
| **Assets & Discovery** | `assets`, `domains`, `hosts`, `host_addresses`, `services`, `endpoints`, `parameters`, `technologies`, `asset_technologies`, `api_schemas`, `asset_discoveries` | 11 |
| **Tools & Execution** | `tools`, `tool_versions`, `tool_capabilities`, `scans`, `scan_stage_runs`, `tool_executions`, `tool_selection_decisions`, `agent_runs`, `auth_contexts`, `test_cases`, `operation_approvals` | 11 |
| **Evidence & Operational** | `evidence_objects`, `http_exchanges`, `secret_refs`, `audit_logs`, `outbox_events`, `cost_entries` | 6 |
| **Findings & Correlation** | `finding_clusters`, `findings`, `finding_evidence`, `cluster_relations` | 4 |
| **Validation & Reports** | `validations`, `validation_checks`, `finding_state_transitions`, `reports` | 4 |
| **AI Subsystem** | `ai_providers`, `ai_models`, `prompt_templates`, `ai_routing_policies`, `ai_invocations` | 5 |
| **Total** | | **50** |

Per `IMPLEMENTATION_ROADMAP.md` §4 and `DATABASE_DESIGN.md` §12:
"Design full model now; additive migrations later."
Implementing all 50 interconnected tables ensures complete foreign-key integrity (e.g. `evidence_objects` references `tool_executions`, `validations` references `ai_invocations`, `findings` references `assets` and `endpoints`).

---

## 5. Missing Database Functionality in P2.1

1. **ORM Layer:** No SQLAlchemy models or Base class currently exist.
2. **Session Lifecycle:** No engine, sessionmaker, or request-scoped database dependency in FastAPI.
3. **UUIDv7 Implementation:** No centralized UUIDv7 generator or PostgreSQL UUID type mapping.
4. **Alembic Pipeline:** No `alembic.ini`, `env.py`, or initial migration script.
5. **Partitioned Table Support:** No declarative partitioning configuration for `scope_decisions`, `http_exchanges`, and `audit_logs`.

---

## 6. Architecture Ambiguities

1. **Sessions / Refresh Tokens:**
   - Prompt mentions "Sessions and refresh-token records" as a functional group.
   - However, `DATABASE_DESIGN.md` lists exactly 50 tables and does **not** define a `sessions` or `user_sessions` table.
   - `API_CONTRACTS.md` §3.1 describes browser session cookies with 30-minute access and 14-day refresh tokens.
   - `SYSTEM_ARCHITECTURE.md` §6 notes Redis acts as ephemeral cache and broker.
   - **Resolution:** In strict accordance with rule #1 ("DATABASE_DESIGN.md is the database source of truth. Do not add speculative tables"), no speculative `sessions` table is invented in PostgreSQL. Session management belongs to P2.4 (Redis/session cookie handling).
2. **PostgreSQL Partitioning in SQLAlchemy:**
   - `scope_decisions`, `http_exchanges`, and `audit_logs` are partitioned by range on `timestamptz`.
   - In SQLAlchemy, partitioned tables require composite primary keys including the partition key (`(id, decided_at)`, `(id, occurred_at)`, `(id, created_at)`).
   - In Alembic migrations, default partition tables (`_default`) must be created to ensure writes succeed safely across any timestamp range.

---

## 7. P2.2 Implementation Plan

1. **P2.2.1 — Schema Coverage Specification:** Create `docs/implementation/P2_2_SCHEMA_COVERAGE.md`.
2. **P2.2.2 — SQLAlchemy 2.x Foundation:**
   - `backend/app/db/base.py`: Declarative Base with naming conventions (`pk_`, `fk_`, `uq_`, `ck_`, `ix_`).
   - `backend/app/db/types.py`: Centralized UUIDv7 generator and custom type helpers.
   - `backend/app/db/session.py`: Connection pool pre-ping, session factory, `get_db()` dependency.
3. **P2.2.3 — Tenancy & Authorization Models:**
   - `backend/app/db/models/identity.py`: `users`, `api_keys`, `projects`, `project_members`, `authorization_records`, `scope_versions`, `scope_rules`, `scope_decisions`, `targets`.
4. **P2.2.4 — Asset Intelligence Models:**
   - `backend/app/db/models/assets.py`: `assets`, `domains`, `hosts`, `host_addresses`, `services`, `endpoints`, `parameters`, `technologies`, `asset_technologies`, `api_schemas`, `asset_discoveries`.
5. **P2.2.5 — Execution & Tool Models:**
   - `backend/app/db/models/execution.py`: `tools`, `tool_versions`, `tool_capabilities`, `scans`, `scan_stage_runs`, `tool_executions`, `tool_selection_decisions`, `agent_runs`, `auth_contexts`, `test_cases`, `operation_approvals`.
6. **P2.2.6 — Evidence & Operational Models:**
   - `backend/app/db/models/evidence.py`: `evidence_objects`, `http_exchanges`.
   - `backend/app/db/models/security.py`: `secret_refs`.
   - `backend/app/db/models/audit.py`: `audit_logs`, `outbox_events`, `cost_entries`.
7. **P2.2.7 — Findings, Validation & AI Models:**
   - `backend/app/db/models/findings.py`: `finding_clusters`, `findings`, `finding_evidence`, `cluster_relations`.
   - `backend/app/db/models/validation.py`: `validations`, `validation_checks`, `finding_state_transitions`, `reports`.
   - `backend/app/db/models/ai.py`: `ai_providers`, `ai_models`, `prompt_templates`, `ai_routing_policies`, `ai_invocations`.
8. **P2.2.8 — Alembic Migration Setup:**
   - `alembic.ini`, `backend/alembic/env.py`, initial revision `0001_initial_phase2_schema.py`.
9. **P2.2.9 — Test Verification:**
   - Unit tests for UUIDv7, models, constraints, relationships, indexes, sessions, and migration consistency.
10. **P2.2.10 — Quality & Documentation:**
   - Run Ruff, Mypy, and Pytest. Update `docs/implementation/PHASE_2_PROGRESS.md` and schema coverage report.
