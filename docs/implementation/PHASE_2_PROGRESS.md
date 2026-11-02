# VulnOS — Phase 2 Implementation Progress

**Active Phase:** Phase 2 (Backend and intelligence database)  
**Current Milestone:** P2.5 — Target Management, Scope Rules & Deterministic Scope Validation  
**Status:** Completed (P2.5.1 through P2.5.6 Completed)  
**Last Updated:** 2026-11-02  

---

## 1. Milestones Overview

- **P2.1:** Repository scaffold, runnable backend & infrastructure — **COMPLETED**
- **P2.2:** PostgreSQL Database Foundation, SQLAlchemy Models & Alembic — **COMPLETED**
- **P2.3:** PostgreSQL Row-Level Security (RLS) & Cross-Project Isolation — **COMPLETED**
- **P2.4:** Authentication, Session Management, API Keys & Authorization — **COMPLETED**
- **P2.5:** Target & Scope Management — **COMPLETED**
  - **P2.5.1:** Repository audit & scope security architecture — **COMPLETED** (`P2_5_SECURITY_AUDIT.md`)
  - **P2.5.2:** Target normalization & security classification service — **COMPLETED** (`P2_5_NORMALIZATION_DESIGN.md`)
  - **P2.5.3:** Target CRUD API with RLS tenant context & authorization guard — **COMPLETED** (`P2_5_TARGET_MANAGEMENT_DESIGN.md`)
  - **P2.5.4:** Authorization records lifecycle, evaluation engine & legal consent — **COMPLETED** (`P2_5_AUTHORIZATION_DESIGN.md`, `P2_5_AUTHORIZATION_LIFECYCLE.md`, `P2_5_AUTHORIZATION_TEST_MATRIX.md`)
  - **P2.5.5:** Deterministic scope rule matching engine — **COMPLETED** (`P2_5_SCOPE_RULE_MATCHING_AUDIT.md`, `P2_5_SCOPE_RULE_MATCHING_DESIGN.md`, `P2_5_SCOPE_RULE_MATCHING_TEST_MATRIX.md`)
  - **P2.5.6:** Scope versioning, rule CRUD, activation & validation dry-run endpoint — **COMPLETED** (`P2_5_SCOPE_VERSIONING_DESIGN.md`, `P2_5_SCOPE_VALIDATION_DESIGN.md`)

---

## 2. P2.5 Completed Deliverables

| Deliverable | Description | Status |
|---|---|---|
| **P2.5.1 Security Audit** | Authored `docs/implementation/P2_5_SECURITY_AUDIT.md` covering existing schema, target architecture, scope models, project ownership boundaries, immutable versioning strategy, and attack surface. | Completed |
| **P2.5.2 Target Normalization Service** | Implemented `backend/app/scope/normalization.py` providing canonicalization for domain, host, ip, url, api_base, repository, IDNA UTS #46 processing, RFC 5952 IPv6 compression, IPv4-mapped IPv6 unpacking, RFC 3986 URL path resolution, and non-overridable cloud IMDS hard-blocking (`169.254.169.254`, etc.). | Completed |
| **P2.5.2 Design Documentation** | Authored `docs/implementation/P2_5_NORMALIZATION_DESIGN.md` detailing grammar, rules, idempotency proofs, security classifications, and exception hierarchy. | Completed |
| **P2.5.2 Security Test Suite** | 51 dedicated unit and adversarial tests across domain, host, IP/CIDR, URL, API base, repository, SSRF classification, and idempotency in `backend/tests/security/scope/test_normalization.py`. | Completed |
| **P2.5.3 Target Management Service** | Implemented `backend/app/scope/targets.py` supporting creation, retrieval, project-scoped listing, metadata updates, and soft-delete archiving with append-only audit logging and the critical discovery seed non-authorization invariant. | Completed |
| **P2.5.3 Pydantic Schemas & Router** | Implemented `backend/app/scope/schemas.py` and `backend/app/api/v1/targets.py` enforcing RBAC (`admin` for write/archive, `viewer` for read), API key scopes, and non-member 404 enumeration prevention. | Completed |
| **P2.5.3 Design Documentation** | Authored `docs/implementation/P2_5_TARGET_MANAGEMENT_DESIGN.md` detailing lifecycle states, invariants, API contracts, RLS context establishment, and audit events. | Completed |
| **P2.5.3 Security Test Suites** | 27 dedicated tests: 16 service security tests (`test_targets.py`) and 11 HTTP endpoint tests (`test_target_endpoints.py`). | Completed |
| **P2.5.4 Migration Reconciliation** | Created Alembic migration `backend/alembic/versions/0003_phase2_authorization_records.py` aligning draft baseline DDL with canonical `AuthorizationRecord` model and `DATABASE_DESIGN.md`. | Completed |
| **P2.5.4 Authorization Service & Router** | Implemented `backend/app/scope/authorizations.py` and `backend/app/api/v1/authorizations.py` supporting creation, retrieval, paginated listing, idempotent revocation, and deterministic evaluation engine (`evaluate_authorization`). | Completed |
| **P2.5.4 Design & Lifecycle Docs** | Authored `P2_5_AUTHORIZATION_AUDIT.md`, `P2_5_AUTHORIZATION_SCHEMA_DESIGN.md`, `P2_5_AUTHORIZATION_DESIGN.md`, `P2_5_AUTHORIZATION_LIFECYCLE.md`, and `P2_5_AUTHORIZATION_TEST_MATRIX.md`. | Completed |
| **P2.5.4 Security Test Suites** | 44 dedicated tests: 14 schema tests (`test_authorization_schemas.py`), 15 service/evaluation tests (`test_authorizations.py`), and 15 HTTP endpoint tests (`test_authorization_endpoints.py`). | Completed |
| **P2.5.5 Scope Rule Matching Engine** | Implemented `backend/app/scope/matching.py` with pure, deterministic rule evaluation (`match_scope_rules`), safe path-boundary prefix matching, DNS label boundary suffix matching, wildcard apex exclusion (`*.example.com != example.com`), strict CIDR containment, port/protocol constraints, global deny-overrides-allow precedence, and deterministic diagnostic tie-breaking. | Completed |
| **P2.5.5 Design & Audit Docs** | Authored `P2_5_SCOPE_RULE_MATCHING_AUDIT.md`, `P2_5_SCOPE_RULE_MATCHING_DESIGN.md`, and `P2_5_SCOPE_RULE_MATCHING_TEST_MATRIX.md`. | Completed |
| **P2.5.5 Security Test Suite** | 30 dedicated adversarial tests in `backend/tests/security/scope/test_rule_matching.py` covering all 7 match types, wildcard edge cases, IDNA normalization, IP/CIDR boundaries, port ranges, protocols, global deny precedence, immutability, and deterministic tie-breaking. | Completed |
| **P2.5.6 Scope Rules Migration** | Created Alembic migration `backend/alembic/versions/0004_phase2_scope_rules.py` reconciling draft baseline DDL with canonical `ScopeRule` model and `DATABASE_DESIGN.md` §4.4. | Completed |
| **P2.5.6 Scope Versioning & Validation** | Implemented `backend/app/scope/versions.py` and `backend/app/api/v1/scope.py` supporting scope version creation, rule set replacement, activation with legal consent checks, atomic superseding, deterministic content hashing, and validation decision evaluation with append-only auditing. | Completed |
| **P2.5.6 Design Documentation** | Authored `P2_5_SCOPE_VERSIONING_DESIGN.md` and `P2_5_SCOPE_VALIDATION_DESIGN.md` detailing lifecycle state transitions, activation gates, and evaluation pipeline. | Completed |
| **P2.5.6 Integration & Security Test Suite** | 17 dedicated security tests in `backend/tests/security/scope/test_scope_versioning.py` covering the complete lifecycle, immutability enforcement, atomic superseding, authorization gating, cloud IMDS protection, and decision audit logging. | Completed |

---

## 3. P2.4 Completed Deliverables

| Deliverable | Description | Status |
|---|---|---|
| **Security Audit** | Authored `docs/implementation/P2_4_SECURITY_AUDIT.md` covering existing identity architecture, password storage requirements, session strategy, API key lifecycle, Redis security, and attack surface analysis. | Completed |
| **Argon2id Password Hashing** | Implemented `backend/app/auth/passwords.py` with OWASP-recommended parameters (time_cost=3, memory_cost=65536 KiB, parallelism=4, hash_len=32, salt_len=16). Constant-time dummy verification path for non-existent users mitigates timing-based username enumeration. | Completed |
| **JWT Access Tokens** | Implemented `backend/app/auth/tokens.py` with HS256, strict issuer/audience claims validation, token type isolation, and configurable TTL. Refresh token generation uses `secrets.token_bytes(32)` with SHA-256 hashing. | Completed |
| **Redis Session Management** | Implemented `backend/app/auth/sessions.py` providing stateful sessions stored exclusively in Redis. No relational sessions table. Includes atomic refresh token rotation with replay detection and token family revocation. | Completed |
| **API Key Lifecycle** | Implemented `backend/app/auth/api_keys.py` with `vulnos_{prefix}_{secret}` format, HMAC-SHA-256 verification using server `API_KEY_PEPPER`, prefix-based database lookup, constant-time digest comparison, scopes, expiration, and revocation. | Completed |
| **RBAC & Project Access** | Implemented `backend/app/authorization/permissions.py` and `project_access.py` with role hierarchy (viewer < operator < admin < owner), scope evaluation for API keys, and 404 responses for non-members to prevent project existence enumeration. | Completed |
| **Authentication Service** | Implemented `backend/app/auth/service.py` providing `register_user()`, `authenticate_user()`, and `change_password()` with constant-time verification paths. | Completed |
| **FastAPI Auth Dependencies** | Implemented `backend/app/auth/dependencies.py` with Bearer/cookie dual resolution, CSRF double-submit verification, and project access guard that establishes RLS tenant context only after identity + RBAC verification. | Completed |
| **Rate Limiting & Audit** | Implemented `backend/app/auth/rate_limits.py` with Redis sliding window counter and append-only `AuditLog` recorder with automatic secrets scrubbing. | Completed |
| **Auth Routers** | Implemented `backend/app/api/v1/auth.py` (register, login, refresh, logout, logout-all, change-password, me) and `backend/app/api/v1/api_keys.py` (create, list, get, revoke). | Completed |
| **Pydantic Schemas** | Implemented `backend/app/auth/schemas.py` with `EmailStr` validation, strict password length enforcement, and safe response models that never expose credentials. | Completed |
| **Security Test Suite** | 30 dedicated auth security tests across 7 test files in `backend/tests/security/auth/`. | Completed |
| **Documentation** | `P2_4_AUTH_DESIGN.md`, `P2_4_SESSION_DESIGN.md`, `P2_4_API_KEY_DESIGN.md`, `P2_4_AUTH_TEST_MATRIX.md`. | Completed |

---

## 4. P2.3 Completed Deliverables

| Deliverable | Description | Status |
|---|---|---|
| **Security Audit & Table Ownership** | Authored `docs/implementation/P2_3_SECURITY_AUDIT.md` providing an exhaustive classification of all 50 tables across 5 isolation tiers (Direct Project, Root Tenant, Indirect Project, Mixed, User, Global Catalog). | Completed |
| **PostgreSQL Verification Runbook** | Authored `docs/implementation/P2_3_POSTGRESQL_VERIFICATION.md` detailing static schema compilation, dialect verification, and Docker/PostgreSQL runbook. | Completed |
| **RLS Architecture & Policy Design** | Authored `docs/implementation/P2_3_RLS_DESIGN.md` defining transaction-local settings (`set_config(..., true)`), helper SQL functions (`current_project_id()`), pool safety, and least-privilege role separation (`vulnos_admin` vs `vulnos_app`). | Completed |
| **Tenant Context Module** | Implemented `backend/app/db/tenant.py` providing `set_tenant_context()`, `clear_tenant_context()`, `tenant_context()` context manager, `get_current_tenant_context()`, and FastAPI dependency `get_tenant_db()`. | Completed |
| **Connection Pool Leakage Prevention** | Engine pool event listeners registered in `backend/app/db/session.py` to execute `RESET ALL;` upon connection checkout/checkin. | Completed |
| **Alembic RLS Migration** | Created `backend/alembic/versions/0002_phase2_rls.py` enabling and forcing RLS on 35 direct project tables, `projects` root, 2 indirect tables, 3 partitions, append-only `audit_logs`, and cross-project FK check triggers. Complete symmetric downgrade routine. | Completed |
| **Security Test Suite** | 20 dedicated security tests across `backend/tests/security/` covering tenant context lifecycle, RLS migration DDL compilation, AST verification, and multi-tenant isolation matrices. | Completed |

---

## 5. Database Schema & RLS Policy Summary (50 Tables)

### Isolation Tiers:
1. **Direct Project Tables (35 tables):** Policy: `project_id = current_project_id()` for all DML operations.
2. **Tenant Root (1 table):** `projects`: `id = current_project_id()`.
3. **Indirect Project Tables (2 tables):** `scope_rules`, `validation_checks`: Isolated via FK subquery.
4. **Append-Only Immutability (1 table):** `audit_logs`: Tenant reads own logs; `UPDATE` and `DELETE` rejected.
5. **Default Partitions (3 partition tables):** `scope_decisions_default`, `http_exchanges_default`, `audit_logs_default`.
6. **User Tier (2 tables):** `users`, `api_keys`: Protected via user authentication and session management.
7. **Global Catalogs & Infra (9 tables):** Shared read-only catalogs.

---

## 6. Test Execution & Quality Gates

All checks executed locally using Python 3.13:

### Code Formatting, Linting & Type Checking
```bash
uv run ruff check .
# Result: All checks passed! (0 errors)

uv run ruff format --check .
# Result: 92 files already formatted

uv run mypy backend tests
# Result: Success: no issues found in 89 source files (0 errors)
```

### Full Test Suite Execution
```bash
uv run pytest -v
# Result: 417 passed in 11.97s
```

Test suite breakdown:
- **P2.5 Scope, Target & Authorization Tests: 169 tests** (`backend/tests/security/scope/`)
  - Target normalization & security classification: 51 tests (`test_normalization.py`)
  - Target management service, RLS & invariants: 16 tests (`test_targets.py`)
  - Target HTTP endpoints, RBAC & API key scopes: 11 tests (`test_target_endpoints.py`)
  - Authorization schemas & validation: 14 tests (`test_authorization_schemas.py`)
  - Authorization service & evaluation engine: 15 tests (`test_authorizations.py`)
  - Authorization HTTP endpoints, RBAC & immutability: 15 tests (`test_authorization_endpoints.py`)
  - Scope rule matching engine & adversarial edge cases: 30 tests (`test_rule_matching.py`)
  - Scope versioning, lifecycle, activation & validation audit: 17 tests (`test_scope_versioning.py`)
- **P2.4 Auth Security Tests: 30 tests** (`backend/tests/security/auth/`)
  - Password hashing & timing mitigation: 4 tests (`test_passwords.py`)
  - JWT access tokens & claims: 6 tests (`test_tokens.py`)
  - Redis sessions & replay detection: 5 tests (`test_sessions.py`)
  - API key lifecycle & HMAC: 5 tests (`test_api_keys.py`)
  - RBAC & project access: 5 tests (`test_rbac.py`)
  - RLS/auth integration: 3 tests (`test_rls_auth_integration.py`)
  - E2E HTTP endpoints: 2 tests (`test_auth_endpoints.py`)
- **P2.3 Security Tests: 20 tests** (`backend/tests/security/`)
  - Tenant isolation matrix: 8 tests (`test_isolation_matrix.py`)
  - RLS migration DDL: 5 tests (`test_rls_migration_ddl.py`)
  - Tenant context lifecycle: 7 tests (`test_tenant_context.py`)
- **P2.1 & P2.2 Core Tests: 196 tests**
  - Table registration, PKs, columns, relationships: 121 tests (`test_models.py`)
  - Constraints, cascades, indexes: 18 tests (`test_constraints.py`)
  - UUIDv7 compliance: 13 tests (`test_uuid7.py`)
  - Probes & API contracts: 10 tests (`test_app.py`)
  - Configuration & production fail-fast: 8 tests (`test_settings.py`)
  - Redaction & safety: 6 tests (`test_redaction.py`)
  - Readiness & TCP honesty: 5 tests (`test_readiness.py`)
  - Alembic configuration: 5 tests (`test_alembic.py`)
  - Database session lifecycle: 4 tests (`test_session.py`)
  - Logging & correlation: 4 tests (`test_logging.py`)
  - Infrastructure & Dockerfile: 2 tests (`test_infra_config.py`)

---

## 6. Architectural & Security Decisions

### P2.5 Scope Rule Matching Decisions

1. **Global Deny Precedence:** Any matching `deny` rule immediately overrides any matching `allow` rule, regardless of rule priority or specificity. This guarantees fail-closed semantics for critical operational exclusions.
2. **Wildcard Apex Exclusion Invariant:** `wildcard_domain: *.example.com` matches subdomains only; it strictly **rejects** the apex domain `example.com`. To authorize both the apex and subdomains, `domain_suffix: example.com` must be used.
3. **Safe Path-Boundary Prefix Matching:** `url_prefix` matching enforces strict path segment boundaries (`/` or exact match). A rule with `/api` matches `/api` and `/api/v1`, but strictly rejects `/apiv2` or `/api-docs`.
4. **Deterministic Diagnostic Selection:** When multiple rules of the winning effect match, the representative rule reported in `matched_rule_id` is selected by `priority DESC`, then `id ASC`. This ensures 100% reproducible audit logs without affecting the binary decision.
5. **Fail-Closed Malformed Input Handling:** Targets that fail normalization or rules with unknown match types fail closed (`ALLOWED=False`, `reason_code=INVALID_TARGET` or `UNSUPPORTED_RULE`) without throwing uncaught runtime exceptions.

### P2.4 Authentication Decisions

1. **Argon2id with OWASP Parameters:** `time_cost=3`, `memory_cost=65536` (64 MiB), `parallelism=4`. Provides strong resistance against GPU/ASIC attacks while maintaining acceptable latency.
2. **Constant-Time Dummy Verification:** When user is not found during login, `verify_password(None, password)` runs against a pre-computed dummy Argon2id hash to equalize response timing.
3. **Stateful Redis Sessions:** Browser sessions live exclusively in Redis with `vulnos_session` HttpOnly/Secure/SameSite=Lax cookie. No relational sessions table.
4. **Atomic Refresh Token Rotation:** Each rotation marks the current token as `used=1`, generates a new token in the same family, and stores both atomically in a Redis pipeline. Replay detection triggers immediate family-wide revocation.
5. **HMAC-SHA-256 API Keys with Pepper:** API key secrets are hashed with a server-side `API_KEY_PEPPER` environment variable. Prefix-based database lookup avoids full-table scans; constant-time `hmac.compare_digest` prevents timing attacks.
6. **Fail-Closed RLS Integration:** `get_project_access_guard()` establishes the PostgreSQL transaction-local `app.current_project_id` **only** after successful authentication + RBAC verification. The client never directly specifies the tenant context.
7. **Non-Member 404:** Non-members of a project receive HTTP 404 (not 403) to prevent project existence enumeration.
8. **Append-Only Audit Integrity:** `record_auth_audit_event()` automatically scrubs sensitive keys (password, token, secret, key, hash) from metadata before writing to `audit_logs`.

### P2.3 RLS Decisions

1. **Transaction-Local Isolation:** `set_config('app.current_project_id', :project_id, true)` with `is_local=true`.
2. **Connection Pool Scavenging:** `RESET ALL;` on connection checkin/reset.
3. **Defense-in-Depth:** `FORCE ROW LEVEL SECURITY` on all tenant tables.
4. **Cross-Project FK Triggers:** `check_cross_project_reference()` prevents cross-project foreign key pollution.

---

## 7. Known Environmental Blockers

1. **Docker Runtime:** Docker is not installed on the host environment's PATH. Static Compose, Dockerfile, dialect DDL compilation, and AST verification pass, but physical PostgreSQL 16 container execution is blocked until Docker Desktop / WSL2 is configured.
2. **Missing Documents from Phase 1:** `PHASE_1_REVIEW.md` was identified as missing from the repository baseline.

---

## 8. Phase 2 Completion & Next Steps

Phase 2 is now **100% complete across all milestones (P2.1, P2.2, P2.3, P2.4, P2.5)**.
- **P2.1:** Repository scaffold, FastAPI app, logging, telemetry & Docker/Compose setup.
- **P2.2:** PostgreSQL 16 schema, 50 SQLAlchemy models, Alembic migrations baseline & seed fixtures.
- **P2.3:** Row-Level Security (RLS), multi-tenant isolation, session reset listeners & migration DDL.
- **P2.4:** Argon2id password hashing, JWT access tokens, Redis sessions, HMAC API keys & RBAC.
- **P2.5:** Target normalization, target CRUD, authorization record lifecycle, deterministic scope rule matching, scope versioning, atomic activation with consent checks & validation decision auditing.

### Next Roadmap Phase:
- **Phase 2.6 (Asset Inventory Service):** Asset management service layer for discovered assets (Domains, Subdomains, IP Addresses, Services/Ports, HTTP Endpoints, Technologies) with RLS enforcement and immutable provenance linking.
- **Phase 3 (Reconnaissance & Tool Execution Pipeline):** Orchestration engine, tool sandboxing, Celery/temporal execution tasks, and automated discovery workflows strictly bound by `POST /projects/{id}/scope/validate`.

---

## 9. Git Safety Compliance

- No commits, merges, or pushes have been performed.
- Baseline `c2e8bb72298e2a5f03716cf70da4d837a1a9ace8` is preserved.
