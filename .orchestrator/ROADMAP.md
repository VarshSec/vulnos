# VulnOS — Engineering Roadmap & Milestone Tracking
## Master Product Roadmap & Autonomous Task Backlog

**Document Version:** 1.0.0  
**Effective Date:** 2026-11-02  
**Target Path:** `.orchestrator/ROADMAP.md`  

---

## 1. High-Level Seven-Phase Architecture

```text
Phase 1: Architecture Blueprint & Threat Model ............... [COMPLETED]
Phase 2: Platform Foundation, Auth, RLS & Scope Core ........ [COMPLETED]
Phase 3: Reconnaissance, Asset Discovery & Pipeline ......... [ACTIVE / IN PROGRESS]
Phase 4: Active Vulnerability Scanning & Tool Harnesses ..... [PLANNED]
Phase 5: Autonomous AI Agent Investigation & Validation ...... [PLANNED]
Phase 6: Finding Correlation, Provenance Graph & Reports .... [PLANNED]
Phase 7: Enterprise Operations, Compliance & Hardening ....... [PLANNED]
```

---

## 2. Phase Breakdown & Current Status

### Phase 1: Architectural Blueprint [COMPLETED]
- 10 canonical architectural documents in `docs/architecture/`.
- Full threat modeling, STRIDE analysis, and ADRs 001–010.

### Phase 2: Core Platform & Security Foundation [COMPLETED]
- **P2.1:** Runnable FastAPI application, middleware, readiness/liveness, structured logging.
- **P2.2:** Core database models and Alembic baseline migration `0001`.
- **P2.3:** Multi-tenant isolation and PostgreSQL Row-Level Security migration `0002`.
- **P2.4:** Authentication engine: Argon2id, JWTs, Redis sessions, API keys, RBAC.
- **P2.5:** Scope & Authorization: Seed targets, normalization, deterministic rule matching, scope versioning, written authorizations (migrations `0003`, `0004`).
- **Baseline:** 477 passing tests across all components.

---

### Phase 3: Reconnaissance, Asset Discovery & Pipeline [IN PROGRESS]

> [!IMPORTANT]
> **Anti-Fragmentation Directive:** Phase 3 must NOT be subdivided into micro-submilestones. Work is grouped into cohesive, independently testable deliverables.

#### Completed Phase 3 Deliverables:
- **P3.1.1 / P3.1.2:** Reconnaissance architecture, execution contracts, threat model, worker security.
- **P3.1.3.1 / P3.1.3.2:** Lifecycle schema audit, gap analysis, and transition matrices.
- **P3.1.3.3:** Scan lifecycle state machine (`backend/app/recon/lifecycle.py`) with 20 security tests.
- **P3.1.3.4.1–3:** ToolExecution pure transition validator and transactional service (`backend/app/recon/task_lifecycle.py`) with 40 security tests.
- **P3.1.3.4.4.1:** Worker attempt fencing architectural audit (`P3_1_3_4_4_WORKER_ATTEMPT_FENCING_AUDIT.md`).
- **Stabilization Audit:** Comprehensive project audit (`docs/audits/VULNOS_PROJECT_STABILIZATION_AUDIT.md`).

#### Immediate Phase 3 Backlog (Cohesive Milestones):

| Milestone ID | Title | Scope & Acceptance Criteria | Status |
|---|---|---|---|
| **P3-A** | **Git Checkpoint & CI Stabilization** | Commit all accumulated Phase 2 and Phase 3 code to `main`. Add live PostgreSQL container testing to GitHub Actions CI. | **Ready for Execution** |
| **P3-B** | **Worker Fencing & Scan REST API** | Implement `claim_task_lease` and `accept_worker_result` in `task_lifecycle.py`. Add 11 adversarial tests. Expose `/api/v1/scans` routes in FastAPI. | **Ready for Execution** |
| **P3-C** | **Celery Worker & First Recon Tool** | Implement Celery task worker. Package first reconnaissance tool (`subfinder` or passive DNS) in a hardened Docker runner with runtime scope checks. | Backlog |
| **P3-D** | **Observation Ingestion & Asset Inventory** | Build the observation parser to transform raw tool outputs into `Asset`, `Hostname`, `IPAddress`, and `EvidenceObject` records under tenant isolation. | Backlog |
| **P3-E** | **Active Discovery & Port Fingerprinting** | Integrate active network and HTTP discovery (`httpx`, `nmap` service detection) with rate limiting and budget enforcement. | Backlog |
| **P3-F** | **Web Crawling & API Schema Discovery** | Implement headless crawling (Playwright/katana) and OpenAPI/GraphQL schema discovery. | Backlog |

---

## 3. Definition of Done (DoD) for Any Milestone

A milestone or feature PR is strictly considered **DONE** only when:
1. **Implementation Evidence:** The code is completely implemented in the repository, not described speculatively.
2. **Quality Gates Green:**
   - `uv run ruff check .` passes with 0 errors.
   - `uv run ruff format --check .` passes with 0 formatting issues.
   - `uv run mypy backend tests` passes with 0 type errors.
   - `uv run alembic heads` confirms schema synchronization.
   - `uv run pytest -v` passes 100% of all existing and new tests.
3. **Security Invariant Verification:**
   - Multi-tenant queries include `project_id`.
   - Network interactions pass through deterministic scope validation.
   - Database mutations on tasks adhere to hierarchical locking (**Scan $\rightarrow$ ToolExecution**).
   - Sensitive values are scrubbed from logs and audit records.
4. **Documentation Accuracy:** Authoritative documentation and roadmap trackers are updated to match reality.
