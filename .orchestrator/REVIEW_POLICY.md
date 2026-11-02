# VulnOS — AI Engineering Review Policy
## Pull Request Review Standards, Security Invariant Verification & Merge Criteria

**Document Version:** 1.0.0  
**Effective Date:** 2026-11-02  
**Target Path:** `.orchestrator/REVIEW_POLICY.md`  

---

## 1. Objective of the Review Policy

This policy governs how the **AI Engineering Manager** reviews, approves, requests corrections for, or rejects Pull Requests authored by autonomous agents (such as Antigravity).

The goal is to maintain absolute security integrity, prevent architectural drift, ensure zero regression in the 477+ test baseline, and deliver working software according to the roadmap.

---

## 2. Mandatory Review Checklist

Every Pull Request must be evaluated against the following 6 review dimensions:

### 2.1 Scope Compliance
- [ ] Does the PR address *only* the specific issue it was assigned to solve?
- [ ] Are all modified files within the assigned scope boundary?
- [ ] Did the agent avoid unnecessary refactoring, dependency churn, or cosmetic tweaks in unrelated files?

### 2.2 Security Invariants & Defensive Design
- [ ] **Tenant Isolation:** Are all database queries properly filtered by `project_id`? Is tenant context preserved?
- [ ] **Deterministic Scope Matching:** Does the feature pass all target destinations through the scope matching engine (`evaluate_scope_validation`)? Does it fail closed on denial?
- [ ] **Hierarchical Locking:** If modifying `ToolExecution`, is the parent `Scan` row locked FIRST with `with_for_update()` and `ToolExecution` locked SECOND?
- [ ] **Server-Controlled Timestamps:** Are timestamps generated using server UTC (`utc_now()`), rejecting unverified worker timestamps?
- [ ] **Audit Trail Completeness:** Is an `AuditLog` entry persisted in the exact same transaction as any state mutation?
- [ ] **Secret Sanitization:** Are all tokens, passwords, and sensitive inputs properly excluded or redacted from logs, error messages, and audit metadata?

### 2.3 Test Coverage & Adversarial Testing
- [ ] Are all happy paths covered by unit tests?
- [ ] Are adversarial and boundary scenarios explicitly tested (e.g., stale worker attempts, unauthorized cross-tenant access, expired leases)?
- [ ] Are assertions rigorous and specific (no trivial `assert True` or loose status-code-only checks)?
- [ ] Did existing tests remain unmodified unless the issue explicitly mandated a behavioral change?

### 2.4 Code Quality & Style
- [ ] Does the code pass `uv run ruff check .` with 0 warnings/errors?
- [ ] Does the code pass `uv run ruff format --check .` with 0 formatting changes?
- [ ] Does the code pass `uv run mypy backend tests` with 0 type errors?
- [ ] Are all functions, methods, and classes typed with complete type annotations?

### 2.5 Database Schema & Migration Integrity
- [ ] If the schema was altered, does a valid Alembic migration script exist in `backend/alembic/versions/`?
- [ ] Does `uv run alembic heads` succeed?
- [ ] Are all check constraints, foreign keys, and indexes explicitly defined and tested?

### 2.6 Documentation & Traceability
- [ ] Does the PR body follow `.github/pull_request_template.md`?
- [ ] Is the issue properly linked (`Closes #<id>`)?
- [ ] Are execution logs, test results, and command outputs included as concrete evidence?

---

## 3. Review Outcomes & Feedback Protocol

The AI Engineering Manager issues one of three formal decisions:

### A. APPROVED (Ready to Merge)
- All 6 dimensions pass without qualification.
- CI pipeline is green.
- Label: `status:approved`.
- Action: Merge into `main` via Squash and Merge, preserving a clean history.

### B. CHANGES REQUESTED (Actionable Correction Loop)
- One or more criteria failed (e.g. missing test scenario, lock inversion, unredacted log message).
- Label: `status:changes-requested`.
- Review Feedback Format:
  1. **Defect Summary:** Clear statement of what failed.
  2. **Violated Invariant / Rule:** Reference to specific section in `.orchestrator/ARCHITECTURE.md` or `.orchestrator/EXECUTION_POLICY.md`.
  3. **Required Action:** Specific, minimal changes required to achieve compliance.
  4. **Target Files:** Explicit files requiring modification.
- Agent Action: The agent resumes work on the existing branch, implements corrections, re-runs all quality gates, updates the PR, and reapplies label `status:review-needed`.

### C. REJECTED / CLOSED
- The PR fundamentally violates VulnOS security boundaries (e.g. attempting to scan unauthorized targets, hardcoding credentials, or altering core architecture without an ADR).
- Label: `status:rejected`.
- Action: PR is closed without merging.
