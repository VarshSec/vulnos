## 1. Summary of Changes
<!-- Provide a concise description of what was implemented, fixed, or modified. -->

Closes #<!-- issue number -->

---

## 2. Scope & Boundary Confinement
- [ ] Changes are strictly confined to the files specified in the linked issue.
- [ ] No unrelated refactoring, dependency churn, or cosmetic edits were introduced.
- [ ] Protected default branch (`main`) was not modified directly.

### Files Modified / Created:
<!-- List all files touched by this PR -->
- `path/to/file1.py`
- `path/to/file2.py`

---

## 3. Security & Architecture Invariants Checklist
- [ ] **Tenant Isolation:** All database queries are scoped by `project_id`.
- [ ] **Deterministic Scope Gate:** Egress or scan destinations are validated against active `AuthorizationRecord` and `ScopeRule`.
- [ ] **Hierarchical Locking:** Task mutations acquire parent `Scan` lock FIRST and child `ToolExecution` lock SECOND.
- [ ] **Server-Controlled Timestamps:** All state transition timestamps use server UTC (`utc_now()`).
- [ ] **Audit Trail Persistence:** Every transition flushes an `AuditLog` row in the same transaction.
- [ ] **Secret Sanitization:** No credentials, tokens, or private keys are exposed in logs, exceptions, or audit metadata.

---

## 4. Pre-Submission Quality Gates
<!-- All 5 commands must pass locally before opening this PR. Check each box to confirm. -->
- [ ] `uv run ruff check .` passed with 0 errors.
- [ ] `uv run ruff format --check .` passed with 0 formatting issues.
- [ ] `uv run mypy backend tests` passed with 0 type errors.
- [ ] `uv run alembic heads` confirmed schema alignment.
- [ ] `uv run pytest -v` passed with 100% test success rate.

---

## 5. Verification Evidence
<!-- Paste the exact terminal output from the test run and type checker -->
```text
=== Pytest Summary ===
<paste pytest output here, e.g. 477 passed in 9.79s>

=== Linter & Type Check Summary ===
<paste ruff and mypy output here>
```
