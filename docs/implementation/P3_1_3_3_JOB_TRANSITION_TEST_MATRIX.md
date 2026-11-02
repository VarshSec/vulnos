# VulnOS — P3.1.3.3 Reconnaissance Job Transition Test Matrix
## Complete Coverage Matrix for Reconnaissance Job Lifecycle

**Date:** 2026-11-02  
**Milestone:** P3.1.3.3  
**Status:** Complete & Passing  
**Test File:** `backend/tests/security/recon/test_job_lifecycle.py`  
**Execution:** 20 passed in 0.78s

---

## 1. Test Coverage Overview

| Category | Count | Status | Target Functions |
|---|---|---|---|
| State Transition Graph | 6 | Passed | `validate_scan_transition()` |
| Execution Immutability | 2 | Passed | `assert_scan_context_immutable()` |
| Transactional Execution | 4 | Passed | `transition_scan()` |
| Cancellation Lifecycle | 4 | Passed | `request_scan_cancellation()` |
| Pause / Resume & Legal Revalidation | 4 | Passed | `pause_scan()`, `resume_scan()` |
| **Total** | **20** | **100% Pass** | |

---

## 2. Exhaustive Test Case Matrix

| # | Test Function Name | Transitions / Actions Tested | Category | What It Validates | Security Property Enforced |
|---|---|---|---|---|---|
| 1 | `test_validate_scan_transition_allowed_paths` | T-J01 to T-J11 | State Transition Graph | Verifies all 11 defined graph edges succeed with authorized actors. | Whitelisted state transitions only; fail-closed on unlisted paths. |
| 2 | `test_validate_scan_transition_idempotent` | Self-transitions (`X -> X`) | State Transition Graph | Calling transition to current state returns True without side effects. | Idempotency under duplicated events; prevents spurious state errors. |
| 3 | `test_validate_scan_transition_terminal_reactivation_rejected` | `completed -> *`, `failed -> *`, `cancelled -> *` | Terminal Invariance | Transitions attempting to leave terminal states raise `ReconJobAlreadyTerminalError`. | Terminal state immutability; historical scan evidence cannot be tampered with. |
| 4 | `test_validate_scan_transition_illegal_transitions_rejected` | `draft -> running`, `draft -> completed`, `queued -> completed`, `completed -> running`, etc. | State Transition Graph | Invalid jumps across the state graph raise `ReconJobInvalidStateError`. | Deterministic workflow; jobs cannot skip staging, leasing, or execution phases. |
| 5 | `test_validate_scan_transition_invalid_actors` | Unpermitted actor roles | RBAC & Actor Authorization | Client trying to force `running` or `completed` raises `ReconInvalidActorError`. | Privilege separation; untrusted clients cannot mark scans started or finished. |
| 6 | `test_validate_scan_transition_unknown_status` | Malformed/bogus status | Schema & Integrity | Non-existent status values raise `ReconJobInvalidStateError`. | Schema integrity; strict enum validation matching DB check constraint. |
| 7 | `test_assert_scan_context_immutable_allows_draft` | Updates while `draft` | Context Immutability | Mutating targets, authorization, scope, or budget in `draft` status is allowed. | Legitimate scan configuration permitted before queueing. |
| 8 | `test_assert_scan_context_immutable_rejects_queued_or_running` | Updates while `queued`, `running`, `paused` | Context Immutability | Mutating immutable parameters raises `ReconJobContextImmutableError`. | Zero TOCTOU; scan parameters cannot be tampered with once queued or running. |
| 9 | `test_transition_scan_full_lifecycle` | T-J01 -> T-J02 -> T-J04 -> T-J06 | Transactional Transitions | Full end-to-end traversal from draft to completed; verifies timestamps & `AuditLog`. | Concurrency locking; server-controlled timestamps; audit trail completeness. |
| 10 | `test_transition_scan_partial_completion` | T-J06 with `is_partial=True` | Partial Completion | Scan status becomes `completed`, `stats["partially_completed"]=True`, `ScanStageRun.status='partial'`. | Graceful partial completion without violating DB check constraints. |
| 11 | `test_transition_scan_timeout_failure` | T-J07 with `failure_reason="timeout"` | Timeout Handling | Scan status becomes `failed`, `stats["failure_reason"]="timeout"`, audit action is `recon_job.timed_out`. | Execution budget bound enforcement; fail-closed on run-away executions. |
| 12 | `test_transition_scan_not_found_and_cross_project` | Missing scan & cross-tenant | Multitenancy & RLS | Cross-project or non-existent scan ID raises `ReconJobNotFoundError`. | Strict tenant isolation; zero cross-project leakage under row-level lock. |
| 13 | `test_request_scan_cancellation_from_queued` | T-J05 | Cancellation Lifecycle | Cancelling a queued job transitions to `cancelled` and sets `cancel_requested_at`. | Prompt worker eviction; unstarted jobs cleanly cancelled. |
| 14 | `test_request_scan_cancellation_from_running` | T-J08 | Cancellation Lifecycle | Cancelling a running job transitions to `cancelled`, sets `finished_at`, records reason. | Cooperative cancellation signaling for in-flight worker draining. |
| 15 | `test_request_scan_cancellation_idempotency` | Multiple cancel requests | Cancellation Lifecycle | Second cancel request returns scan without duplicate audit log entries or error. | Idempotent cancel handling in distributed queue environments. |
| 16 | `test_request_scan_cancellation_on_completed_rejected` | Cancel on terminal | Cancellation Lifecycle | Attempting to cancel an already completed job raises `ReconJobAlreadyTerminalError`. | Terminal state protection; prevents retroactively falsifying scan outcome. |
| 17 | `test_pause_and_resume_scan_success` | T-J09 -> T-J10 | Pause / Resume | Pauses running job and resumes successfully with valid authorization & scope. | Operator control; seamless pause and resume with integrity preservation. |
| 18 | `test_resume_scan_rejects_revoked_authorization` | T-J10 with revoked consent | Legal Compliance Gate | Resuming with `AuthorizationRecord.revoked_at` set raises `ReconJobAuthorizationInvalidError`. | Immediate compliance stop; revoked consent prevents resuming operations. |
| 19 | `test_resume_scan_rejects_expired_authorization` | T-J10 with expired consent | Legal Compliance Gate | Resuming after `AuthorizationRecord.valid_to` raises `ReconJobAuthorizationInvalidError`. | Temporal validity enforcement; expired authorization prevents execution. |
| 20 | `test_resume_scan_rejects_non_paused` | T-J10 on running or draft | State Machine Integrity | Calling `resume_scan` on a scan not in `paused` state raises `ReconJobInvalidStateError`. | State machine safety; only paused jobs can be resumed. |

---

## 3. Verification Details

- **Test Framework:** Pytest 8.4.2 with asyncio mode `AUTO`
- **Execution Command:** `uv run pytest backend/tests/security/recon/test_job_lifecycle.py -v`
- **Result:** `20 passed in 0.78s`
- **Overall Project Suite:** `437 passed in 32.41s` (0 failures, 100% passing)
- **Linter & Types:** `uv run ruff check .` (Clean), `uv run ruff format --check .` (Clean), `uv run mypy backend/app/recon` (Clean).
