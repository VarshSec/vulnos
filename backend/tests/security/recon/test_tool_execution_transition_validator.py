"""Unit tests for VulnOS Pure ToolExecution State Transition Validator.

Validates:
1. Every approved transition (T-T01 to T-T11).
2. Every rejected transition edge.
3. Terminal-state invariance.
4. Permanent non-retryability of scope violations.
5. Missing or invalid retry contexts.
6. Authorized timeout and failure retries.
7. Retry rejection for succeeded tasks.
8. Retry rejection for cancelled tasks.
9. Retry rejection for skipped tasks.
10. Retry rejection for scope violations.
11. Unauthorized actor category rejection.
12. Worker privilege restrictions (preventing operator-level transitions).
13. Invalid attempt values and max attempt bounds.
14. Missing worker context (worker_id, attempt).
15. Parent Scan state policies (scheduling, claiming, completion, retry).
16. Unknown task status validation.
17. Unknown actor type validation.
18. Deterministic, side-effect-free validation results.
19. Zero mutation of input context dictionaries.
20. Explicit distinction between task creation and ordinary transition.
"""

from __future__ import annotations

import copy
from typing import Any

import pytest

from backend.app.recon.exceptions import (
    ReconTaskInvalidActorError,
    ReconTaskInvalidAttemptError,
    ReconTaskInvalidTransitionError,
    ReconTaskParentStateInvalidError,
    ReconTaskRetryNotAllowedError,
    ReconTaskTerminalStateError,
)
from backend.app.recon.task_lifecycle import (
    ACTOR_ADMIN,
    ACTOR_OPERATOR,
    ACTOR_ORCHESTRATOR,
    ACTOR_OWNER,
    ACTOR_SCOPE_ENFORCEMENT,
    ACTOR_SYSTEM,
    ACTOR_TIMEOUT_CONTROLLER,
    ACTOR_WORKER,
    SCAN_STATUS_CANCELLED,
    SCAN_STATUS_COMPLETED,
    SCAN_STATUS_DRAFT,
    SCAN_STATUS_FAILED,
    SCAN_STATUS_PAUSED,
    SCAN_STATUS_QUEUED,
    SCAN_STATUS_RUNNING,
    STATUS_CANCELLED,
    STATUS_FAILED,
    STATUS_QUEUED,
    STATUS_RUNNING,
    STATUS_SCOPE_VIOLATION,
    STATUS_SKIPPED,
    STATUS_SUCCEEDED,
    STATUS_TIMEOUT,
    validate_tool_execution_transition,
)


def test_every_approved_transition() -> None:
    """Validate all 11 approved transitions (T-T01 to T-T11) succeed with authorized actors."""
    # T-T01: None -> queued (creation)
    assert validate_tool_execution_transition(
        current_status=None,
        requested_status=STATUS_QUEUED,
        actor_type=ACTOR_ORCHESTRATOR,
        parent_scan_status=SCAN_STATUS_RUNNING,
    )

    # T-T02: queued -> running (worker claims lease)
    assert validate_tool_execution_transition(
        current_status=STATUS_QUEUED,
        requested_status=STATUS_RUNNING,
        actor_type=ACTOR_WORKER,
        parent_scan_status=SCAN_STATUS_RUNNING,
        context={"worker_id": "worker-1"},
    )

    # T-T03: queued -> cancelled
    assert validate_tool_execution_transition(
        current_status=STATUS_QUEUED,
        requested_status=STATUS_CANCELLED,
        actor_type=ACTOR_OPERATOR,
        parent_scan_status=SCAN_STATUS_RUNNING,
    )

    # T-T04: running -> succeeded
    assert validate_tool_execution_transition(
        current_status=STATUS_RUNNING,
        requested_status=STATUS_SUCCEEDED,
        actor_type=ACTOR_WORKER,
        parent_scan_status=SCAN_STATUS_RUNNING,
        context={"worker_id": "worker-1", "attempt": 1},
    )

    # T-T05: running -> failed
    assert validate_tool_execution_transition(
        current_status=STATUS_RUNNING,
        requested_status=STATUS_FAILED,
        actor_type=ACTOR_WORKER,
        parent_scan_status=SCAN_STATUS_RUNNING,
        context={"worker_id": "worker-1", "attempt": 1},
    )

    # T-T06: running -> timeout
    assert validate_tool_execution_transition(
        current_status=STATUS_RUNNING,
        requested_status=STATUS_TIMEOUT,
        actor_type=ACTOR_TIMEOUT_CONTROLLER,
        parent_scan_status=SCAN_STATUS_RUNNING,
    )

    # T-T07: running -> cancelled
    assert validate_tool_execution_transition(
        current_status=STATUS_RUNNING,
        requested_status=STATUS_CANCELLED,
        actor_type=ACTOR_OPERATOR,
        parent_scan_status=SCAN_STATUS_RUNNING,
    )

    # T-T08: running -> scope_violation
    assert validate_tool_execution_transition(
        current_status=STATUS_RUNNING,
        requested_status=STATUS_SCOPE_VIOLATION,
        actor_type=ACTOR_SCOPE_ENFORCEMENT,
        parent_scan_status=SCAN_STATUS_RUNNING,
    )

    # T-T09: queued -> skipped
    assert validate_tool_execution_transition(
        current_status=STATUS_QUEUED,
        requested_status=STATUS_SKIPPED,
        actor_type=ACTOR_ORCHESTRATOR,
        parent_scan_status=SCAN_STATUS_RUNNING,
    )

    # T-T10: failed -> queued (retry)
    assert validate_tool_execution_transition(
        current_status=STATUS_FAILED,
        requested_status=STATUS_QUEUED,
        actor_type=ACTOR_ORCHESTRATOR,
        parent_scan_status=SCAN_STATUS_RUNNING,
        context={"is_retry": True, "attempt": 1, "max_attempts": 3},
    )

    # T-T11: timeout -> queued (retry)
    assert validate_tool_execution_transition(
        current_status=STATUS_TIMEOUT,
        requested_status=STATUS_QUEUED,
        actor_type=ACTOR_ADMIN,
        parent_scan_status=SCAN_STATUS_RUNNING,
        context={"is_retry": True, "attempt": 2, "max_attempts": 3},
    )


def test_every_rejected_transition() -> None:
    """Verify illegal status transition edges are rejected."""
    illegal_transitions = [
        (None, STATUS_RUNNING),
        (None, STATUS_SUCCEEDED),
        (None, STATUS_FAILED),
        (STATUS_QUEUED, STATUS_SUCCEEDED),
        (STATUS_QUEUED, STATUS_FAILED),
        (STATUS_QUEUED, STATUS_TIMEOUT),
        (STATUS_QUEUED, STATUS_SCOPE_VIOLATION),
        (STATUS_RUNNING, STATUS_QUEUED),  # Running cannot jump to queued
        (STATUS_SUCCEEDED, STATUS_RUNNING),
        (STATUS_CANCELLED, STATUS_RUNNING),
        (STATUS_FAILED, STATUS_RUNNING),
        (STATUS_TIMEOUT, STATUS_RUNNING),
        (STATUS_SKIPPED, STATUS_RUNNING),
    ]

    for current, requested in illegal_transitions:
        with pytest.raises((ReconTaskInvalidTransitionError, ReconTaskTerminalStateError)):
            validate_tool_execution_transition(
                current_status=current,
                requested_status=requested,
                actor_type=ACTOR_ORCHESTRATOR,
                parent_scan_status=SCAN_STATUS_RUNNING,
                context={"worker_id": "w1", "attempt": 1},
            )


def test_terminal_state_invariance() -> None:
    """Verify succeeded, cancelled, and skipped tasks cannot transition to any state."""
    terminal_statuses = [STATUS_SUCCEEDED, STATUS_CANCELLED, STATUS_SKIPPED]
    target_statuses = [
        STATUS_QUEUED,
        STATUS_RUNNING,
        STATUS_SUCCEEDED,
        STATUS_FAILED,
        STATUS_TIMEOUT,
        STATUS_CANCELLED,
        STATUS_SKIPPED,
        STATUS_SCOPE_VIOLATION,
    ]

    for terminal in terminal_statuses:
        for target in target_statuses:
            if terminal == target:
                # Idempotent self-transition returns True
                assert validate_tool_execution_transition(
                    current_status=terminal,
                    requested_status=target,
                    actor_type=ACTOR_ORCHESTRATOR,
                )
            else:
                with pytest.raises(ReconTaskTerminalStateError):
                    validate_tool_execution_transition(
                        current_status=terminal,
                        requested_status=target,
                        actor_type=ACTOR_ORCHESTRATOR,
                        context={"is_retry": True},
                    )


def test_scope_violation_non_retryability() -> None:
    """Verify tasks failing with scope_violation can NEVER be retried or transitioned."""
    # Attempt retry
    with pytest.raises(ReconTaskRetryNotAllowedError) as exc_info:
        validate_tool_execution_transition(
            current_status=STATUS_SCOPE_VIOLATION,
            requested_status=STATUS_QUEUED,
            actor_type=ACTOR_ORCHESTRATOR,
            context={"is_retry": True, "attempt": 1},
        )
    assert "permanently non-retryable" in str(exc_info.value)

    # Attempt normal transition to running
    with pytest.raises(ReconTaskRetryNotAllowedError):
        validate_tool_execution_transition(
            current_status=STATUS_SCOPE_VIOLATION,
            requested_status=STATUS_RUNNING,
            actor_type=ACTOR_WORKER,
            context={"worker_id": "w1"},
        )


def test_failed_retry_with_missing_retry_context() -> None:
    """Verify failed tasks cannot transition to queued without explicit retry context."""
    # No context at all
    with pytest.raises(ReconTaskRetryNotAllowedError) as exc_info:
        validate_tool_execution_transition(
            current_status=STATUS_FAILED,
            requested_status=STATUS_QUEUED,
            actor_type=ACTOR_ORCHESTRATOR,
            context=None,
        )
    assert "explicit retry context" in str(exc_info.value)

    # is_retry=False
    with pytest.raises(ReconTaskRetryNotAllowedError):
        validate_tool_execution_transition(
            current_status=STATUS_FAILED,
            requested_status=STATUS_QUEUED,
            actor_type=ACTOR_ORCHESTRATOR,
            context={"is_retry": False},
        )


def test_timeout_retry_with_valid_context() -> None:
    """Verify timeout tasks can be retried when valid retry context is provided."""
    res = validate_tool_execution_transition(
        current_status=STATUS_TIMEOUT,
        requested_status=STATUS_QUEUED,
        actor_type=ACTOR_ORCHESTRATOR,
        parent_scan_status=SCAN_STATUS_RUNNING,
        context={"is_retry": True, "attempt": 1, "max_attempts": 3},
    )
    assert res is True


def test_retry_rejected_for_succeeded_tasks() -> None:
    """Verify succeeded tasks cannot be retried even if is_retry=True is passed."""
    with pytest.raises(ReconTaskTerminalStateError):
        validate_tool_execution_transition(
            current_status=STATUS_SUCCEEDED,
            requested_status=STATUS_QUEUED,
            actor_type=ACTOR_OPERATOR,
            context={"is_retry": True, "attempt": 1},
        )


def test_retry_rejected_for_cancelled_tasks() -> None:
    """Verify cancelled tasks cannot be retried."""
    with pytest.raises(ReconTaskTerminalStateError):
        validate_tool_execution_transition(
            current_status=STATUS_CANCELLED,
            requested_status=STATUS_QUEUED,
            actor_type=ACTOR_OPERATOR,
            context={"is_retry": True, "attempt": 1},
        )


def test_retry_rejected_for_skipped_tasks() -> None:
    """Verify skipped tasks cannot be retried."""
    with pytest.raises(ReconTaskTerminalStateError):
        validate_tool_execution_transition(
            current_status=STATUS_SKIPPED,
            requested_status=STATUS_QUEUED,
            actor_type=ACTOR_ORCHESTRATOR,
            context={"is_retry": True, "attempt": 1},
        )


def test_retry_rejected_for_scope_violations() -> None:
    """Verify scope_violation tasks cannot be retried even by admin."""
    with pytest.raises(ReconTaskRetryNotAllowedError):
        validate_tool_execution_transition(
            current_status=STATUS_SCOPE_VIOLATION,
            requested_status=STATUS_QUEUED,
            actor_type=ACTOR_ADMIN,
            context={"is_retry": True, "attempt": 1},
        )


def test_unauthorized_actor_rejection() -> None:
    """Verify invalid or arbitrary actor strings are rejected."""
    invalid_actors = ["untrusted", "anonymous", "hacker", "client", "user", ""]

    for actor in invalid_actors:
        with pytest.raises(ReconTaskInvalidActorError):
            validate_tool_execution_transition(
                current_status=STATUS_QUEUED,
                requested_status=STATUS_RUNNING,
                actor_type=actor,
                context={"worker_id": "w1"},
            )


def test_worker_cannot_perform_operator_only_transitions() -> None:
    """Verify workers cannot trigger cancellations, retries, creation, or skipping."""
    # Worker cannot create tasks
    with pytest.raises(ReconTaskInvalidActorError):
        validate_tool_execution_transition(
            current_status=None,
            requested_status=STATUS_QUEUED,
            actor_type=ACTOR_WORKER,
            context={"worker_id": "w1"},
        )

    # Worker cannot cancel queued task
    with pytest.raises(ReconTaskInvalidActorError):
        validate_tool_execution_transition(
            current_status=STATUS_QUEUED,
            requested_status=STATUS_CANCELLED,
            actor_type=ACTOR_WORKER,
            context={"worker_id": "w1"},
        )

    # Worker cannot cancel running task
    with pytest.raises(ReconTaskInvalidActorError):
        validate_tool_execution_transition(
            current_status=STATUS_RUNNING,
            requested_status=STATUS_CANCELLED,
            actor_type=ACTOR_WORKER,
            context={"worker_id": "w1"},
        )

    # Worker cannot skip task
    with pytest.raises(ReconTaskInvalidActorError):
        validate_tool_execution_transition(
            current_status=STATUS_QUEUED,
            requested_status=STATUS_SKIPPED,
            actor_type=ACTOR_WORKER,
            context={"worker_id": "w1"},
        )

    # Worker cannot retry failed task
    with pytest.raises(ReconTaskInvalidActorError):
        validate_tool_execution_transition(
            current_status=STATUS_FAILED,
            requested_status=STATUS_QUEUED,
            actor_type=ACTOR_WORKER,
            context={"is_retry": True, "attempt": 1, "worker_id": "w1"},
        )


def test_invalid_attempt_values() -> None:
    """Verify zero, negative, boolean, and non-integer attempt values are rejected."""
    bad_attempts = [0, -1, -5, True, False, "1", 2.5]

    for attempt in bad_attempts:
        # Test in retry context
        with pytest.raises(ReconTaskInvalidAttemptError):
            validate_tool_execution_transition(
                current_status=STATUS_FAILED,
                requested_status=STATUS_QUEUED,
                actor_type=ACTOR_ORCHESTRATOR,
                context={"is_retry": True, "attempt": attempt},
            )

        # Test in worker completion context
        with pytest.raises(ReconTaskInvalidAttemptError):
            validate_tool_execution_transition(
                current_status=STATUS_RUNNING,
                requested_status=STATUS_SUCCEEDED,
                actor_type=ACTOR_WORKER,
                context={"worker_id": "w1", "attempt": attempt},
            )

    # Test attempt >= max_attempts
    with pytest.raises(ReconTaskRetryNotAllowedError) as exc_info:
        validate_tool_execution_transition(
            current_status=STATUS_FAILED,
            requested_status=STATUS_QUEUED,
            actor_type=ACTOR_ORCHESTRATOR,
            context={"is_retry": True, "attempt": 3, "max_attempts": 3},
        )
    assert "exceeded maximum allowed attempts" in str(exc_info.value)


def test_missing_worker_context_where_required() -> None:
    """Verify worker transitions require worker_id and attempt where appropriate."""
    # Worker claiming task without worker_id
    with pytest.raises(ReconTaskInvalidActorError) as exc_info:
        validate_tool_execution_transition(
            current_status=STATUS_QUEUED,
            requested_status=STATUS_RUNNING,
            actor_type=ACTOR_WORKER,
            context=None,
        )
    assert "worker_id" in str(exc_info.value)

    # Worker claiming task with empty worker_id
    with pytest.raises(ReconTaskInvalidActorError):
        validate_tool_execution_transition(
            current_status=STATUS_QUEUED,
            requested_status=STATUS_RUNNING,
            actor_type=ACTOR_WORKER,
            context={"worker_id": ""},
        )

    # Worker completing task without attempt
    with pytest.raises(ReconTaskInvalidAttemptError) as attempt_exc_info:
        validate_tool_execution_transition(
            current_status=STATUS_RUNNING,
            requested_status=STATUS_SUCCEEDED,
            actor_type=ACTOR_WORKER,
            context={"worker_id": "w1"},
        )
    assert "attempt" in str(attempt_exc_info.value)


def test_invalid_parent_scan_state() -> None:
    """Verify task operations are rejected when parent Scan state violates policy."""
    # 1. Scheduling (None -> queued): allowed in draft, queued, running;
    # rejected in paused, terminal
    for invalid_scan_state in [
        SCAN_STATUS_PAUSED,
        SCAN_STATUS_COMPLETED,
        SCAN_STATUS_FAILED,
        SCAN_STATUS_CANCELLED,
    ]:
        with pytest.raises(ReconTaskParentStateInvalidError):
            validate_tool_execution_transition(
                current_status=None,
                requested_status=STATUS_QUEUED,
                actor_type=ACTOR_ORCHESTRATOR,
                parent_scan_status=invalid_scan_state,
            )

    # 2. Claiming (queued -> running): allowed in queued, running;
    # rejected in draft, paused, terminal
    for invalid_scan_state in [
        SCAN_STATUS_DRAFT,
        SCAN_STATUS_PAUSED,
        SCAN_STATUS_COMPLETED,
        SCAN_STATUS_FAILED,
        SCAN_STATUS_CANCELLED,
    ]:
        with pytest.raises(ReconTaskParentStateInvalidError):
            validate_tool_execution_transition(
                current_status=STATUS_QUEUED,
                requested_status=STATUS_RUNNING,
                actor_type=ACTOR_WORKER,
                parent_scan_status=invalid_scan_state,
                context={"worker_id": "w1"},
            )

    # 3. Completion (running -> succeeded): allowed in running, paused; rejected in terminal, draft
    for invalid_scan_state in [
        SCAN_STATUS_DRAFT,
        SCAN_STATUS_QUEUED,
        SCAN_STATUS_COMPLETED,
        SCAN_STATUS_FAILED,
        SCAN_STATUS_CANCELLED,
    ]:
        with pytest.raises(ReconTaskParentStateInvalidError):
            validate_tool_execution_transition(
                current_status=STATUS_RUNNING,
                requested_status=STATUS_SUCCEEDED,
                actor_type=ACTOR_WORKER,
                parent_scan_status=invalid_scan_state,
                context={"worker_id": "w1", "attempt": 1},
            )

    # 4. Retrying (failed -> queued): allowed ONLY in running
    for invalid_scan_state in [
        SCAN_STATUS_DRAFT,
        SCAN_STATUS_QUEUED,
        SCAN_STATUS_PAUSED,
        SCAN_STATUS_COMPLETED,
        SCAN_STATUS_FAILED,
        SCAN_STATUS_CANCELLED,
    ]:
        with pytest.raises(ReconTaskParentStateInvalidError):
            validate_tool_execution_transition(
                current_status=STATUS_FAILED,
                requested_status=STATUS_QUEUED,
                actor_type=ACTOR_ORCHESTRATOR,
                parent_scan_status=invalid_scan_state,
                context={"is_retry": True, "attempt": 1},
            )


def test_unknown_task_status() -> None:
    """Verify unknown status strings are rejected."""
    with pytest.raises(ReconTaskInvalidTransitionError):
        validate_tool_execution_transition(
            current_status=STATUS_QUEUED,
            requested_status="bogus_status",
            actor_type=ACTOR_ORCHESTRATOR,
        )

    with pytest.raises(ReconTaskInvalidTransitionError):
        validate_tool_execution_transition(
            current_status="invalid_current",
            requested_status=STATUS_RUNNING,
            actor_type=ACTOR_ORCHESTRATOR,
        )


def test_unknown_actor_type() -> None:
    """Verify unrecognized actor categories are rejected."""
    with pytest.raises(ReconTaskInvalidActorError):
        validate_tool_execution_transition(
            current_status=STATUS_QUEUED,
            requested_status=STATUS_RUNNING,
            actor_type="mysterious_agent",
        )


def test_deterministic_validation_results() -> None:
    """Verify validator is pure and returns deterministic results across repeated invocations."""
    kwargs: dict[str, Any] = {
        "current_status": STATUS_QUEUED,
        "requested_status": STATUS_RUNNING,
        "actor_type": ACTOR_WORKER,
        "parent_scan_status": SCAN_STATUS_RUNNING,
        "context": {"worker_id": "worker-42"},
    }

    # Run 50 times and assert all return True
    results = [validate_tool_execution_transition(**kwargs) for _ in range(50)]
    assert all(r is True for r in results)


def test_no_mutation_of_input_context() -> None:
    """Verify that validator never mutates the input context dictionary."""
    orig_context: dict[str, Any] = {
        "is_retry": True,
        "attempt": 2,
        "max_attempts": 3,
        "worker_id": "worker-abc",
        "nested": {"key": "val"},
    }
    context_copy = copy.deepcopy(orig_context)

    # Valid invocation
    validate_tool_execution_transition(
        current_status=STATUS_TIMEOUT,
        requested_status=STATUS_QUEUED,
        actor_type=ACTOR_OWNER,
        parent_scan_status=SCAN_STATUS_RUNNING,
        context=context_copy,
    )
    assert context_copy == orig_context

    # Errored invocation
    with pytest.raises(ReconTaskTerminalStateError):
        validate_tool_execution_transition(
            current_status=STATUS_SUCCEEDED,
            requested_status=STATUS_QUEUED,
            actor_type=ACTOR_OWNER,
            parent_scan_status=SCAN_STATUS_RUNNING,
            context=context_copy,
        )
    assert context_copy == orig_context


def test_explicit_distinction_between_task_creation_and_transition() -> None:
    """Verify explicit handling of None -> queued (creation) vs queued -> queued (idempotent)."""
    # Creation: None -> queued succeeds with management actors
    assert validate_tool_execution_transition(
        current_status=None,
        requested_status=STATUS_QUEUED,
        actor_type=ACTOR_ORCHESTRATOR,
        parent_scan_status=SCAN_STATUS_DRAFT,
    )

    # Idempotent: queued -> queued returns True
    assert validate_tool_execution_transition(
        current_status=STATUS_QUEUED,
        requested_status=STATUS_QUEUED,
        actor_type=ACTOR_SYSTEM,
    )

    # None -> None is an invalid transition
    with pytest.raises(ReconTaskInvalidTransitionError):
        validate_tool_execution_transition(
            current_status=None,
            requested_status=None,  # type: ignore[arg-type]
            actor_type=ACTOR_ORCHESTRATOR,
        )

    # Creation directly to running without queueing is forbidden
    with pytest.raises(ReconTaskInvalidTransitionError):
        validate_tool_execution_transition(
            current_status=None,
            requested_status=STATUS_RUNNING,
            actor_type=ACTOR_ORCHESTRATOR,
        )
