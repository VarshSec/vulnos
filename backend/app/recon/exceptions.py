"""Typed lifecycle and operational exceptions for the VulnOS reconnaissance subsystem."""

from __future__ import annotations


class ReconError(Exception):
    """Base exception for all reconnaissance subsystem errors."""

    code: str = "RECON_ERROR"

    def __init__(self, message: str, code: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        if code:
            self.code = code


class ReconJobNotFoundError(ReconError):
    """Raised when a reconnaissance job (Scan) does not exist or does not belong to the project."""

    code = "RECON_JOB_NOT_FOUND"


class ReconJobInvalidStateError(ReconError):
    """Raised when a requested job state transition is illegal or violates lifecycle rules."""

    code = "RECON_JOB_INVALID_STATE"


class ReconJobAlreadyTerminalError(ReconError):
    """Raised when attempting to mutate or reactivate a job that is already in a terminal state."""

    code = "RECON_JOB_ALREADY_TERMINAL"


class ReconJobProjectMismatchError(ReconError):
    """Raised when cross-project entities or tokens are supplied for a reconnaissance job."""

    code = "RECON_JOB_PROJECT_MISMATCH"


class ReconJobCancellationRequestedError(ReconError):
    """Raised when attempting to schedule tasks on a job undergoing cancellation."""

    code = "RECON_JOB_CANCELLATION_REQUESTED"


class ReconJobScopeInvalidError(ReconError):
    """Raised when the pinned scope version for a job is invalid or missing."""

    code = "RECON_JOB_SCOPE_INVALID"


class ReconJobAuthorizationInvalidError(ReconError):
    """Raised when the authorization record for a job is revoked, expired, or invalid."""

    code = "RECON_JOB_AUTHORIZATION_INVALID"


class ReconJobContextImmutableError(ReconError):
    """Raised when attempting to alter immutable execution parameters after job queueing."""

    code = "RECON_JOB_CONTEXT_IMMUTABLE"


class ReconInvalidActorError(ReconError):
    """Raised when an actor lacks permission to trigger a specific lifecycle transition."""

    code = "RECON_INVALID_ACTOR"


class ReconTaskNotFoundError(ReconError):
    """Raised when an individual task (ToolExecution) cannot be found."""

    code = "RECON_TASK_NOT_FOUND"


class ReconTaskInvalidStateError(ReconError):
    """Raised when a task state transition violates the task state machine."""

    code = "RECON_TASK_INVALID_STATE"


class ReconTaskAlreadyTerminalError(ReconError):
    """Raised when attempting to transition or mutate a task already in a terminal state."""

    code = "RECON_TASK_ALREADY_TERMINAL"


class ReconTaskScopeDeniedError(ReconError):
    """Raised when a task is denied by the scope engine or egress guard (non-retryable)."""

    code = "RECON_TASK_SCOPE_DENIED"


class ReconTaskBudgetExceededError(ReconError):
    """Raised when a task exceeds allocated execution budget (wall-clock, requests, cost)."""

    code = "RECON_TASK_BUDGET_EXCEEDED"


class ReconToolNotRegisteredError(ReconError):
    """Raised when attempting to execute a tool not present in the static Tool Registry."""

    code = "RECON_TOOL_NOT_REGISTERED"


class ReconStaleWorkerResultError(ReconError):
    """Raised when a worker reports a result for a superseded attempt or terminated task."""

    code = "RECON_STALE_WORKER_RESULT"


class ReconTaskInvalidTransitionError(ReconTaskInvalidStateError):
    """Raised when a task transition is not permitted in the transition matrix."""

    code = "RECON_TASK_INVALID_TRANSITION"


class ReconTaskInvalidActorError(ReconInvalidActorError):
    """Raised when an actor lacks permission to trigger a specific task lifecycle transition."""

    code = "RECON_TASK_INVALID_ACTOR"


class ReconTaskTerminalStateError(ReconTaskAlreadyTerminalError):
    """Raised when attempting to transition or mutate a task already in a terminal state."""

    code = "RECON_TASK_TERMINAL_STATE"


class ReconTaskRetryNotAllowedError(ReconError):
    """Raised when an unauthorized or illegal retry is attempted on a task."""

    code = "RECON_TASK_RETRY_NOT_ALLOWED"


class ReconTaskInvalidAttemptError(ReconError):
    """Raised when an invalid attempt value or attempt context is provided."""

    code = "RECON_TASK_INVALID_ATTEMPT"


class ReconTaskParentStateInvalidError(ReconError):
    """Raised when the parent Scan state forbids the requested task transition."""

    code = "RECON_TASK_PARENT_STATE_INVALID"


class ReconTaskWorkerMismatchError(ReconError):
    """Raised when a worker submitting a task result does not match the assigned worker."""

    code = "RECON_TASK_WORKER_MISMATCH"


class ReconTaskProjectMismatchError(ReconError):
    """Raised when cross-project access or references are detected on a task."""

    code = "RECON_TASK_PROJECT_MISMATCH"


class ReconTaskAlreadyClaimedError(ReconTaskInvalidStateError):
    """Raised when a worker attempts to claim a task that is already running, claimed, or not.

    The task must be in queued status to be claimed.
    """

    code = "RECON_TASK_ALREADY_CLAIMED"


class ReconTaskInvalidTimeoutError(ReconError):
    """Raised when a lease claim specifies a timeout outside permitted bounds (30-86400s)."""

    code = "RECON_TASK_INVALID_TIMEOUT"


class ReconTaskInvalidTokenError(ReconStaleWorkerResultError):
    """Raised when a worker submits a missing, malformed, or mismatched lease token."""

    code = "RECON_TASK_INVALID_TOKEN"


class ReconTaskLeaseExpiredError(ReconStaleWorkerResultError):
    """Raised when a worker attempts to submit a result after its lease deadline has passed."""

    code = "RECON_TASK_LEASE_EXPIRED"
