"""VulnOS Phase 2 Database Models package.

Exports all 50 mapped SQLAlchemy 2.x declarative models representing the complete
schema defined in `docs/architecture/DATABASE_DESIGN.md`.
"""

from backend.app.db.models.ai import (
    AIInvocation,
    AIModel,
    AIProvider,
    AIRoutingPolicy,
    PromptTemplate,
)
from backend.app.db.models.assets import (
    APISchema,
    Asset,
    AssetDiscovery,
    AssetTechnology,
    Domain,
    Endpoint,
    Host,
    HostAddress,
    Parameter,
    Service,
    Technology,
)
from backend.app.db.models.audit import (
    AuditLog,
    CostEntry,
    OutboxEvent,
)
from backend.app.db.models.evidence import (
    EvidenceObject,
    HTTPExchange,
)
from backend.app.db.models.execution import (
    AgentRun,
    OperationApproval,
    Scan,
    ScanStageRun,
    TestCase,
    Tool,
    ToolCapability,
    ToolExecution,
    ToolSelectionDecision,
    ToolVersion,
)
from backend.app.db.models.findings import (
    ClusterRelation,
    Finding,
    FindingCluster,
    FindingEvidence,
)
from backend.app.db.models.identity import (
    APIKey,
    AuthorizationRecord,
    Project,
    ProjectMember,
    ScopeDecision,
    ScopeRule,
    ScopeVersion,
    Target,
    User,
)
from backend.app.db.models.security import (
    AuthContext,
    SecretRef,
)
from backend.app.db.models.validation import (
    FindingStateTransition,
    Report,
    Validation,
    ValidationCheck,
)

__all__ = [
    "AIInvocation",
    "AIModel",
    "AIProvider",
    "AIRoutingPolicy",
    "APIKey",
    "APISchema",
    "AgentRun",
    "Asset",
    "AssetDiscovery",
    "AssetTechnology",
    "AuditLog",
    "AuthContext",
    "AuthorizationRecord",
    "ClusterRelation",
    "CostEntry",
    "Domain",
    "Endpoint",
    "EvidenceObject",
    "Finding",
    "FindingCluster",
    "FindingEvidence",
    "FindingStateTransition",
    "HTTPExchange",
    "Host",
    "HostAddress",
    "OperationApproval",
    "OutboxEvent",
    "Parameter",
    "Project",
    "ProjectMember",
    "PromptTemplate",
    "Report",
    "Scan",
    "ScanStageRun",
    "ScopeDecision",
    "ScopeRule",
    "ScopeVersion",
    "SecretRef",
    "Service",
    "Target",
    "Technology",
    "TestCase",
    "Tool",
    "ToolCapability",
    "ToolExecution",
    "ToolSelectionDecision",
    "ToolVersion",
    "User",
    "Validation",
    "ValidationCheck",
]
