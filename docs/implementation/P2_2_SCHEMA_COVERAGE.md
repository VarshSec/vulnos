# VulnOS — Database Schema Coverage Matrix (Phase 2.2)

**Source of Truth:** `docs/architecture/DATABASE_DESIGN.md`  
**ORM:** SQLAlchemy 2.x Declarative Models  
**Migration Engine:** Alembic (`0001_phase2_baseline.py`)  
**Status:** Mapped and Covered  

---

## Complete Table Coverage Matrix

| Documented Table | SQLAlchemy Model Class | Target File | Constraints | Indexes | Test Coverage |
|---|---|---|---|---|---|
| `users` | `User` | `backend/app/db/models/identity.py` | PK `id`, UQ `lower(email)`, CK `auth_provider` | `ix_users_email` | `test_models.py::test_identity_models` |
| `api_keys` | `APIKey` | `backend/app/db/models/identity.py` | PK `id`, FK `user_id`, UQ `key_hash` | `ix_api_keys_user_id` | `test_models.py::test_identity_models` |
| `projects` | `Project` | `backend/app/db/models/identity.py` | PK `id`, UQ `slug`, FK `owner_id`, CK `status`, CK `retention` | `ix_projects_slug`, `ix_projects_owner_id` | `test_models.py::test_identity_models` |
| `project_members` | `ProjectMember` | `backend/app/db/models/identity.py` | PK `(project_id, user_id)`, FKs, CK `role` | `ix_project_members_user_id` | `test_models.py::test_identity_models` |
| `authorization_records` | `AuthorizationRecord` | `backend/app/db/models/identity.py` | PK `id`, FK `project_id`, FK `created_by`, CK `valid_to > valid_from` | `ix_authorization_records_project_id` | `test_models.py::test_identity_models` |
| `scope_versions` | `ScopeVersion` | `backend/app/db/models/identity.py` | PK `id`, FK `project_id`, FK `authorization_id`, UQ `(project_id, version)`, CK `status` | Partial UQ active per project | `test_models.py::test_identity_models` |
| `scope_rules` | `ScopeRule` | `backend/app/db/models/identity.py` | PK `id`, FK `scope_version_id`, CK `effect`, CK `match_type` | `ix_scope_rules_version_effect` | `test_models.py::test_identity_models` |
| `scope_decisions` | `ScopeDecision` | `backend/app/db/models/identity.py` | PK `(id, decided_at)`, FKs, CK `reason_code` (Partitioned) | `(project_id, decided_at DESC)`, `(scan_id)` | `test_models.py::test_identity_models` |
| `targets` | `Target` | `backend/app/db/models/identity.py` | PK `id`, FK `project_id`, UQ `(project_id, seed_type, seed_value)`, CK `seed_type` | `(project_id, status)` | `test_models.py::test_identity_models` |
| `assets` | `Asset` | `backend/app/db/models/assets.py` | PK `id`, FK `project_id`, UQ `(project_id, kind, canonical_key)`, CK `confidence` | `(project_id, last_seen_at DESC)` | `test_models.py::test_asset_models` |
| `domains` | `Domain` | `backend/app/db/models/assets.py` | PK `asset_id`, FK `asset_id`, FK `project_id`, UQ `(project_id, name)` | `ix_domains_project_id_name` | `test_models.py::test_asset_models` |
| `hosts` | `Host` | `backend/app/db/models/assets.py` | PK `asset_id`, FK `asset_id`, FK `project_id`, UQ `(project_id, canonical_name)` | `ix_hosts_project_canonical` | `test_models.py::test_asset_models` |
| `host_addresses` | `HostAddress` | `backend/app/db/models/assets.py` | PK `id`, FK `host_id`, FK `project_id`, UQ `(host_id, ip)` | `ix_host_addresses_host_id_ip` | `test_models.py::test_asset_models` |
| `services` | `Service` | `backend/app/db/models/assets.py` | PK `asset_id`, FK `host_id`, UQ `(host_id, port, transport)`, CK `port`, CK `transport` | `ix_services_host_port_transport` | `test_models.py::test_asset_models` |
| `endpoints` | `Endpoint` | `backend/app/db/models/assets.py` | PK `asset_id`, FKs, UQ `(project_id, method, url_hash)`, CK `method`, CK `scheme` | `(project_id, host_id)`, `(url_hash)` | `test_models.py::test_asset_models` |
| `parameters` | `Parameter` | `backend/app/db/models/assets.py` | PK `id`, FK `endpoint_id`, UQ `(endpoint_id, location, name)`, CK `location` | `ix_parameters_endpoint_loc_name` | `test_models.py::test_asset_models` |
| `technologies` | `Technology` | `backend/app/db/models/assets.py` | PK `id`, UQ `(name, category)` | `ix_technologies_name_category` | `test_models.py::test_asset_models` |
| `asset_technologies` | `AssetTechnology` | `backend/app/db/models/assets.py` | PK `(asset_id, technology_id)`, FKs, CK `confidence` | `ix_asset_technologies_proj_tech` | `test_models.py::test_asset_models` |
| `api_schemas` | `APISchema` | `backend/app/db/models/assets.py` | PK `id`, FKs, UQ `(project_id, asset_id, schema_type, spec_hash)`, CK `schema_type` | `ix_api_schemas_asset_id` | `test_models.py::test_asset_models` |
| `asset_discoveries` | `AssetDiscovery` | `backend/app/db/models/assets.py` | PK `id`, FKs, CK `confidence` | `(asset_id, discovered_at DESC)`, `(scan_id)` | `test_models.py::test_asset_models` |
| `tools` | `Tool` | `backend/app/db/models/execution.py` | PK `id`, UQ `name`, CK `category`, CK `maintenance_status` | `ix_tools_name` | `test_models.py::test_execution_models` |
| `tool_versions` | `ToolVersion` | `backend/app/db/models/execution.py` | PK `id`, FK `tool_id`, UQ `(tool_id, version, image_digest)`, CK `verification_status` | `ix_tool_versions_lookup` | `test_models.py::test_execution_models` |
| `tool_capabilities` | `ToolCapability` | `backend/app/db/models/execution.py` | PK `id`, FK `tool_version_id` UNIQUE, CK `cost_tier`, CK `safety` | GIN `(vulnerability_classes)`, `(overlap_group)` | `test_models.py::test_execution_models` |
| `scans` | `Scan` | `backend/app/db/models/execution.py` | PK `id`, FK `project_id`, FK `scope_version_id`, FK `authorization_id`, CK `status` | `(project_id, status)`, `(project_id, created_at DESC)` | `test_models.py::test_execution_models` |
| `scan_stage_runs` | `ScanStageRun` | `backend/app/db/models/execution.py` | PK `id`, FK `scan_id`, UQ `(scan_id, stage, attempt)`, CK `stage`, CK `status` | `ix_scan_stage_runs_lookup` | `test_models.py::test_execution_models` |
| `tool_executions` | `ToolExecution` | `backend/app/db/models/execution.py` | PK `id`, FK `scan_id`, FK `tool_version_id`, CK `status` | `(scan_id, status)`, `(project_id, created_at DESC)` | `test_models.py::test_execution_models` |
| `tool_selection_decisions` | `ToolSelectionDecision` | `backend/app/db/models/execution.py` | PK `id`, FK `scan_id`, FK `tool_version_id`, CK `decision` | `(scan_id, decision)` | `test_models.py::test_execution_models` |
| `agent_runs` | `AgentRun` | `backend/app/db/models/execution.py` | PK `execution_id`, FK `tool_executions(id)`, FK `target_asset_id`, CK `status` | Partial UQ active per target | `test_models.py::test_execution_models` |
| `auth_contexts` | `AuthContext` | `backend/app/db/models/security.py` | PK `id`, FK `project_id`, FK `secret_ref_id`, UQ `(project_id, label)`, CK `identity_type` | `ix_auth_contexts_proj_label` | `test_models.py::test_security_models` |
| `test_cases` | `TestCase` | `backend/app/db/models/execution.py` | PK `id`, FK `scan_id`, FK `endpoint_id`, UQ `(scan_id, coverage_key)`, CK `status` | `(project_id, endpoint_id, vulnerability_class)` | `test_models.py::test_execution_models` |
| `operation_approvals` | `OperationApproval` | `backend/app/db/models/execution.py` | PK `id`, FK `scan_id`, UQ `(scan_id, action_hash)`, CK `risk_level`, CK `expires_at > approved_at` | `(scan_id, action_hash)` | `test_models.py::test_execution_models` |
| `evidence_objects` | `EvidenceObject` | `backend/app/db/models/evidence.py` | PK `id`, FK `project_id`, UQ `(project_id, sha256, kind)`, CK `kind`, CK `encryption_mode` | `(retention_until) WHERE deleted_at IS NULL` | `test_models.py::test_evidence_models` |
| `http_exchanges` | `HTTPExchange` | `backend/app/db/models/evidence.py` | PK `(id, occurred_at)`, FKs (Partitioned by range) | `(project_id, occurred_at DESC)`, `(scan_id)` | `test_models.py::test_evidence_models` |
| `finding_clusters` | `FindingCluster` | `backend/app/db/models/findings.py` | PK `id`, FK `project_id`, UQ `(project_id, canonical_key)`, CK `severity`, CK `status` | `(project_id, status, severity)` | `test_models.py::test_findings_models` |
| `findings` | `Finding` | `backend/app/db/models/findings.py` | PK `id`, FKs, CK `source_type`, CK `status` | `(project_id, cluster_id)`, `(fingerprint)` | `test_models.py::test_findings_models` |
| `finding_evidence` | `FindingEvidence` | `backend/app/db/models/findings.py` | PK `id`, FKs, CK `cluster_id IS NOT NULL OR finding_id IS NOT NULL`, CK `role` | Partial UQs on finding and cluster | `test_models.py::test_findings_models` |
| `cluster_relations` | `ClusterRelation` | `backend/app/db/models/findings.py` | PK `id`, FKs, UQ `(from_cluster_id, to_cluster_id, relation_type)`, CK `from <> to` | `ix_cluster_relations_lookup` | `test_models.py::test_findings_models` |
| `validations` | `Validation` | `backend/app/db/models/validation.py` | PK `id`, FK `cluster_id`, CK `stage`, CK `status`, CK `verdict` | `(cluster_id, created_at DESC)`, `(status)` | `test_models.py::test_validation_models` |
| `validation_checks` | `ValidationCheck` | `backend/app/db/models/validation.py` | PK `id`, FK `validation_id`, CK `check_type`, CK `result` | `(validation_id, check_type)` | `test_models.py::test_validation_models` |
| `finding_state_transitions` | `FindingStateTransition` | `backend/app/db/models/validation.py` | PK `id` identity, FK `cluster_id`, CK `actor_type` | `(cluster_id, created_at)` | `test_models.py::test_validation_models` |
| `reports` | `Report` | `backend/app/db/models/validation.py` | PK `id`, FK `scan_id`, UQ `(scan_id, version, format)`, CK `format`, CK `status` | `ix_reports_scan_ver_format` | `test_models.py::test_validation_models` |
| `ai_providers` | `AIProvider` | `backend/app/db/models/ai.py` | PK `id`, UQ `name`, CK `kind` | `ix_ai_providers_name` | `test_models.py::test_ai_models` |
| `ai_models` | `AIModel` | `backend/app/db/models/ai.py` | PK `id`, FK `provider_id`, UQ `(provider_id, model_id)`, CK `status` | `ix_ai_models_provider_model` | `test_models.py::test_ai_models` |
| `prompt_templates` | `PromptTemplate` | `backend/app/db/models/ai.py` | PK `id`, UQ `(name, version)`, CK `version > 0` | `ix_prompt_templates_name_version` | `test_models.py::test_ai_models` |
| `ai_routing_policies` | `AIRoutingPolicy` | `backend/app/db/models/ai.py` | PK `id`, UQ `task_class`, FK `preferred_model_id`, CK `min_tier`, CK `temperature` | `ix_ai_routing_policies_task_class` | `test_models.py::test_ai_models` |
| `ai_invocations` | `AIInvocation` | `backend/app/db/models/ai.py` | PK `id`, FKs, CK `status` | `(project_id, created_at DESC)`, `(scan_id)` | `test_models.py::test_ai_models` |
| `cost_entries` | `CostEntry` | `backend/app/db/models/audit.py` | PK `id` identity, FK `project_id`, CK `category` | `(project_id, created_at)`, `(scan_id, category)` | `test_models.py::test_audit_models` |
| `secret_refs` | `SecretRef` | `backend/app/db/models/security.py` | PK `id`, FK `project_id`, UQ `(project_id, name)`, CK `backend` | `ix_secret_refs_proj_name` | `test_models.py::test_security_models` |
| `audit_logs` | `AuditLog` | `backend/app/db/models/audit.py` | PK `(id, created_at)`, FK `project_id`, CK `actor_type` (Partitioned) | `(project_id, created_at DESC)`, `(actor_type, actor_id)` | `test_models.py::test_audit_models` |
| `outbox_events` | `OutboxEvent` | `backend/app/db/models/audit.py` | PK `id` identity | Partial `(created_at) WHERE published_at IS NULL` | `test_models.py::test_audit_models` |

---

## Architecture Clarification on Sessions
As noted in `P2_2_AUDIT.md`, `DATABASE_DESIGN.md` explicitly specifies these 50 tables and contains no `sessions` table. Browser sessions are stateless HTTP-only cookies with cryptographic signing per `API_CONTRACTS.md` §3.1, with session lifetime (30m access, 14d refresh) managed via Redis/cookies in milestone P2.4. No speculative session tables are added.
