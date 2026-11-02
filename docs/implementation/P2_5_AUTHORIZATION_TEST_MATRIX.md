# VulnOS Phase 2.5.4 — Authorization Security Test Matrix

## 1. Overview

Phase 2.5.4 establishes the legal consent boundary and deterministic evaluation engine for VulnOS. The test suite is organized into three dedicated modules covering schemas, service layer operations, evaluation boundaries, and HTTP API endpoints:

1. `backend/tests/security/scope/test_authorization_schemas.py` (14 tests)
2. `backend/tests/security/scope/test_authorizations.py` (15 tests)
3. `backend/tests/security/scope/test_authorization_endpoints.py` (15 tests)

**Total P2.5.4 test coverage: 44 tests.**
**Total VulnOS platform test suite: 369 passed, 0 failures.**

---

## 2. Comprehensive Test Matrix

| Test File | Test Name | Category | What It Validates | Security Invariant Enforced |
| :--- | :--- | :--- | :--- | :--- |
| `test_authorization_schemas.py` | `test_valid_authorization_create_request` | Schema Validation | Valid payload parsing and UTC normalization | Strict request validation |
| `test_authorization_schemas.py` | `test_missing_required_fields_rejected` | Schema Validation | Missing required fields raise ValidationError | Rejection of incomplete consent |
| `test_authorization_schemas.py` | `test_empty_or_whitespace_strings_rejected` | Schema Validation | Empty/whitespace string values are rejected | Non-empty legal references |
| `test_authorization_schemas.py` | `test_naive_timestamp_rejected` | Schema Validation | Offset-naive datetimes raise ValidationError | Enforce explicit timezone awareness |
| `test_authorization_schemas.py` | `test_utc_normalization` | Schema Validation | Non-UTC offsets are converted to UTC | Deterministic UTC comparison |
| `test_authorization_schemas.py` | `test_valid_to_must_be_strictly_after_valid_from` | Schema Validation | `valid_to <= valid_from` is rejected | Window check: $T_{end} > T_{start}$ |
| `test_authorization_schemas.py` | `test_allowed_actions_case_folding_and_deduplication` | Action Vocabulary | Case normalization & deduplication | Deterministic action array |
| `test_authorization_schemas.py` | `test_unknown_action_rejected` | Action Vocabulary | Unlisted action names rejected | Strict action allowlist |
| `test_authorization_schemas.py` | `test_empty_actions_list_rejected` | Action Vocabulary | Empty action lists rejected | Explicit action specification |
| `test_authorization_schemas.py` | `test_boolean_permissions_secure_defaults` | Security Defaults | Booleans default to `False` | Default-deny security posture |
| `test_authorization_schemas.py` | `test_max_requests_per_scan_positive_and_nullable` | Boundary Check | Hard ceiling bounds ($1 \le N \le 10^7$) | DoS / rate abuse prevention |
| `test_authorization_schemas.py` | `test_document_evidence_id_validation` | Format Validation | UUID format validation on evidence ID | Valid document reference |
| `test_authorization_schemas.py` | `test_authorization_response_model` | Output Formatting | Serializes response cleanly | Information disclosure prevention |
| `test_authorization_schemas.py` | `test_authorization_evaluation_result_reason_codes` | Output Formatting | Evaluation result reason codes match StrEnum | Deterministic decision audit |
| `test_authorizations.py` | `test_create_authorization_minimal` | Service Layer | Minimal required fields persist | Correct DB mapping |
| `test_authorizations.py` | `test_create_authorization_full` | Service Layer | Optional fields persist accurately | Field fidelity |
| `test_authorizations.py` | `test_create_authorization_appends_audit_log` | Auditability | Appends `authorization.create` audit log | Immutable forensic audit trail |
| `test_authorizations.py` | `test_create_authorization_duplicate_reference_rejected` | Integrity | Duplicate active reference raises error | Duplicate active permit prevention |
| `test_authorizations.py` | `test_create_authorization_same_reference_allowed_after_revocation` | Lifecycle | Re-issuing reference after revocation | Append-only superseding workflow |
| `test_authorizations.py` | `test_get_authorization_success_and_cross_project_isolation` | Tenant Isolation | Cross-project retrieval returns 404 | Project isolation & non-enumeration |
| `test_authorizations.py` | `test_get_authorization_not_found` | Error Handling | Non-existent ID returns 404 | Expected error mapping |
| `test_authorizations.py` | `test_list_authorizations_pagination_and_active_filter` | Query Service | Pagination and active-only temporal filter | Accurate active records listing |
| `test_authorizations.py` | `test_revoke_authorization_idempotence_and_audit` | Revocation | Setting `revoked_at` is strictly idempotent | Safe retry & audit persistence |
| `test_authorizations.py` | `test_evaluate_authorization_not_found_and_project_mismatch` | Evaluation Engine | None or cross-project record denied | Default deny on mismatch |
| `test_authorizations.py` | `test_evaluate_authorization_revoked_takes_precedence` | Evaluation Engine | Revocation takes top priority | Immediate operation halt |
| `test_authorizations.py` | `test_evaluate_authorization_temporal_boundaries` | Boundary Check | Exact boundary checks ($now = T_{start}$, $now = T_{end}$) | Boundary precision |
| `test_authorizations.py` | `test_evaluate_authorization_action_allowlist` | Evaluation Engine | Action allowlist evaluation | Action gating |
| `test_authorizations.py` | `test_evaluate_authorization_destructive_and_private_range_permissions` | Permission Gating | Intrusive & private range gating | Strict risk controls |
| `test_authorizations.py` | `test_evaluate_authorization_db_lookup` | Integration | End-to-end DB query and evaluation | Full service pipeline |
| `test_authorization_endpoints.py` | `test_admin_creates_authorization_201` | API Endpoints | Project admin creates record (201) | Role enforcement: Admin |
| `test_authorization_endpoints.py` | `test_viewer_cannot_create_authorization_403` | RBAC Enforcement | Project viewer denied creation (403) | Privilege escalation prevention |
| `test_authorization_endpoints.py` | `test_operator_cannot_create_authorization_403` | RBAC Enforcement | Project operator denied creation (403) | Privilege escalation prevention |
| `test_authorization_endpoints.py` | `test_non_member_receives_404_on_create` | Tenant Isolation | Non-member receives 404 | Project enumeration defense |
| `test_authorization_endpoints.py` | `test_api_key_admin_scope_creates_authorization` | API Key Auth | API key with `admin` scope succeeds | Key scope enforcement |
| `test_authorization_endpoints.py` | `test_api_key_read_scope_rejected_on_create_403` | API Key Auth | API key with `read` scope denied (403) | Key scope restriction |
| `test_authorization_endpoints.py` | `test_create_authorization_with_past_valid_to_rejected_422` | API Validation | `valid_to` in past rejected with 422 | Inactive record creation prevention |
| `test_authorization_endpoints.py` | `test_create_authorization_duplicate_reference_409` | API Conflict | Duplicate reference returns 409 | Conflict reporting |
| `test_authorization_endpoints.py` | `test_viewer_can_list_authorizations_200` | API Endpoints | Project viewer can list records (200) | Read role permission |
| `test_authorization_endpoints.py` | `test_non_member_receives_404_on_list` | Tenant Isolation | Non-member receives 404 on list | Project enumeration defense |
| `test_authorization_endpoints.py` | `test_viewer_can_get_single_authorization_200` | API Endpoints | Viewer can retrieve single record (200) | Read role permission |
| `test_authorization_endpoints.py` | `test_cross_project_get_authorization_404` | Tenant Isolation | Cross-project GET returns 404 | Tenant boundary defense |
| `test_authorization_endpoints.py` | `test_admin_revokes_authorization_idempotent_200` | API Endpoints | Admin revokes authorization (200) | Revocation workflow |
| `test_authorization_endpoints.py` | `test_viewer_cannot_revoke_authorization_403` | RBAC Enforcement | Viewer denied revocation (403) | Unauthorized revocation prevention |
| `test_authorization_endpoints.py` | `test_immutability_patch_put_delete_not_allowed` | Immutability | PATCH, PUT, and DELETE return 405 | Strict terms immutability |

---

## 3. Test Execution Verification

```bash
uv run pytest backend/tests/security/scope/ -v
# 122 passed in 1.94s

uv run pytest -v
# 369 passed in 5.50s

uv run ruff check .
# All checks passed!

uv run ruff format --check .
# 90 files already formatted

uv run mypy backend tests
# Success: no issues found in 87 source files
```
