# VulnOS — P3.1.3.2 Execution Contract Inventory & Field Mapping
## Database Schema, Nullable Semantics, Immutability & API Exposure Matrix

**Date:** 2026-11-02  
**Milestone:** P3.1.3.2  
**Status:** Completed  
**Author:** Principal Security Architect & Senior Backend Engineer  

---

## 1. Executive Summary

This inventory establishes the canonical field-by-field schema mapping for the reconnaissance execution models (`Scan` and `ToolExecution`), verifying database types, nullable behavior, validation requirements, client vs. server control boundaries, and immutability rules.

---

## 2. Reconnaissance Job Mapping: `Scan` (`scans` table)

| Column Name | Database Type | Nullable | Client Controllable | Server Controllable | Immutable After Scheduling | Exposed in API Response | Validation & Constraint Rules |
|---|---|---|---|---|---|---|---|
| `id` | `UUID` (UUIDv7) | No | No | Yes | Yes | Yes | Primary key; generated via `uuid7()`. |
| `project_id` | `UUID` | No | No | Yes | Yes | Yes | Foreign key `projects.id ON DELETE CASCADE`. Enforced via RLS and URL path parameter. |
| `name` | `Text` | No | Yes (Creation) | No | Yes | Yes | `min_length=3`, `max_length=120`. Stripped of control characters. |
| `scan_type` | `Text` | No | No | Yes | Yes | Yes | Fixed to `'recon'` for reconnaissance jobs. Check constraint `ck_scans_scan_type`. |
| `status` | `Text` | No | No | Yes | No | Yes | State machine controlled. Check constraint `ck_scans_status`. Default `'draft'`. |
| `scope_version_id` | `UUID` | No | No | Yes | Yes | Yes | Foreign key `scope_versions.id`. Pinned to active scope version at scheduling. |
| `authorization_id` | `UUID` | No | No | Yes | Yes | Yes | Foreign key `authorization_records.id`. Pinned to active authorization at scheduling. |
| `target_ids` | `ARRAY(UUID)` | No | Yes (Creation) | Yes | Yes | Yes | `min_length=1`, `max_length=50`. Must belong to `project_id`. |
| `profile` | `JSONB` | No | Yes (Creation) | Yes | Yes | Yes | Module selection list (e.g., `["dns", "ports", "http"]`). `extra="forbid"`. |
| `budget` | `JSONB` | No | Yes (Creation) | Yes | Yes | Yes | Structured limits: `max_wall_clock_minutes`, `max_requests`, `max_cost_usd`, `max_concurrency`. |
| `requested_by` | `UUID` | No | No | Yes | Yes | Yes | Foreign key `users.id`. Bound to authenticated user identity (`current_user.id`). |
| `started_at` | `DateTime(tz)` | Yes | No | Yes | No | Yes | Set atomically when first worker task claims lease. |
| `finished_at` | `DateTime(tz)` | Yes | No | Yes | No | Yes | Set atomically upon terminal transition (`completed`, `failed`, `cancelled`). |
| `cancel_requested_at` | `DateTime(tz)` | Yes | No | Yes | No | Yes | Set atomically upon cooperative cancellation request. |
| `cost_usd` | `Numeric(12,6)` | No | No | Yes | No | Yes | Aggregated dollar compute/network cost. Default 0.0. |
| `stats` | `JSONB` | No | No | Yes | No | Yes | Telemetry dictionary: `requests_sent`, `assets_discovered`, `tasks_succeeded`, etc. |
| `created_at` | `DateTime(tz)` | No | No | Yes | Yes | Yes | Creation timestamp via `utc_now()`. |
| `updated_at` | `DateTime(tz)` | No | No | Yes | No | Yes | Last modification timestamp. |

---

## 3. Reconnaissance Task Mapping: `ToolExecution` (`tool_executions` table)

| Column Name | Database Type | Nullable | Client Controllable | Server Controllable | Immutable After Scheduling | Exposed in API Response | Validation & Constraint Rules |
|---|---|---|---|---|---|---|---|
| `id` | `UUID` (UUIDv7) | No | No | Yes | Yes | Yes | Primary key; generated via `uuid7()`. |
| `project_id` | `UUID` | No | No | Yes | Yes | Yes | Foreign key `projects.id`. Enforced by RLS. |
| `scan_id` | `UUID` | No | No | Yes | Yes | Yes | Foreign key `scans.id ON DELETE CASCADE`. Binds task to parent recon job. |
| `stage` | `Text` | No | No | Yes | Yes | Yes | Set to `'recon'`. Matches stage in `ScanStageRun`. |
| `tool_version_id` | `UUID` | No | No | Yes | Yes | Yes | Foreign key `tool_versions.id`. Resolves exact container image and digest. |
| `status` | `Text` | No | No | Yes | No | Yes | State machine controlled. Check constraint `ck_tool_executions_status`. |
| `target_asset_id` | `UUID` | Yes | No | Yes | Yes | Yes | Optional foreign key `assets.id` if analyzing an existing discovered asset. |
| `endpoint_id` | `UUID` | Yes | No | Yes | Yes | Yes | Optional foreign key `endpoints.asset_id` for HTTP probing tasks. |
| `auth_context_id` | `UUID` | Yes | No | Yes | Yes | Yes | References `auth_contexts.id` (target web app persona/roles). **Not legal authorization.** |
| `input` | `JSONB` | No | No | Yes | Yes | Yes | Bounded parameters passed to worker envelope. |
| `command_redacted` | `Text` | Yes | No | Yes | Yes | Yes | Audit-safe string representation of executed tool argv. |
| `worker_id` | `Text` | Yes | No | Yes | No | Yes | Identity of worker node/container executing the task. |
| `attempt` | `Integer` | No | No | Yes | Yes | Yes | Attempt counter. Default 1. Maximum attempts bounded by policy. |
| `parent_execution_id` | `UUID` | Yes | No | Yes | Yes | Yes | Foreign key `tool_executions.id`. Upstream task in DAG. |
| `started_at` | `DateTime(tz)` | Yes | No | Yes | No | Yes | Set when worker begins execution. |
| `finished_at` | `DateTime(tz)` | Yes | No | Yes | No | Yes | Set when worker finishes execution. |
| `exit_code` | `Integer` | Yes | No | Yes | No | Yes | Process return code from container. |
| `error_code` | `Text` | Yes | No | Yes | No | Yes | Categorical failure code (`TIMEOUT`, `SCOPE_VIOLATION`, `CRASH`). |
| `error_message` | `Text` | Yes | No | Yes | No | Yes | Sanitized, non-sensitive failure explanation. |
| `coverage_summary` | `JSONB` | No | No | Yes | No | Yes | Metrics on endpoints or ports covered. |
| `stats` | `JSONB` | No | No | Yes | No | Yes | Telemetry dictionary: `requests_sent`, `latency_ms`, etc. |
| `cost_usd` | `Numeric(12,6)` | No | No | Yes | No | Yes | Dollar cost for this task execution. Default 0.0. |

---

## 4. Authorization Context Disambiguation (`Scan.authorization_id` vs `ToolExecution.auth_context_id`)

A critical distinction discovered during the audit:

1. **`Scan.authorization_id`:**
   - **Target Model:** `AuthorizationRecord` (`authorization_records` table).
   - **Semantics:** Legal, contractual, and regulatory consent granting permission to scan/test.
   - **Attributes:** Contract reference, authorized by name/contact, validity window (`valid_from` to `valid_to`), allowed actions, and destructive operation permissions.
   - **Role:** Mandatory scope boundary prerequisite.

2. **`ToolExecution.auth_context_id`:**
   - **Target Model:** `AuthContext` (`auth_contexts` table in `backend/app/db/models/security.py`).
   - **Semantics:** Target web application user identity / persona (e.g., anonymous session, regular customer account, administrative role).
   - **Attributes:** `identity_type IN ('anonymous','user','admin','service')`, `label`, and optional `secret_ref_id` pointing to target application credentials.
   - **Role:** Optional testing persona used during authenticated web application scanning.

**Invariant:** `ToolExecution.auth_context_id` must NEVER be confused with or substituted for `Scan.authorization_id`.
