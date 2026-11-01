# VulnOS — API Contracts

**Document status:** Phase 1 baseline
**Version:** 1.0
**Base path:** `/api/v1`
**Companion to:** [DATABASE_DESIGN.md](DATABASE_DESIGN.md)

---

## 1. Purpose and phase boundary

This document defines the initial REST contract for VulnOS. It is normative for Phase 2
onward. FastAPI will generate the OpenAPI document from these schemas; this file explains the
semantics that OpenAPI cannot express (authorization, idempotency, lifecycle, error codes).

**Phase 1 implements none of these endpoints.** Phase 2 implements authentication, projects,
targets, scope, assets, endpoints and execution history. Findings, validation and report
endpoints are implemented in Phases 4–7 but are specified now so the data model stays
coherent.

---

## 2. Conventions

| Convention | Rule |
|---|---|
| Versioning | URL major version `/api/v1`; breaking changes require `/api/v2` |
| Format | JSON (`application/json`), UTF-8 |
| Timestamps | ISO 8601 UTC, e.g. `2026-11-01T10:00:00Z` |
| IDs | UUID strings |
| Field names | `snake_case` |
| Enums | lowercase `snake_case` |
| Null vs absent | `null` is explicit; omitted means "not provided" on update |
| Updates | `PATCH` is partial; `PUT` replaces a resource (scope draft) |
| Pagination | Cursor-based |
| Errors | One envelope, stable codes |
| Rate limiting | Per user and per project; `429` with `Retry-After` |
| Request IDs | `X-Request-ID` accepted or generated; echoed in responses |
| Idempotency | `Idempotency-Key` required on scan/validation/report creation |
| Caching | `Cache-Control: no-store` on authenticated resources |
| Compression | gzip/br supported for large responses; evidence uses signed URLs |

---

## 3. Authentication

### 3.1 Browser sessions

- `POST /auth/login` sets an HttpOnly, Secure, SameSite=Lax session cookie.
- Browser mutations require a CSRF token (`X-CSRF-Token`) bound to the session
  (double-submit or synchronizer token).
- Session lifetime: 30 minutes access, 14 days refresh (configurable).
- Sensitive operations (scope activation, authorization creation, destructive approval)
  require recent re-authentication (≤15 minutes).

### 3.2 API keys

- `Authorization: Bearer vulnos_<random>`
- Stored as HMAC-SHA-256 with a server pepper; only a prefix is displayed after creation.
- Scoped (`read`, `scan`, `validate`, `report`, `admin`) and optionally project-bound.
- Expiry and revocation are enforced on every request.

### 3.3 Unauthenticated endpoints

Only `GET /health` and `GET /ready` are unauthenticated. Everything else requires a valid
session or API key.

---

## 4. Authorization model

Roles are per project:

| Role | Read | Create scan | Validate | Manage targets/scope | Approve destructive | Manage members | Delete project |
|---|---:|---:|---:|---:|---:|---:|---:|
| `viewer` | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `operator` | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ |
| `admin` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
| `owner` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

Rules:

- Authorization is checked server-side for every request; the UI is not a security boundary.
- Non-members receive `404 not_found` for project resources to avoid existence leaks.
- Scope and authorization changes always require `admin` or `owner` plus a new scope version.
- A scan pins the scope version; later scope edits do not affect it.
- Destructive approvals require `owner` or `admin` with recent re-authentication.

---

## 5. Error model

All errors use:

```json
{
  "error": {
    "code": "scope_not_authorized",
    "message": "The target is not covered by the active scope version.",
    "details": {
      "target": "api.example.com",
      "scope_version_id": "0192...",
      "matched_rule_id": null
    },
    "request_id": "req_01J..."
  }
}
```

| HTTP | Code | Meaning |
|---|---|---|
| 400 | `validation_error` | Malformed request or field validation failure |
| 401 | `unauthenticated` | Missing/expired credentials |
| 403 | `forbidden` | Authenticated but lacking role/scope |
| 404 | `not_found` | Resource absent or not visible to the principal |
| 409 | `conflict` | State conflict (duplicate slug, active scan, stale version) |
| 409 | `idempotency_conflict` | Same key used with a different body |
| 422 | `semantic_error` | Well-formed but invalid for the domain (e.g. expired authorization) |
| 422 | `scope_not_authorized` | Target outside the pinned scope |
| 422 | `authorization_expired` | Authorization record no longer valid |
| 429 | `rate_limited` | Too many requests |
| 500 | `internal_error` | Unexpected server error; no internals leaked |
| 503 | `dependency_unavailable` | Database/queue/storage/AI provider unavailable |

Validation errors include field paths:

```json
{
  "error": {
    "code": "validation_error",
    "message": "Request validation failed.",
    "details": {
      "fields": [
        {"path": "budget.max_cost_usd", "issue": "must be greater than 0"}
      ]
    },
    "request_id": "req_01J..."
  }
}
```

---

## 6. Pagination, filtering and idempotency

### 6.1 Pagination

```http
GET /projects/{project_id}/findings?limit=50&cursor=eyJpZCI6...
```

```json
{
  "items": [],
  "next_cursor": "eyJpZCI6...",
  "has_more": true
}
```

- `limit`: 1–200, default 50.
- Cursor is opaque and stable for the life of the query.
- Default order: `created_at DESC, id DESC` unless documented otherwise.
- No total count on large collections; `X-Total-Count` is optional and may be omitted for
  performance.

### 6.2 Filtering

Common filters:

| Parameter | Applies to | Example |
|---|---|---|
| `status` | scans, findings, validations | `status=validated` |
| `severity` | findings | `severity=high,critical` |
| `vuln_class` | findings | `vuln_class=xss_reflected` |
| `asset_id` | findings, endpoints | UUID |
| `scan_id` | findings, executions | UUID |
| `q` | projects, assets, findings | free-text, server-side safe |
| `created_after` / `created_before` | list endpoints | ISO 8601 |

Filters combine with AND; comma-separated values within a filter combine with OR.

### 6.3 Idempotency

`POST /projects/{id}/scans`, validation requests and report creation require:

```http
Idempotency-Key: 8f14e45f-ea0c-4f7a-9c2d-3b1f0e2a6c11
```

- Same key + same canonical body → the original response is replayed (`200`/`202`).
- Same key + different body → `409 idempotency_conflict`.
- Keys are retained for 24 hours.
- The key is scoped to the authenticated principal and route.

---

## 7. Resource schemas

### 7.1 Project

```json
{
  "id": "0192a0b1-7c3e-7d4a-9f01-2b3c4d5e6f70",
  "name": "Acme External Assessment",
  "slug": "acme-external",
  "description": "Q4 authorized external web and API assessment.",
  "status": "active",
  "owner_id": "0192a0b1-...",
  "default_retention_days": 90,
  "created_at": "2026-11-01T09:00:00Z",
  "updated_at": "2026-11-01T09:00:00Z",
  "archived_at": null,
  "role": "owner"
}
```

### 7.2 Target

```json
{
  "id": "0192a0b1-...",
  "project_id": "0192a0b1-...",
  "name": "Primary web application",
  "seed_type": "domain",
  "seed_value": "example.com",
  "description": "Production domain listed in contract section 2.1.",
  "status": "active",
  "created_at": "2026-11-01T09:05:00Z"
}
```

### 7.3 Scope version

```json
{
  "id": "0192a0b1-...",
  "project_id": "0192a0b1-...",
  "authorization_id": "0192a0b1-...",
  "version": 3,
  "status": "active",
  "content_hash": "sha256:9f2c...",
  "rules": [
    {
      "id": "0192a0b1-...",
      "effect": "allow",
      "match_type": "domain_suffix",
      "value": "example.com",
      "ports": [80, 443],
      "protocols": ["https"],
      "priority": 100,
      "note": "Contract section 2.1"
    },
    {
      "id": "0192a0b1-...",
      "effect": "deny",
      "match_type": "domain_suffix",
      "value": "billing.example.com",
      "ports": null,
      "protocols": null,
      "priority": 1000,
      "note": "Excluded by client; payment provider"
    }
  ],
  "created_at": "2026-11-01T09:10:00Z",
  "activated_at": "2026-11-01T09:12:00Z"
}
```

### 7.4 Asset

```json
{
  "id": "0192a0b1-...",
  "kind": "host",
  "canonical_key": "api.example.com",
  "display_name": "api.example.com",
  "first_seen_at": "2026-11-01T10:00:00Z",
  "last_seen_at": "2026-11-01T10:20:00Z",
  "confidence": 0.98,
  "attributes": {"technologies": ["nginx", "spring_boot"]},
  "sources": ["subfinder", "httpx"]
}
```

### 7.5 Endpoint

```json
{
  "id": "0192a0b1-...",
  "asset_id": "0192a0b1-...",
  "host": "api.example.com",
  "method": "GET",
  "scheme": "https",
  "port": 443,
  "path": "/v1/users/12345",
  "path_template": "/v1/users/{id}",
  "query_template": "include=",
  "auth_required": true,
  "content_type": "application/json",
  "last_status_code": 200,
  "parameters": [
    {"name": "include", "location": "query", "data_type": "string"}
  ],
  "first_seen_at": "2026-11-01T10:10:00Z",
  "last_seen_at": "2026-11-01T10:20:00Z"
}
```

### 7.6 Tool

```json
{
  "id": "0192a0b1-...",
  "name": "nuclei",
  "category": "scanner",
  "version": "vX.Y.Z",
  "verification_status": "contract_tested",
  "available": true,
  "capabilities": {
    "vulnerability_classes": ["cve", "misconfiguration", "exposure"],
    "target_types": ["web"],
    "auth_support": true,
    "passive": false,
    "active": true,
    "state_changing": false,
    "destructive": false,
    "overlap_group": "web_vuln_scanner",
    "cost_tier": "low"
  }
}
```

### 7.7 Scan

```json
{
  "id": "0192a0b1-...",
  "project_id": "0192a0b1-...",
  "name": "External full scan",
  "scan_type": "full",
  "status": "running",
  "scope_version_id": "0192a0b1-...",
  "authorization_id": "0192a0b1-...",
  "target_ids": ["0192a0b1-..."],
  "budget": {
    "max_wall_clock_minutes": 120,
    "max_requests": 50000,
    "max_cost_usd": 25,
    "max_ai_tokens": 2000000
  },
  "cost_usd": 1.42,
  "stages": [
    {"stage": "scope", "status": "succeeded"},
    {"stage": "recon", "status": "succeeded"},
    {"stage": "discovery", "status": "running"}
  ],
  "started_at": "2026-11-01T10:00:00Z",
  "finished_at": null
}
```

### 7.8 Finding cluster

```json
{
  "id": "0192a0b1-...",
  "vulnerability_class": "xss_reflected",
  "title": "Reflected XSS in search parameter",
  "severity": "high",
  "status": "validated",
  "asset_id": "0192a0b1-...",
  "endpoint_id": "0192a0b1-...",
  "parameter": {"name": "q", "location": "query"},
  "auth_context": "anonymous",
  "confidence_score": 92.5,
  "root_cause": "Unescaped reflection of the q parameter in the search results template.",
  "confidence_factors": {
    "reproducibility": 1.0,
    "evidence_completeness": 1.0,
    "control_comparison": 0.9,
    "impact": 0.9,
    "scope_auth_clarity": 1.0,
    "independent_review": 1.0,
    "signal_consistency": 0.8
  },
  "first_detected_at": "2026-11-01T10:30:00Z",
  "validated_at": "2026-11-01T11:05:00Z",
  "occurrences": 2
}
```

### 7.9 Evidence

```json
{
  "id": "0192a0b1-...",
  "kind": "http_response",
  "content_type": "text/html",
  "size_bytes": 18422,
  "sha256": "9f2c...",
  "redaction_status": "redacted",
  "retention_until": "2027-01-30T00:00:00Z",
  "download_url": "https://.../signed?...",
  "expires_at": "2026-11-01T11:10:00Z"
}
```

### 7.10 Validation

```json
{
  "id": "0192a0b1-...",
  "cluster_id": "0192a0b1-...",
  "stage": "complete",
  "status": "passed",
  "verdict": "validated",
  "checks": [
    {"check_type": "scope", "result": "pass"},
    {"check_type": "reproducibility", "result": "pass"},
    {"check_type": "control_comparison", "result": "pass"},
    {"check_type": "independent_review", "result": "pass"}
  ],
  "reviewer_type": "model",
  "confidence_score": 92.5,
  "rationale": "Controlled re-test reproduced the reflection with a control comparison; independent reviewer accepted the evidence.",
  "created_at": "2026-11-01T11:00:00Z"
}
```

### 7.11 Report

```json
{
  "id": "0192a0b1-...",
  "scan_id": "0192a0b1-...",
  "format": "json",
  "status": "ready",
  "version": 1,
  "finding_ids": ["0192a0b1-..."],
  "content_hash": "sha256:...",
  "generated_at": "2026-11-01T12:00:00Z",
  "download_url": "https://.../signed?..."
}
```

---

## 8. Endpoint catalog

### 8.1 Health

| Method | Path | Auth | Purpose | Success |
|---|---|---|---|---|
| GET | `/health` | none | Liveness | `200 {"status":"ok"}` |
| GET | `/ready` | none | DB/Redis/S3 readiness | `200` or `503` |

### 8.2 Authentication and keys

| Method | Path | Min role | Purpose | Success |
|---|---|---|---|---|
| POST | `/auth/login` | none | Create session | `200` + cookie |
| POST | `/auth/refresh` | session | Refresh access | `200` |
| POST | `/auth/logout` | session | Revoke session | `204` |
| GET | `/auth/me` | any | Current principal | `200` |
| GET | `/api-keys` | any | List own keys | `200` |
| POST | `/api-keys` | any | Create key (plaintext shown once) | `201` |
| DELETE | `/api-keys/{key_id}` | owner of key | Revoke | `204` |

### 8.3 Projects

| Method | Path | Min role | Purpose | Success | Errors |
|---|---|---|---|---|---|
| POST | `/projects` | authenticated | Create project | `201` Project | 400, 409 |
| GET | `/projects` | authenticated | List visible projects | `200` page | 401 |
| GET | `/projects/{project_id}` | viewer | Get project | `200` Project | 404 |
| PATCH | `/projects/{project_id}` | admin | Update name/description/retention | `200` Project | 404, 409 |
| DELETE | `/projects/{project_id}` | owner | Archive project | `200` Project | 404, 409 |

Delete is an archive by default. Permanent purge requires
`DELETE /projects/{id}?purge=true` plus a confirmation token and is audited.

### 8.4 Members

| Method | Path | Min role | Purpose | Success |
|---|---|---|---|---|
| GET | `/projects/{project_id}/members` | viewer | List members | `200` |
| POST | `/projects/{project_id}/members` | admin | Add member | `201` |
| PATCH | `/projects/{project_id}/members/{user_id}` | admin | Change role | `200` |
| DELETE | `/projects/{project_id}/members/{user_id}` | admin | Remove member | `204` |

An owner cannot be removed if it would leave the project without an owner.

### 8.5 Authorization records

| Method | Path | Min role | Purpose | Success |
|---|---|---|---|---|
| GET | `/projects/{project_id}/authorizations` | viewer | List | `200` |
| POST | `/projects/{project_id}/authorizations` | admin | Create | `201` |
| GET | `/projects/{project_id}/authorizations/{authorization_id}` | viewer | Get | `200` |
| POST | `/projects/{project_id}/authorizations/{authorization_id}/revoke` | admin | Revoke | `200` |

Creating an authorization with `valid_to` in the past is rejected (`422`).

### 8.6 Scope

| Method | Path | Min role | Purpose | Success |
|---|---|---|---|---|
| GET | `/projects/{project_id}/scope` | viewer | Active scope + versions | `200` |
| POST | `/projects/{project_id}/scope` | admin | Create draft version | `201` ScopeVersion |
| GET | `/projects/{project_id}/scope/{version}` | viewer | Get version | `200` |
| PUT | `/projects/{project_id}/scope/{version}/rules` | admin | Replace draft rules | `200` |
| POST | `/projects/{project_id}/scope/{version}/activate` | admin | Activate (immutable) | `200` |
| POST | `/projects/{project_id}/scope/validate` | operator | Dry-run a target | `200` ScopeDecision |

Rules:

- Only `draft` versions can be edited.
- Activation requires a valid authorization record and at least one allow rule.
- Activation supersedes the previous active version atomically.
- `scope/validate` never makes a network request beyond DNS resolution required for the
  decision; it does not scan.

### 8.7 Targets

| Method | Path | Min role | Purpose | Success |
|---|---|---|---|---|
| GET | `/projects/{project_id}/targets` | viewer | List | `200` |
| POST | `/projects/{project_id}/targets` | admin | Add | `201` |
| GET | `/projects/{project_id}/targets/{target_id}` | viewer | Get | `200` |
| PATCH | `/projects/{project_id}/targets/{target_id}` | admin | Update metadata/archive | `200` |
| DELETE | `/projects/{project_id}/targets/{target_id}` | admin | Archive | `200` |

### 8.8 Assets and endpoints

| Method | Path | Min role | Purpose | Success |
|---|---|---|---|---|
| GET | `/projects/{project_id}/assets` | viewer | List assets | `200` |
| GET | `/projects/{project_id}/assets/{asset_id}` | viewer | Get asset | `200` |
| GET | `/projects/{project_id}/assets/{asset_id}/endpoints` | viewer | Endpoints for asset | `200` |
| GET | `/projects/{project_id}/assets/{asset_id}/discovery` | viewer | Discovery history | `200` |
| GET | `/projects/{project_id}/endpoints` | viewer | List endpoints | `200` |
| GET | `/projects/{project_id}/endpoints/{endpoint_id}` | viewer | Endpoint detail | `200` |

Filters: `kind`, `host`, `method`, `status_code`, `path_contains`, `first_seen_after`.

### 8.9 Tools

| Method | Path | Min role | Purpose | Success |
|---|---|---|---|---|
| GET | `/tools` | viewer | List registry | `200` |
| GET | `/tools/{tool_id}` | viewer | Tool detail | `200` |
| GET | `/tools/{tool_id}/versions` | viewer | Versions + verification | `200` |
| GET | `/tools/{tool_id}/capabilities` | viewer | Capability metadata | `200` |
| GET | `/tools/status` | operator | Installation/health snapshot | `200` |

`/tools/status` reports `available`, `verification_status`, `last_successful_execution_at`
and `reason` when unavailable. It must never report a tool as available based only on a
configuration entry.

### 8.10 Scans and execution

| Method | Path | Min role | Purpose | Success |
|---|---|---|---|---|
| POST | `/projects/{project_id}/scans` | operator | Create + queue scan | `202` Scan |
| GET | `/projects/{project_id}/scans` | viewer | List scans | `200` |
| GET | `/scans/{scan_id}` | viewer | Scan status | `200` |
| POST | `/scans/{scan_id}/cancel` | operator | Request cancellation | `202` |
| GET | `/scans/{scan_id}/stages` | viewer | Stage history | `200` |
| GET | `/scans/{scan_id}/executions` | viewer | Tool executions | `200` |
| GET | `/scans/{scan_id}/agent-runs` | viewer | Agent runs | `200` |
| GET | `/scans/{scan_id}/coverage` | viewer | Coverage + gaps | `200` |
| GET | `/scans/{scan_id}/decisions` | viewer | TISE rationale | `200` |

### 8.11 Approvals

| Method | Path | Min role | Purpose | Success |
|---|---|---|---|---|
| GET | `/scans/{scan_id}/approvals` | viewer | Pending/history | `200` |
| POST | `/approvals/{approval_id}/grant` | owner/admin | Approve action hash | `200` |
| POST | `/approvals/{approval_id}/deny` | owner/admin | Deny | `200` |

Approval endpoints require recent re-authentication and are bound to the exact action hash,
scan and expiration.

### 8.12 Findings and evidence

| Method | Path | Min role | Purpose | Success |
|---|---|---|---|---|
| GET | `/projects/{project_id}/findings` | viewer | List clusters | `200` |
| GET | `/findings/{cluster_id}` | viewer | Cluster detail | `200` |
| GET | `/findings/{cluster_id}/occurrences` | viewer | Source occurrences | `200` |
| GET | `/findings/{cluster_id}/evidence` | viewer | Evidence manifest | `200` |
| GET | `/findings/{cluster_id}/validations` | viewer | Validation history | `200` |
| POST | `/findings/{cluster_id}/validations` | operator | Request validation | `202` Validation |
| GET | `/validations/{validation_id}` | viewer | Validation detail | `200` |
| GET | `/evidence/{evidence_id}` | viewer | Metadata + signed URL | `200` |

### 8.13 Reports

| Method | Path | Min role | Purpose | Success |
|---|---|---|---|---|
| POST | `/projects/{project_id}/reports` | operator | Generate report | `202` Report |
| GET | `/projects/{project_id}/reports` | viewer | List reports | `200` |
| GET | `/reports/{report_id}` | viewer | Report status | `200` |
| GET | `/reports/{report_id}/download` | viewer | Signed download | `302`/`200` URL |

### 8.14 Audit and summary

| Method | Path | Min role | Purpose | Success |
|---|---|---|---|---|
| GET | `/projects/{project_id}/audit-logs` | admin | Project audit trail | `200` |
| GET | `/projects/{project_id}/summary` | viewer | Counts, cost, coverage | `200` |

---

## 9. Detailed contracts

### 9.1 POST `/projects`

**Auth:** authenticated user.

**Request:**

```json
{
  "name": "Acme External Assessment",
  "slug": "acme-external",
  "description": "Q4 authorized external web and API assessment.",
  "default_retention_days": 90
}
```

**Response `201`:** Project.

**Errors:** `400 validation_error`, `409 conflict` (slug taken), `401 unauthenticated`.

**Side effects:** inserts project, owner membership, audit log.

---

### 9.2 POST `/projects/{project_id}/authorizations`

**Auth:** project `admin`.

**Request:**

```json
{
  "reference": "ENG-2026-041",
  "document_evidence_id": "0192...",
  "authorized_by_name": "Jane Doe",
  "authorized_by_contact": "security@example.com",
  "valid_from": "2026-11-01T00:00:00Z",
  "valid_to": "2026-12-01T00:00:00Z",
  "allowed_actions": ["scan", "validate", "agent_run"],
  "destructive_allowed": false,
  "allow_private_ranges": false,
  "max_requests_per_scan": 50000,
  "notes": "External only; no social engineering."
}
```

**Response `201`:** Authorization record.

**Errors:** `422 semantic_error` if dates are invalid, `403 forbidden` if role insufficient.

---

### 9.3 POST `/projects/{project_id}/scope`

Creates a **draft** version. Does not affect running scans.

**Request:**

```json
{
  "authorization_id": "0192...",
  "rules": [
    {
      "effect": "allow",
      "match_type": "domain_suffix",
      "value": "example.com",
      "ports": [80, 443],
      "protocols": ["https"],
      "priority": 100,
      "note": "Contract section 2.1"
    },
    {
      "effect": "deny",
      "match_type": "domain_suffix",
      "value": "billing.example.com",
      "priority": 1000,
      "note": "Excluded by client"
    }
  ]
}
```

**Response `201`:** ScopeVersion with `status: "draft"`.

**Errors:** `422 semantic_error` for no allow rule, invalid CIDR, wildcard too broad,
authorization mismatch.

---

### 9.4 POST `/projects/{project_id}/scope/{version}/activate`

**Auth:** project `admin`, recent re-authentication.

**Request:** empty body or `{"confirm": true}`.

**Response `200`:** ScopeVersion with `status: "active"`.

**Errors:** `409 conflict` if another activation is in progress; `422` if the version has no
allow rules or the authorization is expired.

**Side effects:** previous active version becomes `superseded`; audit log; outbox event.

---

### 9.5 POST `/projects/{project_id}/scope/validate`

**Auth:** project `operator`.

**Request:**

```json
{
  "target": "https://api.example.com/v1/users/1",
  "method": "GET",
  "scope_version_id": "0192..."
}
```

**Response `200`:**

```json
{
  "allowed": false,
  "reason_code": "explicit_deny",
  "matched_rule_id": "0192...",
  "policy_hash": "sha256:...",
  "resolved_ips": ["203.0.113.10"],
  "scope_version_id": "0192...",
  "evaluated_at": "2026-11-01T10:00:00Z"
}
```

This endpoint is a dry run. It does not scan, send a request to the target, or bypass the
scope guard used by workers.

---

### 9.6 POST `/projects/{project_id}/scans`

**Auth:** project `operator`.

**Headers:** `Idempotency-Key` required.

**Request:**

```json
{
  "name": "External full scan",
  "scan_type": "full",
  "target_ids": ["0192..."],
  "scope_version_id": "0192...",
  "authorization_id": "0192...",
  "profile": {
    "use_autonomous_agent": true,
    "agent_primary": "strix",
    "max_crawl_depth": 2
  },
  "budget": {
    "max_wall_clock_minutes": 120,
    "max_requests": 50000,
    "max_cost_usd": 25,
    "max_ai_tokens": 2000000
  }
}
```

**Response `202`:**

```json
{
  "id": "0192...",
  "status": "queued",
  "scope_version_id": "0192...",
  "authorization_id": "0192...",
  "created_at": "2026-11-01T10:00:00Z"
}
```

**Errors:**

| Code | Condition |
|---|---|
| `scope_not_authorized` | A target seed is not covered by the scope version |
| `authorization_expired` | Authorization is not currently valid |
| `semantic_error` | Scope version is not active, or target belongs to another project |
| `conflict` | Project already has the maximum concurrent scans |
| `idempotency_conflict` | Key reused with a different body |

**Side effects:** scan row, stage rows, outbox event, budget ledger initialization.

---

### 9.7 GET `/scans/{scan_id}/coverage`

**Response `200`:**

```json
{
  "scan_id": "0192...",
  "coverage": [
    {
      "endpoint_id": "0192...",
      "vulnerability_class": "xss_reflected",
      "status": "tested",
      "tool": "dalfox",
      "tested_at": "2026-11-01T10:30:00Z"
    }
  ],
  "gaps": [
    {
      "endpoint_id": "0192...",
      "vulnerability_class": "bola",
      "reason": "no_verification_tool_configured"
    }
  ]
}
```

Coverage gaps are first-class output. The UI and reports must display them.

---

### 9.8 POST `/findings/{cluster_id}/validations`

**Auth:** project `operator`.

**Headers:** `Idempotency-Key` required.

**Request:**

```json
{
  "mode": "standard",
  "requested_checks": [
    "scope",
    "reproducibility",
    "evidence_completeness",
    "control_comparison",
    "impact",
    "duplicate"
  ],
  "budget": {"max_cost_usd": 2, "max_ai_tokens": 150000}
}
```

**Response `202`:**

```json
{
  "id": "0192...",
  "cluster_id": "0192...",
  "stage": "evidence_review",
  "status": "pending"
}
```

**Errors:** `409 conflict` if a validation is already running; `422` if the cluster is
`report_ready` or out of scope.

---

### 9.9 POST `/projects/{project_id}/reports`

**Auth:** project `operator`.

**Request:**

```json
{
  "scan_id": "0192...",
  "format": "json",
  "filters": {"status": ["report_ready"], "severity": ["high", "critical"]},
  "include_coverage": true,
  "include_rejected_appendix": false
}
```

**Response `202`:**

```json
{
  "id": "0192...",
  "status": "queued",
  "format": "json",
  "version": 1
}
```

**Errors:** `422` if no report-ready findings match; `409` if an identical report version
already exists.

---

### 9.10 GET `/evidence/{evidence_id}`

**Auth:** project `viewer`.

**Response `200`:**

```json
{
  "id": "0192...",
  "kind": "http_response",
  "content_type": "text/html",
  "size_bytes": 18422,
  "sha256": "9f2c...",
  "redaction_status": "redacted",
  "retention_until": "2027-01-30T00:00:00Z",
  "download_url": "https://storage.example/signed?...",
  "expires_at": "2026-11-01T11:10:00Z"
}
```

The URL is short-lived (default 300 s). The API never proxies raw evidence by default, to
avoid memory pressure and accidental caching.

---

## 10. OpenAPI and client generation

- FastAPI generates `/openapi.json`; it is the machine-readable contract.
- Pydantic models are the single source for request/response schemas.
- The frontend client is generated from OpenAPI in CI; hand-written types are not allowed.
- Contract tests assert that every endpoint in this document exists with the expected
  method/path and that error envelopes match.
- Breaking changes require a version bump and a migration note.

### 10.1 Contract test matrix (minimum)

| Area | Tests |
|---|---|
| Auth | Missing/invalid/expired session and key; CSRF failure |
| RBAC | Each role against each mutating endpoint |
| Tenancy | Cross-project ID returns 404 |
| Scope | Denied target on scan creation and dry-run |
| Idempotency | Replay and conflict |
| Pagination | Stable cursor, limit bounds |
| Errors | Envelope shape and codes |
| State machines | Invalid scan/finding transitions rejected |

---

## 11. Explicit non-goals for this contract

- No GraphQL API in the initial phase.
- No public webhooks in the initial phase (outbox events are internal).
- No bulk import API for findings; imports go through adapters.
- No endpoint that executes arbitrary tools or commands.
- No endpoint that lets a client supply a raw URL to a scanner outside scope validation.
- No report endpoint that returns unredacted evidence.

---

## 12. Consistency checklist

- [ ] Every endpoint has an auth requirement.
- [ ] Every mutating endpoint states its minimum role.
- [ ] Every project-scoped path validates membership.
- [ ] Every create-scan path validates scope and authorization.
- [ ] Every list endpoint is paginated.
- [ ] Every error uses the standard envelope.
- [ ] Every lifecycle transition endpoint rejects invalid states.
- [ ] No endpoint exposes secrets or cross-project data.
- [ ] Phase 2 scope is explicitly limited to the endpoints marked for it.
