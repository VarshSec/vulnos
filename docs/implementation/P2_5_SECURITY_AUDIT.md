# VulnOS — Phase 2.5 Security Audit & Architectural Specification
## Target Management, Authorization Records, Scope Rules & Deterministic Scope Validation

**Date:** 2026-11-02  
**Milestone:** P2.5.1  
**Status:** Audit & Architecture Review Complete  
**Author:** VulnOS Senior Application Security Architecture Team  

---

## 1. Executive Summary

Phase 2.5 establishes the mandatory authorization and scope boundary for the entire VulnOS platform. All subsequent reconnaissance, scanning, intelligent tool execution, autonomous penetration testing agents, and finding validation depend strictly on this subsystem.

In an offensive security engine, scope validation is the ultimate safeguard against unauthorized access, computer crime liability (e.g., CFAA / Section 1 Computer Misuse Act violations), and third-party collateral damage. A flaw in scope validation or target normalization could permit scanning of uncontracted infrastructure, cloud provider hypervisors, payment gateways, or third-party APIs.

This audit evaluates the existing database models, tenant isolation controls, cryptographic primitives, and API contracts inherited from Phases 2.1–2.4, maps every data element to the target and scope domain, identifies residual risks, and specifies the deterministic scope validation engine architecture.

---

## 2. Repository & Baseline Audit

### 2.1 Git Status & Integrity Check
- **Current Branch:** `main`
- **Current HEAD:** `c2e8bb72298e2a5f03716cf70da4d837a1a9ace8` ("docs: add VulnOS Phase 1 engineering blueprint")
- **Working Tree:** Untracked implementation files for P2.1, P2.2, P2.3, and P2.4. Zero unstaged or staged git commits. Baseline is strictly intact.

### 2.2 Prior Phase Infrastructure Audit
- **P2.1 (FastAPI & Scaffold):** Base framework running on Python 3.13 with strict Pydantic settings, structured logging (`structlog`), request correlation (`X-Request-ID`), health/ready probes, and fail-fast production configuration.
- **P2.2 (Database Foundation):** 50 PostgreSQL tables modeled in SQLAlchemy 2.x declarative Base, application-generated time-ordered UUIDv7 (`uuid6.uuid7`), integer range types (`int4range`), CIDR/IP network types (`inet`), and migration infrastructure (`alembic`).
- **P2.3 (PostgreSQL RLS):** 35 direct project-owned tables and 2 indirect tables (`scope_rules`, `validation_checks`) protected with `FORCE ROW LEVEL SECURITY`. Strict multi-tenant isolation via transaction-local setting `app.current_project_id` and engine pool connection scavenging (`RESET ALL;`). Cross-project foreign key check triggers prevent cross-tenant reference pollution.
- **P2.4 (Authentication & Authorization):** Argon2id password hashing with constant-time dummy verification, stateless JWT access tokens (`HS256`, 30m TTL), stateful Redis sessions (`vulnos_session` cookie, 14d TTL) with cryptographic single-use refresh token rotation and replay family revocation, HMAC-SHA-256 API keys with pepper, and role-based access control (`viewer`, `operator`, `admin`, `owner`).

---

## 3. Existing Schema & Model Mapping (P2.5 Boundary)

The repository already defines the core entities required for Phase 2.5 in `backend/app/db/models/identity.py`:

```
+-----------------------------------------------------------------------------------------+
|                                      Project                                            |
|                               (Tenancy Root Boundary)                                   |
+-----------------------------------------------------------------------------------------+
       |                                       |                                    |
       | 1:N                                   | 1:N                                | 1:N
       v                                       v                                    v
+-----------------------+           +-----------------------+            +----------------+
| AuthorizationRecord   |           |     ScopeVersion      |            |     Target     |
| (Legal Authorization) |<----------| (Immutable Snapshot)  |            | (Operator Seed)|
+-----------------------+   1:N     +-----------------------+            +----------------+
                                               |
                                               | 1:N (cascade delete)
                                               v
                                    +-----------------------+
                                    |       ScopeRule       |
                                    | (Allow / Deny Rules)  |
                                    +-----------------------+
                                               |
                                               | 1:N audit reference
                                               v
                                    +-----------------------+
                                    |     ScopeDecision     |
                                    | (Partitioned Audit)   |
                                    +-----------------------+
```

### 3.1 `Target` Model
- **Table:** `targets`
- **Primary Key:** `id` (UUIDv7)
- **Foreign Key:** `project_id` → `projects.id` ON DELETE CASCADE
- **Columns:**
  - `name`: Text identifier
  - `seed_type`: Text, restricted by CheckConstraint to `('domain', 'host', 'ip', 'url', 'api_base', 'repository')`
  - `seed_value`: Canonical target string
  - `description`: Text (optional)
  - `status`: Text, restricted to `('active', 'archived')`
  - `created_by`: UUID → `users.id`
  - `created_at`: timestamptz (default UTC)
  - `archived_at`: timestamptz (nullable)
- **Constraints & Indexes:**
  - `uq_targets_project_seed_type_value`: `UNIQUE (project_id, seed_type, seed_value)`
  - `ix_targets_project_status`: Index on `(project_id, status)`
- **Tenant Isolation:** Direct project table. Protected by PostgreSQL RLS: `project_id = current_project_id()`.

### 3.2 `AuthorizationRecord` Model
- **Table:** `authorization_records`
- **Primary Key:** `id` (UUIDv7)
- **Foreign Key:** `project_id` → `projects.id` ON DELETE CASCADE
- **Columns:**
  - `reference`: Text identifier for contract/ticket/engagement letter
  - `document_evidence_id`: UUID → `evidence_objects.id` (optional reference to encrypted proof)
  - `authorized_by_name`: Text (e.g., CISO or authorized legal representative)
  - `authorized_by_contact`: Text (email or phone)
  - `valid_from`: timestamptz (start of validity window)
  - `valid_to`: timestamptz (hard expiration cutoff)
  - `allowed_actions`: Array of Text (e.g. `['scan', 'validate', 'agent_run']`)
  - `destructive_allowed`: Boolean (default `false`)
  - `allow_private_ranges`: Boolean (default `false`)
  - `max_requests_per_scan`: BigInteger (optional request ceiling)
  - `notes`: Text (limitations, rules of engagement)
  - `created_by`: UUID → `users.id`
  - `created_at`: timestamptz
  - `revoked_at`: timestamptz (nullable)
- **Constraints & Indexes:**
  - `ck_authorization_records_validity_window`: `valid_to > valid_from`
  - `ix_authorization_records_project_id`: Index on `project_id`
- **Tenant Isolation:** Direct project table. Protected by PostgreSQL RLS: `project_id = current_project_id()`.

### 3.3 `ScopeVersion` Model
- **Table:** `scope_versions`
- **Primary Key:** `id` (UUIDv7)
- **Foreign Keys:**
  - `project_id` → `projects.id` ON DELETE CASCADE
  - `authorization_id` → `authorization_records.id` ON DELETE RESTRICT
- **Columns:**
  - `version`: Integer (> 0)
  - `status`: Text, restricted to `('draft', 'active', 'superseded')`
  - `content_hash`: LargeBinary (SHA-256 digest of canonically serialized rules)
  - `created_by`: UUID → `users.id`
  - `created_at`: timestamptz
  - `activated_at`: timestamptz (nullable)
  - `superseded_at`: timestamptz (nullable)
- **Constraints & Indexes:**
  - `uq_scope_versions_project_version`: `UNIQUE (project_id, version)`
  - `uq_scope_active`: Partial unique index `UNIQUE (project_id) WHERE status = 'active'`
- **Tenant Isolation:** Direct project table. Protected by PostgreSQL RLS: `project_id = current_project_id()`.

### 3.4 `ScopeRule` Model
- **Table:** `scope_rules`
- **Primary Key:** `id` (UUIDv7)
- **Foreign Key:** `scope_version_id` → `scope_versions.id` ON DELETE CASCADE
- **Columns:**
  - `effect`: Text, restricted to `('allow', 'deny')`
  - `match_type`: Text, restricted to `('exact_url', 'url_prefix', 'exact_host', 'domain_suffix', 'wildcard_domain', 'ip', 'cidr')`
  - `value`: Text (normalized rule value)
  - `ports`: INT4RANGE (nullable, `NULL` = any port)
  - `protocols`: Array of Text (nullable, e.g. `['http', 'https']`, `NULL` = any protocol)
  - `priority`: Integer (default 100)
  - `note`: Text (optional justification or exclusion reason)
  - `created_at`: timestamptz
- **Constraints & Indexes:**
  - `ck_scope_rules_effect`: `effect IN ('allow', 'deny')`
  - `ck_scope_rules_match_type`: `match_type IN (...)`
  - `ix_scope_rules_version_effect`: Index on `(scope_version_id, effect)`
- **Tenant Isolation:** Indirect table. Protected by PostgreSQL RLS via subquery:
  `scope_version_id IN (SELECT id FROM scope_versions WHERE project_id = current_project_id())`.

### 3.5 `ScopeDecision` Model
- **Table:** `scope_decisions` (Partitioned by RANGE on `decided_at`)
- **Primary Key:** Composite `(id, decided_at)`
- **Foreign Keys:**
  - `project_id` → `projects.id`
  - `scan_id` → `scans.id` (nullable, for scan execution attribution)
  - `scope_version_id` → `scope_versions.id`
  - `authorization_id` → `authorization_records.id`
  - `matched_rule_id` → `scope_rules.id` (nullable)
- **Columns:**
  - `id`: BigInteger (Identity)
  - `subject`: Text (evaluated host, domain, IP, or URL)
  - `method`: Text (HTTP verb, nullable)
  - `allowed`: Boolean
  - `reason_code`: Text (explainable machine-readable reason)
  - `resolved_ips`: Array of INET (DNS resolved IP addresses)
  - `policy_hash`: LargeBinary (SHA-256 snapshot of active policy)
  - `decided_at`: timestamptz
  - `context`: JSONB (metadata: tool name, requested action, port, protocol)
- **Tenant Isolation:** Direct project table. Protected by PostgreSQL RLS: `project_id = current_project_id()`.

---

## 4. Current Weaknesses & Attack Surface Analysis

Before implementing Phase 2.5, the audit identified several critical security vectors that must be defended:

1. **Target Seeds vs Authorized Assets:**
   - *Weakness:* Operators may assume that adding a target to a project automatically authorizes testing against it.
   - *Design Defense:* Targets are purely **discovery seeds**. A target record does NOT confer authorization. Testing is permitted **only** when an active `AuthorizationRecord` exists and an active `ScopeVersion` contains an explicit `allow` rule covering the evaluated subject.

2. **Domain Label Boundary Smuggling:**
   - *Weakness:* Naive substring matching (e.g., `target.endswith("example.com")`) mistakenly matches `notexample.com`, `evilexample.com`, and `attacker-example.com`.
   - *Design Defense:* Domain matching must strictly enforce DNS label boundaries. `domain_suffix: example.com` matches `example.com` and `*.example.com` (subdomains separated by a dot), but never string prefixes without a label boundary.

3. **Wildcard Apex Confusion:**
   - *Weakness:* `wildcard_domain: *.example.com` is mistakenly interpreted as allowing the root domain `example.com`.
   - *Design Defense:* Per VulnOS specifications, `wildcard_domain: *.example.com` allows subdomains only (`api.example.com`, `app.example.com`). To allow both the root and subdomains, `domain_suffix: example.com` must be used.

4. **URL Prefix Normalization & Traversal Bypasses:**
   - *Weakness:* A naive prefix rule `https://example.com/api` matches `https://example.com/apiv2` or `https://example.com/api/../admin`.
   - *Design Defense:* URL canonicalization must remove dot segments (`/../`, `/./`), normalize percent-encoded characters, lower-case scheme and host, strip default ports (`80` for HTTP, `443` for HTTPS), reject credentials (`http://user:pass@host`), and verify path boundaries (e.g. prefix matches must end with `/` or match exact segment boundaries).

5. **Cloud Metadata & Private Range SSRF Hazards:**
   - *Weakness:* Autonomous tools or scanners resolve a target or follow a redirect to internal cloud metadata (`169.254.169.254`) or loopback/private RFC 1918 addresses.
   - *Design Defense:* Cloud metadata addresses are **hard-blocked and non-overridable**. Private RFC 1918 and link-local ranges are blocked by default, unless the project's active `AuthorizationRecord` has `allow_private_ranges = true` **AND** an explicit `allow` rule covers the specific private range.

6. **DNS-Derived Scope Expansion:**
   - *Weakness:* An authorized domain `example.com` resolves to a CDN IP shared with thousands of other organizations, or DNS poisoning / dynamic rebinding injects unauthorized IPs into scope.
   - *Design Defense:* DNS answers are treated as untrusted runtime data. Authorizing a domain does **not** authorize arbitrary network-level scanning of every IP it resolves to. Furthermore, resolving to an unauthorized IP blocks the network operation.

7. **Stale / Reused Scope Decisions:**
   - *Weakness:* A decision made 2 hours ago is reused for a subsequent scan stage after an authorization record was revoked or expired.
   - *Design Defense:* `ScopeDecision` records are **append-only audit logs**, never cached execution permits. Every network dispatch must perform a fresh evaluation against the current active policy.

8. **Draft Scope Modification Concurrency:**
   - *Weakness:* Race condition during scope activation where rules are added while a version is transitioning from draft to active, resulting in an unhashed or tampered active policy.
   - *Design Defense:* Scope rule modification is strictly prohibited unless `status = 'draft'`. Scope version activation locks the record, computes an atomic canonical `content_hash` over all sorted rules, marks the version `active`, and supersedes any previously active version within a single database transaction.

---

## 5. Normalization Specification (`normalization.py`)

Deterministic normalization must precede all scope rule evaluation and target persistence.

### 5.1 Domain Normalization Rules
1. Strip leading and trailing whitespace and trailing dots (`example.com.` → `example.com`).
2. Convert Unicode to ASCII via IDNA 2008 / UTS #46 Punycode (`münchen.de` → `xn--mnchen-3ya.de`).
3. Lowercase all characters.
4. Validate DNS label syntax per RFC 1035 and RFC 1123:
   - 1 to 63 octets per label.
   - Total length ≤ 253 octets.
   - Labels contain only `[a-z0-9-]`.
   - Labels must not start or end with a hyphen.
   - Reject empty labels (consecutive dots `..`).

### 5.2 IP and CIDR Normalization Rules
1. Parse using Python `ipaddress.ip_address` and `ipaddress.ip_network(strict=True)`.
2. IPv4 addresses formatted as canonical 4-octet dotted decimal (no leading zeros).
3. IPv6 addresses formatted per RFC 5952 (lowercase, compressed consecutive zero groups).
4. IPv4-mapped IPv6 addresses (`::ffff:192.0.2.1`) unpacked to their underlying IPv4 address.
5. Strict CIDR validation rejects host bits set in network prefixes (e.g. `192.168.1.5/24` is rejected; must be `192.168.1.0/24`).

### 5.3 URL Normalization Rules
1. Scheme must be strictly `http` or `https` (lowercase). Reject `ftp`, `file`, `gopher`, `javascript`, etc.
2. Host extracted, stripped of userinfo (embedded credentials like `user:pass@` trigger immediate rejection), and normalized per Domain or IP rules.
3. Port normalized: omit default ports (`80` for http, `443` for https). Reject ports outside `1–65535`.
4. Path canonicalized via RFC 3986 section 5.2.4 (remove dot segments `/./`, `/../`). Empty path normalized to `/`.
5. Preserve case in path segments where semantically required, but lowercase percent-encoded hex sequences.
6. Strip URL fragments (`#...`). Query parameters sorted alphabetically if present.

---

## 6. Scope Rule Engine Architecture & Precedence

The validation engine evaluates a requested subject against the active scope policy in a strictly deterministic sequence:

```mermaid
flowchart TD
    Start([Evaluate Subject]) --> Step1[1. Validate Tenant & Auth Context]
    Step1 -->|Invalid| Deny1[DENY: Invalid Context / Not Found]
    Step1 -->|Valid| Step2[2. Check Active Authorization Record]
    Step2 -->|Missing / Expired / Revoked| Deny2[DENY: Authorization Inactive]
    Step2 -->|Active| Step3[3. Check Active Scope Version]
    Step3 -->|No Active Version| Deny3[DENY: Scope Version Missing]
    Step3 -->|Active| Step4[4. Normalize Subject]
    Step4 -->|Malformed| Deny4[DENY: Invalid Target Syntax]
    Step4 -->|Valid| Step5[5. Check Cloud Metadata / Private IP Limits]
    Step5 -->|Metadata / Disallowed Private| Deny5[DENY: Metadata or Private Range Blocked]
    Step5 -->|Allowed Range| Step6[6. Evaluate Explicit DENY Rules]
    Step6 -->|Matched Deny Rule| Deny6[DENY: Explicit Deny Rule Overrides Allow]
    Step6 -->|No Deny Match| Step7[7. Evaluate Explicit ALLOW Rules]
    Step7 -->|No Match| Deny7[DENY: Default Deny - No Allow Rule]
    Step7 -->|Matched Allow Rule| Step8[8. Verify Operation Permission]
    Step8 -->|Action Not in allowed_actions| Deny8[DENY: Operation Not Permitted]
    Step8 -->|Action Permitted| Allow([ALLOW: Target Authorized])
```

### 6.1 Invariant: Deny Overrides Allow
An explicit `deny` rule **always** supersedes an `allow` rule, regardless of rule specificity, priority, or creation timestamp.

### 6.2 Match Type Definitions
- `exact_host`: Exact match of fully-qualified domain name or hostname (case-insensitive).
- `domain_suffix`: Matches the specified apex domain and any valid subdomain (e.g., `example.com` matches `example.com`, `api.example.com`, `v1.api.example.com`).
- `wildcard_domain`: Matches subdomains only, excluding the apex (e.g., `*.example.com` matches `api.example.com`, but NOT `example.com`).
- `exact_url`: Exact match of normalized scheme, host, port, path, and query.
- `url_prefix`: Path-boundary-aware prefix matching. `https://example.com/api` matches `https://example.com/api/` and `https://example.com/api/v1`, but rejects `https://example.com/apiv2`.
- `ip`: Exact match of normalized IPv4 or IPv6 address.
- `cidr`: IP subnet containment via `ipaddress` network boundaries.

### 6.3 Explainable Decision Codes
Every decision must emit an unambiguous machine-readable reason code:
- `ALLOW_EXACT_MATCH`
- `ALLOW_DOMAIN_SUFFIX_MATCH`
- `ALLOW_WILDCARD_SUBDOMAIN_MATCH`
- `ALLOW_IP_MATCH`
- `ALLOW_CIDR_MATCH`
- `ALLOW_URL_PREFIX_MATCH`
- `DENY_EXPLICIT_RULE`
- `DENY_NO_ALLOW_RULE`
- `DENY_AUTHORIZATION_MISSING`
- `DENY_AUTHORIZATION_EXPIRED`
- `DENY_AUTHORIZATION_REVOKED`
- `DENY_SCOPE_VERSION_MISSING`
- `DENY_METADATA_ENDPOINT`
- `DENY_PRIVATE_RANGE_BLOCKED`
- `DENY_INVALID_TARGET`
- `DENY_PORT_DISALLOWED`
- `DENY_PROTOCOL_DISALLOWED`
- `DENY_OPERATION_NOT_PERMITTED`

---

## 7. Scope Versioning & Concurrency Strategy

1. **State Machine:**
   - `draft` → `active` (upon publication / activation)
   - `active` → `superseded` (atomically when a subsequent version is activated)
2. **Immutability Invariant:**
   - Once a `ScopeVersion` has status `active` or `superseded`, its rules cannot be added, edited, or deleted. Any modification requires creating a new `draft` version.
3. **Atomic Content Hash:**
   - Before activation, all rules under the version are canonically sorted and serialized to compute a SHA-256 `content_hash`. This hash is sealed into the `ScopeVersion` row.
4. **Concurrency Control:**
   - Version activation executes inside an explicit database transaction with row-level locking (`SELECT ... FOR UPDATE` on `ScopeVersion` and `Project`) to prevent race conditions during activation.
   - Partial unique index `uq_scope_active` guarantees at most one active scope version per project at the database level.

---

## 8. API Integration Architecture

In accordance with `docs/architecture/API_CONTRACTS.md`, the Phase 2.5 REST endpoints will be mounted on the FastAPI application:

### 8.1 Authorization Records API (`/projects/{project_id}/authorizations`)
- `GET /projects/{project_id}/authorizations`: List project authorizations (Min role: `viewer`)
- `POST /projects/{project_id}/authorizations`: Create authorization record (Min role: `admin`)
- `GET /projects/{project_id}/authorizations/{authorization_id}`: Get details (Min role: `viewer`)
- `POST /projects/{project_id}/authorizations/{authorization_id}/revoke`: Revoke authorization (Min role: `admin`)

### 8.2 Scope API (`/projects/{project_id}/scope`)
- `GET /projects/{project_id}/scope`: Get active scope version and list of versions (Min role: `viewer`)
- `POST /projects/{project_id}/scope`: Create new draft scope version (Min role: `admin`)
- `GET /projects/{project_id}/scope/{version}`: Get specific scope version with rules (Min role: `viewer`)
- `PUT /projects/{project_id}/scope/{version}/rules`: Replace draft rules (Min role: `admin`)
- `POST /projects/{project_id}/scope/{version}/activate`: Activate version & compute content hash (Min role: `admin`)
- `POST /projects/{project_id}/scope/validate`: Deterministic dry-run scope validation (Min role: `operator`)

### 8.3 Targets API (`/projects/{project_id}/targets`)
- `GET /projects/{project_id}/targets`: List targets (Min role: `viewer`)
- `POST /projects/{project_id}/targets`: Add target seed (Min role: `admin`)
- `GET /projects/{project_id}/targets/{target_id}`: Get target detail (Min role: `viewer`)
- `PATCH /projects/{project_id}/targets/{target_id}`: Update metadata (Min role: `admin`)
- `DELETE /projects/{project_id}/targets/{target_id}`: Archive target (Min role: `admin`)

All routes integrate with Phase 2.4 dependency `require_project_context()`, guaranteeing that:
1. User or API key is authenticated.
2. Project membership is verified (returning `404 Not Found` for non-members).
3. RBAC minimum role is enforced (`viewer` < `operator` < `admin` < `owner`).
4. API key scopes are checked.
5. Transaction-local PostgreSQL RLS context is established.

---

## 9. Implementation Roadmap & Milestones

- **P2.5.1 (Current):** Security audit and schema mapping. (Complete)
- **P2.5.2:** Target normalization service (`backend/app/scope/normalization.py`).
- **P2.5.3:** Target management service and schemas (`backend/app/scope/targets.py`).
- **P2.5.4:** Authorization record lifecycle management (`backend/app/scope/authorizations.py`).
- **P2.5.5:** Scope rule matching engine (`backend/app/scope/matcher.py`).
- **P2.5.6:** Scope versioning & immutable activation (`backend/app/scope/versions.py`).
- **P2.5.7:** Deterministic scope decision engine & explainable codes (`backend/app/scope/validator.py`).
- **P2.5.8:** Scope decision persistence & audit logging integration.
- **P2.5.9:** FastAPI API routers & dependency wiring (`backend/app/api/v1/`).
- **P2.5.10:** Adversarial security test suite in `backend/tests/security/scope/`.
- **P2.5.11:** Documentation, regression validation, and quality gates.

---

## 10. Audit Sign-Off & Verification

- **Schema Consistency:** The existing SQLAlchemy models (`Target`, `AuthorizationRecord`, `ScopeVersion`, `ScopeRule`, `ScopeDecision`) in `backend/app/db/models/identity.py` and existing Alembic baseline migration `0001_phase2_baseline.py` fully satisfy the P2.5 requirements without needing schema changes.
- **RLS Consistency:** RLS migration `0002_phase2_rls.py` already covers all project-isolated tables.
- **Ready for Implementation:** Phase 2.5 implementation may proceed starting with Milestone P2.5.2 (Target Normalization).
