# VulnOS — Phase 2.4 Authentication & Authorization Security Test Matrix

**Document Status:** Complete Test Matrix & Security Verification Record  
**Phase:** 2.4 (Authentication, Session Management, API Keys & RBAC)  
**Author:** Senior Security Documentation Engineer  
**Date:** 2026-11-02  
**Repository:** `https://github.com/VarshSec/vulnos`  
**Git HEAD:** `c2e8bb72298e2a5f03716cf70da4d837a1a9ace8` (Baseline)  

---

## 1. Overview & Test Suite Status

Phase 2.4 establishes the core identity, credential validation, session persistence, machine-to-machine authentication, and role-based access control (RBAC) foundation for VulnOS. Because VulnOS conducts active vulnerability discovery and stores high-impact security findings, every authentication and authorization boundary is engineered under strict **defense-in-depth**, **least-privilege**, and **fail-secure** principles.

The Phase 2.4 security test suite consists of **30 dedicated security test cases** covering every layer from low-level cryptographic primitives to FastAPI HTTP endpoints and PostgreSQL Row-Level Security (RLS) context establishment.

### 1.1 Test Suite Summary

- **Phase 2.4 Dedicated Security Tests:** **30 passed** (0 failed, 0 skipped) in `1.34s`
- **Total Project Test Suite:** **246 passed** (0 failed, 0 skipped) in `2.91s`
- **Pass Rate:** **100%**
- **Test Command:**
  ```powershell
  python -m pytest backend/tests/security/auth
  python -m pytest
  ```

### 1.2 Core Security Objectives Validated

1. **Cryptographic Rigor:** Enforcing RFC 9106 Argon2id password hashing, RFC 7519 HMAC-SHA-256 JWT access tokens, and constant-time HMAC-SHA-256 peppered API keys.
2. **Side-Channel & Timing Attack Mitigation:** Pre-computed dummy Argon2id hash verification preventing user enumeration when invalid emails are queried.
3. **Session Integrity & Anti-Replay:** Atomic single-use refresh token rotation in Redis with immediate token family invalidation upon replay detection.
4. **Zero Persistent Relational Sessions:** Ephemeral browser sessions strictly managed in Redis with TTLs, preventing relational database contention and maintaining clear architectural boundaries.
5. **Anti-Enumeration RBAC:** Non-project members receive `404 Not Found` (via [`ProjectAccessDeniedError`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/app/auth/exceptions.py#L38-L41)) rather than `403 Forbidden` to prevent project identifier probing.
6. **Strict RLS Tenant Context Binding:** Guaranteed transaction-local PostgreSQL tenant context establishment only after authentication and RBAC validation succeed, reverting cleanly upon request completion.

---

## 2. Test Coverage Matrix

The table below catalogs all 30 security tests implemented across the 7 dedicated Phase 2.4 test modules.

| Test File | Test Name | Category | What It Validates | Security Property |
|---|---|---|---|---|
| [`test_passwords.py`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/tests/security/auth/test_passwords.py) | [`test_password_policy_validation`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/tests/security/auth/test_passwords.py#L14-L32) | Password Security | Validates length constraints (12–128 chars), null-byte (`\x00`) rejection, and boundary inputs. | **Input Validation & DoS Mitigation:** Prevents buffer/null-byte injection and Argon2 CPU DoS via oversized input. |
| [`test_passwords.py`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/tests/security/auth/test_passwords.py) | [`test_password_hashing_and_verification`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/tests/security/auth/test_passwords.py#L34-L51) | Password Security | Validates Argon2id format (`$argon2id$m=65536,t=3,p=4`), valid match, wrong password rejection, and rehash checks. | **Cryptographic Soundness:** RFC 9106 memory-hard password storage resistant to GPU/ASIC offline attacks. |
| [`test_passwords.py`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/tests/security/auth/test_passwords.py) | [`test_hash_salt_uniqueness`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/tests/security/auth/test_passwords.py#L53-L62) | Password Security | Confirms that identical plaintext passwords generate distinct hash outputs due to per-credential random salts. | **Pre-computation Resistance:** Prevents rainbow table lookups and credential clustering. |
| [`test_passwords.py`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/tests/security/auth/test_passwords.py) | [`test_dummy_verification_timing_mitigation`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/tests/security/auth/test_passwords.py#L64-L74) | Password Security | Verifies that verification against missing (`None`), empty, or invalid hashes executes safely using dummy hash. | **Side-Channel Resistance:** Neutralizes timing discrepancy between existing and non-existing accounts. |
| [`test_tokens.py`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/tests/security/auth/test_tokens.py) | [`test_create_and_decode_access_token`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/tests/security/auth/test_tokens.py#L22-L34) | JWT Tokens | Verifies complete JWT claim structure (`sub`, `iss`, `aud`, `typ`, `jti`, `iat`, `exp`) on issuance and decoding. | **Authenticity & Non-Repudiation:** RFC 7519 compliance and cryptographically verifiable principal claims. |
| [`test_tokens.py`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/tests/security/auth/test_tokens.py) | [`test_expired_token_rejection`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/tests/security/auth/test_tokens.py#L36-L44) | JWT Tokens | Verifies that tokens with expired timestamps raise [`TokenExpiredError`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/app/auth/exceptions.py#L21-L24) upon decoding. | **Temporal Credential Bounding:** Enforces limited access token lifetime (default 30 mins) to restrict exposure window. |
| [`test_tokens.py`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/tests/security/auth/test_tokens.py) | [`test_invalid_signature_rejection`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/tests/security/auth/test_tokens.py#L46-L57) | JWT Tokens | Verifies that tampering with the token payload or cryptographic signature raises [`TokenInvalidError`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/app/auth/exceptions.py#L26-L29). | **Tamper Detection:** Protects token claims against client-side modification or forging. |
| [`test_tokens.py`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/tests/security/auth/test_tokens.py) | [`test_wrong_issuer_and_audience`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/tests/security/auth/test_tokens.py#L59-L92) | JWT Tokens | Rejects tokens bearing untrusted `iss` (`!= 'vulnos'`) or untrusted `aud` (`!= 'vulnos-api'`). | **Confused Deputy Mitigation:** Prevents tokens issued by or meant for other microservices from authenticating. |
| [`test_tokens.py`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/tests/security/auth/test_tokens.py) | [`test_token_type_confusion_rejection`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/tests/security/auth/test_tokens.py#L94-L113) | JWT Tokens | Rejects tokens claiming `typ` other than `'access'` (e.g. `'refresh'`) during access token decoding. | **Token Type Separation:** Eliminates type confusion attacks where long-lived tokens masquerade as access tokens. |
| [`test_tokens.py`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/tests/security/auth/test_tokens.py) | [`test_refresh_token_generation_and_hashing`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/tests/security/auth/test_tokens.py#L115-L124) | JWT Tokens | Confirms generation of 32-byte URL-safe cryptographic tokens and deterministic SHA-256 64-char hex digests. | **CSPRNG Entropy & One-Way Storage:** Raw tokens are never stored plaintext; Redis retains only SHA-256 digests. |
| [`test_sessions.py`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/tests/security/auth/test_sessions.py) | [`test_session_creation_and_retrieval`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/tests/security/auth/test_sessions.py#L121-L141) | Session Management | Validates session creation in Redis, user agent/IP tracking, CSRF token issuance, and state retrieval. | **Ephemeral Session Security:** Encapsulated in Redis with strict TTLs; no relational DB writes. |
| [`test_sessions.py`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/tests/security/auth/test_sessions.py) | [`test_session_revocation`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/tests/security/auth/test_sessions.py#L143-L152) | Session Management | Validates single-session revocation removes session key, token family hashes, and user set membership. | **Immediate Invalidation:** Single-session termination guarantees immediate revocation across all endpoints. |
| [`test_sessions.py`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/tests/security/auth/test_sessions.py) | [`test_revoke_all_user_sessions`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/tests/security/auth/test_sessions.py#L154-L173) | Session Management | Confirms `revoke_all_user_sessions` enumerates user session set and invalidates all concurrent sessions. | **Global Credential Invalidation:** Essential control executed upon password changes or suspected breach. |
| [`test_sessions.py`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/tests/security/auth/test_sessions.py) | [`test_atomic_refresh_token_rotation_success`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/tests/security/auth/test_sessions.py#L175-L196) | Session Management | Validates sequential refresh token rotations issuing new access/refresh pairs while invalidating parent tokens. | **Forward Secrecy & Sliding Windows:** Every rotation generates fresh single-use secrets. |
| [`test_sessions.py`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/tests/security/auth/test_sessions.py) | [`test_refresh_token_replay_attack_detection`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/tests/security/auth/test_sessions.py#L198-L216) | Session Management | Validates that reusing an already-rotated token triggers [`TokenReplayError`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/app/auth/exceptions.py#L31-L34) and destroys entire token family. | **Replay Attack Defense:** Protects against exfiltrated/intercepted refresh tokens by nullifying session on reuse. |
| [`test_api_keys.py`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/tests/security/auth/test_api_keys.py) | [`test_api_key_format_and_hashing`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/tests/security/auth/test_api_keys.py#L42-L53) | API Keys | Validates format `vulnos_{prefix8}_{secret32}` and HMAC-SHA-256 peppered digest computation. | **Standardized Key Entropy & Salt/Pepper Protection:** Public prefix enables fast lookup without leaking secret hash. |
| [`test_api_keys.py`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/tests/security/auth/test_api_keys.py) | [`test_api_key_authentication_success`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/tests/security/auth/test_api_keys.py#L55-L76) | API Keys | Validates successful authentication using plaintext key, loading user and key records, and updating `last_used_at`. | **Principal Authentication & Auditability:** Enables automated machine access while tracking last utilization. |
| [`test_api_keys.py`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/tests/security/auth/test_api_keys.py) | [`test_api_key_invalid_format_and_tampered_secret`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/tests/security/auth/test_api_keys.py#L78-L105) | API Keys | Rejects malformed strings, non-existent prefixes (`404`), and tampered secret suffixes with matching prefixes (`401`). | **Constant-Time Verification:** Uses `hmac.compare_digest` to prevent secret byte-by-byte timing leaks. |
| [`test_api_keys.py`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/tests/security/auth/test_api_keys.py) | [`test_api_key_revocation_rejection`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/tests/security/auth/test_api_keys.py#L107-L127) | API Keys | Validates that an API key with `revoked_at` set fails authentication with [`APIKeyRevokedError`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/app/auth/exceptions.py#L50-L53). | **Immediate Machine Revocation:** Guarantees decommissioned or leaked API keys cannot execute further actions. |
| [`test_api_keys.py`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/tests/security/auth/test_api_keys.py) | [`test_api_key_expiration_rejection`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/tests/security/auth/test_api_keys.py#L129-L147) | API Keys | Validates that keys with expired `expires_at` timestamps fail authentication with [`APIKeyExpiredError`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/app/auth/exceptions.py#L46-L49). | **Temporal Machine Credential Hygiene:** Prevents indefinite persistence of machine access tokens. |
| [`test_rbac.py`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/tests/security/auth/test_rbac.py) | [`test_role_hierarchy`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/tests/security/auth/test_rbac.py#L35-L57) | RBAC | Validates monotonic hierarchy: `owner` (40) > `admin` (30) > `operator` (20) > `viewer` (10). | **Privilege Escalation Prevention:** Lower roles cannot perform actions requiring higher privileges. |
| [`test_rbac.py`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/tests/security/auth/test_rbac.py) | [`test_api_key_scope_evaluation`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/tests/security/auth/test_rbac.py#L59-L69) | RBAC | Validates exact scope evaluation (`read`, `scan`, `validate`, `report`) and `admin` wildcard delegation. | **Least-Privilege Machine Scoping:** Restricts machine tokens to authorized sub-actions. |
| [`test_rbac.py`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/tests/security/auth/test_rbac.py) | [`test_verify_project_access_authorized`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/tests/security/auth/test_rbac.py#L71-L93) | RBAC | Confirms member with equal or superior role (`operator` accessing as `viewer` or `operator`) is authorized. | **Authorized Collaboration:** Permits authorized members to access designated project assets. |
| [`test_rbac.py`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/tests/security/auth/test_rbac.py) | [`test_verify_project_access_insufficient_role`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/tests/security/auth/test_rbac.py#L95-L113) | RBAC | Verifies member with inadequate role (`viewer` attempting `operator` action) raises [`PermissionDeniedError`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/app/auth/exceptions.py#L42-L45) (`403`). | **Vertical Authorization Barrier:** Enforces explicit permission checks on mutating actions. |
| [`test_rbac.py`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/tests/security/auth/test_rbac.py) | [`test_verify_project_access_non_member_not_found`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/tests/security/auth/test_rbac.py#L115-L129) | RBAC | Verifies non-members querying a project receive [`ProjectAccessDeniedError`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/app/auth/exceptions.py#L38-L41) (`404 "Project not found"`). | **Anti-Enumeration & Default-Deny:** Masks project existence from unauthorized tenants to mitigate IDOR probing. |
| [`test_rls_auth_integration.py`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/tests/security/auth/test_rls_auth_integration.py) | [`test_authorized_member_establishes_rls_context`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/tests/security/auth/test_rls_auth_integration.py#L36-L81) | RLS Integration | Confirms dependency establishes transaction-local tenant context (`project_id`, `user_id`, `request_id`) and clears on teardown. | **Defense-in-Depth Bridge:** Connects application-layer authentication directly to Phase 2.3 PostgreSQL RLS enforcement. |
| [`test_rls_auth_integration.py`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/tests/security/auth/test_rls_auth_integration.py) | [`test_unauthorized_member_never_establishes_rls_context`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/tests/security/auth/test_rls_auth_integration.py#L83-L112) | RLS Integration | Confirms that non-member request aborts with `HTTP 404` and database tenant context remains strictly `None`. | **Context Poisoning Prevention:** Blocked requests cannot leak or set session tenant context in database pools. |
| [`test_rls_auth_integration.py`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/tests/security/auth/test_rls_auth_integration.py) | [`test_insufficient_role_never_establishes_rls_context`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/tests/security/auth/test_rls_auth_integration.py#L114-L147) | RLS Integration | Confirms that member with insufficient role aborts with `HTTP 403` and database tenant context remains strictly `None`. | **Atomic Boundary Invariant:** RLS context is only established if both identity and role hierarchy gates succeed. |
| [`test_auth_endpoints.py`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/tests/security/auth/test_auth_endpoints.py) | [`test_register_and_login_flow`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/tests/security/auth/test_auth_endpoints.py#L87-L123) | E2E Endpoints | Tests full HTTP lifecycle: registration (`201`), login (`200` returning JWT + session cookie), and `/api/v1/auth/me`. | **End-to-End Credential Handling:** Confirms passwords and hashes are never leaked in JSON responses; verifies bearer flow. |
| [`test_auth_endpoints.py`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/tests/security/auth/test_auth_endpoints.py) | [`test_api_key_lifecycle_endpoints`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/tests/security/auth/test_auth_endpoints.py#L126-L181) | E2E Endpoints | Tests HTTP key issuance (`201`), secret masking in listings, authentication via API key, revocation (`204`), and 401 rejection. | **Machine Lifecycle Invariants:** Secret returned strictly once upon creation; revoked key immediately rejected. |

---

## 3. Test Categories & Architectural Analysis

### 3.1 Password Security (4 Tests)
The password storage implementation in [`passwords.py`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/app/auth/passwords.py) implements strict adherence to RFC 9106 and OWASP Application Security Verification Standard (ASVS) Level 3 requirements:
- **Parameters:** Argon2id with memory cost $m = 65536\text{ KiB}$ (64 MiB), time cost $t = 3$ iterations, parallelism $p = 4$ threads, hash length 32 bytes, salt length 16 bytes.
- **Timing Attack Mitigation:** In [`test_dummy_verification_timing_mitigation`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/tests/security/auth/test_passwords.py#L64-L74), when an email address is not present in the database, the backend executes an identical Argon2id verification against a pre-computed constant dummy hash (`_DUMMY_HASH`). This prevents remote threat actors from determining whether an email exists by measuring execution latency.
- **Length Bounding:** Passwords are constrained to between 12 and 128 characters. The 128-character upper bound mitigates algorithmic complexity exhaustion attacks against the memory-hard hasher.

### 3.2 JWT Access Tokens & Refresh Primitives (6 Tests)
The JWT access token implementation in [`tokens.py`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/app/auth/tokens.py) enforces algorithm pinning and claim validation:
- **Algorithm Pinning:** Strictly pins `algorithm="HS256"`. Any incoming token claiming `"none"` or asymmetric algorithms without explicit backend configuration is rejected.
- **Explicit Claim Validation:** Validates `iss="vulnos"`, `aud="vulnos-api"`, `sub=<UUIDv7>`, `typ="access"`, `jti=<UUIDv7>`, and timestamps `iat` and `exp`.
- **Token Type Isolation:** Tokens claiming `typ != "access"` are rejected, neutralizing token confusion vulnerabilities.
- **Refresh Token Generation:** Generated via `secrets.token_urlsafe(32)` (256 bits of CSPRNG entropy). Refresh tokens are immediately hashed with SHA-256 before storage in Redis, preventing token compromise in the event of memory dumps or Redis log exfiltration.

### 3.3 Session Management & Token Families (5 Tests)
The session architecture implemented in [`sessions.py`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/app/auth/sessions.py) enforces stateful, ephemeral session management:
- **Relational Cleanliness:** As mandated by the VulnOS database architecture, zero relational database tables exist for browser sessions. Redis manages all session records with strict TTLs (`REFRESH_TOKEN_TTL_DAYS * 86400`).
- **Atomic Single-Use Rotation:** Every call to `rotate_refresh_token()` marks the consumed token hash as `used=1` and registers a new cryptographically generated token pair inside an atomic Redis pipeline.
- **Replay Detection & Family Invalidation:** If an already-consumed refresh token hash (`used=1`) is submitted again, the system recognizes a replay attack. The entire token family associated with that `family_id` is immediately revoked in Redis, and the parent session is terminated.

### 3.4 API Keys (5 Tests)
The API key architecture in [`api_keys.py`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/app/auth/api_keys.py) provides machine-to-machine authentication:
- **Format:** `vulnos_{prefix}_{secret}`, where `prefix` is 8 hexadecimal characters (4 bytes) and `secret` is 32 hexadecimal characters (16 bytes).
- **HMAC-SHA-256 Peppered Hash:** Hashes are computed using a server-side secret pepper (`API_KEY_PEPPER`):
  $$\text{key\_hash} = \text{HMAC-SHA-256}(\text{key}=\text{API\_KEY\_PEPPER}, \text{msg}=\text{secret})$$
- **Fast Indexed Lookup:** The database table `api_keys` indexes `key_prefix`. When a key is presented, the system queries by `key_prefix` and then executes a constant-time comparison (`hmac.compare_digest`) against the stored `key_hash`.
- **Lifecycle Guarantees:** Rejects keys if `revoked_at` is populated or if `expires_at` has passed.

### 3.5 Role-Based Access Control (RBAC) (5 Tests)
The RBAC implementation in [`permissions.py`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/app/authorization/permissions.py) and [`project_access.py`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/app/authorization/project_access.py) establishes:
- **Role Hierarchy:**
  $$\text{viewer}\ (10) \subset \text{operator}\ (20) \subset \text{admin}\ (30) \subset \text{owner}\ (40)$$
- **Scope Delegation:** API keys support granular scopes (`read`, `scan`, `validate`, `report`) or wildcard `admin`.
- **Anti-Enumeration Invariant:** Querying a project where the user is not a member raises [`ProjectAccessDeniedError`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/app/auth/exceptions.py#L38-L41), translated to `HTTP 404 Not Found` ("Project not found"). This prevents attackers from enumerating valid project UUIDs across the platform.

### 3.6 Row-Level Security Integration (3 Tests)
The integration bridge in [`dependencies.py`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/app/auth/dependencies.py) connects application-layer authorization to PostgreSQL Row-Level Security:
- **Dependency Flow:**
  $$\text{Principal Authenticated} \longrightarrow \text{Project Member Verified} \longrightarrow \text{Role Hierarchy Evaluated} \longrightarrow \text{Tenant Context Set}$$
- **Fail-Secure Boundary:** If an unauthorized user or a user with an insufficient role accesses the endpoint, execution aborts before `set_tenant_context()` is called.
- **Teardown Cleanup:** The dependency utilizes a Python generator with a `finally: clear_tenant_context(db)` block, guaranteeing that connections returned to the pool cannot retain residual tenant context.

### 3.7 End-to-End API Endpoints (2 Tests)
The endpoint integration tests in [`test_auth_endpoints.py`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/tests/security/auth/test_auth_endpoints.py) validate full HTTP ASGI requests:
- **Credential Redaction:** Registration responses serialize the [`User`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/app/db/models/identity.py#L18-L41) model into schemas that strictly exclude `password_hash`.
- **One-Time Secret Revelation:** API key creation returns `full_key` only in the `201 Created` payload. Subsequent `GET /api/v1/api-keys` queries omit the secret token, displaying only `key_prefix`, `name`, `scopes`, and timestamps.

---

## 4. Test Infrastructure Notes

To ensure high execution speed, deterministic assertions, and zero external dependency friction during test runs, the test suite utilizes several specialized testing utilities.

```
                    +---------------------------------------+
                    |           pytest Test Runner          |
                    +-------------------+-------------------+
                                        |
                 +----------------------+----------------------+
                 |                                             |
+----------------v-----------------+         +-----------------v-----------------+
|   AsyncClient / ASGI Transport   |         |      Synchronous Unit Tests       |
+----------------+-----------------+         +-----------------+-----------------+
                 |                                             |
+----------------v-----------------+                           |
|       StaticPool (SQLite)        |                           |
|  - check_same_thread=False       |                           |
|  - Shared in-memory DB           |                           |
+----------------+-----------------+                           |
                 |                                             |
                 +----------------------+----------------------+
                                        |
                 +----------------------+----------------------+
                 |                                             |
+----------------v-----------------+         +-----------------v-----------------+
|      SQLite ARRAY Adapters       |         |         FakeRedisClient           |
|  - conftest.py custom compilers  |         |  - In-memory key-value & sets     |
|  - JSON serialization for ARRAY  |         |  - FakeRedisPipeline mock         |
+----------------------------------+         +-----------------------------------+
```

### 4.1 In-Memory Redis Mock: `FakeRedisClient` & `FakeRedisPipeline`
Defined in [`test_sessions.py`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/tests/security/auth/test_sessions.py#L18-L113) and reused across [`test_auth_endpoints.py`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/tests/security/auth/test_auth_endpoints.py#L46-L56):
- **Command Simulation:** Implements key-value storage (`set`, `get`, `delete`), set operations (`sadd`, `srem`, `smembers`), TTL tracking (`expire`, `ttl`), and command queuing.
- **Pipeline Atomicity:** The [`FakeRedisPipeline`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/tests/security/auth/test_sessions.py#L18-L74) records calls and commits all operations synchronously upon `.execute()`, matching production Redis pipeline semantics.
- **Test Isolation:** Each test fixture instantiates an isolated `FakeRedisClient` instance, eliminating test pollution without requiring an active Redis network service.

### 4.2 SQLite Dialect Adapters for PostgreSQL Types (`conftest.py`)
Because production VulnOS utilizes PostgreSQL-specific types (`ARRAY`, `INET`, `INT4RANGE`, `INT8RANGE`, `JSONB`), running fast in-memory tests against SQLite requires dialect compilation adapters defined in [`backend/tests/conftest.py`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/tests/conftest.py):
- **`PG_ARRAY` / `BASE_ARRAY` Adaptation:**
  ```python
  def _array_bind_processor(self: Any, dialect: Any) -> Any:
      if dialect.name == "sqlite":
          return lambda val: json.dumps(val) if val is not None else None
      return _orig_array_bind(self, dialect)

  def _array_result_processor(self: Any, dialect: Any, coltype: Any) -> Any:
      if dialect.name == "sqlite":
          return lambda val: json.loads(val) if val is not None else None
      return _orig_array_result(self, dialect, coltype)
  ```
  This allows model fields such as [`APIKey.scopes`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/app/db/models/identity.py#L58) (`ARRAY(Text)`) to be stored as `TEXT` in SQLite and seamlessly converted to and from Python `list[str]` objects.
- **`AuditLog` SQLite Identity Hook:** SQLite does not natively support `Identity(always=True)` on composite primary keys. An event listener listening on `AuditLog.before_insert` dynamically assigns monotonic IDs during SQLite test runs.

### 4.3 `StaticPool` for Multi-Threaded Async HTTP Testing
In [`test_auth_endpoints.py`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/tests/security/auth/test_auth_endpoints.py#L21-L39):
- **Thread Safety:** When `AsyncClient` executes requests through `ASGITransport`, requests may run across different threads in the anyio/asyncio threadpool.
- **Single Connection Persistence:** Standard SQLite in-memory databases (`sqlite:///:memory:`) close and purge data when a connection drops. Configuring `poolclass=StaticPool` with `connect_args={"check_same_thread": False}` guarantees that all threads share the identical in-memory database connection, preserving schema DDL and committed test data throughout the request lifecycle.

---

## 5. Coverage Gaps & Hardening Recommendations

While Phase 2.4 achieves 100% test pass rate across 30 comprehensive security tests, the following areas represent recommendations for ongoing security hardening in subsequent phases:

### 5.1 Rate Limiting Saturation & Lockout Tests
- **Current State:** [`rate_limits.py`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/app/auth/rate_limits.py) implements Redis-backed sliding window rate limiters for login attempts (per IP and per email) and API key requests.
- **Observation:** Endpoint tests currently verify nominal authentication without repeatedly hitting thresholds to trigger `HTTP 429 Too Many Requests`.
- **Recommendation:** Implement a dedicated test suite (`test_rate_limits.py`) asserting:
  1. Login failure rate limiting triggering temporary account lockouts after 5 failed attempts within 15 minutes.
  2. IP-based global rate limiting rejecting credential-stuffing sweeps.
  3. Proper serialization of standard rate-limiting HTTP headers (`Retry-After`, `X-RateLimit-Limit`, `X-RateLimit-Remaining`).

### 5.2 Explicit Cookie CSRF State-Changing Endpoint Tests
- **Current State:** [`get_current_principal`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/app/auth/dependencies.py#L49-L123) enforces CSRF verification (`X-CSRF-Token` header matching `session_data.csrf_token`) on all cookie-authenticated requests with mutating HTTP verbs (`POST`, `PUT`, `PATCH`, `DELETE`).
- **Observation:** `test_auth_endpoints.py` exercises E2E authentication primarily via Bearer tokens (JWT and API keys).
- **Recommendation:** Add an explicit test case invoking a mutating endpoint with an active session cookie:
  1. Assert `HTTP 403 Forbidden` ("CSRF token validation failed") when the `X-CSRF-Token` header is omitted or mismatched.
  2. Assert `HTTP 200/204` when the valid `X-CSRF-Token` header is supplied.

### 5.3 High-Concurrency Token Rotation Race Conditions
- **Current State:** Refresh token rotation verifies that reusing a rotated token revokes the token family.
- **Observation:** When multiple client requests (e.g. concurrent browser tabs opening simultaneously on page load) attempt to rotate the same refresh token concurrently, network race conditions can occur.
- **Recommendation:** In Phase 3, migrate the multi-step Redis rotation pipeline into an atomic **Redis Lua script**. Add a concurrency test using `asyncio.gather` with 20 parallel rotation requests to confirm exactly one request succeeds while all others trigger replay revocation or are safely queued.

### 5.4 End-to-End Project-Scoped Resource Endpoints
- **Current State:** Project-level RBAC and RLS context binding are validated in isolation via [`test_rbac.py`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/tests/security/auth/test_rbac.py) and [`test_rls_auth_integration.py`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/tests/security/auth/test_rls_auth_integration.py).
- **Observation:** Business domain endpoints (such as `GET /api/v1/projects/{project_id}/targets` or `POST /api/v1/projects/{project_id}/scans`) will be fully implemented in Phase 3.
- **Recommendation:** Integrate the Phase 2.4 `require_project_context` dependency across all Phase 3 project-scoped routers and implement cross-tenant HTTP integration tests asserting that Tenant B receives `404 Not Found` when querying Tenant A's project resources.

### 5.5 Federated Identity (OIDC / SSO) Flow
- **Current State:** The [`User`](file:///C:/Users/varsh/.gemini/antigravity/scratch/vulnos/backend/app/db/models/identity.py#L18-L41) model supports `auth_provider IN ('local', 'oidc')` and allows `password_hash = None`.
- **Observation:** Only the `local` password and API key providers are tested in Phase 2.4.
- **Recommendation:** When enterprise OIDC/SSO (e.g. Okta, Keycloak, Google Workspace) is activated, develop test suites validating OpenID Connect discovery, ID token signature verification with JWKS rotation, and account linking.
