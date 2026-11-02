# VulnOS Phase 2.5.5 — Scope Rule Matching Engine Design

## 1. Architectural Purpose & Security Boundaries

The **Scope Rule Matching Engine** (`backend/app/scope/matching.py`) performs in-memory, deterministic policy evaluation of target destinations against active scope rules in VulnOS.

### 1.1 Critical Architectural Invariants

1. **Non-Authorization Invariant:**
   > **A matching allow rule is NOT permission to initiate a network operation.**
   
   Scope rule matching is one mandatory component of the overall authorization evaluation pipeline. Final network dispatch requires:
   - A valid, active, non-expired, non-revoked `AuthorizationRecord` (P2.5.4).
   - An active, immutable `ScopeVersion` with matching content hash (P2.5.6).
   - At least one matching `allow` rule.
   - **Zero** matching `deny` rules.
   - Conformance with operational limits (action allowlist, destructive testing flag, private range policy).

2. **Global Deny Overrides Allow Invariant:**
   > **Any matching `deny` rule overrides every matching `allow` rule, regardless of priority or specificity.**
   
   Unlike discretionary firewall rules where a more specific allow might override a broad deny, VulnOS enforces strict, uncompromised deny precedence across all match types. If an asset matches an allow rule for `domain_suffix: example.com` but also matches a deny rule for `exact_host: admin.example.com`, the evaluation outcome is **DENY** (`explicit_deny`).

3. **No Network Side-Effects:**
   The matching engine is a pure, side-effect-free function. It never triggers DNS resolution, HTTP requests, ping probes, or autonomous agent execution.

---

## 2. Multi-Tenant Isolation & Version Boundary

```
[ Active Scan / Policy Request ]
               │
               ▼
   [ Pinned ScopeVersion ] (status = 'active')
               │
               ▼
      [ ScopeRule Set ] (Belonging exclusively to this ScopeVersion)
               │
               ▼
[ match_scope_rules(rules, destination, protocol, port) ]
               │
               ├── 1. Canonicalize destination via normalization.py
               ├── 2. Evaluate all rules against destination
               ├── 3. Filter by port & protocol restrictions
               └── 4. Apply Global Deny Precedence
```

- **Tenant Isolation:** `ScopeRule` records are tied to a `ScopeVersion`, which is tied to a `Project`. Rules from multiple versions or projects must never be mixed.
- **Immutability:** Rule records are never mutated during matching.
- **Draft Exclusion:** In-flight scanning and live authorization only evaluate against versions in `status = 'active'`.

---

## 3. Supported Match Types & Evaluation Algorithms

The engine supports seven canonical match types defined in `DATABASE_DESIGN.md` §4.4:

| Match Type | Target Subject | Evaluation Logic | Path / Label Boundaries |
| :--- | :--- | :--- | :--- |
| `exact_url` | URL | Full canonical URL match (`scheme://host:port/path?query`) | Path prefix does not match. Fragments stripped. Query sorted. |
| `url_prefix` | URL | Common scheme, host, port, and hierarchical path prefix | Strictly enforces `/` segment boundaries. `/api` does NOT match `/apiv2`. |
| `exact_host` | Host / IP / URL | Canonical hostname or IP address | Exact match only. Subdomains and apex do NOT match. |
| `domain_suffix` | Domain / URL | Apex domain and all subdomains | Enforces DNS label boundaries (`target == rule` OR `target.endswith("." + rule)`). Rejects `notexample.com`. |
| `wildcard_domain` | Subdomains | Subdomains of domain (`*.example.com`) | Matches `api.example.com`. **Strictly rejects apex `example.com`**. |
| `ip` | IP Address / URL | Exact IPv4 or IPv6 address | Unpacks IPv4-mapped IPv6 (`::ffff:x.x.x.x` → `x.x.x.x`). |
| `cidr` | IP Address / URL | Subnet containment (`dest_ip in rule_net`) | Strict CIDR validation (host bits must be 0). |

---

## 4. URL Path-Boundary Semantics

To prevent prefix-bypass vulnerabilities (such as `/api` inadvertently allowing access to `/apiv2` or `/api-docs`):

```python
if rule_path == "/":
    path_matched = True
elif rule_path.endswith("/"):
    path_matched = dest_path.startswith(rule_path) or dest_path == rule_path.rstrip("/")
else:
    path_matched = dest_path == rule_path or dest_path.startswith(rule_path + "/")
```

Dot-segments (`/api/../secret`) are canonicalized via RFC 3986 §5.2.4 prior to path comparison.

---

## 5. Port and Protocol Constraints

A `ScopeRule` may specify optional `ports` and `protocols` constraints:

1. **Port Restriction (`ports`):**
   - Stored as `INT4RANGE` in PostgreSQL.
   - Evaluated against `effective_port` (explicitly passed or inferred from URL scheme/netloc).
   - `NULL` = unrestricted (all ports 1–65535 permitted).
   - If destination has no port and rule restricts ports, the rule **does not match**.
2. **Protocol Restriction (`protocols`):**
   - Stored as `ARRAY(Text)` containing values from `{"http", "https", "tcp", "udp"}`.
   - Evaluated against `effective_protocol` (explicitly passed or inferred from URL scheme).
   - `NULL` = unrestricted (all protocols permitted).
   - If destination has no protocol and rule restricts protocols, the rule **does not match**.

---

## 6. Precedence, Determinism & Representative Selection

### Precedence Matrix

| Matched Rules Set | Decision (`effect`) | `matched` | Reason Code |
| :--- | :--- | :--- | :--- |
| **No rules match** | `deny` | `False` | `default_deny` |
| **Only `allow` rules match** | `allow` | `True` | `allowed_rule` |
| **Only `deny` rules match** | `deny` | `True` | `explicit_deny` |
| **Both `allow` and `deny` match** | `deny` | `True` | `explicit_deny` |

### Deterministic Representative Rule Selection
When multiple rules of the winning effect match, the engine selects a single representative rule for audit logging:
1. Sort matching rules by `priority DESC` (higher priority wins).
2. If priorities are equal, break ties deterministically by `id ASC` (lexicographical string UUID order).
3. Populate `matched_rule_id` and `match_type` from the winning representative.
4. *Invariance Guarantee:* Representative selection is purely diagnostic; it **never alters the decision effect**.

---

## 7. Known Limitations & Non-Goals

1. **No DNS Resolution:**
   The engine evaluates hostnames against domain/host rules and IPs against IP/CIDR rules. It does not resolve hostnames to IPs during matching. DNS verification and pinned IP comparison are handled separately in the egress proxy layer (P2.5.6 / Phase 3).
2. **No Scope Version Mutation:**
   P2.5.5 operates strictly on already-selected rule sets. It does not create, activate, or publish scope versions.
