# VulnOS Phase 2.5.5 — Scope Rule Matching Engine Audit

**Date:** 2026-11-02  
**Milestone:** P2.5.5.1 — Repository Audit and Rule Schema Review  
**Status:** Audit Complete — No Architectural Inconsistencies Blocking Implementation  

---

## 1. Executive Summary

Milestone **P2.5.5** implements the **Deterministic Scope Rule Matching Engine** for VulnOS. The engine evaluates normalized destination subjects (URLs, hostnames, IP addresses) against a set of `ScopeRule` records belonging to a specific, pre-selected `ScopeVersion`.

### Critical Invariants

1. **Non-Authorization Boundary:**
   > **A matching allow rule is NOT permission to execute a network operation.**
   Final authorization requires the confluence of:
   - A valid, active, non-expired, non-revoked `AuthorizationRecord`.
   - An active, immutable `ScopeVersion` with matching content hash.
   - At least one matching `allow` rule.
   - **Zero** matching `deny` rules.
   - Strict operation restrictions (action allowlist, destructive flag, private range flag).
2. **Deny Always Overrides Allow:**
   > **Any matching `deny` rule overrides every matching `allow` rule, regardless of priority or specificity.**
   There is no concept of a "specific allow overriding a general deny".
3. **No Network Side-Effects:**
   Scope rule matching is a pure, in-memory, deterministic computation. It never performs DNS lookups, HTTP requests, socket connections, or autonomous agent execution.

---

## 2. Actual `ScopeRule` Schema Analysis

The canonical definition of `ScopeRule` is maintained in `backend/app/db/models/identity.py`:

```python
class ScopeRule(Base):
    """Allow or deny scope policy rule within a scope version."""

    __tablename__ = "scope_rules"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid7)
    scope_version_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scope_versions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    effect: Mapped[str] = mapped_column(Text, nullable=False)
    match_type: Mapped[str] = mapped_column(Text, nullable=False)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    ports: Mapped[Any | None] = mapped_column(INT4RANGE, nullable=True)
    protocols: Mapped[list[str] | None] = mapped_column(ARRAY(Text), nullable=True)
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=100)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )

    __table_args__ = (
        CheckConstraint("effect IN ('allow', 'deny')", name="ck_scope_rules_effect"),
        CheckConstraint(
            "match_type IN ('exact_url', 'url_prefix', 'exact_host', 'domain_suffix', "
            "'wildcard_domain', 'ip', 'cidr')",
            name="ck_scope_rules_match_type",
        ),
        Index("ix_scope_rules_version_effect", "scope_version_id", "effect"),
    )
```

### 2.1 Field Semantics & Types

| Field | SQLAlchemy Type | PostgreSQL DDL | Constraints & Invariants |
| :--- | :--- | :--- | :--- |
| `id` | `UUID(as_uuid=True)` | `uuid` | Primary Key, default UUIDv7. |
| `scope_version_id` | `UUID(as_uuid=True)` | `uuid` | Foreign Key → `scope_versions(id)` `ON DELETE CASCADE`. Indexed. |
| `effect` | `Text` | `text` | Check constraint: `IN ('allow', 'deny')`. |
| `match_type` | `Text` | `text` | Check constraint: `IN ('exact_url', 'url_prefix', 'exact_host', 'domain_suffix', 'wildcard_domain', 'ip', 'cidr')`. |
| `value` | `Text` | `text` | Canonical normalized representation of the rule pattern. |
| `ports` | `INT4RANGE` | `int4range` | Nullable. `NULL` indicates all ports (unrestricted). Range `[lower, upper)` defines allowed port bounds. |
| `protocols` | `ARRAY(Text)` | `text[]` | Nullable. `NULL` indicates all protocols. Allowed items: `{'http', 'https', 'tcp', 'udp'}`. |
| `priority` | `Integer` | `integer` | Default 100. Higher integer denotes higher administrative preference within the same effect. |
| `note` | `Text` | `text` | Optional description or engagement justification. |
| `created_at` | `DateTime(timezone=True)` | `timestamptz` | Immutable timestamp (UTC). |

### 2.2 Migration Reconciliation Note
In `backend/alembic/versions/0001_phase2_baseline.py` (lines 245–270), `scope_rules` was initially drafted with prototype columns (`asset_type`, `pattern`, `conditions`). Consistent with the reconciliation performed for `authorization_records` in `0003`, the authoritative runtime model is defined in `identity.py` and `DATABASE_DESIGN.md` §4.4.

---

## 3. Supported Match Types & Evaluation Semantics

The engine supports seven explicit match types:

### 3.1 `exact_url`
- **Definition:** Matches a single, fully-qualified canonical URL.
- **Semantics:** Requires exact matching of scheme, host, port, path, and sorted query parameters.
- **Normalization Invariant:**
  - Default ports stripped (`http://example.com:80/` → `http://example.com/`).
  - Dot-segments removed via RFC 3986 5.2.4.
  - Query parameters sorted alphabetically (`?b=2&a=1` → `?a=1&b=2`).
  - Fragments (`#section`) stripped before evaluation.
- **Security Check:** A path prefix is never an exact URL match (`https://example.com/api` does NOT match `https://example.com/api/v1`).

### 3.2 `url_prefix`
- **Definition:** Matches URLs sharing a common scheme, host, port, and hierarchical path prefix.
- **Path-Boundary Enforcement:** Path boundaries must be strictly observed.
  - Rule: `https://example.com/api` or `https://example.com/api/`
  - Matches: `https://example.com/api/v1/users`, `https://example.com/api`
  - Rejects: `https://example.com/apiv2`, `https://example.com/api-docs`
- **Security Check:** Dot-segments (`/api/../admin`) must be canonicalized before matching to prevent traversal escapes.

### 3.3 `exact_host`
- **Definition:** Matches an exact hostname or IP address without subdomains or path components.
- **Semantics:**
  - `example.com` matches `example.com` ONLY.
  - Does NOT match `api.example.com`, `admin.example.com`, or `notexample.com`.

### 3.4 `domain_suffix`
- **Definition:** Matches an apex domain and all its hierarchical subdomains.
- **DNS Label Boundary Enforcement:**
  - Rule: `example.com`
  - Matches: `example.com`, `api.example.com`, `deep.sub.api.example.com`.
  - Rejects: `notexample.com`, `evilexample.com`, `attacker-example.com`.
- **Lookalike Defense:** Uses strict dot-separated label matching (`target == rule` OR `target.endswith("." + rule)`).

### 3.5 `wildcard_domain`
- **Definition:** Matches subdomains of a specified domain, excluding the apex domain.
- **Wildcard Syntax:** `*.example.com`
  - Matches: `api.example.com`, `auth.corp.example.com`.
  - **Rejects Apex:** `example.com` is strictly NOT matched.
  - Rejects Lookalikes: `evil-example.com` is strictly NOT matched.

### 3.6 `ip`
- **Definition:** Matches an exact IPv4 or IPv6 network address.
- **Canonicalization:**
  - IPv4: 4-octet dotted decimal.
  - IPv6: RFC 5952 compressed lowercase.
  - IPv4-mapped IPv6 (`::ffff:192.0.2.1`) unpacked to IPv4 (`192.0.2.1`).

### 3.7 `cidr`
- **Definition:** Matches any IP address within an IPv4 or IPv6 network range.
- **Strict Network Invariant:**
  - `ipaddress.ip_network(rule.value, strict=True)` enforces that host bits are zero (`192.168.1.0/24` valid; `192.168.1.5/24` rejected).
- **Subnet Containment:** Evaluated using Python `ip_obj in network_obj`.

---

## 4. Port and Protocol Constraints

A `ScopeRule` may optionally restrict ports and protocols:

```
[ Rule Matches Destination Host/URL/IP? ]
                  │ YES
                  ▼
         [ ports IS NULL? ]
          ├── YES ─► Unrestricted: any port matches (1-65535)
          └── NO  ─► Does destination port fall within rule.ports range?
                      ├── YES ─► Port Matched
                      └── NO  ─► RULE DOES NOT MATCH
                  │
                  ▼
       [ protocols IS NULL? ]
          ├── YES ─► Unrestricted: any protocol matches
          └── NO  ─► Is destination protocol in rule.protocols array?
                      ├── YES ─► Protocol Matched
                      └── NO  ─► RULE DOES NOT MATCH
                  │
                  ▼
            RULE MATCHED!
```

### Port Representation
- PostgreSQL `INT4RANGE` maps to Python range or tuple `[lower, upper)`.
- If a destination has no port specified:
  - If URL: default scheme port is implied (HTTP=80, HTTPS=443).
  - If Host/IP without port context: unrestricted rules match; rules with port constraints do NOT match.

### Protocol Representation
- PostgreSQL `ARRAY(Text)` containing values from `{"http", "https", "tcp", "udp"}`.
- Casing is normalized to lowercase before comparison.

---

## 5. Allow and Deny Precedence & Decision Logic

The matching engine enforces deterministic, fail-closed precedence:

| Matched Rules Set | Final Decision (`effect`) | `matched` | Explanation |
| :--- | :--- | :--- | :--- |
| **No rules match** | `deny` | `False` | Default-deny posture. |
| **Only `allow` rules match** | `allow` | `True` | Permitted by active scope. |
| **Only `deny` rules match** | `deny` | `True` | Explicitly forbidden. |
| **Both `allow` and `deny` match** | `deny` | `True` | **Deny overrides allow globally.** |

### Deterministic Representative Rule Selection
When multiple rules of the winning effect match, the engine selects a deterministic representative rule for audit logging:
1. Sort matching rules by `priority DESC` (higher priority wins).
2. If priorities are equal, break tie by `id ASC` (lexicographical UUID order).
3. The selected rule ID is populated in `matched_rule_id`.
4. *Critical guarantee:* Rule selection affects only diagnostics and attribution; it **never changes the decision outcome**.

---

## 6. Multi-Tenant Isolation

1. **Indirect Project Association:**
   `ScopeRule` does not have a direct `project_id` column. It belongs to `ScopeVersion`, which belongs to `Project`.
2. **RLS Policy:**
   ```sql
   CREATE POLICY scope_rules_project_isolation ON scope_rules
       FOR ALL
       USING (scope_version_id IN (
           SELECT id FROM scope_versions WHERE project_id = current_project_id()
       ));
   ```
3. **Application Guard:**
   The matching engine requires the caller to provide either a verified `ScopeVersion` object or a set of rules already filtered by `scope_version_id`. Rules from multiple versions or projects must never be co-evaluated.

---

## 7. Identified Attack Vectors & Defensive Mitigations

| Attack Vector | Vulnerability Description | Engine Mitigation |
| :--- | :--- | :--- |
| **Domain Suffix Confusion** | Attacker registers `evilexample.com` to match `example.com`. | Strict DNS label boundary check: `sub.endswith("." + domain)`. |
| **Wildcard Apex Hijack** | Attacker targets root `example.com` under `*.example.com`. | Wildcard explicitly rejects apex: requires at least one dot before domain. |
| **Path Traversal Bypass** | Target `https://example.com/api/../admin` bypasses `/admin` deny rule. | Canonicalization via `remove_dot_segments` before rule matching. |
| **URL Prefix Boundary Escape** | Rule `/api` matches `/apiv2/secret`. | Path boundary enforcement: prefix must terminate with `/` or exact string match. |
| **Priority Inversion** | Operator sets `allow` rule priority 9999 to override `deny` rule priority 10. | Global deny precedence: deny rules are evaluated with absolute priority over allows. |
| **Port Smuggling** | Request specifies port 8080 against a rule restricted to ports 80/443. | Strict range boundary check against `ports` range. |
| **IPv4-Mapped IPv6 Evasion** | Attacker probes `::ffff:127.0.0.1` or `::ffff:169.254.169.254` to evade IPv4 deny rule. | IP unpacked to IPv4 before CIDR and exact IP evaluation. |
| **Row Order Non-Determinism** | Different database query order causes fluctuating decision reasons. | In-memory sorting by priority, rule ID, and effect. |

---

## 8. Milestone P2.5.5 Implementation Plan

- **P2.5.5.1 (Current):** Repository audit and rule schema review (`docs/implementation/P2_5_SCOPE_RULE_MATCHING_AUDIT.md`).
- **P2.5.5.2:** Matching input and result contracts (`ScopeMatchInput`, `ScopeMatchResult`, `ScopeRuleMatchCode`).
- **P2.5.5.3:** URL exact and path-prefix matching logic.
- **P2.5.5.4:** Hostname, domain suffix, and wildcard matching logic.
- **P2.5.5.5:** IP address and CIDR subnet matching logic.
- **P2.5.5.6:** Port range and protocol constraints filtering.
- **P2.5.5.7:** Global deny precedence engine and deterministic representative selection (`match_scope_rules`).
- **P2.5.5.8:** Adversarial security test matrix (`backend/tests/security/scope/test_rule_matching.py`).
- **P2.5.5.9:** Architecture documentation (`P2_5_SCOPE_RULE_MATCHING_DESIGN.md`, `P2_5_SCOPE_RULE_MATCHING_TEST_MATRIX.md`) and quality gates.
