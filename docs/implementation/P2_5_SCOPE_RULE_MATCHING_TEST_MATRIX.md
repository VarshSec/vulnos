# VulnOS Phase 2.5.5 — Scope Rule Matching Security Test Matrix

## 1. Overview

Phase 2.5.5 establishes the deterministic, fail-closed scope rule matching engine for VulnOS. The test suite is located at:

`backend/tests/security/scope/test_rule_matching.py` (30 tests)

**Total Platform Test Suite:** **399 passed, 0 failures in 15.79s.**  
**Backend Line Coverage:** **90% across 3,181 statements.**

---

## 2. Comprehensive Test Matrix

| Test Name | Category | What It Validates | Security Invariant Enforced |
| :--- | :--- | :--- | :--- |
| `test_no_rules_returns_default_deny` | Precedence | Empty rule set evaluates to deny | Default-deny posture |
| `test_one_matching_allow` | Matching | Single matching allow rule returns allow | Scope permission |
| `test_one_matching_deny` | Matching | Single matching deny rule returns deny | Explicit exclusion |
| `test_allow_plus_deny_returns_deny` | Precedence | Matching deny overrides matching allow | Global deny precedence |
| `test_deny_wins_regardless_of_specificity` | Precedence | Broad deny overrides specific allow | Specificity cannot bypass deny |
| `test_deny_wins_regardless_of_priority` | Precedence | Priority 999999 allow overridden by priority 1 deny | Priority cannot bypass deny |
| `test_multiple_matching_allows_deterministic_selection` | Determinism | Representative allow selected by priority DESC, ID ASC | Deterministic decision attribution |
| `test_multiple_matching_denies_deterministic_selection` | Determinism | Representative deny selected by priority DESC, ID ASC | Deterministic decision attribution |
| `test_unsupported_rule_type_fails_closed` | Robustness | Unknown/unsupported match_type is safely ignored | Fail-closed on corrupted rule |
| `test_malformed_destination_fails_closed` | Robustness | Control chars or invalid ports return `invalid_target` | Input validation enforcement |
| `test_exact_url_matching` | URL Match | Exact canonical URL matching (scheme, host, port, path, query) | Path prefix is not an exact match |
| `test_exact_url_embedded_credentials_rejected` | URL Security | Embedded credentials (`user:pass@`) rejected | Credential disclosure prevention |
| `test_exact_url_dot_segment_traversal_resolution` | URL Security | RFC 3986 dot-segments (`/api/../secret`) resolved | Traversal evasion prevention |
| `test_url_prefix_matching_and_path_boundaries` | URL Match | Path prefix matches sub-paths; rejects boundary escapes | `/api` does not match `/apiv2` |
| `test_url_prefix_root_path` | URL Match | Root `/` prefix matches all paths on host | Hierarchical boundary match |
| `test_exact_host_matching` | Host Match | Exact host matches identical; rejects subdomains/apex | No implicit host expansion |
| `test_domain_suffix_matching` | Domain Match | Matches apex and subdomains; rejects lookalikes | Rejects `evilexample.com` |
| `test_wildcard_domain_matching_rejects_apex` | Domain Security | Wildcard matches subdomains; strictly rejects apex | `*.example.com != example.com` |
| `test_idna_domain_normalization_matching` | IDNA | Unicode IDNA matches Punycode equivalent | Homograph attack prevention |
| `test_ipv4_exact_match` | IP Match | Exact IPv4 address matching | IP boundary precision |
| `test_ipv6_exact_match` | IP Match | Exact IPv6 matching across RFC 5952 compression | Canonical IPv6 comparison |
| `test_ipv4_mapped_ipv6_matching` | IP Security | `::ffff:x.x.x.x` unpacked to IPv4 | IPv6 encapsulation evasion defense |
| `test_cidr_matching_boundaries` | CIDR Match | Subnet containment and boundary address testing | Accurate subnet boundaries |
| `test_ipv6_cidr_matching` | CIDR Match | IPv6 CIDR subnet containment | Subnet containment |
| `test_invalid_cidr_host_bits_fails_closed` | CIDR Security | Non-zero host bits in strict CIDR fails closed | Malformed rule fail-closed |
| `test_port_constraints` | Constraints | Port ranges, discrete lists, and missing ports | Port smuggling defense |
| `test_protocol_constraints` | Constraints | Protocol matching and missing protocol behavior | Protocol boundary defense |
| `test_determinism_under_shuffled_rule_order` | Determinism | Rule list shuffling yields identical result & representative | Row-order independence |
| `test_matching_with_orm_scope_rule_instances` | ORM Integration | Transparent operation on SQLAlchemy `ScopeRule` models | ORM model compatibility |
| `test_rules_are_not_mutated_during_matching` | Immutability | Rule instances are untouched during evaluation | Immutability preservation |

---

## 3. Test Execution Verification

```bash
uv run pytest backend/tests/security/scope/test_rule_matching.py -v
# 30 passed in 0.45s

uv run pytest -v --cov=backend/app --cov-report=term-missing
# 399 passed in 15.79s
# Total coverage: 90%
```
