"""Security and adversarial tests for VulnOS Deterministic Scope Rule Matching (P2.5.5).

Validates:
- Fail-closed default-deny when no rules match.
- Absolute precedence: Deny overrides allow regardless of specificity or priority.
- Deterministic representative selection tie-broken by priority DESC then ID ASC.
- Exact URL matching, scheme/port/query strictness, and credential rejection.
- URL prefix path-boundary enforcement (prevents /api matching /apiv2).
- Exact host matching and subdomain non-match.
- Domain suffix label-boundary enforcement (rejects evilexample.com).
- Wildcard domain subdomain matching and strict apex rejection (*.example.com != example.com).
- IPv4, IPv6, and strict CIDR subnet matching.
- IPv4-mapped IPv6 address unpacking (::ffff:192.168.1.1).
- Port range bounds, discrete lists, and protocol filtering.
- Immutability of rule instances during evaluation.
"""

from __future__ import annotations

import random
from uuid import UUID

from backend.app.db.models.identity import ScopeRule
from backend.app.db.types import uuid7
from backend.app.scope.matching import match_scope_rules
from backend.app.scope.schemas import (
    ScopeMatchReasonCode,
    ScopeRuleData,
)


def _make_rule(
    effect: str,
    match_type: str,
    value: str,
    priority: int = 100,
    ports: object = None,
    protocols: list[str] | None = None,
    rule_id: UUID | None = None,
) -> ScopeRuleData:
    """Helper to create a ScopeRuleData instance."""
    return ScopeRuleData(
        id=rule_id or uuid7(),
        effect=effect,  # type: ignore[arg-type]
        match_type=match_type,  # type: ignore[arg-type]
        value=value,
        priority=priority,
        ports=ports,
        protocols=protocols,
    )


# -----------------------------------------------------------------------------
# 1. General Matching & Precedence Tests
# -----------------------------------------------------------------------------


def test_no_rules_returns_default_deny() -> None:
    """Empty rule list deterministically evaluates to default deny."""
    result = match_scope_rules(rules=[], destination="https://example.com/api")
    assert result.matched is False
    assert result.effect == "deny"
    assert result.reason_code == ScopeMatchReasonCode.DEFAULT_DENY
    assert result.matched_rule_id is None
    assert result.evaluated_rule_count == 0


def test_one_matching_allow() -> None:
    """Single matching allow rule returns allowed_rule."""
    rule = _make_rule("allow", "exact_host", "example.com")
    result = match_scope_rules(rules=[rule], destination="example.com")
    assert result.matched is True
    assert result.effect == "allow"
    assert result.reason_code == ScopeMatchReasonCode.ALLOWED_RULE
    assert result.matched_rule_id == rule.id
    assert result.evaluated_rule_count == 1


def test_one_matching_deny() -> None:
    """Single matching deny rule returns explicit_deny."""
    rule = _make_rule("deny", "exact_host", "internal.corp")
    result = match_scope_rules(rules=[rule], destination="internal.corp")
    assert result.matched is True
    assert result.effect == "deny"
    assert result.reason_code == ScopeMatchReasonCode.EXPLICIT_DENY
    assert result.matched_rule_id == rule.id


def test_allow_plus_deny_returns_deny() -> None:
    """When both allow and deny rules match, deny strictly wins."""
    rule_allow = _make_rule("allow", "domain_suffix", "example.com", priority=100)
    rule_deny = _make_rule("deny", "exact_host", "admin.example.com", priority=100)

    result = match_scope_rules(
        rules=[rule_allow, rule_deny],
        destination="admin.example.com",
    )
    assert result.matched is True
    assert result.effect == "deny"
    assert result.reason_code == ScopeMatchReasonCode.EXPLICIT_DENY
    assert result.matched_rule_id == rule_deny.id


def test_deny_wins_regardless_of_specificity() -> None:
    """Broad deny rule overrides specific allow rule."""
    rule_allow = _make_rule("allow", "exact_url", "https://api.example.com/v1/health")
    rule_deny = _make_rule("deny", "domain_suffix", "example.com")

    result = match_scope_rules(
        rules=[rule_allow, rule_deny],
        destination="https://api.example.com/v1/health",
    )
    assert result.matched is True
    assert result.effect == "deny"
    assert result.reason_code == ScopeMatchReasonCode.EXPLICIT_DENY
    assert result.matched_rule_id == rule_deny.id


def test_deny_wins_regardless_of_priority() -> None:
    """Allow rule with maximum priority cannot override low-priority deny rule."""
    rule_allow = _make_rule("allow", "exact_host", "example.com", priority=999999)
    rule_deny = _make_rule("deny", "domain_suffix", "example.com", priority=1)

    result = match_scope_rules(
        rules=[rule_allow, rule_deny],
        destination="example.com",
    )
    assert result.matched is True
    assert result.effect == "deny"
    assert result.reason_code == ScopeMatchReasonCode.EXPLICIT_DENY
    assert result.matched_rule_id == rule_deny.id


def test_multiple_matching_allows_deterministic_selection() -> None:
    """Highest priority allow rule is selected as representative; ties broken by ID ASC."""
    id_low = UUID("00000000-0000-0000-0000-000000000001")
    id_high = UUID("00000000-0000-0000-0000-000000000002")

    rule_p10 = _make_rule("allow", "domain_suffix", "example.com", priority=10)
    rule_p50 = _make_rule("allow", "exact_host", "api.example.com", priority=50)

    res = match_scope_rules(rules=[rule_p10, rule_p50], destination="api.example.com")
    assert res.matched is True
    assert res.effect == "allow"
    assert res.matched_rule_id == rule_p50.id  # Priority 50 > 10

    # Tie-breaking by ID
    rule_tie_1 = _make_rule("allow", "exact_host", "api.example.com", priority=100, rule_id=id_low)
    rule_tie_2 = _make_rule("allow", "domain_suffix", "example.com", priority=100, rule_id=id_high)

    res_tie = match_scope_rules(rules=[rule_tie_2, rule_tie_1], destination="api.example.com")
    assert res_tie.matched_rule_id == id_low


def test_multiple_matching_denies_deterministic_selection() -> None:
    """Highest priority deny rule is selected as representative; ties broken by ID ASC."""
    rule_deny_10 = _make_rule("deny", "domain_suffix", "example.com", priority=10)
    rule_deny_50 = _make_rule("deny", "exact_host", "api.example.com", priority=50)

    res = match_scope_rules(rules=[rule_deny_10, rule_deny_50], destination="api.example.com")
    assert res.matched is True
    assert res.effect == "deny"
    assert res.matched_rule_id == rule_deny_50.id


def test_unsupported_rule_type_fails_closed() -> None:
    """Rule with invalid/unknown match_type is safely ignored (fails closed)."""

    class BadRule:
        id = uuid7()
        effect = "allow"
        match_type = "unsupported_magic_regex"
        value = ".*example.*"
        priority = 100
        ports = None
        protocols = None

    res = match_scope_rules(rules=[BadRule()], destination="api.example.com")
    assert res.matched is False
    assert res.effect == "deny"
    assert res.reason_code == ScopeMatchReasonCode.DEFAULT_DENY


def test_malformed_destination_fails_closed() -> None:
    """Malformed destination returns INVALID_TARGET."""
    rule = _make_rule("allow", "exact_host", "example.com")

    # Control chars
    res_ctrl = match_scope_rules(rules=[rule], destination="example.com\x00")
    assert res_ctrl.matched is False
    assert res_ctrl.reason_code == ScopeMatchReasonCode.INVALID_TARGET

    # Empty string
    res_empty = match_scope_rules(rules=[rule], destination="   ")
    assert res_empty.matched is False
    assert res_empty.reason_code == ScopeMatchReasonCode.INVALID_TARGET

    # Invalid port
    res_port = match_scope_rules(rules=[rule], destination="example.com", port=70000)
    assert res_port.matched is False
    assert res_port.reason_code == ScopeMatchReasonCode.INVALID_TARGET


# -----------------------------------------------------------------------------
# 2. URL Matching Tests (exact_url, url_prefix)
# -----------------------------------------------------------------------------


def test_exact_url_matching() -> None:
    """exact_url matches identical canonical URL and rejects mismatches."""
    rule = _make_rule("allow", "exact_url", "https://example.com/api/v1?mode=full")

    # Exact match (query order independent)
    assert match_scope_rules([rule], "https://example.com/api/v1?mode=full").matched is True

    # Path prefix must NOT match exact_url
    assert match_scope_rules([rule], "https://example.com/api/v1/users?mode=full").matched is False

    # Path mismatch
    assert match_scope_rules([rule], "https://example.com/api/v2?mode=full").matched is False

    # Scheme mismatch
    assert match_scope_rules([rule], "http://example.com/api/v1?mode=full").matched is False

    # Port mismatch
    assert match_scope_rules([rule], "https://example.com:8443/api/v1?mode=full").matched is False

    # Default port omitted (80 for http, 443 for https) canonicalizes cleanly
    rule_def = _make_rule("allow", "exact_url", "https://example.com:443/test")
    assert match_scope_rules([rule_def], "https://example.com/test").matched is True

    # Fragments stripped
    assert match_scope_rules([rule_def], "https://example.com/test#fragment").matched is True


def test_exact_url_embedded_credentials_rejected() -> None:
    """URLs containing embedded credentials fail closed with INVALID_TARGET."""
    rule = _make_rule("allow", "exact_url", "https://example.com/api")
    res = match_scope_rules([rule], "https://user:password@example.com/api")
    assert res.matched is False
    assert res.reason_code == ScopeMatchReasonCode.INVALID_TARGET


def test_exact_url_dot_segment_traversal_resolution() -> None:
    """RFC 3986 dot segments are resolved before matching."""
    rule = _make_rule("allow", "exact_url", "https://example.com/secret")
    # /api/../secret resolves to /secret -> matches!
    assert match_scope_rules([rule], "https://example.com/api/../secret").matched is True


def test_url_prefix_matching_and_path_boundaries() -> None:
    """url_prefix strictly enforces path boundaries and prevents prefix escapes."""
    rule = _make_rule("allow", "url_prefix", "https://example.com/api")

    # Exact path matches
    assert match_scope_rules([rule], "https://example.com/api").matched is True
    assert match_scope_rules([rule], "https://example.com/api/").matched is True

    # Sub-path matches
    assert match_scope_rules([rule], "https://example.com/api/v1/users").matched is True

    # Boundary escape attempts MUST FAIL: /api must not match /apiv2 or /api-docs!
    assert match_scope_rules([rule], "https://example.com/apiv2").matched is False
    assert match_scope_rules([rule], "https://example.com/api-docs").matched is False
    assert match_scope_rules([rule], "https://example.com/api_internal").matched is False

    # Host/scheme mismatch
    assert match_scope_rules([rule], "http://example.com/api/v1").matched is False
    assert match_scope_rules([rule], "https://other.com/api/v1").matched is False


def test_url_prefix_root_path() -> None:
    """Root url_prefix matches all paths on that host."""
    rule = _make_rule("allow", "url_prefix", "https://example.com/")
    assert match_scope_rules([rule], "https://example.com/").matched is True
    assert match_scope_rules([rule], "https://example.com/anything/nested").matched is True


# -----------------------------------------------------------------------------
# 3. Host & Domain Matching Tests (exact_host, domain_suffix, wildcard_domain)
# -----------------------------------------------------------------------------


def test_exact_host_matching() -> None:
    """exact_host matches exact hostname and rejects subdomains and superdomains."""
    rule = _make_rule("allow", "exact_host", "api.example.com")

    # Exact hostname
    assert match_scope_rules([rule], "api.example.com").matched is True
    assert match_scope_rules([rule], "https://api.example.com/v1").matched is True

    # Case insensitive
    assert match_scope_rules([rule], "API.EXAMPLE.COM").matched is True

    # Subdomain of exact host does NOT match
    assert match_scope_rules([rule], "v1.api.example.com").matched is False

    # Apex domain does NOT match
    assert match_scope_rules([rule], "example.com").matched is False


def test_domain_suffix_matching() -> None:
    """domain_suffix matches apex and subdomains while preventing suffix confusion."""
    rule = _make_rule("allow", "domain_suffix", "example.com")

    # Apex matches
    assert match_scope_rules([rule], "example.com").matched is True
    assert match_scope_rules([rule], "https://example.com/test").matched is True

    # Subdomains match
    assert match_scope_rules([rule], "api.example.com").matched is True
    assert match_scope_rules([rule], "sub.api.example.com").matched is True

    # Suffix confusion attacks MUST BE REJECTED!
    assert match_scope_rules([rule], "notexample.com").matched is False
    assert match_scope_rules([rule], "evilexample.com").matched is False
    assert match_scope_rules([rule], "attacker-example.com").matched is False
    assert match_scope_rules([rule], "example.com.evil.test").matched is False


def test_wildcard_domain_matching_rejects_apex() -> None:
    """wildcard_domain (*.example.com) matches subdomains but STRICTLY REJECTS apex."""
    rule = _make_rule("allow", "wildcard_domain", "*.example.com")

    # Subdomains match
    assert match_scope_rules([rule], "api.example.com").matched is True
    assert match_scope_rules([rule], "sub.api.example.com").matched is True
    assert match_scope_rules([rule], "https://auth.example.com/login").matched is True

    # APEX MUST NOT MATCH (Architectural Invariant)
    assert match_scope_rules([rule], "example.com").matched is False
    assert match_scope_rules([rule], "https://example.com/").matched is False

    # Lookalikes rejected
    assert match_scope_rules([rule], "evil-example.com").matched is False


def test_idna_domain_normalization_matching() -> None:
    """Unicode IDNA domains match their Punycode equivalent."""
    rule = _make_rule("allow", "domain_suffix", "münchen.de")
    assert match_scope_rules([rule], "xn--mnchen-3ya.de").matched is True
    assert match_scope_rules([rule], "api.münchen.de").matched is True


# -----------------------------------------------------------------------------
# 4. IP & CIDR Matching Tests (ip, cidr)
# -----------------------------------------------------------------------------


def test_ipv4_exact_match() -> None:
    """ip match type matches exact IPv4 address."""
    rule = _make_rule("allow", "ip", "192.168.1.100")
    assert match_scope_rules([rule], "192.168.1.100").matched is True
    assert match_scope_rules([rule], "http://192.168.1.100:8080/").matched is True
    assert match_scope_rules([rule], "192.168.1.101").matched is False


def test_ipv6_exact_match() -> None:
    """ip match type matches exact IPv6 address across compression representations."""
    rule = _make_rule("allow", "ip", "2001:db8::1")
    assert match_scope_rules([rule], "2001:0db8:0000:0000:0000:0000:0000:0001").matched is True
    assert match_scope_rules([rule], "2001:db8::2").matched is False


def test_ipv4_mapped_ipv6_matching() -> None:
    """IPv4-mapped IPv6 address is unpacked and matches IPv4 rules."""
    rule_ip = _make_rule("allow", "ip", "192.0.2.1")
    assert match_scope_rules([rule_ip], "::ffff:192.0.2.1").matched is True

    rule_cidr = _make_rule("allow", "cidr", "192.0.2.0/24")
    assert match_scope_rules([rule_cidr], "::ffff:192.0.2.55").matched is True


def test_cidr_matching_boundaries() -> None:
    """cidr match type correctly tests subnet boundaries and rejects out-of-range IPs."""
    rule = _make_rule("allow", "cidr", "10.0.0.0/16")

    # Inside subnet
    assert match_scope_rules([rule], "10.0.0.1").matched is True
    assert match_scope_rules([rule], "10.0.255.254").matched is True
    assert match_scope_rules([rule], "http://10.0.50.1:80/").matched is True

    # Outside subnet
    assert match_scope_rules([rule], "10.1.0.1").matched is False
    assert match_scope_rules([rule], "192.168.1.1").matched is False


def test_ipv6_cidr_matching() -> None:
    """IPv6 CIDR subnet matching."""
    rule = _make_rule("allow", "cidr", "2001:db8:abcd::/48")
    assert match_scope_rules([rule], "2001:db8:abcd::1").matched is True
    assert match_scope_rules([rule], "2001:db8:ffff::1").matched is False


def test_invalid_cidr_host_bits_fails_closed() -> None:
    """Rule with non-zero host bits in strict CIDR fails closed."""
    rule_invalid = _make_rule("allow", "cidr", "192.168.1.5/24")  # Host bit 5 set!
    assert match_scope_rules([rule_invalid], "192.168.1.5").matched is False


# -----------------------------------------------------------------------------
# 5. Port and Protocol Constraints Tests
# -----------------------------------------------------------------------------


def test_port_constraints() -> None:
    """Port constraints restrict matching to specified ports or ranges."""
    # Discrete ports list: [80, 443]
    rule_ports = _make_rule("allow", "exact_host", "example.com", ports=[80, 443])

    # Port 443 matches
    assert match_scope_rules([rule_ports], "example.com", port=443).matched is True
    assert match_scope_rules([rule_ports], "https://example.com/").matched is True

    # Port 8080 does NOT match
    assert match_scope_rules([rule_ports], "example.com", port=8080).matched is False
    assert match_scope_rules([rule_ports], "https://example.com:8080/").matched is False

    # Destination without port against port-restricted rule does NOT match
    assert match_scope_rules([rule_ports], "example.com").matched is False

    # Port range: range(8000, 8010)
    rule_range = _make_rule("allow", "exact_host", "example.com", ports=range(8000, 8010))
    assert match_scope_rules([rule_range], "example.com", port=8005).matched is True
    assert match_scope_rules([rule_range], "example.com", port=8015).matched is False


def test_protocol_constraints() -> None:
    """Protocol constraints restrict matching to specified protocols."""
    rule = _make_rule("allow", "exact_host", "example.com", protocols=["https"])

    # HTTPS matches
    assert match_scope_rules([rule], "https://example.com/").matched is True
    assert match_scope_rules([rule], "example.com", protocol="https").matched is True

    # HTTP rejected
    assert match_scope_rules([rule], "http://example.com/").matched is False
    assert match_scope_rules([rule], "example.com", protocol="http").matched is False

    # Destination without protocol against protocol-restricted rule does NOT match
    assert match_scope_rules([rule], "example.com").matched is False


# -----------------------------------------------------------------------------
# 6. Determinism & ORM Compatibility Tests
# -----------------------------------------------------------------------------


def test_determinism_under_shuffled_rule_order() -> None:
    """Shuffled rules yield the exact same decision and representative rule."""
    id_deny_hi = UUID("00000000-0000-0000-0000-000000000010")
    id_deny_lo = UUID("00000000-0000-0000-0000-000000000011")

    rules = [
        _make_rule("allow", "exact_host", "api.example.com", priority=500),
        _make_rule("allow", "domain_suffix", "example.com", priority=200),
        _make_rule("deny", "domain_suffix", "example.com", priority=100, rule_id=id_deny_hi),
        _make_rule("deny", "exact_host", "api.example.com", priority=50, rule_id=id_deny_lo),
    ]

    # Baseline evaluation
    base_res = match_scope_rules(rules, "api.example.com")
    assert base_res.effect == "deny"
    assert base_res.matched_rule_id == id_deny_hi

    # Shuffled evaluations (5 iterations)
    for _ in range(5):
        shuffled = list(rules)
        random.shuffle(shuffled)
        res = match_scope_rules(shuffled, "api.example.com")
        assert res.effect == base_res.effect
        assert res.matched_rule_id == base_res.matched_rule_id
        assert res.reason_code == base_res.reason_code


def test_matching_with_orm_scope_rule_instances() -> None:
    """Matching engine operates transparently on SQLAlchemy ScopeRule ORM instances."""
    version_id = uuid7()
    rule_orm = ScopeRule(
        id=uuid7(),
        scope_version_id=version_id,
        effect="allow",
        match_type="domain_suffix",
        value="example.com",
        priority=100,
    )

    res = match_scope_rules([rule_orm], "https://sub.example.com/api")
    assert res.matched is True
    assert res.effect == "allow"
    assert res.matched_rule_id == rule_orm.id


def test_rules_are_not_mutated_during_matching() -> None:
    """Rule instances are not modified during matching."""
    rule = _make_rule("allow", "domain_suffix", "example.com", priority=100)
    original_dict = rule.model_dump()

    match_scope_rules([rule], "https://sub.example.com/api")
    assert rule.model_dump() == original_dict
