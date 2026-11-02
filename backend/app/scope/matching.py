"""Deterministic scope rule matching engine for VulnOS.

Provides pure, in-memory evaluation of destinations (URLs, hostnames, IPs)
against scope policy rules.

CRITICAL ARCHITECTURAL INVARIANTS:
1. Matching rules does NOT grant permission to execute network operations.
   Final authorization requires an active AuthorizationRecord, an active ScopeVersion,
   at least one matching allow rule, zero matching deny rules, and operation-specific gating.
2. Any matching deny rule overrides every matching allow rule, regardless of priority
   or specificity.
3. No network operations: this engine performs pure string and mathematical IP
   computations. No DNS resolution, HTTP requests, or socket connections are made.
"""

from __future__ import annotations

import ipaddress
import urllib.parse
from collections.abc import Sequence
from typing import Any
from uuid import UUID

from backend.app.scope.normalization import (
    TargetNormalizationError,
    normalize_domain,
    normalize_host,
    normalize_ip_or_cidr,
    normalize_url,
)
from backend.app.scope.schemas import (
    ScopeMatchReasonCode,
    ScopeMatchResult,
)


def _port_in_range(port: int | None, rule_ports: Any) -> bool:
    """Check if port satisfies rule port restriction.

    None rule_ports indicates unrestricted (all ports allowed).
    """
    if rule_ports is None:
        return True
    if port is None:
        # Rule specifies a port restriction, but destination has no port
        return False
    if port < 1 or port > 65535:
        return False

    if isinstance(rule_ports, range):
        return port in rule_ports

    if isinstance(rule_ports, set):
        return port in rule_ports

    if isinstance(rule_ports, (list, tuple)):
        # Check if list of discrete ports or 2-element interval [start, end]
        if (
            len(rule_ports) == 2
            and isinstance(rule_ports[0], int)
            and isinstance(rule_ports[1], int)
            and rule_ports[0] <= rule_ports[1]
        ):
            return rule_ports[0] <= port <= rule_ports[1]
        return port in rule_ports

    # Handle SQLAlchemy / psycopg Range objects (INT4RANGE)
    if hasattr(rule_ports, "lower") and hasattr(rule_ports, "upper"):
        if hasattr(rule_ports, "isempty") and rule_ports.isempty:
            return False
        lower = rule_ports.lower
        upper = rule_ports.upper
        lower_inc = getattr(rule_ports, "lower_inc", True)
        upper_inc = getattr(rule_ports, "upper_inc", False)

        lower_ok = True if lower is None else (port >= lower if lower_inc else port > lower)
        upper_ok = True if upper is None else (port <= upper if upper_inc else port < upper)
        return lower_ok and upper_ok

    return False


def _protocol_matches(rule_protocols: list[str] | None, protocol: str | None) -> bool:
    """Check if protocol satisfies rule protocol restriction.

    None or empty rule_protocols indicates unrestricted (all protocols allowed).
    """
    if not rule_protocols:
        return True
    if protocol is None:
        return False
    clean_proto = protocol.strip().lower()
    return clean_proto in [p.strip().lower() for p in rule_protocols]


def _match_exact_url(rule_value: str, dest_canonical: str | None) -> bool:
    """Evaluate exact_url match type."""
    if dest_canonical is None:
        return False
    try:
        rule_canonical, _, _, _, _ = normalize_url(rule_value)
        return dest_canonical == rule_canonical
    except (TargetNormalizationError, ValueError):
        return False


def _match_url_prefix(
    rule_value: str,
    dest_parts: tuple[str, str, int | None, str, str | None] | None,
) -> bool:
    """Evaluate url_prefix match type with safe path-boundary enforcement."""
    if dest_parts is None:
        return False

    try:
        rule_canonical, rule_host, rule_port, rule_path, rule_query = normalize_url(rule_value)
    except (TargetNormalizationError, ValueError):
        return False

    dest_canonical, dest_host, dest_port, dest_path, dest_query = dest_parts

    # Scheme and host must match
    if dest_host != rule_host:
        return False

    # Extract schemes from canonical URLs
    dest_scheme = dest_canonical.split("://", 1)[0]
    rule_scheme = rule_canonical.split("://", 1)[0]
    if dest_scheme != rule_scheme:
        return False

    # Port must match
    if dest_port != rule_port:
        return False

    # Enforce safe path boundaries
    if rule_path == "/":
        path_matched = True
    elif rule_path.endswith("/"):
        path_matched = dest_path.startswith(rule_path) or dest_path == rule_path.rstrip("/")
    else:
        path_matched = dest_path == rule_path or dest_path.startswith(rule_path + "/")

    if not path_matched:
        return False

    # Query parameters: if rule specifies queries, destination must contain all of them
    if rule_query:
        rule_q_params = set(urllib.parse.parse_qsl(rule_query))
        dest_q_params = set(urllib.parse.parse_qsl(dest_query or ""))
        if not rule_q_params.issubset(dest_q_params):
            return False

    return True


def _match_exact_host(rule_value: str, dest_host: str | None) -> bool:
    """Evaluate exact_host match type."""
    if dest_host is None:
        return False
    try:
        rule_host, _ = normalize_host(rule_value)
        return dest_host == rule_host
    except (TargetNormalizationError, ValueError):
        return False


def _match_domain_suffix(rule_value: str, dest_host: str | None, is_ip: bool) -> bool:
    """Evaluate domain_suffix match type with DNS label boundary enforcement."""
    if dest_host is None or is_ip:
        return False
    try:
        rule_domain = normalize_domain(rule_value, allow_wildcard=False, min_labels=1)
        return dest_host == rule_domain or dest_host.endswith("." + rule_domain)
    except (TargetNormalizationError, ValueError):
        return False


def _match_wildcard_domain(rule_value: str, dest_host: str | None, is_ip: bool) -> bool:
    """Evaluate wildcard_domain match type (subdomains only, apex strictly rejected)."""
    if dest_host is None or is_ip:
        return False
    try:
        clean_rule = rule_value.strip().lower()
        base_domain_raw = clean_rule[2:] if clean_rule.startswith("*.") else clean_rule
        base_domain = normalize_domain(base_domain_raw, allow_wildcard=False, min_labels=1)

        # Invariant: wildcard_domain (*.example.com) must NOT match the apex domain (example.com)
        if dest_host == base_domain:
            return False

        return dest_host.endswith("." + base_domain)
    except (TargetNormalizationError, ValueError):
        return False


def _match_ip(
    rule_value: str,
    dest_ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None,
) -> bool:
    """Evaluate exact ip match type."""
    if dest_ip is None:
        return False
    try:
        rule_ip_str, is_cidr = normalize_ip_or_cidr(rule_value)
        if is_cidr:
            return False
        rule_ip = ipaddress.ip_address(rule_ip_str)
        return dest_ip == rule_ip
    except (TargetNormalizationError, ValueError):
        return False


def _match_cidr(
    rule_value: str,
    dest_ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None,
) -> bool:
    """Evaluate cidr match type using strict subnet containment."""
    if dest_ip is None:
        return False
    try:
        rule_net_str, is_cidr = normalize_ip_or_cidr(rule_value)
        if not is_cidr:
            return False
        network = ipaddress.ip_network(rule_net_str, strict=True)
        return dest_ip in network
    except (TargetNormalizationError, ValueError, TypeError):
        return False


def match_scope_rules(
    rules: Sequence[Any],
    destination: str,
    protocol: str | None = None,
    port: int | None = None,
) -> ScopeMatchResult:
    """Deterministically evaluate whether a destination matches a set of scope rules.

    Precedence:
    1. Input Validation: Invalid destination returns DEFAULT_DENY with INVALID_TARGET.
    2. Deny Overrides Allow: Any matching deny rule causes a DENY decision,
       regardless of rule priority or specificity.
    3. Allow Match: If >=1 allow rules match and 0 deny rules match, decision is ALLOW.
    4. Default Deny: If 0 rules match, decision is DENY with DEFAULT_DENY.
    5. Deterministic Representative: Tie-broken by priority DESC, then rule ID ASC.

    Args:
        rules: Collection of ScopeRule or ScopeRuleData objects.
        destination: Subject string (URL, hostname, or IP address).
        protocol: Optional explicit protocol (e.g. 'http', 'https', 'tcp', 'udp').
        port: Optional explicit destination port (1-65535).

    Returns:
        ScopeMatchResult containing decision, representative rule ID, and reason code.
    """
    if not destination or not isinstance(destination, str):
        return ScopeMatchResult(
            matched=False,
            effect="deny",
            reason_code=ScopeMatchReasonCode.INVALID_TARGET,
            normalized_destination=None,
            evaluated_rule_count=0,
        )

    clean_dest = destination.strip()
    if not clean_dest or any(ord(c) < 32 or ord(c) == 127 for c in clean_dest):
        return ScopeMatchResult(
            matched=False,
            effect="deny",
            reason_code=ScopeMatchReasonCode.INVALID_TARGET,
            normalized_destination=None,
            evaluated_rule_count=0,
        )

    if port is not None and (port < 1 or port > 65535):
        return ScopeMatchResult(
            matched=False,
            effect="deny",
            reason_code=ScopeMatchReasonCode.INVALID_TARGET,
            normalized_destination=None,
            evaluated_rule_count=0,
        )

    # 1. Parse and classify destination
    dest_url_parts: tuple[str, str, int | None, str, str | None] | None = None
    dest_canonical_url: str | None = None
    dest_host: str | None = None
    dest_ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None
    is_dest_ip = False
    effective_port: int | None = port
    effective_protocol: str | None = protocol.strip().lower() if protocol else None
    canonical_repr: str

    if "://" in clean_dest:
        # Destination is a URL
        try:
            dest_url_parts = normalize_url(clean_dest)
            dest_canonical_url, dest_host, url_port, _path, _query = dest_url_parts
            canonical_repr = dest_canonical_url

            # Infer scheme/protocol if not explicitly supplied
            url_scheme = dest_canonical_url.split("://", 1)[0].lower()
            if effective_protocol is None:
                effective_protocol = url_scheme

            # Infer port if not explicitly supplied
            if effective_port is None:
                if url_port is not None:
                    effective_port = url_port
                elif url_scheme == "http":
                    effective_port = 80
                elif url_scheme == "https":
                    effective_port = 443

            # Check if host in URL is an IP address
            try:
                raw_ip = ipaddress.ip_address(dest_host)
                if isinstance(raw_ip, ipaddress.IPv6Address) and raw_ip.ipv4_mapped is not None:
                    dest_ip = raw_ip.ipv4_mapped
                else:
                    dest_ip = raw_ip
                is_dest_ip = True
            except ValueError:
                is_dest_ip = False
        except (TargetNormalizationError, ValueError):
            return ScopeMatchResult(
                matched=False,
                effect="deny",
                reason_code=ScopeMatchReasonCode.INVALID_TARGET,
                normalized_destination=None,
                evaluated_rule_count=0,
            )
    else:
        # Destination is a Host or IP
        try:
            # Check IP or CIDR first
            ip_str, _is_cidr = normalize_ip_or_cidr(clean_dest)
            raw_ip = ipaddress.ip_address(ip_str)
            if isinstance(raw_ip, ipaddress.IPv6Address) and raw_ip.ipv4_mapped is not None:
                dest_ip = raw_ip.ipv4_mapped
            else:
                dest_ip = raw_ip
            dest_host = str(dest_ip)
            is_dest_ip = True
            canonical_repr = dest_host
        except (TargetNormalizationError, ValueError):
            # Not an IP, attempt host normalization
            try:
                dest_host, is_dest_ip = normalize_host(clean_dest)
                canonical_repr = dest_host
                if is_dest_ip:
                    dest_ip = ipaddress.ip_address(dest_host)
            except (TargetNormalizationError, ValueError):
                return ScopeMatchResult(
                    matched=False,
                    effect="deny",
                    reason_code=ScopeMatchReasonCode.INVALID_TARGET,
                    normalized_destination=None,
                    evaluated_rule_count=0,
                )

    # 2. Iterate through rules and test matches
    matched_allows: list[tuple[int, str, Any]] = []
    matched_denies: list[tuple[int, str, Any]] = []
    evaluated_count = 0

    for rule in rules:
        evaluated_count += 1
        rule_effect = getattr(rule, "effect", "").strip().lower()
        rule_type = getattr(rule, "match_type", "").strip().lower()
        rule_val = getattr(rule, "value", "")
        rule_ports = getattr(rule, "ports", None)
        rule_protocols = getattr(rule, "protocols", None)
        rule_priority = int(getattr(rule, "priority", 100))
        rule_id_str = str(getattr(rule, "id", ""))

        if rule_effect not in ("allow", "deny"):
            continue

        # Evaluate match_type
        matches = False
        if rule_type == "exact_url":
            matches = _match_exact_url(rule_val, dest_canonical_url)
        elif rule_type == "url_prefix":
            matches = _match_url_prefix(rule_val, dest_url_parts)
        elif rule_type == "exact_host":
            matches = _match_exact_host(rule_val, dest_host)
        elif rule_type == "domain_suffix":
            matches = _match_domain_suffix(rule_val, dest_host, is_dest_ip)
        elif rule_type == "wildcard_domain":
            matches = _match_wildcard_domain(rule_val, dest_host, is_dest_ip)
        elif rule_type == "ip":
            matches = _match_ip(rule_val, dest_ip)
        elif rule_type == "cidr":
            matches = _match_cidr(rule_val, dest_ip)
        else:
            # Unsupported match type fails closed
            continue

        if not matches:
            continue

        # Check port restriction
        if not _port_in_range(effective_port, rule_ports):
            continue

        # Check protocol restriction
        if not _protocol_matches(rule_protocols, effective_protocol):
            continue

        # Rule matched!
        rule_tuple = (rule_priority, rule_id_str, rule)
        if rule_effect == "deny":
            matched_denies.append(rule_tuple)
        else:
            matched_allows.append(rule_tuple)

    # 3. Apply Deny-Overrides-Allow Precedence
    if matched_denies:
        # Sort by priority DESC, then rule ID ASC (deterministic tie-breaking)
        matched_denies.sort(key=lambda t: (-t[0], t[1]))
        winning_rule = matched_denies[0][2]
        rule_id: UUID | None = (
            winning_rule.id if isinstance(winning_rule.id, UUID) else UUID(str(winning_rule.id))
        )
        return ScopeMatchResult(
            matched=True,
            effect="deny",
            matched_rule_id=rule_id,
            match_type=getattr(winning_rule, "match_type", None),
            reason_code=ScopeMatchReasonCode.EXPLICIT_DENY,
            normalized_destination=canonical_repr,
            evaluated_rule_count=evaluated_count,
        )

    if matched_allows:
        matched_allows.sort(key=lambda t: (-t[0], t[1]))
        winning_rule = matched_allows[0][2]
        rule_id = (
            winning_rule.id if isinstance(winning_rule.id, UUID) else UUID(str(winning_rule.id))
        )
        return ScopeMatchResult(
            matched=True,
            effect="allow",
            matched_rule_id=rule_id,
            match_type=getattr(winning_rule, "match_type", None),
            reason_code=ScopeMatchReasonCode.ALLOWED_RULE,
            normalized_destination=canonical_repr,
            evaluated_rule_count=evaluated_count,
        )

    # Default deny (no matching rules)
    return ScopeMatchResult(
        matched=False,
        effect="deny",
        matched_rule_id=None,
        match_type=None,
        reason_code=ScopeMatchReasonCode.DEFAULT_DENY,
        normalized_destination=canonical_repr,
        evaluated_rule_count=evaluated_count,
    )
