"""Deterministic target normalization and security classification service for VulnOS.

Provides canonicalization, IDNA processing, strict RFC syntax validation,
and SSRF/cloud-metadata classification across all supported target seed types.
"""

from __future__ import annotations

import ipaddress
import re
import urllib.parse
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

import idna

# -----------------------------------------------------------------------------
# Constants & Enums
# -----------------------------------------------------------------------------

ALLOWED_URL_SCHEMES: Final[frozenset[str]] = frozenset({"http", "https"})

# Well-known Cloud Provider Instance Metadata Service (IMDS) addresses
# These addresses must be classified as non-overridable blocked destinations.
CLOUD_METADATA_IPS: Final[frozenset[ipaddress.IPv4Address | ipaddress.IPv6Address]] = frozenset(
    {
        ipaddress.IPv4Address("169.254.169.254"),  # AWS, GCP, Azure, OpenStack IMDS
        ipaddress.IPv4Address("169.254.169.253"),  # Cloud DNS / metadata services
        ipaddress.IPv4Address("169.254.170.2"),  # AWS ECS Task metadata
        ipaddress.IPv4Address("100.100.100.200"),  # Alibaba Cloud metadata
        ipaddress.IPv6Address("fd00:ec2::254"),  # AWS IPv6 IMDS
    }
)


class TargetType(StrEnum):
    """Supported target seed types corresponding to database constraints."""

    DOMAIN = "domain"
    HOST = "host"
    IP = "ip"
    URL = "url"
    API_BASE = "api_base"
    REPOSITORY = "repository"


class IPAddressCategory(StrEnum):
    """Network range classification categories."""

    PUBLIC = "public"
    PRIVATE_RFC1918 = "private_rfc1918"
    LOOPBACK = "loopback"
    LINK_LOCAL = "link_local"
    CLOUD_METADATA = "cloud_metadata"
    MULTICAST = "multicast"
    UNSPECIFIED = "unspecified"
    RESERVED = "reserved"


# -----------------------------------------------------------------------------
# Exceptions
# -----------------------------------------------------------------------------


class TargetNormalizationError(ValueError):
    """Base error raised when a target fails normalization or syntax validation."""


class InvalidTargetTypeError(TargetNormalizationError):
    """Raised when an unsupported target type is specified."""


class MalformedTargetError(TargetNormalizationError):
    """Raised when a target fails RFC syntactic constraints or contains control chars."""


class CredentialInURLError(TargetNormalizationError):
    """Raised when a URL contains embedded userinfo (username/password credentials)."""


class DisallowedSchemeError(TargetNormalizationError):
    """Raised when a URL uses a scheme other than HTTP or HTTPS."""


class InvalidPortError(TargetNormalizationError):
    """Raised when a target port is outside the valid TCP/UDP range (1-65535)."""


# -----------------------------------------------------------------------------
# Data Models
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class IPClassificationResult:
    """Security classification outcome for an IP address."""

    ip: ipaddress.IPv4Address | ipaddress.IPv6Address
    category: IPAddressCategory
    is_blocked_by_default: bool
    is_non_overridable: bool
    reason: str


@dataclass(frozen=True, slots=True)
class NormalizedTarget:
    """Structured, immutable result of deterministic target normalization."""

    raw_value: str
    target_type: TargetType
    canonical_value: str
    hostname: str | None = None
    ip_address: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None
    ip_network: ipaddress.IPv4Network | ipaddress.IPv6Network | None = None
    scheme: str | None = None
    port: int | None = None
    path: str | None = None
    query: str | None = None
    is_ip: bool = False
    is_cidr: bool = False
    ip_classification: IPClassificationResult | None = None


# -----------------------------------------------------------------------------
# Security & SSRF Classification Helpers
# -----------------------------------------------------------------------------


def classify_ip_address(
    ip: str | ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> IPClassificationResult:
    """Classify an IP address against security boundaries, RFC ranges, and cloud metadata.

    Security Rule: Cloud metadata addresses are non-overridable and always blocked.
    Private RFC 1918 ranges are blocked by default unless authorized at project scope.
    """
    ip_obj = ipaddress.ip_address(ip.strip()) if isinstance(ip, str) else ip

    # 1. Unpack IPv4-mapped IPv6 address (e.g. ::ffff:169.254.169.254)
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped is not None:
        ip_obj = ip_obj.ipv4_mapped

    # 2. Cloud Metadata Check (Hard-blocked, non-overridable)
    if ip_obj in CLOUD_METADATA_IPS:
        return IPClassificationResult(
            ip=ip_obj,
            category=IPAddressCategory.CLOUD_METADATA,
            is_blocked_by_default=True,
            is_non_overridable=True,
            reason="Cloud instance metadata service address",
        )

    # 3. Unspecified (0.0.0.0 / ::)
    if ip_obj.is_unspecified:
        return IPClassificationResult(
            ip=ip_obj,
            category=IPAddressCategory.UNSPECIFIED,
            is_blocked_by_default=True,
            is_non_overridable=True,
            reason="Unspecified network address",
        )

    # 4. Multicast (224.0.0.0/4 / ff00::/8)
    if ip_obj.is_multicast:
        return IPClassificationResult(
            ip=ip_obj,
            category=IPAddressCategory.MULTICAST,
            is_blocked_by_default=True,
            is_non_overridable=True,
            reason="Multicast address range",
        )

    # 5. Loopback (127.0.0.0/8 / ::1)
    if ip_obj.is_loopback:
        return IPClassificationResult(
            ip=ip_obj,
            category=IPAddressCategory.LOOPBACK,
            is_blocked_by_default=True,
            is_non_overridable=False,
            reason="Loopback host address",
        )

    # 6. Link-Local (169.254.0.0/16 / fe80::/10)
    if ip_obj.is_link_local:
        return IPClassificationResult(
            ip=ip_obj,
            category=IPAddressCategory.LINK_LOCAL,
            is_blocked_by_default=True,
            is_non_overridable=False,
            reason="Link-local network address",
        )

    # 7. Private RFC 1918 / RFC 4193
    if ip_obj.is_private:
        return IPClassificationResult(
            ip=ip_obj,
            category=IPAddressCategory.PRIVATE_RFC1918,
            is_blocked_by_default=True,
            is_non_overridable=False,
            reason="Private RFC 1918 / RFC 4193 internal network range",
        )

    # 8. Reserved (e.g. documentation ranges 192.0.2.0/24, 2001:db8::/32)
    if ip_obj.is_reserved:
        return IPClassificationResult(
            ip=ip_obj,
            category=IPAddressCategory.RESERVED,
            is_blocked_by_default=True,
            is_non_overridable=False,
            reason="IETF reserved or documentation network address",
        )

    # 9. Public Internet address
    return IPClassificationResult(
        ip=ip_obj,
        category=IPAddressCategory.PUBLIC,
        is_blocked_by_default=False,
        is_non_overridable=False,
        reason="Globally routable public address",
    )


# -----------------------------------------------------------------------------
# Domain Normalization
# -----------------------------------------------------------------------------

_DNS_LABEL_REGEX: Final[re.Pattern[str]] = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$")


def normalize_domain(
    raw_domain: str,
    allow_wildcard: bool = False,
    min_labels: int = 2,
) -> str:
    """Normalize a domain name per RFC 1035, RFC 1123, and IDNA (UTS #46).

    Args:
        raw_domain: Input domain string.
        allow_wildcard: If True, allows a leading '*.'.
        min_labels: Minimum number of DNS labels required (default 2 for domains).

    Returns:
        Canonical lowercase ASCII domain name.
    """
    if not raw_domain or not isinstance(raw_domain, str):
        raise MalformedTargetError("Domain must be a non-empty string")

    clean = raw_domain.strip()
    if not clean:
        raise MalformedTargetError("Domain cannot be blank")

    # Reject control characters or whitespace within the domain
    if any(ord(c) < 32 or ord(c) == 127 or c.isspace() for c in clean):
        raise MalformedTargetError("Domain contains illegal whitespace or control characters")

    # Check and handle wildcard prefix if explicitly permitted
    is_wildcard = False
    if clean.startswith("*."):
        if not allow_wildcard:
            raise MalformedTargetError("Wildcard domains are not permitted for this target type")
        is_wildcard = True
        clean = clean[2:]

    # Remove trailing dot if present (DNS canonical representation)
    if clean.endswith("."):
        clean = clean[:-1]

    if not clean:
        raise MalformedTargetError("Domain cannot resolve to an empty name")

    # Check for empty labels (e.g. 'example..com' or leading '.')
    if clean.startswith(".") or clean.endswith(".") or ".." in clean:
        raise MalformedTargetError("Domain contains consecutive or invalid label-separating dots")

    for raw_label in clean.split("."):
        if len(raw_label) < 1 or len(raw_label) > 63:
            raise MalformedTargetError(f"DNS label length must be 1-63 characters: {raw_label!r}")
        if raw_label.startswith("-") or raw_label.endswith("-"):
            raise MalformedTargetError(
                f"DNS label contains invalid characters or illegal hyphens: {raw_label!r}"
            )

    if len(clean) > 253:
        raise MalformedTargetError(f"Domain exceeds maximum length of 253 octets: {len(clean)}")

    # Convert Unicode IDN to ASCII Punycode via IDNA 2008 / UTS #46
    try:
        ascii_name = idna.encode(clean, uts46=True).decode("ascii").lower()
    except Exception as exc:
        raise MalformedTargetError(f"IDNA domain encoding failed: {exc}") from exc

    # RFC 1035: Total length must not exceed 253 octets
    if len(ascii_name) > 253:
        raise MalformedTargetError(
            f"Domain exceeds maximum length of 253 octets: {len(ascii_name)}"
        )

    labels = ascii_name.split(".")
    if len(labels) < min_labels:
        raise MalformedTargetError(
            f"Domain must have at least {min_labels} labels, got {len(labels)} ({ascii_name!r})"
        )

    for label in labels:
        if len(label) < 1 or len(label) > 63:
            raise MalformedTargetError(f"DNS label length must be 1-63 characters: {label!r}")
        if not _DNS_LABEL_REGEX.match(label):
            raise MalformedTargetError(
                f"DNS label contains invalid characters or illegal hyphens: {label!r}"
            )

    return f"*.{ascii_name}" if is_wildcard else ascii_name


# -----------------------------------------------------------------------------
# Host Normalization
# -----------------------------------------------------------------------------


def normalize_host(raw_host: str) -> tuple[str, bool]:
    """Normalize a hostname or IP address string.

    Returns:
        tuple[canonical_string, is_ip]: Canonical representation and boolean flag.
    """
    if not raw_host or not isinstance(raw_host, str):
        raise MalformedTargetError("Host must be a non-empty string")

    clean = raw_host.strip()
    if clean.startswith("[") and clean.endswith("]"):
        clean = clean[1:-1]

    # 1. Attempt IP parsing
    try:
        ip = ipaddress.ip_address(clean)
        # Apply IPv4-mapped IPv6 policy
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            return str(ip.ipv4_mapped), True
        return ip.compressed.lower(), True
    except ValueError:
        pass

    # 2. Otherwise treat as hostname (allows single-label hostnames like 'localhost')
    domain = normalize_domain(clean, allow_wildcard=False, min_labels=1)
    return domain, False


# -----------------------------------------------------------------------------
# IP & CIDR Normalization
# -----------------------------------------------------------------------------


def normalize_ip_or_cidr(raw_value: str) -> tuple[str, bool]:
    """Normalize an IPv4/IPv6 address or CIDR range.

    Policy:
    - IPv4-mapped IPv6 addresses (::ffff:x.x.x.x) are unpacked to their canonical IPv4 format.
    - CIDRs are parsed strictly: host bits must not be set (e.g. 192.168.1.0/24).
    - IPs are formatted canonically (IPv4: 4-octet dotted decimal, IPv6: RFC 5952 lowercase).

    Returns:
        tuple[canonical_string, is_cidr]
    """
    if not raw_value or not isinstance(raw_value, str):
        raise MalformedTargetError("IP/CIDR must be a non-empty string")

    clean = raw_value.strip()

    # CIDR evaluation
    if "/" in clean:
        try:
            network = ipaddress.ip_network(clean, strict=True)
            return network.compressed.lower(), True
        except ValueError as exc:
            raise MalformedTargetError(
                f"Invalid CIDR network or non-zero host bits: {exc}"
            ) from exc

    # Single IP evaluation
    try:
        ip = ipaddress.ip_address(clean)
        # Apply IPv4-mapped IPv6 policy
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            return str(ip.ipv4_mapped), False
        return ip.compressed.lower(), False
    except ValueError as exc:
        raise MalformedTargetError(f"Invalid IP address: {exc}") from exc


# -----------------------------------------------------------------------------
# URL Path & Dot-Segment Canonicalization (RFC 3986 5.2.4)
# -----------------------------------------------------------------------------


def remove_dot_segments(path: str) -> str:
    """Implement RFC 3986 Section 5.2.4 dot-segment removal algorithm.

    Resolves '.' and '..' path segments while preserving intended trailing slashes.
    """
    if not path or path == "/":
        return "/"

    segments = path.split("/")
    output: list[str] = []

    for seg in segments:
        if seg in ("", "."):
            continue
        if seg == "..":
            if output:
                output.pop()
        else:
            output.append(seg)

    res = "/" + "/".join(output)
    # If the original path ended in '/' or '.' or '..' and is not just '/', preserve trailing slash
    if path.endswith(("/", "/.", "/..")) and not res.endswith("/"):
        res += "/"
    return res


# -----------------------------------------------------------------------------
# URL Normalization
# -----------------------------------------------------------------------------


def normalize_url(raw_url: str) -> tuple[str, str, int | None, str, str | None]:
    """Normalize and validate an HTTP or HTTPS URL.

    Requirements:
    - Schemes strictly restricted to http or https.
    - Rejects embedded username/password credentials.
    - Normalizes scheme and host to lowercase.
    - Omit default ports (80 for http, 443 for https).
    - Preserves non-default ports (1-65535).
    - Resolves dot segments (/./, /../) via RFC 3986.
    - Strips URL fragments (#).
    - Deterministically sorts query parameters.

    Returns:
        tuple[canonical_url, hostname, port, path, query]
    """
    if not raw_url or not isinstance(raw_url, str):
        raise MalformedTargetError("URL must be a non-empty string")

    clean = raw_url.strip()
    if not clean:
        raise MalformedTargetError("URL cannot be blank")

    # Reject control characters
    if any(ord(c) < 32 or ord(c) == 127 for c in clean):
        raise MalformedTargetError("URL contains illegal control characters")

    try:
        parts = urllib.parse.urlsplit(clean)
    except Exception as exc:
        raise MalformedTargetError(f"Malformed URL structure: {exc}") from exc

    # 1. Scheme Validation
    if not parts.scheme:
        raise MalformedTargetError("URL missing scheme (must be http:// or https://)")
    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_URL_SCHEMES:
        raise DisallowedSchemeError(
            f"Unsupported URL scheme {scheme!r}; only HTTP and HTTPS allowed"
        )

    # 2. Reject Embedded Credentials (RFC 3986 userinfo)
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise CredentialInURLError("Embedded credentials in target URLs are forbidden")

    # 3. Hostname and Port Validation
    if not parts.hostname:
        raise MalformedTargetError("URL missing hostname or host is empty")

    raw_hostname = parts.hostname
    normalized_host, is_ip = normalize_host(raw_hostname)

    # 4. Port Normalization
    try:
        port = parts.port
    except ValueError as exc:
        raise InvalidPortError(f"Port is out of valid range (1-65535): {exc}") from exc

    if port is not None:
        if port < 1 or port > 65535:
            raise InvalidPortError(f"Port {port} is out of valid range (1-65535)")
        # Drop default ports
        if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
            port = None

    # Format netloc (bracket IPv6 if necessary)
    host_netloc = f"[{normalized_host}]" if is_ip and ":" in normalized_host else normalized_host
    netloc = f"{host_netloc}:{port}" if port is not None else host_netloc

    # 5. Path Canonicalization
    raw_path = parts.path
    path = "/" if not raw_path else remove_dot_segments(raw_path)

    # 6. Query Parameters Sorting & Deterministic Encoding
    query: str | None = None
    if parts.query:
        params = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
        params.sort(key=lambda item: (item[0], item[1]))
        query = urllib.parse.urlencode(params)

    # 7. Fragments are strictly stripped
    canonical = f"{scheme}://{netloc}{path}"
    if query:
        canonical = f"{canonical}?{query}"

    return canonical, normalized_host, port, path, query


# -----------------------------------------------------------------------------
# API Base Normalization
# -----------------------------------------------------------------------------


def normalize_api_base(raw_api_base: str) -> str:
    """Normalize an API base URL (e.g. 'https://api.example.com/v1').

    Differs from standard URL:
    - Disallows query parameters and fragments.
    - Strips trailing slash from path to facilitate clean endpoint path appending.
    """
    canonical_url, _, _, _path, query = normalize_url(raw_api_base)
    if query:
        raise MalformedTargetError("API base URL must not contain query parameters")

    # Split into scheme+netloc and path
    parts = urllib.parse.urlsplit(canonical_url)
    clean_path = parts.path.rstrip("/")
    if not clean_path:
        clean_path = ""

    return f"{parts.scheme}://{parts.netloc}{clean_path}"


# -----------------------------------------------------------------------------
# Repository Normalization
# -----------------------------------------------------------------------------

_HTTPS_REPO_REGEX: Final[re.Pattern[str]] = re.compile(
    r"^https://([a-zA-Z0-9.-]+)/([a-zA-Z0-9_.-]+)/([a-zA-Z0-9_.-]+?)(?:\.git)?$",
    re.IGNORECASE,
)
_SSH_REPO_REGEX: Final[re.Pattern[str]] = re.compile(
    r"^(?:ssh://)?(?:git@)?([a-zA-Z0-9.-]+)[:/]([a-zA-Z0-9_.-]+)/([a-zA-Z0-9_.-]+?)(?:\.git)?$",
    re.IGNORECASE,
)


def normalize_repository(raw_repo: str) -> str:
    """Normalize a source code repository target (HTTPS or SSH Git format).

    Standardizes repository URL into canonical HTTPS git representation:
    e.g. 'https://github.com/org/repo'
    """
    if not raw_repo or not isinstance(raw_repo, str):
        raise MalformedTargetError("Repository target must be a non-empty string")

    clean = raw_repo.strip()

    # 1. Match HTTPS format
    m_https = _HTTPS_REPO_REGEX.match(clean)
    if m_https:
        host, owner, repo = m_https.groups()
        norm_host = normalize_domain(host, min_labels=1)
        return f"https://{norm_host}/{owner}/{repo}"

    # 2. Match SSH format
    m_ssh = _SSH_REPO_REGEX.match(clean)
    if m_ssh:
        host, owner, repo = m_ssh.groups()
        norm_host = normalize_domain(host, min_labels=1)
        return f"https://{norm_host}/{owner}/{repo}"

    raise MalformedTargetError(
        f"Unsupported or malformed repository format {clean!r}. "
        "Must be a valid Git HTTPS or SSH URL."
    )


# -----------------------------------------------------------------------------
# Central Normalization Entry Point
# -----------------------------------------------------------------------------


def normalize_target(
    target_type: str | TargetType,
    raw_value: str,
) -> NormalizedTarget:
    """Central deterministic normalization entry point for all VulnOS targets.

    Validates, normalizes, and classifies target input according to its seed type.

    Args:
        target_type: Type of target ('domain', 'host', 'ip', 'url', 'api_base', 'repository').
        raw_value: Raw input string provided by user or automation.

    Returns:
        NormalizedTarget with canonical value and extracted metadata.

    Raises:
        InvalidTargetTypeError: If target_type is unrecognized.
        TargetNormalizationError: If value violates syntactic or security constraints.
    """
    if not isinstance(target_type, TargetType):
        try:
            target_type = TargetType(str(target_type).strip().lower())
        except ValueError as exc:
            raise InvalidTargetTypeError(f"Unsupported target type: {target_type!r}") from exc

    if not raw_value or not isinstance(raw_value, str) or not raw_value.strip():
        raise MalformedTargetError(f"Target value for {target_type.value} cannot be empty")

    raw_clean = raw_value.strip()

    if target_type == TargetType.DOMAIN:
        canonical = normalize_domain(raw_clean, allow_wildcard=False, min_labels=2)
        return NormalizedTarget(
            raw_value=raw_clean,
            target_type=target_type,
            canonical_value=canonical,
            hostname=canonical,
            is_ip=False,
            is_cidr=False,
        )

    if target_type == TargetType.HOST:
        canonical, is_ip = normalize_host(raw_clean)
        ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None
        classification: IPClassificationResult | None = None
        if is_ip:
            ip_obj = ipaddress.ip_address(canonical)
            classification = classify_ip_address(ip_obj)

        return NormalizedTarget(
            raw_value=raw_clean,
            target_type=target_type,
            canonical_value=canonical,
            hostname=canonical if not is_ip else None,
            ip_address=ip_obj,
            is_ip=is_ip,
            is_cidr=False,
            ip_classification=classification,
        )

    if target_type == TargetType.IP:
        canonical, is_cidr = normalize_ip_or_cidr(raw_clean)
        ip_obj = None
        network_obj = None
        classification = None
        if is_cidr:
            network_obj = ipaddress.ip_network(canonical)
            # Classify network based on its network address
            classification = classify_ip_address(network_obj.network_address)
        else:
            ip_obj = ipaddress.ip_address(canonical)
            classification = classify_ip_address(ip_obj)

        return NormalizedTarget(
            raw_value=raw_clean,
            target_type=target_type,
            canonical_value=canonical,
            ip_address=ip_obj,
            ip_network=network_obj,
            is_ip=not is_cidr,
            is_cidr=is_cidr,
            ip_classification=classification,
        )

    if target_type == TargetType.URL:
        canonical, host, port, path, query = normalize_url(raw_clean)
        return NormalizedTarget(
            raw_value=raw_clean,
            target_type=target_type,
            canonical_value=canonical,
            hostname=host,
            scheme=urllib.parse.urlsplit(canonical).scheme,
            port=port,
            path=path,
            query=query,
        )

    if target_type == TargetType.API_BASE:
        canonical = normalize_api_base(raw_clean)
        parts = urllib.parse.urlsplit(canonical)
        return NormalizedTarget(
            raw_value=raw_clean,
            target_type=target_type,
            canonical_value=canonical,
            hostname=parts.hostname,
            scheme=parts.scheme,
            port=parts.port,
            path=parts.path or "/",
        )

    if target_type == TargetType.REPOSITORY:
        canonical = normalize_repository(raw_clean)
        parts = urllib.parse.urlsplit(canonical)
        return NormalizedTarget(
            raw_value=raw_clean,
            target_type=target_type,
            canonical_value=canonical,
            hostname=parts.hostname,
            scheme=parts.scheme,
            path=parts.path,
        )

    raise InvalidTargetTypeError(f"Unsupported target type: {target_type!r}")
