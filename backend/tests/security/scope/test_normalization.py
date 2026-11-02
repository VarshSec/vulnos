"""Security unit tests for target normalization, validation, and IP classification."""

import ipaddress

import pytest

from backend.app.scope.normalization import (
    CredentialInURLError,
    DisallowedSchemeError,
    InvalidPortError,
    InvalidTargetTypeError,
    IPAddressCategory,
    MalformedTargetError,
    TargetType,
    classify_ip_address,
    normalize_api_base,
    normalize_domain,
    normalize_host,
    normalize_ip_or_cidr,
    normalize_repository,
    normalize_target,
    normalize_url,
    remove_dot_segments,
)


class TestDomainNormalization:
    """Tests for DNS domain name canonicalization and syntax enforcement."""

    def test_uppercase_and_trailing_dots(self) -> None:
        assert normalize_domain("EXAMPLE.COM") == "example.com"
        assert normalize_domain("example.com.") == "example.com"
        assert normalize_domain("  API.Example.Com.  ") == "api.example.com"

    def test_subdomains(self) -> None:
        assert normalize_domain("sub.v1.api.example.com") == "sub.v1.api.example.com"

    def test_idna_unicode_and_punycode(self) -> None:
        # German umlaut
        assert normalize_domain("münchen.de") == "xn--mnchen-3ya.de"
        assert normalize_domain("XN--MNCHEN-3YA.DE") == "xn--mnchen-3ya.de"
        # Idempotency
        assert normalize_domain(normalize_domain("münchen.de")) == "xn--mnchen-3ya.de"

    def test_domain_label_validation(self) -> None:
        # Valid hyphen in middle
        assert normalize_domain("evil-example.com") == "evil-example.com"
        assert normalize_domain("my-app-123.test.co.uk") == "my-app-123.test.co.uk"

    def test_reject_single_label_domain(self) -> None:
        # Domain requires at least 2 labels
        with pytest.raises(MalformedTargetError, match="must have at least 2 labels"):
            normalize_domain("localhost")

        with pytest.raises(MalformedTargetError, match="must have at least 2 labels"):
            normalize_domain("internal")

    def test_reject_leading_trailing_hyphens_in_labels(self) -> None:
        with pytest.raises(MalformedTargetError, match="invalid characters or illegal hyphens"):
            normalize_domain("-example.com")

        with pytest.raises(MalformedTargetError, match="invalid characters or illegal hyphens"):
            normalize_domain("example-.com")

        with pytest.raises(MalformedTargetError, match="invalid characters or illegal hyphens"):
            normalize_domain("sub.-bad.example.com")

    def test_reject_empty_labels_and_consecutive_dots(self) -> None:
        with pytest.raises(MalformedTargetError, match="consecutive or invalid"):
            normalize_domain("example..com")

        with pytest.raises(MalformedTargetError, match="consecutive or invalid"):
            normalize_domain(".example.com")

        with pytest.raises(MalformedTargetError):
            normalize_domain(".")

    def test_reject_control_characters_and_whitespace(self) -> None:
        with pytest.raises(MalformedTargetError, match="illegal whitespace or control"):
            normalize_domain("example\x00.com")

        with pytest.raises(MalformedTargetError, match="illegal whitespace or control"):
            normalize_domain("example\n.com")

        with pytest.raises(MalformedTargetError, match="illegal whitespace or control"):
            normalize_domain("exam ple.com")

    def test_reject_oversized_domain_and_labels(self) -> None:
        # Label over 63 chars
        long_label = "a" * 64
        with pytest.raises(MalformedTargetError, match="label length must be 1-63"):
            normalize_domain(f"{long_label}.com")

        # Total name over 253 octets
        long_domain = ".".join(["abcde" for _ in range(50)]) + ".com"
        assert len(long_domain) > 253
        with pytest.raises(MalformedTargetError, match="exceeds maximum length of 253"):
            normalize_domain(long_domain)

    def test_wildcard_handling(self) -> None:
        # Wildcard rejected by default for standard domains
        with pytest.raises(MalformedTargetError, match="Wildcard domains are not permitted"):
            normalize_domain("*.example.com", allow_wildcard=False)

        # Wildcard permitted when explicit flag set
        assert normalize_domain("*.example.com", allow_wildcard=True) == "*.example.com"
        assert normalize_domain("*.SUB.EXAMPLE.COM.", allow_wildcard=True) == "*.sub.example.com"


class TestHostNormalization:
    """Tests for host normalization (accepts domains, single-label hostnames, or IPs)."""

    def test_hostname_normalization(self) -> None:
        host, is_ip = normalize_host("API.EXAMPLE.COM")
        assert host == "api.example.com"
        assert is_ip is False

    def test_single_label_host_normalization(self) -> None:
        host, is_ip = normalize_host("localhost")
        assert host == "localhost"
        assert is_ip is False

    def test_ip_host_normalization(self) -> None:
        host1, is_ip1 = normalize_host("192.0.2.1")
        assert host1 == "192.0.2.1"
        assert is_ip1 is True

        host2, is_ip2 = normalize_host("[2001:db8::1]")
        assert host2 == "2001:db8::1"
        assert is_ip2 is True


class TestIPAndCIDRNormalization:
    """Tests for IPv4, IPv6, and strict CIDR parsing."""

    def test_ipv4_canonicalization(self) -> None:
        val, is_cidr = normalize_ip_or_cidr("192.0.2.1")
        assert val == "192.0.2.1"
        assert is_cidr is False

    def test_ipv6_rfc5952_compressed_lowercase(self) -> None:
        val, is_cidr = normalize_ip_or_cidr("2001:0DB8:0000:0000:0000:0000:0000:0001")
        assert val == "2001:db8::1"
        assert is_cidr is False

        val2, _ = normalize_ip_or_cidr("FE80::1")
        assert val2 == "fe80::1"

    def test_ipv4_mapped_ipv6_unpacking_policy(self) -> None:
        # Dual-stack IPv4-mapped IPv6 must unpack to underlying IPv4
        val, is_cidr = normalize_ip_or_cidr("::ffff:192.0.2.42")
        assert val == "192.0.2.42"
        assert is_cidr is False

    def test_strict_cidr_parsing(self) -> None:
        val, is_cidr = normalize_ip_or_cidr("192.168.1.0/24")
        assert val == "192.168.1.0/24"
        assert is_cidr is True

        val6, is_cidr6 = normalize_ip_or_cidr("2001:db8::/32")
        assert val6 == "2001:db8::/32"
        assert is_cidr6 is True

    def test_strict_cidr_rejects_host_bits(self) -> None:
        # 192.168.1.5 has host bits set for /24 network
        with pytest.raises(MalformedTargetError, match="non-zero host bits"):
            normalize_ip_or_cidr("192.168.1.5/24")

    def test_invalid_ips_and_cidrs(self) -> None:
        with pytest.raises(MalformedTargetError, match="Invalid IP"):
            normalize_ip_or_cidr("999.999.999.999")

        with pytest.raises(MalformedTargetError, match="Invalid IP"):
            normalize_ip_or_cidr("not-an-ip")

        with pytest.raises(MalformedTargetError):
            normalize_ip_or_cidr("192.168.1.0/33")


class TestURLNormalization:
    """Tests for HTTP/HTTPS URL parsing, dot-segments, credentials, and port handling."""

    def test_basic_url_normalization(self) -> None:
        url, host, port, path, query = normalize_url("HTTPS://EXAMPLE.COM")
        assert url == "https://example.com/"
        assert host == "example.com"
        assert port is None
        assert path == "/"
        assert query is None

    def test_default_ports_stripped(self) -> None:
        # http:80 stripped
        url1, _, port1, _, _ = normalize_url("http://example.com:80/api")
        assert url1 == "http://example.com/api"
        assert port1 is None

        # https:443 stripped
        url2, _, port2, _, _ = normalize_url("https://example.com:443/api")
        assert url2 == "https://example.com/api"
        assert port2 is None

    def test_non_default_ports_preserved(self) -> None:
        url1, _, port1, _, _ = normalize_url("http://example.com:8080/test")
        assert url1 == "http://example.com:8080/test"
        assert port1 == 8080

        url2, _, port2, _, _ = normalize_url("https://example.com:8443/")
        assert url2 == "https://example.com:8443/"
        assert port2 == 8443

    def test_bracketed_ipv6_url(self) -> None:
        url, host, port, path, _ = normalize_url("https://[2001:db8::1]:8443/v1")
        assert url == "https://[2001:db8::1]:8443/v1"
        assert host == "2001:db8::1"
        assert port == 8443
        assert path == "/v1"

    def test_embedded_credentials_rejected(self) -> None:
        # Basic auth user:pass
        with pytest.raises(CredentialInURLError, match="Embedded credentials"):
            normalize_url("https://admin:secret@example.com/dashboard")

        # Username only
        with pytest.raises(CredentialInURLError, match="Embedded credentials"):
            normalize_url("https://admin@example.com/")

    def test_unsupported_schemes_rejected(self) -> None:
        with pytest.raises(DisallowedSchemeError, match="Unsupported URL scheme"):
            normalize_url("ftp://example.com/pub")

        with pytest.raises(DisallowedSchemeError, match="Unsupported URL scheme"):
            normalize_url("file:///etc/passwd")

        with pytest.raises(DisallowedSchemeError, match="Unsupported URL scheme"):
            normalize_url("javascript:alert(1)")

        with pytest.raises(DisallowedSchemeError, match="Unsupported URL scheme"):
            normalize_url("gopher://example.com/")

    def test_invalid_ports_rejected(self) -> None:
        with pytest.raises(InvalidPortError, match="out of valid range"):
            normalize_url("https://example.com:0/api")

        with pytest.raises(InvalidPortError, match="out of valid range"):
            normalize_url("https://example.com:70000/api")

    def test_rfc3986_dot_segments_and_path_boundaries(self) -> None:
        # /api/../admin -> /admin
        url1, _, _, path1, _ = normalize_url("https://example.com/api/../admin")
        assert url1 == "https://example.com/admin"
        assert path1 == "/admin"

        # /api/./v1 -> /api/v1
        url2, _, _, path2, _ = normalize_url("https://example.com/api/./v1")
        assert url2 == "https://example.com/api/v1"
        assert path2 == "/api/v1"

        # Trailing slash preserved
        url3, _, _, path3, _ = normalize_url("https://example.com/api/")
        assert url3 == "https://example.com/api/"
        assert path3 == "/api/"

        # Path without trailing slash preserved
        url4, _, _, path4, _ = normalize_url("https://example.com/api")
        assert url4 == "https://example.com/api"
        assert path4 == "/api"

    def test_query_sorting_and_fragment_removal(self) -> None:
        # Query sorted by key, then value; fragment stripped
        raw = "https://example.com/search?q=test&page=2&b=1&a=2#section3"
        url, _, _, _, query = normalize_url(raw)
        assert url == "https://example.com/search?a=2&b=1&page=2&q=test"
        assert query == "a=2&b=1&page=2&q=test"
        assert "#" not in url

    def test_dot_segment_helper_unit(self) -> None:
        assert remove_dot_segments("/a/b/c/./../../g") == "/a/g"
        assert remove_dot_segments("mid/content=5/../6") == "/mid/6"
        assert remove_dot_segments("/.") == "/"
        assert remove_dot_segments("/..") == "/"
        assert remove_dot_segments("/a/b/../") == "/a/"


class TestAPIBaseNormalization:
    """Tests for API base URL normalization."""

    def test_api_base_normalizes_and_strips_trailing_slash(self) -> None:
        assert normalize_api_base("HTTPS://API.EXAMPLE.COM:443/v1/") == "https://api.example.com/v1"
        assert (
            normalize_api_base("http://api.example.com:8080/v2") == "http://api.example.com:8080/v2"
        )

    def test_api_base_root(self) -> None:
        assert normalize_api_base("https://api.example.com/") == "https://api.example.com"
        assert normalize_api_base("https://api.example.com") == "https://api.example.com"

    def test_api_base_rejects_query_parameters(self) -> None:
        with pytest.raises(MalformedTargetError, match="must not contain query parameters"):
            normalize_api_base("https://api.example.com/v1?version=latest")


class TestRepositoryNormalization:
    """Tests for Git repository target canonicalization."""

    def test_https_git_repo(self) -> None:
        assert (
            normalize_repository("https://github.com/VarshSec/vulnos.git")
            == "https://github.com/VarshSec/vulnos"
        )
        assert (
            normalize_repository("HTTPS://GITLAB.COM/Org-Name/Project.Repo")
            == "https://gitlab.com/Org-Name/Project.Repo"
        )

    def test_ssh_git_repo(self) -> None:
        assert (
            normalize_repository("git@github.com:VarshSec/vulnos.git")
            == "https://github.com/VarshSec/vulnos"
        )
        assert (
            normalize_repository("ssh://git@github.com/VarshSec/vulnos")
            == "https://github.com/VarshSec/vulnos"
        )

    def test_invalid_repo_rejected(self) -> None:
        with pytest.raises(MalformedTargetError, match="Unsupported or malformed repository"):
            normalize_repository("not-a-repo-url")


class TestSecurityClassificationHelpers:
    """Tests for SSRF prevention, cloud metadata classification, and IP categorization."""

    def test_cloud_metadata_hard_blocked(self) -> None:
        # AWS/GCP/Azure IMDSv1/v2
        res1 = classify_ip_address("169.254.169.254")
        assert res1.category == IPAddressCategory.CLOUD_METADATA
        assert res1.is_blocked_by_default is True
        assert res1.is_non_overridable is True

        # Cloud DNS / metadata
        res2 = classify_ip_address("169.254.169.253")
        assert res2.category == IPAddressCategory.CLOUD_METADATA
        assert res2.is_non_overridable is True

        # AWS ECS task metadata
        res3 = classify_ip_address("169.254.170.2")
        assert res3.category == IPAddressCategory.CLOUD_METADATA
        assert res3.is_non_overridable is True

        # Alibaba cloud metadata
        res4 = classify_ip_address("100.100.100.200")
        assert res4.category == IPAddressCategory.CLOUD_METADATA
        assert res4.is_non_overridable is True

        # AWS IPv6 IMDS
        res5 = classify_ip_address("fd00:ec2::254")
        assert res5.category == IPAddressCategory.CLOUD_METADATA
        assert res5.is_non_overridable is True

    def test_ipv4_mapped_ipv6_metadata_blocked(self) -> None:
        # IPv4-mapped IPv6 must unpack and trigger metadata classification
        res = classify_ip_address("::ffff:169.254.169.254")
        assert res.category == IPAddressCategory.CLOUD_METADATA
        assert res.is_non_overridable is True
        assert res.ip == ipaddress.IPv4Address("169.254.169.254")

    def test_loopback_classification(self) -> None:
        res1 = classify_ip_address("127.0.0.1")
        assert res1.category == IPAddressCategory.LOOPBACK
        assert res1.is_blocked_by_default is True
        assert res1.is_non_overridable is False

        res2 = classify_ip_address("::1")
        assert res2.category == IPAddressCategory.LOOPBACK
        assert res2.is_blocked_by_default is True

    def test_private_rfc1918_classification(self) -> None:
        # 10.0.0.0/8
        res1 = classify_ip_address("10.0.1.50")
        assert res1.category == IPAddressCategory.PRIVATE_RFC1918
        assert res1.is_blocked_by_default is True
        assert res1.is_non_overridable is False

        # 172.16.0.0/12
        res2 = classify_ip_address("172.20.5.1")
        assert res2.category == IPAddressCategory.PRIVATE_RFC1918

        # 192.168.0.0/16
        res3 = classify_ip_address("192.168.1.1")
        assert res3.category == IPAddressCategory.PRIVATE_RFC1918

        # IPv6 ULA (fc00::/7)
        res4 = classify_ip_address("fd12:3456:789a::1")
        assert res4.category == IPAddressCategory.PRIVATE_RFC1918

    def test_public_ip_classification(self) -> None:
        res1 = classify_ip_address("93.184.216.34")  # example.com
        assert res1.category == IPAddressCategory.PUBLIC
        assert res1.is_blocked_by_default is False
        assert res1.is_non_overridable is False

        res2 = classify_ip_address("2606:2800:220:1:248:1893:25c8:1946")
        assert res2.category == IPAddressCategory.PUBLIC
        assert res2.is_blocked_by_default is False


class TestCentralNormalizeTarget:
    """Tests for the central normalize_target entry point across all seed types."""

    @pytest.mark.parametrize(
        ("seed_type", "input_val", "expected_canonical"),
        [
            (TargetType.DOMAIN, "EXAMPLE.COM.", "example.com"),
            (TargetType.DOMAIN, "münchen.de", "xn--mnchen-3ya.de"),
            (TargetType.HOST, "192.0.2.1", "192.0.2.1"),
            (TargetType.HOST, "API.EXAMPLE.COM", "api.example.com"),
            (TargetType.IP, "192.168.1.0/24", "192.168.1.0/24"),
            (TargetType.IP, "::ffff:192.0.2.1", "192.0.2.1"),
            (TargetType.URL, "HTTPS://EXAMPLE.COM:443/api/./v1/", "https://example.com/api/v1/"),
            (TargetType.API_BASE, "https://api.example.com/v1/", "https://api.example.com/v1"),
            (
                TargetType.REPOSITORY,
                "git@github.com:VarshSec/vulnos.git",
                "https://github.com/VarshSec/vulnos",
            ),
        ],
    )
    def test_normalize_target_success_and_idempotency(
        self, seed_type: TargetType, input_val: str, expected_canonical: str
    ) -> None:
        # First normalization pass
        res = normalize_target(seed_type, input_val)
        assert res.canonical_value == expected_canonical
        assert res.target_type == seed_type

        # Idempotency check: Normalizing the canonical output must produce identical output
        res_second = normalize_target(seed_type, res.canonical_value)
        assert res_second.canonical_value == res.canonical_value

    def test_unsupported_target_type_raises(self) -> None:
        with pytest.raises(InvalidTargetTypeError, match="Unsupported target type"):
            normalize_target("unsupported_type", "example.com")

    def test_empty_value_raises(self) -> None:
        with pytest.raises(MalformedTargetError, match="cannot be empty"):
            normalize_target(TargetType.DOMAIN, "   ")
