# VulnOS Phase 2.5.2 — Target Normalization Service Design

## 1. Architectural Purpose & Security Boundaries

The **Target Normalization Service** (`backend/app/scope/normalization.py`) provides deterministic, RFC-compliant canonicalization, syntax validation, and security classification for all target seeds in VulnOS.

In an autonomous security assessment platform, normalization is the **first line of defense** against scope escape vulnerabilities:
- **Scope Bypass Prevention:** Attackers or confused agents attempting to test targets via alternate representations (`EXAMPLE.COM.`, `example.com:443/`, `::ffff:169.254.169.254`, or `git@github.com:org/repo.git`) must resolve to the identical canonical representation used in authorization boundaries.
- **SSRF & Cloud IMDS Mitigation:** IP classifications provide zero-trust classification of network destinations, hard-blocking non-routable link-local cloud instance metadata services (AWS, Azure, GCP, Alibaba, OpenStack) from accidental or malicious inclusion.
- **Deterministic Idempotency:** For every normalization function $N(x)$, the transformation is strictly idempotent:
  $$N(N(x)) = N(x)$$
  Re-normalizing an already canonicalized target produces the identical output string without mutation or drift.

---

## 2. Supported Target Types & Schemas

VulnOS maps normalization directly to the database constraints defined on `Target.target_type` in the relational schema:

| Target Type (`TargetType`) | Semantic Definition | Example Input | Normalized Canonical Output |
| :--- | :--- | :--- | :--- |
| `domain` | Internet domain name or subdomain (FQDN) | `EXAMPLE.COM.` | `example.com` |
| `host` | DNS hostname or IP address (single-label intranet allowed) | `DC01` / `192.0.2.1` | `dc01` / `192.0.2.1` |
| `ip` | Single IP address (v4/v6) or strict CIDR block | `192.168.1.0/24` | `192.168.1.0/24` |
| `url` | Web URL with HTTP/HTTPS scheme and normalized path | `HTTPS://EXAMPLE.COM:443/api/./v1/?b=2&a=1#frag` | `https://example.com/api/v1/?a=1&b=2` |
| `api_base` | Base endpoint URL for REST / GraphQL services | `https://api.example.com/v1/` | `https://api.example.com/v1` |
| `repository` | Source code repository (Git over HTTPS / SSH) | `git@github.com:VarshSec/vulnos.git` | `https://github.com/VarshSec/vulnos` |

---

## 3. Domain Normalization Specification

Domain normalization (`normalize_domain`) enforces strict RFC 1035, RFC 1123, and IDNA (RFC 5891 / Unicode UTS #46) standards:

1. **Case Folding & Trailing Dots:**
   - Lowercases all ASCII characters.
   - Strips trailing root dots (`example.com.` $\rightarrow$ `example.com`).
2. **Length Validation:**
   - Total domain length: $\le 253$ ASCII octets.
   - Individual label length: $1$ to $63$ octets.
3. **Label Syntactic Rules:**
   - Labels cannot start or end with hyphens (`-example.com` and `example-.com` rejected).
   - Labels cannot be empty (`example..com` rejected).
   - Disallowed characters (spaces, null bytes, newlines, control characters) strictly rejected with `MalformedTargetError`.
4. **Internationalized Domain Names (IDN):**
   - Transcoded via IDNA UTS #46 into ASCII Compatible Encoding (Punycode):
     - `münchen.de` $\rightarrow$ `xn--mnchen-3ya.de`
     - Punycode inputs (`xn--mnchen-3ya.de`) validate and remain unchanged.
5. **Minimum Labels Rule:**
   - By default (`min_labels=2`), public domain names must have at least two labels (preventing standalone TLDs such as `com` or `internal` from being accepted as domain targets).
   - Internal hosts (`min_labels=1`) allow single-label hostnames under the `host` target type.
6. **Wildcards Policy:**
   - Wildcards (`*.example.com`) are **rejected** during target seed normalization.
   - Wildcard semantics are strictly isolated to `ScopeRule` pattern matching definitions.

---

## 4. IP and CIDR Normalization Specification

Network addresses and subnets (`normalize_ip_or_cidr`) utilize Python's standard `ipaddress` module with zero string interpolation:

1. **IPv4 Canonicalization:**
   - Standard dotted-decimal representation (`192.0.2.1`).
   - Octal or hex notation bypass attempts are parsed into canonical decimal.
2. **IPv6 Canonicalization (RFC 5952):**
   - Lowercase hexadecimal characters.
   - Consecutive 16-bit blocks of zeroes compressed with `::`.
   - Canonical format: `2001:db8::1`.
3. **IPv4-Mapped IPv6 Unpacking Policy:**
   - Dual-stack socket targets of the form `::ffff:a.b.c.d` (e.g. `::ffff:192.0.2.1` or `::ffff:169.254.169.254`) represent IPv4 addresses mapped into IPv6 space.
   - **Security Policy:** Normalization automatically unpacks mapped IPv6 addresses to their native IPv4 representation (`::ffff:192.0.2.1` $\rightarrow$ `192.0.2.1`).
   - This ensures SSRF and Cloud Metadata filters cannot be bypassed by obscuring an IPv4 address inside an IPv6 wrapper.
4. **Strict CIDR Masking:**
   - CIDR notation is parsed with `strict=True`.
   - Host bits set within the network prefix are **strictly rejected**:
     - `192.168.1.0/24` $\rightarrow$ Accepted (`192.168.1.0/24`).
     - `192.168.1.1/24` $\rightarrow$ Rejected (`MalformedTargetError: Host bits set in CIDR prefix`).
   - Normalization **never silently zeroes host bits**, and **never silently expands single IPs into /32 or /24 ranges**.

---

## 5. URL and API Base Normalization Specification

URL normalization (`normalize_url` and `normalize_api_base`) canonicalizes HTTP/HTTPS targets according to RFC 3986:

1. **Scheme Restrictions:**
   - Strictly `http` and `https` allowed (`DisallowedSchemeError`).
   - Schemes like `file://`, `gopher://`, `ftp://`, `data:`, `javascript:` are rejected.
2. **Credential Stripping & Rejection:**
   - Any URL containing userinfo credentials (`user:pass@host`) is **strictly rejected** with `CredentialInURLError`.
   - Credentials in target URLs pose security risks of accidental token leakage in logs and authority confusion attacks.
3. **Port Normalization:**
   - Default ports are stripped:
     - `http://example.com:80/` $\rightarrow$ `http://example.com/`
     - `https://example.com:443/` $\rightarrow$ `https://example.com/`
   - Non-default ports are preserved:
     - `https://example.com:8443/` $\rightarrow$ `https://example.com:8443/`
   - Ports outside 1–65535 are rejected with `InvalidPortError`.
4. **Authority Canonicalization:**
   - Hostnames are lowercased and IDNA normalized.
   - IPv6 hosts are enclosed in brackets: `https://[2001:db8::1]:8443/`.
5. **Path Canonicalization (RFC 3986 Section 5.2.4):**
   - Relative dot-segments (`/./` and `/../`) are removed using standard algorithm:
     - `/api/./v1/` $\rightarrow$ `/api/v1/`
     - `/api/v2/../v1/` $\rightarrow$ `/api/v1/`
   - Leading slashes are guaranteed: empty path becomes `/`.
   - **Path Boundaries Preserved:** `/api` is never altered to match `/apiv2`.
6. **Query & Fragment Handling:**
   - Query parameters are deterministically sorted alphabetically by key and value:
     - `?b=2&a=1` $\rightarrow$ `?a=1&b=2`
   - URL fragments (`#section`) are stripped (fragments are client-side only and irrelevant to security scanning).
7. **API Base Specific Rules (`normalize_api_base`):**
   - Query parameters and fragments are strictly forbidden (`MalformedTargetError`).
   - Trailing slashes are stripped (`https://api.example.com/v1/` $\rightarrow$ `https://api.example.com/v1`) to prevent double-slash artifacts (`//`) when path-combining in HTTP clients.

---

## 6. Repository Normalization Specification

Repository normalization (`normalize_repository`) canonicalizes Git source targets:

1. **Supported Formats:**
   - **HTTPS:** `https://github.com/org/repo.git` $\rightarrow$ `https://github.com/org/repo`
   - **SSH:** `git@github.com:org/repo.git` $\rightarrow$ `https://github.com/org/repo`
2. **Transformation Rules:**
   - SSH formats (`git@host:owner/repo`) are transcoded into HTTPS representation.
   - Trailing `.git` suffix is stripped.
   - Hostname is lowercased and normalized.
   - Non-standard git schemes (`git://`, `ssh://`) or malformed formats are rejected with `MalformedTargetError`.

---

## 7. Security Classification & Cloud IMDS Protection

The normalization module exports `classify_ip_address(ip)` which assigns an `IPAddressCategory` to any IPv4 or IPv6 address:

```python
class IPAddressCategory(StrEnum):
    PUBLIC = "public"
    PRIVATE_RFC1918 = "private_rfc1918"
    LOOPBACK = "loopback"
    LINK_LOCAL = "link_local"
    CLOUD_METADATA = "cloud_metadata"
    MULTICAST = "multicast"
    UNSPECIFIED = "unspecified"
    RESERVED = "reserved"
```

### Non-Overridable Cloud Metadata Blocklist (`CLOUD_METADATA_IPS`)

The following addresses are classified under `IPAddressCategory.CLOUD_METADATA` and marked with `is_blocked=True`:

- `169.254.169.254` — AWS, GCP, Azure, OpenStack IMDS
- `169.254.169.253` — Cloud DNS / metadata services
- `169.254.170.2` — AWS ECS Task metadata endpoint
- `100.100.100.200` — Alibaba Cloud metadata endpoint
- `fd00:ec2::254` — AWS IPv6 IMDS endpoint

Dual-stack IPv4-mapped IPv6 representations (`::ffff:169.254.169.254`) unpack to their underlying IPv4 address and are blocked identically.

---

## 8. Exception Hierarchy

All exceptions raised by the normalization engine inherit from `TargetNormalizationError`:

```
TargetNormalizationError (ValueError)
├── InvalidTargetTypeError (unrecognized seed type)
├── MalformedTargetError (RFC syntax violation, control chars, host bits in CIDR)
├── CredentialInURLError (embedded user:pass in URL)
├── DisallowedSchemeError (non-HTTP/HTTPS schemes)
└── InvalidPortError (port out of 1-65535 range)
```

---

## 9. Test Verification Matrix

All 51 test cases in `backend/tests/security/scope/test_normalization.py` validate correctness, security invariants, and edge cases:

| Test Class | Target Area | Cases Verified | Status |
| :--- | :--- | :--- | :--- |
| `TestDomainNormalization` | FQDN validation | Uppercase folding, trailing dots, subdomains, IDNA punycode, label lengths, single-label rejection, hyphen rules, control characters, wildcard rejection | **PASSED** |
| `TestHostNormalization` | Hostname / IP | Intranet single-label hostnames, FQDN hostnames, IPv4/IPv6 host values | **PASSED** |
| `TestIPAndCIDRNormalization` | IP / CIDR | IPv4 dotted decimal, IPv6 RFC 5952 compression, IPv4-mapped IPv6 unpacking, strict CIDR network parsing, host bits rejection, invalid IP rejection | **PASSED** |
| `TestURLNormalization` | Web URLs | Basic normalization, default port removal (:80, :443), non-default port preservation, bracketed IPv6, credential rejection, scheme restrictions, port bounds, RFC 3986 dot segments, query sorting, fragment stripping | **PASSED** |
| `TestAPIBaseNormalization` | API Root Endpoints | Trailing slash removal, root-path API bases, query parameter rejection | **PASSED** |
| `TestRepositoryNormalization` | Git Repositories | HTTPS format canonicalization, SSH format transcoding, trailing .git removal, invalid repo rejection | **PASSED** |
| `TestSecurityClassificationHelpers` | IP Classification | Cloud IMDS hard-blocking, IPv4-mapped IMDS blocking, loopback, RFC 1918 private, public IP classification | **PASSED** |
| `TestCentralNormalizeTarget` | Central Dispatcher | Dispatch for all target types, empty value rejection, unsupported type rejection, end-to-end idempotency $N(N(x)) = N(x)$ | **PASSED** |

### Quality Gate Summary

- **Ruff Linter:** 100% clean (`All checks passed!`).
- **Ruff Formatter:** 100% clean (`78 files already formatted`).
- **Mypy Type Checker:** 100% clean (`Success: no issues found in 75 source files`).
- **Pytest:** 297 total project tests passing (`297 passed in 3.78s`).
