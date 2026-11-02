"""Static validation tests for Dockerfile security properties and compose.yaml."""

from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_compose_yaml_validity_and_services() -> None:
    """Verifies compose.yaml is syntactically valid and satisfies P2.1 topology."""
    compose_path = REPO_ROOT / "compose.yaml"
    assert compose_path.exists(), "compose.yaml must exist at repository root"

    with compose_path.open("r", encoding="utf-8") as f:
        compose_data = yaml.safe_load(f)

    assert "services" in compose_data
    services = compose_data["services"]

    # Required P2.1 services
    expected_services = {"api", "postgres", "redis", "silo"}
    assert expected_services.issubset(set(services.keys()))

    # Verify Silo image and exact approved digest (Part 6 decision)
    silo_service = services["silo"]
    silo_image = silo_service.get("image", "")
    assert "pgsty/silo" in silo_image
    assert "sha256:7bb2aff6b89efe1cb1303c10fc21d579447434ed06649ac9ec05a5e2dbf30ad7" in silo_image

    # Verify Postgres 16 digest pinned
    pg_service = services["postgres"]
    assert "postgres:16" in pg_service.get("image", "")
    assert "@sha256:" in pg_service.get("image", "")

    # Verify Redis 7 digest pinned
    redis_service = services["redis"]
    assert "redis:7" in redis_service.get("image", "")
    assert "@sha256:" in redis_service.get("image", "")

    # Verify healthchecks on all services
    for svc_name in expected_services:
        assert "healthcheck" in services[svc_name], f"Service {svc_name} must define healthcheck"

    # Verify API hardening properties in Compose
    api_service = services["api"]
    assert "security_opt" in api_service
    assert "no-new-privileges:true" in api_service["security_opt"]
    assert "cap_drop" in api_service
    assert "ALL" in api_service["cap_drop"]
    assert api_service.get("read_only") is True

    # Verify dependencies with healthcheck conditions
    depends_on = api_service.get("depends_on", {})
    assert "postgres" in depends_on
    assert depends_on["postgres"]["condition"] == "service_healthy"
    assert "redis" in depends_on
    assert depends_on["redis"]["condition"] == "service_healthy"
    assert "silo" in depends_on
    assert depends_on["silo"]["condition"] == "service_healthy"


def test_dockerfile_security_properties() -> None:
    """Verifies Dockerfile meets container hardening requirements."""
    dockerfile_path = REPO_ROOT / "Dockerfile"
    assert dockerfile_path.exists(), "Dockerfile must exist at repository root"

    content = dockerfile_path.read_text(encoding="utf-8")
    lines = [line.strip() for line in content.splitlines()]

    # 1. Base image pinned by sha256 digest
    from_lines = [line for line in lines if line.startswith("FROM")]
    assert len(from_lines) >= 2, "Dockerfile must use multi-stage build"
    for from_line in from_lines:
        assert "@sha256:" in from_line, f"Base image must be pinned by digest: {from_line}"

    # 2. Non-root user declaration
    user_lines = [line for line in lines if line.startswith("USER")]
    assert len(user_lines) >= 1, "Dockerfile must specify non-root USER"
    assert any("10001" in u or "appuser" in u for u in user_lines)

    # 3. Port 8000 exposed
    expose_lines = [line for line in lines if line.startswith("EXPOSE")]
    assert any("8000" in exp for exp in expose_lines)

    # 4. HEALTHCHECK defined
    healthcheck_lines = [line for line in lines if line.startswith("HEALTHCHECK")]
    assert len(healthcheck_lines) >= 1, "Dockerfile must define HEALTHCHECK instruction"
