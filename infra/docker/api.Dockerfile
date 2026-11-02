# syntax=docker/dockerfile:1
# Pinned copy of API Dockerfile in infra/docker
FROM python:3.13-slim@sha256:2d44738ebf4ce5f63b9d9ea871e9c7cfdc0426f7b0c97cac915fd88ded1d86bb AS builder

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UV_LINK_MODE=copy

WORKDIR /build

COPY --from=ghcr.io/astral-sh/uv:0.11.26 /uv /bin/uv
COPY pyproject.toml uv.lock .python-version ./
COPY backend/ ./backend/
COPY engine/ ./engine/
COPY workers/ ./workers/
COPY README.md ./

RUN uv sync --frozen --no-dev --no-editable

FROM python:3.13-slim@sha256:2d44738ebf4ce5f63b9d9ea871e9c7cfdc0426f7b0c97cac915fd88ded1d86bb AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/app/.venv/bin:$PATH"

RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -s /sbin/nologin -d /app appuser

WORKDIR /app

COPY --from=builder --chown=appuser:appgroup /build/.venv /app/.venv
COPY --chown=appuser:appgroup backend /app/backend
COPY --chown=appuser:appgroup engine /app/engine
COPY --chown=appuser:appgroup workers /app/workers
COPY --chown=appuser:appgroup pyproject.toml /app/

USER 10001:10001

EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

ENTRYPOINT ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
