# syntax=docker/dockerfile:1.7
#
# Adhikar — DPR triage console.
# Multi-stage, non-root, single self-contained image. No Node at runtime:
# the UI bundle (ui/vendor/app.min.js) is precompiled and hash-verified in CI.
# The default backend is the offline mock, so the container runs air-gapped
# (invariant I3). Point HARNESS_BACKEND=konsole at a real endpoint to go live.

##############################################################################
# Stage 1 — builder: resolve Python dependencies into an isolated virtualenv
##############################################################################
FROM python:3.13-slim AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /build
COPY requirements.txt ./
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --upgrade pip \
 && /opt/venv/bin/pip install --require-virtualenv -r requirements.txt

##############################################################################
# Stage 2 — runtime: minimal image, unprivileged user, writable data volume
##############################################################################
FROM python:3.13-slim AS runtime

# Runtime hygiene + safe offline defaults (override at deploy time).
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:$PATH" \
    ENVIRONMENT=development \
    HARNESS_BACKEND=mock \
    HARNESS_MODEL=mock-dpr-v1 \
    DEFAULT_REGION=in \
    DATABASE_PATH=/data/adhikar.db \
    ENABLE_DEMO_ENDPOINTS=true

# Bring the resolved venv over from the builder — no build toolchain in runtime.
COPY --from=builder /opt/venv /opt/venv

# Unprivileged user; /data holds the SQLite store (WAL) and must be writable.
RUN groupadd --system --gid 10001 adhikar \
 && useradd --system --uid 10001 --gid adhikar --home-dir /app --no-create-home adhikar \
 && mkdir -p /app /data \
 && chown -R adhikar:adhikar /app /data

WORKDIR /app

# Copy only what the service serves at runtime. Tests, evals, tooling, docs and
# secrets are excluded via .dockerignore.
COPY --chown=adhikar:adhikar app/ ./app/
COPY --chown=adhikar:adhikar data/ ./data/
COPY --chown=adhikar:adhikar ui/ ./ui/

USER adhikar

EXPOSE 8018
VOLUME ["/data"]

# /api/health returns 200 healthy, 503 degraded (DB + audit-chain readiness).
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8018/api/health', timeout=3).status==200 else 1)"

# uvicorn handles SIGTERM for graceful shutdown; bind 0.0.0.0 inside the container.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8018"]
