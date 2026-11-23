# F07 fix: multi-stage build on a slim base pinned by digest, running as a
# dedicated non-root user. Build tools and pip caches stay in the build stage.
# Both stages use the same base; update the two digests together.
FROM python:3.12-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN python -m venv /opt/venv
COPY requirements.txt /tmp/requirements.txt
RUN /opt/venv/bin/pip install -r /tmp/requirements.txt

FROM python:3.12-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
# Apply Debian security updates published after the base image was built.
# The base digest stays pinned; packages come from Debian's signed archive.
RUN apt-get update \
  && apt-get upgrade -y --no-install-recommends \
  && rm -rf /var/lib/apt/lists/*
# A high UID avoids clashing with users on the host.
RUN groupadd --gid 10001 docvault \
  && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin docvault \
  && mkdir -p /data/documents \
  && chown 10001:10001 /data/documents

COPY --from=build /opt/venv /opt/venv
WORKDIR /app
# The code stays owned by root, so the app cannot modify itself.
COPY . .

ENV PATH=/opt/venv/bin:$PATH \
  PYTHONDONTWRITEBYTECODE=1 \
  PYTHONUNBUFFERED=1
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=30s \
  CMD ["python", "-c", "import sys, urllib.request; sys.exit(urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2).read() != b'ok')"]
# Docker Compose runs everything in one container. Kubernetes splits the
# preparation steps into an init container; see deploy/k8s/20-app.yaml.
CMD ["sh", "-c", "python -m app.wait_for_db && alembic upgrade head && python -m app.seed && exec uvicorn app.main:app --host 0.0.0.0 --port 8000"]
