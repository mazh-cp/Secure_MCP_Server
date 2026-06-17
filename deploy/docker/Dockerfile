# secure-mcp server image — runs the network services (edge PDP / admin console).
# Build context is the repo root:  docker build -f deploy/docker/Dockerfile .
#
# No secrets are baked in. The image only contains the code; all keys/tokens are
# injected at runtime from env / a secrets manager (see docker-compose.yml).

FROM python:3.11-slim AS base

# Non-root runtime user.
RUN useradd --system --create-home --home-dir /home/secure-mcp --shell /usr/sbin/nologin secure-mcp

WORKDIR /app
COPY pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir . && \
    # State + log dirs owned by the runtime user (compose mounts volumes here).
    mkdir -p /etc/secure-mcp /var/log/secure-mcp && \
    chown -R secure-mcp:secure-mcp /etc/secure-mcp /var/log/secure-mcp

USER secure-mcp

# Default command is overridden per service in docker-compose.yml
# (secure-mcp-edge / secure-mcp-admin).
ENTRYPOINT []
CMD ["secure-mcp-edge"]
