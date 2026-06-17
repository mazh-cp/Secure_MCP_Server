#!/usr/bin/env bash
# Generate SELF-SIGNED TLS certs for local/dev (edge + admin). The services
# refuse to bind a non-loopback interface without TLS, so certs are required
# even in the compose network.
#
# Production: use real certificates (Let's Encrypt for the public edge via a
# fronting Caddy/nginx; an internal CA for admin). Do NOT ship self-signed
# certs to production.

set -euo pipefail
cd "$(dirname "$0")"
mkdir -p tls

gen() {
  local name="$1" cn="$2"
  openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -keyout "tls/${name}.key" -out "tls/${name}.crt" \
    -subj "/CN=${cn}" -addext "subjectAltName=DNS:${cn},DNS:localhost,IP:127.0.0.1"
  chmod 600 "tls/${name}.key"
  echo "  wrote tls/${name}.crt + tls/${name}.key"
}

echo "Generating self-signed dev certs in ./tls (gitignored):"
gen edge "${EDGE_CN:-edge.secure-mcp.local}"
gen admin "${ADMIN_CN:-admin.secure-mcp.local}"
echo "Done. These are DEV ONLY — replace with real certs in production."
