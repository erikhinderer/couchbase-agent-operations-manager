# --- build stage -----------------------------------------------------------
FROM node:22-alpine AS build
WORKDIR /app

# Bootstrap: append the corporate CA directly onto the trust bundle that's
# already baked into the base image *before* touching the network. Without
# this, `apk add` itself fails - it fetches the Alpine package index over
# HTTPS from dl-cdn.alpinelinux.org, and a TLS-inspecting proxy's cert isn't
# trusted yet, so apk can't even install the ca-certificates package that
# would normally fix that. Once the bundle already includes the corp CA,
# `apk add`/`update-ca-certificates` (and npm afterwards) all work normally.
COPY certs/ /usr/local/share/ca-certificates/extra/
RUN if find /usr/local/share/ca-certificates/extra -name '*.crt' 2>/dev/null | grep -q .; then \
      cat /usr/local/share/ca-certificates/extra/*.crt >> /etc/ssl/certs/ca-certificates.crt && \
      apk add --no-cache ca-certificates && \
      update-ca-certificates; \
    fi
ENV NODE_EXTRA_CA_CERTS=/etc/ssl/certs/ca-certificates.crt

COPY package.json ./
RUN npm install

COPY . .
RUN npm run build

# --- serve stage -------------------------------------------------------------
FROM nginx:1.27-alpine

COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf.template /etc/nginx/templates/default.conf.template

# Same corporate-CA bootstrap as the build stage above (see the comment
# there) - this is a *separate* base image, so trusting the corp CA in the
# build stage does nothing here. Without this, the `apk add` below fails
# the same way: it fetches Alpine's package index over HTTPS, and a
# TLS-inspecting proxy's cert isn't trusted yet.
COPY certs/ /usr/local/share/ca-certificates/extra/
RUN if find /usr/local/share/ca-certificates/extra -name '*.crt' 2>/dev/null | grep -q .; then \
      cat /usr/local/share/ca-certificates/extra/*.crt >> /etc/ssl/certs/ca-certificates.crt && \
      apk add --no-cache ca-certificates && \
      update-ca-certificates; \
    fi

# Fallback self-signed TLS server certificate so this container serves
# HTTPS out of the box with zero configuration (see nginx.conf.template).
# For a real deployment, mount your own certificate over these same two
# paths (a docker-compose volume mount replaces these files, no image
# rebuild or code change needed) - see docker-compose.yml.
RUN apk add --no-cache openssl curl && \
    mkdir -p /etc/nginx/tls && \
    openssl req -x509 -nodes -newkey rsa:2048 -days 825 \
      -keyout /etc/nginx/tls/server.key -out /etc/nginx/tls/server.crt \
      -subj "/CN=localhost" \
      -addext "subjectAltName=DNS:localhost,DNS:ui,DNS:agent-operations-ui,IP:127.0.0.1" \
      2>/dev/null && \
    chmod 600 /etc/nginx/tls/server.key

ENV OPERATIONS_MANAGER_UPSTREAM=operations-manager:8090 \
    OPERATIONS_MANAGER_SCHEME=https

EXPOSE 80 443

HEALTHCHECK --interval=10s --timeout=5s --start-period=15s --retries=15 \
    CMD curl -kfs https://localhost/ >/dev/null || exit 1
