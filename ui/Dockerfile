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

ENV OPERATIONS_MANAGER_UPSTREAM=operations-manager:8090

EXPOSE 80

HEALTHCHECK --interval=10s --timeout=5s --start-period=15s --retries=15 \
    CMD wget -qO- http://localhost/ >/dev/null || exit 1
