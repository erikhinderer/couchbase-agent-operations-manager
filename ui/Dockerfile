# --- build stage -----------------------------------------------------------
FROM node:22-alpine AS build
WORKDIR /app

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
