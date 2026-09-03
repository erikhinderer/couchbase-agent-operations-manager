#!/bin/sh
# Convenience wrapper around `docker compose up --build` that prints the
# multi-container startup sequence a bit more legibly than raw compose
# output does, and reminds you where everything ends up once it's ready.
set -e

echo "=================================================================="
echo " Couchbase Agent Operations Manager - starting the appliance"
echo "=================================================================="
echo
echo "This brings up five containers:"
echo "  1. couchbase            - Couchbase Server Enterprise Edition"
echo "  2. couchbase-init       - one-shot bucket/scope/collection setup"
echo "  3. sample-mcp-servers   - bundled sample MCP tool servers"
echo "  4. operations-manager   - the operations manager itself (RBAC + vector"
echo "                            search pre-filtering, audit log, API)"
echo "  5. ui                   - the admin dashboard"
echo
echo "First boot downloads the Couchbase Enterprise image and an embedding"
echo "model, and can take a few minutes. Subsequent runs are much faster."
echo

if [ ! -f .env ]; then
  echo "No .env found - copying .env.example to .env with default values."
  cp .env.example .env
  echo
fi

docker compose up --build

echo
echo "=================================================================="
echo " Ready. Open:"
echo "   Dashboard             -> http://localhost:5173"
echo "   Operations Manager API -> http://localhost:8090  (see /docs)"
echo "   Couchbase Web Console -> http://localhost:8091"
echo "     (Administrator / CouchbaseDemo123! by default)"
echo "=================================================================="
