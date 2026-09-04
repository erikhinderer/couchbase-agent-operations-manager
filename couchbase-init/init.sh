#!/bin/sh
# Provisions a fresh Couchbase Server container for the Couchbase Agent
# Operations Manager appliance:
#   1. Initializes the cluster (data, index, query, and search/FTS services)
#   2. Creates the bucket/scope/collections used as the tool registry, the
#      RBAC identity table, and the access audit log
#   3. Creates primary indexes so the app can run N1QL COUNT()/SELECT queries
#
# The two Search (FTS) vector indexes - one over the tool catalog, one over
# the LLM response cache - are created by the operations-manager on startup
# (ensure_search_index() / ensure_llm_cache_index() in
# operations-manager/app/couchbase_client.py) since both depend on the
# embedding model's vector dimension. This script only prepares the
# cluster/bucket/collections.
#
# Safe to re-run: every mutating step tolerates "already exists" failures.

command -v curl >/dev/null 2>&1 || (apt-get update && apt-get install -y curl) || (yum install -y curl) || true

CB_HOST=couchbase
CB_USER="${COUCHBASE_USERNAME:-Administrator}"
CB_PASS="${COUCHBASE_PASSWORD:-CouchbaseDemo123!}"
CB_BUCKET="${COUCHBASE_BUCKET:-agent_operations}"
CB_SCOPE="${COUCHBASE_SCOPE:-agent_operations}"

echo "[couchbase-init] Waiting for Couchbase Server web console..."
until curl -s -o /dev/null http://${CB_HOST}:8091/pools; do
  sleep 2
done

echo "[couchbase-init] Initializing cluster (skips gracefully if already initialized)..."
CLUSTER_INIT_OUTPUT=$(couchbase-cli cluster-init -c ${CB_HOST} \
  --cluster-username "${CB_USER}" \
  --cluster-password "${CB_PASS}" \
  --cluster-ramsize 512 \
  --cluster-index-ramsize 256 \
  --cluster-fts-ramsize 256 \
  --services data,index,query,fts 2>&1)
if echo "${CLUSTER_INIT_OUTPUT}" | grep -qi "already initialized"; then
  echo "[couchbase-init] Cluster was already initialized from a previous run - continuing."
elif echo "${CLUSTER_INIT_OUTPUT}" | grep -qi "SUCCESS"; then
  echo "[couchbase-init] Cluster initialized."
else
  echo "[couchbase-init] cluster-init: ${CLUSTER_INIT_OUTPUT}"
fi

echo "[couchbase-init] Waiting for the cluster to accept authenticated requests..."
until curl -s -o /dev/null -u "${CB_USER}:${CB_PASS}" http://${CB_HOST}:8091/pools/default; do
  sleep 2
done

echo "[couchbase-init] Creating bucket '${CB_BUCKET}' (skips gracefully if it already exists)..."
BUCKET_CREATE_OUTPUT=$(couchbase-cli bucket-create -c ${CB_HOST} -u "${CB_USER}" -p "${CB_PASS}" \
  --bucket ${CB_BUCKET} --bucket-type couchbase --bucket-ramsize 256 2>&1)
if echo "${BUCKET_CREATE_OUTPUT}" | grep -qi "already exists"; then
  echo "[couchbase-init] Bucket '${CB_BUCKET}' already exists from a previous run - continuing."
elif echo "${BUCKET_CREATE_OUTPUT}" | grep -qi "SUCCESS"; then
  echo "[couchbase-init] Bucket '${CB_BUCKET}' created."
else
  echo "[couchbase-init] bucket-create: ${BUCKET_CREATE_OUTPUT}"
fi

sleep 5

echo "[couchbase-init] Creating scope '${CB_SCOPE}'..."
curl -s -u "${CB_USER}:${CB_PASS}" -X POST \
  http://${CB_HOST}:8091/pools/default/buckets/${CB_BUCKET}/scopes \
  -d name=${CB_SCOPE} > /dev/null || true

# servers   - the registered MCP server registry (trust_status, mcp_url, owner)
# tools     - every tool pulled from a trusted registered server: name,
#             description, input_schema, embedding, allowed_roles[], trust
#             status, risk level
# identities- API keys mapped to an RBAC role
# access_log- append-only audit trail of every discovery/invoke decision
# llm_cache - cached LLM completions for agents: prompt hash + embedding,
#             response, token/cost accounting, hit counters (see
#             operations-manager/app/llm_cache.py)
# llm_cache_log - append-only hit/miss/bypass event stream the LLM token
#             savings dashboard is computed from
# settings  - user-editable runtime policy documents (currently
#             settings::llm_cache and settings::ldap, written from the LLM
#             Caching and Settings -> LDAP Authentication pages)
# agent_memory - durable, cross-session agent memory: content + embedding,
#             scoped by user_id/session_id/memory_type (see
#             operations-manager/app/agent_memory.py and the Developer SDK's
#             AOMClient.add_memory/search_memory)
# users     - local dashboard login accounts (bcrypt password hash, role,
#             source local/ldap) - see operations-manager/app/user_auth.py.
#             Not to be confused with `identities` above, which maps agent
#             API keys to an RBAC role.
for COLLECTION in servers tools identities access_log llm_cache llm_cache_log settings agent_memory users; do
  echo "[couchbase-init] Creating collection '${CB_SCOPE}.${COLLECTION}'..."
  curl -s -u "${CB_USER}:${CB_PASS}" -X POST \
    http://${CB_HOST}:8091/pools/default/buckets/${CB_BUCKET}/scopes/${CB_SCOPE}/collections \
    -d name=${COLLECTION} > /dev/null || true
done

echo "[couchbase-init] Waiting for collections to propagate to the Query service..."
sleep 8

echo "[couchbase-init] Creating primary indexes for N1QL support..."
for COLLECTION in servers tools identities access_log llm_cache llm_cache_log settings agent_memory users; do
  curl -s -u "${CB_USER}:${CB_PASS}" http://${CB_HOST}:8093/query/service \
    -d "statement=CREATE PRIMARY INDEX IF NOT EXISTS ON \`${CB_BUCKET}\`.\`${CB_SCOPE}\`.\`${COLLECTION}\`" > /dev/null || true
done

echo "[couchbase-init] Couchbase provisioning complete."

# Provisioning is idempotent and safe to re-run, so rather than exiting
# (which Docker/Docker Desktop shows as a stopped/"unhealthy-looking"
# container even though nothing is wrong), this container marks itself
# done via a sentinel file - the healthcheck in docker-compose.yml just
# checks for its existence - and then idles forever. operations-manager
# waits on this container's *healthcheck*, not its exit code, so this is
# safe: see the service_healthy condition on couchbase-init in
# docker-compose.yml.
echo "[couchbase-init] Marking init complete and idling (keeps this container running so Docker Desktop shows it healthy/green instead of exited)..."
touch /tmp/init-complete
exec tail -f /dev/null
