"""
Couchbase Agent Operations Manager - configuration.

Docker Compose supplies safe defaults for every value here. For a local
non-Docker run, set the corresponding environment variables yourself.
"""
import os

APPLIANCE_NAME = os.getenv("APPLIANCE_NAME", "Couchbase Agent Operations Manager")

COUCHBASE_CONFIG = {
    "connection_string": os.getenv("COUCHBASE_CONNECTION_STRING", "couchbase://localhost"),
    "username": os.getenv("COUCHBASE_USERNAME", "Administrator"),
    "password": os.getenv("COUCHBASE_PASSWORD", "CouchbaseDemo123!"),
    "bucket": os.getenv("COUCHBASE_BUCKET", "agent_operations"),
    "scope": os.getenv("COUCHBASE_SCOPE", "agent_operations"),
    "servers_collection": "servers",
    "tools_collection": "tools",
    "identities_collection": "identities",
    "access_log_collection": "access_log",
    "tools_index": os.getenv("COUCHBASE_TOOLS_INDEX", "tools_rbac_vector_index"),
    "search_host": os.getenv("COUCHBASE_SEARCH_HOST", "localhost"),
    "search_port": int(os.getenv("COUCHBASE_SEARCH_PORT", "8094")),
}

# Base URL for the bundled sample MCP tool servers (jira/zendesk/snowflake/
# shadow-diagnostics). Only used to seed the three *trusted* sample servers
# on first boot - real deployments point server registrations at whatever
# MCP endpoints they actually operate, via the Servers page or POST /v1/servers.
SAMPLE_MCP_SERVERS_BASE_URL = os.getenv("SAMPLE_MCP_SERVERS_BASE_URL", "http://localhost:8100")

# Seed identities: API key -> RBAC role, provisioned into the `identities`
# collection on startup if not already present. Rotate these for anything
# beyond local evaluation - see the Roles page / README.
SEED_API_KEYS = {
    os.getenv("API_KEY_SUPPORT_AGENT", "demo-support-agent-9f21"): "support_agent",
    os.getenv("API_KEY_FINANCE_ANALYST", "demo-finance-analyst-7e83"): "finance_analyst",
    os.getenv("API_KEY_ADMIN", "demo-admin-4c56"): "admin",
}

EMBEDDING_CONFIG = {
    "model_name": os.getenv("EMBEDDING_MODEL", "all-MiniLM-L6-v2"),
    "vector_dim": int(os.getenv("EMBEDDING_VECTOR_DIM", "384")),
}

SERVER_CONFIG = {
    "host": os.getenv("HOST", "0.0.0.0"),
    "port": int(os.getenv("PORT", "8090")),
}

# How long an audit-log entry survives before Couchbase expires it. The
# original demo used 24h; an appliance meant to run continuously gets a
# real retention window instead (default 30 days).
AUDIT_LOG_RETENTION_HOURS = int(os.getenv("AUDIT_LOG_RETENTION_HOURS", str(24 * 30)))

# How many recent audit-log entries the insights engine and dashboard
# time series look back over.
INSIGHTS_LOOKBACK_ENTRIES = int(os.getenv("INSIGHTS_LOOKBACK_ENTRIES", "1000"))

# MCP Tool Hijacking detection (see app/hijack_detection.py). The background
# monitor re-scans every already-ingested tool's stored description against
# the current pattern bank on this interval (no MCP round-trip - see
# catalog_ingest.rescan_all_tools). The chain-correlation window is how long
# after a response-poisoning-flagged invoke a subsequent higher-risk invoke
# by the same subject still counts as a possible cross-tool hijack chain.
HIJACK_SCAN_INTERVAL_MINUTES = int(os.getenv("HIJACK_SCAN_INTERVAL_MINUTES", "5"))
HIJACK_CHAIN_WINDOW_SECONDS = int(os.getenv("HIJACK_CHAIN_WINDOW_SECONDS", "120"))

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
