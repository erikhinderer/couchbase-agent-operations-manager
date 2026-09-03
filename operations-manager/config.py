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
    "llm_cache_collection": "llm_cache",
    "llm_cache_log_collection": "llm_cache_log",
    "settings_collection": "settings",
    "agent_memory_collection": "agent_memory",
    "users_collection": "users",
    "tools_index": os.getenv("COUCHBASE_TOOLS_INDEX", "tools_rbac_vector_index"),
    "llm_cache_index": os.getenv("COUCHBASE_LLM_CACHE_INDEX", "llm_cache_vector_index"),
    "agent_memory_index": os.getenv("COUCHBASE_AGENT_MEMORY_INDEX", "agent_memory_vector_index"),
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


# ---------------------------------------------------------------------------
# LLM response caching for agents (see app/llm_cache.py)
# ---------------------------------------------------------------------------
# Provider API keys. Every one of these is optional: a provider with no key
# configured still answers on a cache miss, from a clearly-labelled offline
# stub, so the caching gateway and its savings dashboard work on first boot
# with no outbound network access. Configure a key to proxy real calls.
LLM_API_KEYS = {
    "anthropic": os.getenv("ANTHROPIC_API_KEY", ""),
    "openai": os.getenv("OPENAI_API_KEY", ""),
    "google": os.getenv("GEMINI_API_KEY", ""),
}

# Runtime cache policy lives in Couchbase (settings::llm_cache) because it is
# user-editable from the LLM Caching page. These are only the bootstrap
# defaults applied the first time the appliance starts with an empty
# settings collection - after that, the stored document wins.
LLM_CACHE_DEFAULTS = {
    "enabled": os.getenv("LLM_CACHE_ENABLED", "true").lower() != "false",
    "provider": os.getenv("LLM_CACHE_PROVIDER", "anthropic"),
    "model": os.getenv("LLM_CACHE_MODEL", "claude-sonnet-4-5"),
    "ttl_seconds": int(os.getenv("LLM_CACHE_TTL_SECONDS", "3600")),
    "max_entries": int(os.getenv("LLM_CACHE_MAX_ENTRIES", "5000")),
    "similarity_threshold": float(os.getenv("LLM_CACHE_SIMILARITY_THRESHOLD", "0.94")),
    "semantic_enabled": os.getenv("LLM_CACHE_SEMANTIC_ENABLED", "true").lower() != "false",
}

# How long a cache hit/miss event survives before Couchbase expires it. The
# savings dashboard is computed from these events, so this is also how far
# back "tokens saved" can look.
LLM_CACHE_LOG_RETENTION_HOURS = int(os.getenv("LLM_CACHE_LOG_RETENTION_HOURS", str(24 * 30)))

# How many recent cache events the savings dashboard aggregates over.
LLM_CACHE_LOOKBACK_ENTRIES = int(os.getenv("LLM_CACHE_LOOKBACK_ENTRIES", "2000"))


# ---------------------------------------------------------------------------
# Local dashboard login (human users of the Settings/Servers/Roles UI - not
# to be confused with the agent identities above, which authenticate with a
# bearer API key and never see a login page).
# ---------------------------------------------------------------------------
# Signs session tokens (see app/user_auth.py) and, via a derived key, encrypts
# secrets stored at rest in Couchbase (currently just the LDAP bind
# password). Docker Compose generates a random one into .env on first
# `start.sh` run - see that script. Set your own for a non-Docker deploy;
# changing it invalidates every existing session and re-encrypts nothing
# already stored, so rotate LDAP bind creds afterward if you change it in
# production.
# "or", not just the getenv default, so an *empty* env var (a .env
# hand-copied from .env.example without running start.sh, which is what
# actually generates one) still falls back instead of signing sessions
# and encrypting the LDAP bind password with an empty string.
AUTH_SECRET_KEY = os.getenv("AUTH_SECRET_KEY") or "dev-only-insecure-secret-change-me"

# How long a browser session stays signed in before the login page reappears.
AUTH_SESSION_TTL_HOURS = int(os.getenv("AUTH_SESSION_TTL_HOURS", "12"))

# The built-in local account every fresh install boots with. It has no
# password until the first person to reach the login page sets one (see
# POST /v1/auth/bootstrap) - there is no factory-default password to leave
# unchanged.
DEFAULT_ADMIN_USERNAME = os.getenv("DEFAULT_ADMIN_USERNAME", "admin")

# Couchbase settings-collection doc id for the LDAP configuration (same
# settings::<name> convention as settings::llm_cache) - see app/user_auth.py.
LDAP_SETTINGS_DOC = "settings::ldap"
