"""
Couchbase Agent Operations Manager.

The FastAPI service that stands between an AI agent and the world of MCP
tool servers. An agent never talks to a downstream MCP server directly
here: it authenticates to this service, asks to *discover* tools for a
task (which runs a Couchbase RBAC + vector-search pre-filter, never a full
unfiltered tool dump), and asks this service to *invoke* whichever tool it
picked - which gets checked against Couchbase again before anything is
proxied downstream. Every discovery and invocation decision is written to
an append-only audit log in Couchbase.

Beyond the core discover/invoke gateway, this module also exposes the
admin surface the dashboard UI runs on: server registration, catalog
inspection, roles, the audit log, a derived stats/insights view, and the
MCP Tool Hijacking detection surface (quarantine/release actions plus a
background monitor that re-scans the catalog on a timer - see
app/hijack_detection.py).
"""
import asyncio
import hashlib
import logging
import os
import time
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, Header, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from app import agent_memory, hijack_detection, insights, llm_cache, mcp_client, sdk_packaging, skill_packaging, user_auth
from app.catalog_ingest import ingest_all, ingest_server, rescan_all_tools, seed_servers
from app.couchbase_client import CouchbaseStore
from app.embeddings import ToolEmbeddings
from app.rbac_policy import ROLES
from config import (
    APPLIANCE_NAME,
    AUTH_SECRET_KEY,
    AUTH_SESSION_TTL_HOURS,
    CORS_ALLOWED_ORIGINS,
    COUCHBASE_CONFIG,
    DEFAULT_ADMIN_USERNAME,
    EMBEDDING_CONFIG,
    HIJACK_CHAIN_WINDOW_SECONDS,
    HIJACK_SCAN_INTERVAL_MINUTES,
    INSIGHTS_LOOKBACK_ENTRIES,
    LDAP_SETTINGS_DOC,
    LLM_API_KEYS,
    LLM_CACHE_DEFAULTS,
    LLM_CACHE_LOOKBACK_ENTRIES,
    SAMPLE_MCP_SERVERS_BASE_URL,
    SEED_API_KEYS,
)

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger("operations-manager")

app = FastAPI(
    title=APPLIANCE_NAME,
    description="RBAC + Couchbase Vector Search pre-filtering gateway for MCP tool servers.",
    version="1.0.0",
)
# CORS: the dashboard session cookie makes this security-sensitive (see
# config.CORS_ALLOWED_ORIGINS) - a wildcard origin combined with
# allow_credentials=True would let *any* site's browser JS ride a logged-in
# admin's session cookie to this API. With no origins configured (the
# out-of-the-box case, since the dashboard is always same-origin through
# nginx - see ui/nginx.conf.template), credentialed cross-origin access is
# simply off; agent callers using a Bearer API key are entirely unaffected,
# since that's a header they set themselves; never something a browser
# attaches automatically the way it does a cookie.
if CORS_ALLOWED_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=CORS_ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
else:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[],
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )


# ---------------------------------------------------------------------------
# Security response headers - CIS/PCI-DSS-4.0/NIST-SC-23-aligned defaults
# for every response this API sends. /docs and /redoc are excluded from the
# CSP because FastAPI's bundled Swagger/ReDoc UI loads its JS/CSS from a
# CDN - a strict default-src 'self' there would just break the docs page,
# not protect anything (it's dev/ops tooling, not an attacker-reachable
# surface any differently than the rest of the API).
# ---------------------------------------------------------------------------
_NO_CSP_PATH_PREFIXES = ("/docs", "/redoc", "/openapi.json")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
    # HSTS only makes sense once a client has actually reached us over TLS -
    # this appliance serves HTTPS by default but DISABLE_TLS=true remains a
    # supported plain-HTTP mode (see docker-entrypoint.sh), and sending
    # HSTS over plain HTTP is a no-op at best and a footgun at worst.
    if request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    if not request.url.path.startswith(_NO_CSP_PATH_PREFIXES):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'self'"
        )
    return response

# Paths reachable with no dashboard login session: the login/bootstrap flow
# itself, the health probe, and every agent-facing endpoint - those already
# authenticate their caller with a bearer API key via authenticate() above,
# which has nothing to do with a human's browser session cookie. Everything
# else under /v1 and /api is the dashboard's own admin surface (servers,
# catalog, roles, audit log, threat detection, insights, LLM caching
# policy, Settings) and requires a valid session.
UNPROTECTED_PATH_PREFIXES = (
    "/api/health",
    "/v1/auth/login",
    "/v1/auth/logout",
    "/v1/auth/bootstrap",
    "/v1/tools/discover",
    "/v1/tools/invoke",
    "/v1/llm/complete",
    "/v1/memory",
    "/v1/sdk/",
    "/v1/skills/",
    "/docs",
    "/redoc",
    "/openapi.json",
)


@app.middleware("http")
async def require_dashboard_session(request: Request, call_next):
    path = request.url.path
    if request.method == "OPTIONS" or path.startswith(UNPROTECTED_PATH_PREFIXES):
        return await call_next(request)

    session = user_auth.decode_session_token(request.cookies.get(user_auth.SESSION_COOKIE_NAME))
    if not session:
        return JSONResponse(status_code=401, content={"detail": "Not authenticated"})
    request.state.user = session
    return await call_next(request)


store = CouchbaseStore()
embeddings: ToolEmbeddings | None = None
ready = False
last_hijack_scan_at: str | None = None

# LLM response caching for agents (see app/llm_cache.py). The policy is
# user-editable from the LLM Caching page and persisted in Couchbase, so it
# is loaded on startup and kept in memory for the hot path - a cache lookup
# should never cost an extra round-trip just to read its own settings.
LLM_CACHE_SETTINGS_DOC = "settings::llm_cache"
llm_config: dict = llm_cache.normalize_config(LLM_CACHE_DEFAULTS)
llm_config_version: str = llm_cache.config_fingerprint(llm_config)
llm_catalog_version: str = ""
last_llm_sweep_at: str | None = None

# Local dashboard login (see app/user_auth.py). The LDAP policy is
# user-editable from Settings -> LDAP Authentication and persisted in
# Couchbase at settings::ldap, loaded into memory here the same way the LLM
# cache policy is - a login attempt should never cost an extra Couchbase
# round-trip just to find out whether LDAP is even enabled.
ldap_config: dict = user_auth.normalize_ldap_config(None)


@app.on_event("startup")
async def startup():
    global embeddings, ready, last_hijack_scan_at
    logger.info("Loading local embedding model...")
    embeddings = ToolEmbeddings(EMBEDDING_CONFIG["model_name"])

    if AUTH_SECRET_KEY == "dev-only-insecure-secret-change-me":
        logger.warning(
            "AUTH_SECRET_KEY is unset - using the insecure built-in default. Dashboard login sessions and any "
            "stored LDAP bind password are only as safe as that well-known string. Set AUTH_SECRET_KEY (start.sh "
            "does this for you automatically) before relying on this outside local evaluation."
        )

    if COUCHBASE_CONFIG["password"] == "CouchbaseDemo123!":
        logger.warning(
            "COUCHBASE_PASSWORD is unset - using the well-known bundled demo password. Anyone who has ever read "
            "this project's README or .env.example knows it. Set COUCHBASE_USERNAME/COUCHBASE_PASSWORD to a real, "
            "unique credential (PCI DSS 4.0 Req. 8.3.1 / CIS 'no default credentials') before relying on this "
            "outside local evaluation - see .env.example."
        )

    logger.info("Connecting to Couchbase...")
    await store.connect()

    if store.connected:
        for api_key, role in SEED_API_KEYS.items():
            await store.upsert_identity(api_key, role, label=f"...{api_key[-4:]}")

        await seed_default_admin()
        await load_ldap_config()

        await seed_servers(store, SAMPLE_MCP_SERVERS_BASE_URL)

        existing = await store.count_tools()
        logger.info("Ingesting registered/trusted MCP server catalogs into Couchbase (currently %d tool doc(s) stored)...", existing)
        await ingest_all(store, embeddings)
        # ingest_all already ran the metadata-poisoning scan against every
        # tool it (re-)ingested, so this counts as the first monitor pass.
        last_hijack_scan_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        asyncio.create_task(hijack_monitor_loop())

        await load_llm_config()
        await refresh_catalog_version()
        asyncio.create_task(llm_cache_sweeper_loop())

    ready = True
    logger.info("Operations manager ready (couchbase_connected=%s)", store.connected)


async def hijack_monitor_loop():
    """The MCP Tool Hijacking monitor: on a fixed interval, re-scan every
    already-ingested tool's stored description against the current pattern
    bank, with no MCP round-trip (see catalog_ingest.rescan_all_tools).
    This is what catches a tool ingested before hijack detection existed,
    or before a pattern-bank update - the ingest-time scan alone only ever
    sees each tool once, at the moment it's (re-)ingested."""
    global last_hijack_scan_at
    while True:
        await asyncio.sleep(HIJACK_SCAN_INTERVAL_MINUTES * 60)
        if not store.connected:
            continue
        try:
            changed = await rescan_all_tools(store)
            last_hijack_scan_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            if changed:
                logger.info("Hijack monitor: %d tool(s) changed trust/hijack status on this pass", changed)
        except Exception as exc:  # noqa: BLE001
            logger.error("Hijack monitor pass failed: %s", exc)


async def seed_default_admin():
    """Provision the built-in `admin` account on first boot, with no
    password set yet - see POST /v1/auth/bootstrap. Idempotent: does
    nothing once that account already exists, so it never resets a
    password an operator has already chosen."""
    existing = await store.get_user(DEFAULT_ADMIN_USERNAME)
    if existing:
        return
    doc = user_auth.new_local_user_doc(role="admin", password_hash=None, source="local", must_change_password=True)
    await store.upsert_user(DEFAULT_ADMIN_USERNAME, doc)
    logger.info("Seeded default local account '%s' - password not yet set (first login sets it).", DEFAULT_ADMIN_USERNAME)


def _warn_if_ldap_tls_unverified(cfg: dict) -> None:
    """LDAPS/StartTLS with no corporate CA configured means ldap3 does not
    validate the directory's certificate at all (see
    user_auth.ldap_authenticate) - functionally equivalent to skipping TLS
    verification, which leaves the bind vulnerable to an on-path MITM
    presenting any certificate. Not escalated to a hard failure here: that
    would break existing working deployments the moment this code shipped,
    for admins who never had a reason to think about this. A loud warning
    at every load/save is the honest middle ground (NIST SC-8, PCI DSS 4.0
    Req. 4.2.1) - see also Settings -> LDAP Authentication for uploading one."""
    if cfg.get("enabled") and (cfg.get("use_ssl") or cfg.get("start_tls")) and not (cfg.get("ca_certificate") or "").strip():
        logger.warning(
            "LDAP is configured for LDAPS/StartTLS but no corporate CA certificate is installed - the directory "
            "server's certificate is NOT being validated (any certificate is accepted), which is vulnerable to an "
            "on-path attacker. Upload your directory's CA certificate under Settings -> LDAP Authentication."
        )


async def load_ldap_config():
    global ldap_config
    stored = await store.get_setting(LDAP_SETTINGS_DOC)
    ldap_config = user_auth.normalize_ldap_config(stored.get("config") if stored else None)
    logger.info("LDAP config loaded (enabled=%s host=%s)", ldap_config["enabled"], ldap_config["host"] or "-")
    _warn_if_ldap_tls_unverified(ldap_config)


async def save_ldap_config(cfg: dict):
    global ldap_config
    ldap_config = user_auth.normalize_ldap_config(cfg)
    await store.upsert_setting(
        LDAP_SETTINGS_DOC,
        {
            "doc_type": "settings",
            "setting_id": "ldap",
            "config": ldap_config,
            "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
    )
    _warn_if_ldap_tls_unverified(ldap_config)


async def load_llm_config():
    """Read the stored cache policy, falling back to the .env bootstrap
    defaults the first time this appliance ever starts."""
    global llm_config, llm_config_version
    stored = await store.get_setting(LLM_CACHE_SETTINGS_DOC)
    llm_config = llm_cache.normalize_config(stored.get("config") if stored else LLM_CACHE_DEFAULTS)
    llm_config_version = llm_cache.config_fingerprint(llm_config)
    if not stored:
        await save_llm_config(llm_config)
    logger.info(
        "LLM cache policy loaded (provider=%s model=%s ttl=%ss semantic=%s)",
        llm_config["provider"], llm_config["model"], llm_config["ttl_seconds"], llm_config["semantic_enabled"],
    )


async def save_llm_config(cfg: dict):
    global llm_config, llm_config_version
    llm_config = llm_cache.normalize_config(cfg)
    llm_config_version = llm_cache.config_fingerprint(llm_config)
    await store.upsert_setting(
        LLM_CACHE_SETTINGS_DOC,
        {
            "doc_type": "settings",
            "setting_id": "llm_cache",
            "config": llm_config,
            "config_version": llm_config_version,
            "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
    )


async def refresh_catalog_version() -> str:
    """A fingerprint of the vetted tool catalog. Only consulted when the
    `invalidate_on_catalog_change` policy is on - an agent's answer can
    depend on which tools it was allowed to see, so a catalog change is a
    legitimate reason to stop reusing an answer produced before it."""
    global llm_catalog_version
    try:
        tools = await store.list_tools()
        material = "|".join(sorted(f"{t.get('tool_id')}:{t.get('trust_status')}" for t in tools))
        llm_catalog_version = hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not compute catalog version: %s", exc)
    return llm_catalog_version


async def llm_cache_sweeper_loop():
    """Enforces the parts of the invalidation policy that nothing else would
    notice on its own: entries whose TTL, reuse limit, model, config or
    catalog fingerprint has gone stale, and overflow past `max_entries`
    under the configured eviction policy.

    Couchbase document expiry already reclaims TTL'd entries, so this is
    belt-and-braces for TTL - but it is the *only* thing that applies the
    other four rules to entries nobody happens to read again."""
    global last_llm_sweep_at
    while True:
        await asyncio.sleep(max(60, int(llm_config.get("sweep_interval_minutes", 5)) * 60))
        if not store.connected:
            continue
        try:
            removed = await sweep_llm_cache()
            last_llm_sweep_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            if removed:
                logger.info("LLM cache sweeper removed %d entr(ies) on this pass", removed)
        except Exception as exc:  # noqa: BLE001
            logger.error("LLM cache sweep failed: %s", exc)


async def sweep_llm_cache() -> int:
    """One sweeper pass. Returns how many entries were removed."""
    await refresh_catalog_version()
    entries = await store.list_cache_entries(limit=10000)
    now = time.time()
    removed = 0
    survivors = []
    for entry in entries:
        state, _reason = llm_cache.evaluate_entry(
            entry, llm_config, now=now,
            config_version=llm_config_version, catalog_version=llm_catalog_version,
        )
        if state == "invalid":
            if await store.delete_cache_entry(entry["entry_id"]):
                removed += 1
        else:
            survivors.append(entry)

    for entry_id in llm_cache.select_evictions(survivors, llm_config):
        if await store.delete_cache_entry(entry_id):
            removed += 1
    return removed


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------
class DiscoverRequest(BaseModel):
    query: str
    top_k: int = 5


class InvokeRequest(BaseModel):
    tool_id: str
    arguments: dict = {}


class RegisterServerRequest(BaseModel):
    server_id: str = Field(..., pattern=r"^[a-z0-9][a-z0-9_-]{1,63}$")
    label: str
    owner: str = "Unassigned"
    mcp_url: str
    trust_status: str = "trusted"  # "trusted" | "untrusted"
    default_allowed_roles: list[str] = Field(default_factory=list)


# -- Local dashboard login ---------------------------------------------------
class LoginRequest(BaseModel):
    username: str
    password: str


class BootstrapRequest(BaseModel):
    password: str


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


class CreateUserRequest(BaseModel):
    username: str = Field(..., pattern=r"^[a-zA-Z0-9._-]{2,64}$")
    password: str
    role: str = user_auth.DEFAULT_LOCAL_ROLE
    must_change_password: bool = True


class UpdateUserRequest(BaseModel):
    role: str | None = None
    active: bool | None = None
    password: str | None = None
    must_change_password: bool | None = None


class LdapConfigRequest(BaseModel):
    # Raw dict, same convention as LLMConfigRequest.config - validated
    # server-side by user_auth.normalize_ldap_config, not by this shape.
    # An included "bind_password" (plain text) sets/replaces the encrypted
    # secret; omitting it (or sending "") leaves the stored one unchanged.
    config: dict
    bind_password: str | None = None


class LdapTestRequest(BaseModel):
    username: str
    password: str


class LdapCaCertificateRequest(BaseModel):
    ca_certificate: str


class ServerCertificateRequest(BaseModel):
    cert_pem: str
    key_pem: str


# ---------------------------------------------------------------------------
# Auth helper
# ---------------------------------------------------------------------------
async def authenticate(authorization: str | None) -> tuple[str, str]:
    """Resolve an `Authorization: Bearer <api_key>` header to (role,
    masked_subject_label). Raises HTTPException(401) if missing/invalid -
    every failure here is exactly the kind of thing an unauthenticated MCP
    setup has no equivalent check for at all."""
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing Authorization: Bearer <api_key> header")
    api_key = authorization.split(" ", 1)[1].strip()
    role = await store.resolve_role(api_key)
    if not role:
        await store.log_access(
            action="authenticate", role=None, subject_label="unknown", query=None,
            tool_id=None, server_id=None, decision="DENY", reason="invalid or unrecognized API key", latency_ms=0,
        )
        raise HTTPException(status_code=401, detail="Invalid API key")
    return role, f"...{api_key[-4:]}"


def require_admin(request: Request) -> dict:
    """Dashboard-session counterpart to authenticate() above: require_dashboard_session
    (the app middleware) already guarantees request.state.user exists on any
    protected path, so this only adds the role check for the Settings
    surface (local accounts, LDAP config) - the parts of Settings the
    request explicitly scopes to admin users."""
    user = getattr(request.state, "user", None)
    if not user or user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")
    return user


# ---------------------------------------------------------------------------
# Health / roles
# ---------------------------------------------------------------------------
@app.get("/api/health")
async def health():
    return {
        "status": "ok" if ready else "starting",
        "appliance": APPLIANCE_NAME,
        "couchbase_connected": store.connected,
        "embeddings_ready": embeddings is not None,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


@app.get("/v1/roles")
async def roles():
    return {"roles": [{"id": rid, "description": desc} for rid, desc in ROLES.items()]}


# ---------------------------------------------------------------------------
# Developer SDK distribution (see Tools -> Developer SDK in the dashboard)
# ---------------------------------------------------------------------------
@app.get("/v1/sdk/info")
async def sdk_info():
    """Metadata for the Developer SDK download button - version, filename
    and size - without shipping the archive bytes themselves."""
    if not sdk_packaging.sdk_available():
        raise HTTPException(status_code=404, detail="Developer SDK is not bundled in this image")
    archive = sdk_packaging.build_sdk_archive()
    return {
        "version": sdk_packaging.sdk_version(),
        "filename": sdk_packaging.sdk_filename(),
        "size_bytes": len(archive),
    }


@app.get("/v1/sdk/download")
async def sdk_download():
    """Zips operations-manager/sdk/ on demand and serves it as an
    attachment, so the download always matches the SDK source shipped in
    this running image rather than a prebuilt artifact that can go stale."""
    if not sdk_packaging.sdk_available():
        raise HTTPException(status_code=404, detail="Developer SDK is not bundled in this image")
    archive = sdk_packaging.build_sdk_archive()
    filename = sdk_packaging.sdk_filename()
    return Response(
        content=archive,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ---------------------------------------------------------------------------
# AI-assistant integration skills (Claude / ChatGPT / Gemini) - same
# integration knowledge as the Developer SDK guide, packaged for each
# assistant's own way of taking custom instructions. See
# operations-manager/skills/ and app/skill_packaging.py.
# ---------------------------------------------------------------------------
@app.get("/v1/skills/{platform}/info")
async def skill_info(platform: str):
    if platform not in skill_packaging.PLATFORMS:
        raise HTTPException(status_code=404, detail=f"Unknown skill platform '{platform}'")
    if not skill_packaging.skill_available(platform):
        raise HTTPException(status_code=404, detail=f"{skill_packaging.skill_label(platform)} is not bundled in this image")
    archive = skill_packaging.build_skill_archive(platform)
    return {
        "platform": platform,
        "label": skill_packaging.skill_label(platform),
        "version": sdk_packaging.sdk_version(),
        "filename": skill_packaging.skill_filename(platform),
        "size_bytes": len(archive),
    }


@app.get("/v1/skills/{platform}/download")
async def skill_download(platform: str):
    if platform not in skill_packaging.PLATFORMS:
        raise HTTPException(status_code=404, detail=f"Unknown skill platform '{platform}'")
    if not skill_packaging.skill_available(platform):
        raise HTTPException(status_code=404, detail=f"{skill_packaging.skill_label(platform)} is not bundled in this image")
    archive = skill_packaging.build_skill_archive(platform)
    filename = skill_packaging.skill_filename(platform)
    return Response(
        content=archive,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ---------------------------------------------------------------------------
# Server registry
# ---------------------------------------------------------------------------
@app.get("/v1/servers")
async def list_servers_route():
    servers = await store.list_servers()
    tools = await store.list_tools()
    counts: dict[str, int] = {}
    for t in tools:
        sid = t.get("server_id")
        counts[sid] = counts.get(sid, 0) + 1
    for s in servers:
        s["tool_count"] = counts.get(s.get("server_id"), 0)
    return {"servers": servers}


@app.post("/v1/servers")
async def register_server(req: RegisterServerRequest):
    if req.trust_status not in ("trusted", "untrusted"):
        raise HTTPException(status_code=400, detail="trust_status must be 'trusted' or 'untrusted'")
    existing = await store.get_server(req.server_id)
    if existing:
        raise HTTPException(status_code=409, detail=f"Server '{req.server_id}' is already registered")

    unknown_roles = [r for r in req.default_allowed_roles if r not in ROLES]
    if unknown_roles:
        raise HTTPException(status_code=400, detail=f"Unknown role(s): {unknown_roles}")

    server_doc = {
        "server_id": req.server_id,
        "label": req.label,
        "owner": req.owner,
        "mcp_url": req.mcp_url,
        "trust_status": req.trust_status,
        "default_allowed_roles": req.default_allowed_roles,
        "seeded": False,
    }
    await store.upsert_server(req.server_id, server_doc)

    ingested_tools = 0
    ingest_error = None
    if req.trust_status == "trusted" and embeddings is not None:
        try:
            ingested_tools = await ingest_server(store, embeddings, server_doc)
        except Exception as exc:  # noqa: BLE001
            ingest_error = str(exc)
            logger.error("Ingestion failed for newly registered server '%s': %s", req.server_id, exc)

    return {"server": server_doc, "ingested_tools": ingested_tools, "ingest_error": ingest_error}


@app.post("/v1/servers/{server_id}/reingest")
async def reingest_server_route(server_id: str):
    server_doc = await store.get_server(server_id)
    if not server_doc:
        raise HTTPException(status_code=404, detail="Server not registered")
    if server_doc.get("trust_status") != "trusted":
        raise HTTPException(status_code=400, detail="Server is not trusted - mark it trusted before ingesting its catalog")
    if embeddings is None:
        raise HTTPException(status_code=503, detail="Operations manager not fully initialized yet")
    try:
        count = await ingest_server(store, embeddings, server_doc)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"Ingestion failed: {exc}") from exc
    return {"server_id": server_id, "ingested_tools": count}


@app.delete("/v1/servers/{server_id}")
async def delete_server_route(server_id: str):
    deleted = await store.delete_server(server_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Server not registered")
    tools_removed = await store.delete_tools_by_server(server_id)
    return {"deleted": True, "server_id": server_id, "tools_removed": tools_removed}


# ---------------------------------------------------------------------------
# Catalog / audit log
# ---------------------------------------------------------------------------
@app.get("/v1/catalog")
async def catalog():
    """Full transparency view of everything actually stored in Couchbase's
    tool registry, for the dashboard UI to display."""
    return {"tools": await store.list_tools()}


@app.get("/v1/audit-log")
async def audit_log(limit: int = 50):
    return {"entries": await store.recent_access_log(limit=min(limit, 200))}


# ---------------------------------------------------------------------------
# Discover / invoke
# ---------------------------------------------------------------------------
@app.post("/v1/tools/discover")
async def discover(req: DiscoverRequest, authorization: str | None = Header(default=None)):
    role, subject = await authenticate(authorization)
    if not store.connected or embeddings is None:
        raise HTTPException(status_code=503, detail="Operations manager not fully initialized yet")

    start = time.time()
    vector = embeddings.embed(req.query)
    tools = await store.discover_tools(role, vector, top_k=req.top_k)
    latency_ms = int((time.time() - start) * 1000)

    await store.log_access(
        action="discover", role=role, subject_label=subject, query=req.query,
        tool_id=None, server_id=None, decision="ALLOW",
        reason=f"{len(tools)} tool(s) matched RBAC+vector pre-filter for role '{role}'", latency_ms=latency_ms,
    )
    return {"role": role, "tools": tools, "latency_ms": latency_ms}


@app.post("/v1/tools/invoke")
async def invoke(req: InvokeRequest, authorization: str | None = Header(default=None)):
    role, subject = await authenticate(authorization)
    start = time.time()

    tool = await store.get_tool(req.tool_id)
    if not tool:
        latency_ms = int((time.time() - start) * 1000)
        await store.log_access(
            action="invoke", role=role, subject_label=subject, query=None, tool_id=req.tool_id, server_id=None,
            decision="DENY", reason="tool not found in the vetted Couchbase catalog", latency_ms=latency_ms,
        )
        raise HTTPException(status_code=404, detail="Unknown tool - it is not in the vetted catalog")

    # Second, independent authorization check - never trust that a client
    # only ever asks for tools it was shown by /v1/tools/discover.
    if tool.get("trust_status") != "trusted" or role not in (tool.get("allowed_roles") or []):
        latency_ms = int((time.time() - start) * 1000)
        await store.log_access(
            action="invoke", role=role, subject_label=subject, query=None, tool_id=req.tool_id,
            server_id=tool.get("server_id"), decision="DENY",
            reason=f"role '{role}' is not authorized for tool '{req.tool_id}' (requires one of {tool.get('allowed_roles')})",
            latency_ms=latency_ms,
        )
        raise HTTPException(status_code=403, detail=f"Role '{role}' is not authorized to invoke '{req.tool_id}'")

    server_doc = await store.get_server(tool.get("server_id"))
    if not server_doc:
        latency_ms = int((time.time() - start) * 1000)
        await store.log_access(
            action="invoke", role=role, subject_label=subject, query=None, tool_id=req.tool_id,
            server_id=tool.get("server_id"), decision="DENY", reason="owning server is not registered", latency_ms=latency_ms,
        )
        raise HTTPException(status_code=404, detail="Owning server is not registered")

    try:
        result = await mcp_client.call_tool(server_doc["mcp_url"], tool["name"], req.arguments)
        latency_ms = int((time.time() - start) * 1000)

        # Response payload poisoning can't be caught at ingest time - the
        # payload doesn't exist until the call happens - so it's scanned
        # here, on every successful invoke, and flagged rather than
        # withheld (see app/hijack_detection.py for why). The finding rides
        # on the audit-log entry itself so chain correlation in the
        # insights engine can pick it up without a second lookup.
        hijack = hijack_detection.scan_response_payload(result)
        reason = "invoked via scoped operations-manager proxy"
        if hijack["flagged"]:
            reason += f" - response flagged for possible prompt injection ({hijack['severity']})"
            logger.warning(
                "Response payload from '%s' flagged: %s", req.tool_id, [s["pattern_id"] for s in hijack["signals"]]
            )

        await store.log_access(
            action="invoke", role=role, subject_label=subject, query=None, tool_id=req.tool_id,
            server_id=tool.get("server_id"), decision="ALLOW", reason=reason, latency_ms=latency_ms,
            hijack_flagged=hijack["flagged"], hijack_severity=hijack["severity"], hijack_signals=hijack["signals"],
        )
        return {
            "role": role,
            "tool_id": req.tool_id,
            "result": result,
            "latency_ms": latency_ms,
            "hijack_warning": hijack if hijack["flagged"] else None,
        }
    except Exception as exc:  # noqa: BLE001
        latency_ms = int((time.time() - start) * 1000)
        await store.log_access(
            action="invoke", role=role, subject_label=subject, query=None, tool_id=req.tool_id,
            server_id=tool.get("server_id"), decision="ERROR", reason=str(exc), latency_ms=latency_ms,
        )
        raise HTTPException(status_code=502, detail=f"Downstream MCP call failed: {exc}") from exc


# ---------------------------------------------------------------------------
# Threat detection (MCP Tool Hijacking)
# ---------------------------------------------------------------------------
@app.get("/v1/threat-detection")
async def threat_detection():
    tools = await store.list_tools()
    log_entries = await store.recent_access_log(limit=INSIGHTS_LOOKBACK_ENTRIES)
    tools_by_id = {t["tool_id"]: t for t in tools if t.get("tool_id")}

    quarantined = [t for t in tools if t.get("trust_status") == "quarantined"]
    flagged_responses = [e for e in log_entries if e.get("action") == "invoke" and e.get("hijack_flagged")][:50]
    chain_findings = hijack_detection.detect_hijack_chains(log_entries, tools_by_id, window_seconds=HIJACK_CHAIN_WINDOW_SECONDS)

    return {
        "last_scan_at": last_hijack_scan_at,
        "scan_interval_minutes": HIJACK_SCAN_INTERVAL_MINUTES,
        "chain_window_seconds": HIJACK_CHAIN_WINDOW_SECONDS,
        "quarantined_tools": quarantined,
        "flagged_responses": flagged_responses,
        "chain_findings": chain_findings,
    }


@app.post("/v1/tools/{tool_id:path}/release")
async def release_tool_route(tool_id: str):
    """Admin action: release a tool from quarantine. Sets a manual
    override that survives future re-ingests and background rescans -
    without it, the next scan pass would just re-quarantine a tool whose
    description still matches a pattern."""
    tool = await store.get_tool(tool_id)
    if not tool:
        raise HTTPException(status_code=404, detail="Tool not found in the catalog")
    tool["trust_status"] = "trusted"
    tool["hijack_manual_override"] = "trusted"
    await store.upsert_tool(tool_id, tool)
    return {"tool_id": tool_id, "trust_status": "trusted"}


@app.post("/v1/tools/{tool_id:path}/quarantine")
async def quarantine_tool_route(tool_id: str):
    """Admin action: quarantine a tool by hand, even if the scanner didn't
    flag it - e.g. a signal an admin caught by reading the description
    that the pattern bank doesn't cover yet."""
    tool = await store.get_tool(tool_id)
    if not tool:
        raise HTTPException(status_code=404, detail="Tool not found in the catalog")
    tool["trust_status"] = "quarantined"
    tool["hijack_manual_override"] = "quarantined"
    await store.upsert_tool(tool_id, tool)
    return {"tool_id": tool_id, "trust_status": "quarantined"}


@app.post("/v1/tools/{tool_id:path}/clear-override")
async def clear_override_route(tool_id: str):
    """Remove a manual release/quarantine override and let the scanner
    decide this tool's trust_status fresh, from its current stored
    description."""
    tool = await store.get_tool(tool_id)
    if not tool:
        raise HTTPException(status_code=404, detail="Tool not found in the catalog")
    tool.pop("hijack_manual_override", None)
    tool = hijack_detection.apply_metadata_scan(tool, {})
    await store.upsert_tool(tool_id, tool)
    return {"tool_id": tool_id, "trust_status": tool["trust_status"]}


# ---------------------------------------------------------------------------
# Dashboard / insights
# ---------------------------------------------------------------------------
@app.get("/v1/insights")
async def insights_route():
    servers = await store.list_servers()
    tools = await store.list_tools()
    log_entries = await store.recent_access_log(limit=INSIGHTS_LOOKBACK_ENTRIES)
    return {"findings": insights.compute_insights(servers, tools, log_entries)}


@app.get("/v1/dashboard")
async def dashboard():
    servers = await store.list_servers()
    tools = await store.list_tools()
    log_entries = await store.recent_access_log(limit=INSIGHTS_LOOKBACK_ENTRIES)

    findings = insights.compute_insights(servers, tools, log_entries)
    decisions = insights.decision_breakdown(log_entries)
    actions = insights.action_breakdown(log_entries)
    hourly = insights.hourly_volume(log_entries, buckets=12)

    cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")
    events_24h = sum(1 for e in log_entries if (e.get("timestamp") or "") >= cutoff)

    total_decisions = decisions["ALLOW"] + decisions["DENY"] + decisions["ERROR"]
    deny_rate_pct = round((decisions["DENY"] / total_decisions) * 100, 1) if total_decisions else 0.0

    return {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "events_examined": len(log_entries),
        "summary": {
            "registered_servers": len(servers),
            "trusted_servers": sum(1 for s in servers if s.get("trust_status") == "trusted"),
            "tools_ingested": len(tools),
            "quarantined_tools": sum(1 for t in tools if t.get("trust_status") == "quarantined"),
            "roles": len(ROLES),
            "access_events_24h": events_24h,
            "deny_rate_pct": deny_rate_pct,
            "open_findings": len(findings),
        },
        "decision_breakdown": decisions,
        "action_breakdown": actions,
        "hourly_volume": hourly,
        "top_findings": findings[:5],
    }


# ---------------------------------------------------------------------------
# LLM response caching for agents
# ---------------------------------------------------------------------------
# Same shape as the tool gateway: the agent authenticates here, the
# operations manager decides, and every decision is recorded. The difference
# is that the decision is "has this already been answered?" - and when the
# answer is yes, no tokens leave the building.
class LLMCompleteRequest(BaseModel):
    prompt: str
    provider: str | None = None
    model: str | None = None
    namespace: str | None = None
    bypass_cache: bool = False
    params: dict = Field(default_factory=dict)


class LLMConfigRequest(BaseModel):
    config: dict


class PurgeCacheRequest(BaseModel):
    provider: str | None = None
    model: str | None = None
    namespace: str | None = None


@app.get("/v1/llm/providers")
async def llm_providers():
    """The selectable LLMs - Claude, ChatGPT and Gemini - with their models
    and list-price estimates, plus whether each one has an API key
    configured. Keys themselves are never returned."""
    return {"providers": llm_cache.provider_catalog(LLM_API_KEYS)}


@app.get("/v1/llm/config")
async def get_llm_config():
    return {
        "config": llm_config,
        "config_version": llm_config_version,
        "defaults": llm_cache.DEFAULT_CACHE_CONFIG,
        "cache_scopes": list(llm_cache.CACHE_SCOPES),
        "eviction_policies": list(llm_cache.EVICTION_POLICIES),
        "last_sweep_at": last_llm_sweep_at,
        "cached_entries": await store.count_cache_entries(),
    }


@app.put("/v1/llm/config")
async def put_llm_config(req: LLMConfigRequest):
    """Save the cache policy. Every value is re-validated server-side (see
    llm_cache.normalize_config) - the setup form is a convenience, not the
    boundary.

    If the change moves the config fingerprint and `invalidate_on_config_change`
    is on, an immediate sweep runs so the user sees the invalidation they just
    asked for rather than waiting for the next timer tick."""
    previous_version = llm_config_version
    previous_model = llm_config.get("model")
    await save_llm_config(req.config)

    config_changed = llm_config.get("invalidate_on_config_change") and llm_config_version != previous_version
    model_changed = llm_config.get("invalidate_on_model_change") and llm_config.get("model") != previous_model
    invalidated = await sweep_llm_cache() if (config_changed or model_changed) else 0
    return {
        "config": llm_config,
        "config_version": llm_config_version,
        "entries_invalidated": invalidated,
    }


@app.post("/v1/llm/complete")
async def llm_complete(req: LLMCompleteRequest, authorization: str | None = Header(default=None)):
    role, subject = await authenticate(authorization)
    if not req.prompt or not req.prompt.strip():
        raise HTTPException(status_code=400, detail="prompt is required")
    if not store.connected:
        raise HTTPException(status_code=503, detail="Operations manager not fully initialized yet")

    cfg = dict(llm_config)
    if req.namespace:
        cfg["namespace"] = req.namespace
        cfg = llm_cache.normalize_config(cfg)

    provider = req.provider or cfg["provider"]
    if provider not in llm_cache.PROVIDERS:
        raise HTTPException(status_code=400, detail=f"Unknown provider '{provider}' (expected one of {list(llm_cache.PROVIDERS)})")
    model = req.model or (cfg["model"] if provider == cfg["provider"] else llm_cache.PROVIDERS[provider]["default_model"])
    if model not in llm_cache.PROVIDERS[provider]["models"]:
        raise HTTPException(status_code=400, detail=f"Model '{model}' is not offered by provider '{provider}'")

    start = time.time()
    scope = llm_cache.scope_key(cfg, role, subject)
    eid = llm_cache.entry_id(cfg, provider, model, req.prompt, req.params, scope)

    bypass_reason = None
    if not cfg.get("enabled"):
        bypass_reason = "caching is disabled in the current policy"
    elif req.bypass_cache:
        bypass_reason = "caller requested bypass_cache"
    else:
        bypass_reason = llm_cache.is_bypassed(req.prompt, cfg, role)

    # ---- read path -------------------------------------------------------
    if not bypass_reason:
        hit, similarity, invalidation = await _lookup_cache(cfg, provider, model, scope, eid, req.prompt)
        if hit:
            latency_ms = int((time.time() - start) * 1000)
            updated = await _record_cache_hit(hit, cfg, similarity is not None)
            saved_ms = max(0, int(hit.get("origin_latency_ms") or 0) - latency_ms)
            outcome = "hit_semantic" if similarity is not None else "hit_exact"
            await store.log_llm_event({
                "doc_type": "llm_cache_event",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "outcome": outcome,
                "provider": provider,
                "model": model,
                "role": role,
                "subject": subject,
                "entry_id": hit["entry_id"],
                "namespace": cfg["namespace"],
                "scope_key": scope,
                "similarity": similarity,
                "prompt_preview": req.prompt.strip()[:240],
                "prompt_tokens": hit.get("prompt_tokens", 0),
                "completion_tokens": hit.get("completion_tokens", 0),
                "total_tokens": hit.get("total_tokens", 0),
                "tokens_saved": hit.get("total_tokens", 0),
                "cost_usd": 0.0,
                "cost_saved_usd": hit.get("cost_usd", 0.0),
                "latency_ms": latency_ms,
                "latency_saved_ms": saved_ms,
                "reason": f"served from cache ({outcome.replace('hit_', '')} match)",
            })
            return {
                "provider": provider,
                "model": model,
                "role": role,
                "response": hit.get("response", ""),
                "cache": {
                    "status": outcome,
                    "entry_id": hit["entry_id"],
                    "similarity": similarity,
                    "hit_count": updated,
                    "created_at": hit.get("created_at"),
                    "reason": invalidation,
                },
                "usage": {
                    "prompt_tokens": hit.get("prompt_tokens", 0),
                    "completion_tokens": hit.get("completion_tokens", 0),
                    "total_tokens": hit.get("total_tokens", 0),
                },
                "cost_usd": 0.0,
                "tokens_saved": hit.get("total_tokens", 0),
                "cost_saved_usd": hit.get("cost_usd", 0.0),
                "latency_ms": latency_ms,
                "stub": bool(hit.get("stub")),
            }

    # ---- miss path -------------------------------------------------------
    try:
        result = await asyncio.to_thread(llm_cache.call_provider, provider, model, req.prompt, cfg, LLM_API_KEYS)
    except Exception as exc:  # noqa: BLE001
        latency_ms = int((time.time() - start) * 1000)
        await store.log_llm_event({
            "doc_type": "llm_cache_event",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "outcome": "error", "provider": provider, "model": model, "role": role, "subject": subject,
            "namespace": cfg["namespace"], "scope_key": scope,
            "prompt_preview": req.prompt.strip()[:240],
            "latency_ms": latency_ms, "reason": str(exc)[:400],
        })
        raise HTTPException(status_code=502, detail=f"{llm_cache.PROVIDERS[provider]['label']} call failed: {exc}") from exc

    latency_ms = int((time.time() - start) * 1000)
    prompt_tokens = int(result["prompt_tokens"])
    completion_tokens = int(result["completion_tokens"])
    total_tokens = prompt_tokens + completion_tokens
    cost_usd = llm_cache.estimate_cost_usd(model, prompt_tokens, completion_tokens)

    if not bypass_reason:
        await _store_cache_entry(
            eid, cfg, provider, model, scope, req.prompt, result,
            prompt_tokens, completion_tokens, cost_usd, latency_ms,
            override=(provider != cfg["provider"] or model != cfg["model"]),
        )

    await store.log_llm_event({
        "doc_type": "llm_cache_event",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "outcome": "bypass" if bypass_reason else "miss",
        "provider": provider, "model": model, "role": role, "subject": subject,
        "entry_id": None if bypass_reason else eid,
        "namespace": cfg["namespace"], "scope_key": scope, "similarity": None,
        "prompt_preview": req.prompt.strip()[:240],
        "prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens, "total_tokens": total_tokens,
        "tokens_saved": 0, "cost_usd": cost_usd, "cost_saved_usd": 0.0,
        "latency_ms": latency_ms, "latency_saved_ms": 0,
        "reason": bypass_reason or "no cached answer - called the provider and stored the result",
    })

    return {
        "provider": provider,
        "model": model,
        "role": role,
        "response": result["text"],
        "cache": {
            "status": "bypass" if bypass_reason else "miss",
            "entry_id": None if bypass_reason else eid,
            "similarity": None,
            "hit_count": 0,
            "created_at": None,
            "reason": bypass_reason,
        },
        "usage": {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": total_tokens,
        },
        "cost_usd": cost_usd,
        "tokens_saved": 0,
        "cost_saved_usd": 0.0,
        "latency_ms": latency_ms,
        "stub": bool(result.get("stub")),
    }


async def _lookup_cache(cfg: dict, provider: str, model: str, scope: str, eid: str, prompt: str):
    """Exact first (one KV get on a deterministic ID), then the semantic
    fallback if it's enabled. Anything the policy says is invalid is deleted
    on the spot rather than left to the sweeper - a read that noticed the
    problem is the cheapest place to fix it."""
    entry = await store.get_cache_entry(eid)
    if entry:
        state, reason = llm_cache.evaluate_entry(
            entry, cfg, config_version=llm_config_version, catalog_version=llm_catalog_version
        )
        if state in ("fresh", "stale"):
            return entry, None, reason
        await store.delete_cache_entry(eid)

    if not cfg.get("semantic_enabled") or embeddings is None:
        return None, None, None

    try:
        vector = embeddings.embed(prompt)
    except ValueError:
        return None, None, None

    candidates = await store.semantic_cache_lookup(
        provider, model, scope, cfg["namespace"], vector, top_k=int(cfg["semantic_candidates"])
    )
    threshold = float(cfg["similarity_threshold"])
    for candidate in candidates:
        if candidate["similarity"] < threshold:
            break
        entry = await store.get_cache_entry(candidate["entry_id"])
        if not entry:
            continue
        state, reason = llm_cache.evaluate_entry(
            entry, cfg, config_version=llm_config_version, catalog_version=llm_catalog_version
        )
        if state in ("fresh", "stale"):
            return entry, candidate["similarity"], reason
        await store.delete_cache_entry(candidate["entry_id"])
    return None, None, None


async def _record_cache_hit(entry: dict, cfg: dict, semantic: bool) -> int:
    """Bump the hit counters and the running savings total on the entry.

    Re-written with the *remaining* TTL as its expiry, never a fresh one: a
    popular entry must still age out on schedule, otherwise a hot prompt
    would never be re-verified against the provider."""
    now = time.time()
    entry["hit_count"] = int(entry.get("hit_count") or 0) + 1
    entry["last_hit_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    if semantic:
        entry["semantic_hits"] = int(entry.get("semantic_hits") or 0) + 1
    else:
        entry["exact_hits"] = int(entry.get("exact_hits") or 0) + 1
    entry["tokens_saved"] = int(entry.get("tokens_saved") or 0) + int(entry.get("total_tokens") or 0)
    entry["cost_saved_usd"] = round(float(entry.get("cost_saved_usd") or 0.0) + float(entry.get("cost_usd") or 0.0), 6)

    ttl = int(cfg.get("ttl_seconds") or 0)
    remaining = 0
    if ttl:
        age = now - llm_cache.parse_timestamp(entry.get("created_at"))
        remaining = max(1, int(ttl + int(cfg.get("stale_while_revalidate_seconds") or 0) - age))
    await store.upsert_cache_entry(entry["entry_id"], entry, ttl_seconds=remaining)
    return entry["hit_count"]


async def _store_cache_entry(
    eid, cfg, provider, model, scope, prompt, result,
    prompt_tokens, completion_tokens, cost_usd, latency_ms, override=False,
):
    embedding = None
    if cfg.get("semantic_enabled") and embeddings is not None:
        try:
            embedding = embeddings.embed(prompt)
        except ValueError:
            embedding = None

    text = result["text"]
    doc = {
        "doc_type": "llm_cache_entry",
        "entry_id": eid,
        "provider": provider,
        "model": model,
        "scope_key": scope,
        "namespace": cfg["namespace"],
        "prompt": prompt,
        "prompt_preview": prompt.strip()[:240],
        "response": text,
        "response_preview": (text or "").strip()[:240],
        "embedding": embedding,
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "total_tokens": prompt_tokens + completion_tokens,
        "cost_usd": cost_usd,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "last_hit_at": None,
        "hit_count": 0,
        "exact_hits": 0,
        "semantic_hits": 0,
        "tokens_saved": 0,
        "cost_saved_usd": 0.0,
        "origin_latency_ms": latency_ms,
        "config_version": llm_config_version,
        "catalog_version": llm_catalog_version,
        # True when this call named a provider/model other than the policy's
        # default. Such entries survive a change to the selected model - see
        # llm_cache.evaluate_entry.
        "override": bool(override),
        "stub": bool(result.get("stub")),
    }
    ttl = int(cfg.get("ttl_seconds") or 0)
    expiry = ttl + int(cfg.get("stale_while_revalidate_seconds") or 0) if ttl else 0
    await store.upsert_cache_entry(eid, doc, ttl_seconds=expiry)


@app.get("/v1/llm/cache")
async def list_llm_cache(limit: int = 100):
    """Cache contents with each entry's live policy verdict attached, so the
    table shows what the gateway would actually do with it right now."""
    entries = await store.list_cache_entries(limit=min(limit, 500))
    now = time.time()
    for entry in entries:
        state, reason = llm_cache.evaluate_entry(
            entry, llm_config, now=now,
            config_version=llm_config_version, catalog_version=llm_catalog_version,
        )
        entry["state"] = state
        entry["state_reason"] = reason
        entry["age_seconds"] = int(max(0, now - llm_cache.parse_timestamp(entry.get("created_at"))))
    return {"entries": entries, "count": len(entries), "total_entries": await store.count_cache_entries()}


@app.post("/v1/llm/cache/purge")
async def purge_llm_cache(req: PurgeCacheRequest):
    """Manual invalidation: everything, or narrowed to one provider, model
    or namespace."""
    removed = await store.purge_cache(provider=req.provider, model=req.model, namespace=req.namespace)
    return {"purged": removed, "provider": req.provider, "model": req.model, "namespace": req.namespace}


@app.post("/v1/llm/cache/sweep")
async def sweep_llm_cache_route():
    """Run the invalidation sweeper now instead of waiting for the timer."""
    global last_llm_sweep_at
    removed = await sweep_llm_cache()
    last_llm_sweep_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return {"removed": removed, "last_sweep_at": last_llm_sweep_at}


@app.delete("/v1/llm/cache/{entry_id:path}")
async def delete_llm_cache_entry(entry_id: str):
    if not await store.delete_cache_entry(entry_id):
        raise HTTPException(status_code=404, detail="Cache entry not found")
    return {"deleted": True, "entry_id": entry_id}


@app.get("/v1/llm/dashboard")
async def llm_dashboard():
    events = await store.recent_llm_events(limit=LLM_CACHE_LOOKBACK_ENTRIES)
    data = llm_cache.build_dashboard(events, buckets=12)
    provider_spec = llm_cache.PROVIDERS[llm_config["provider"]]
    return {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "events_examined": len(events),
        "enabled": llm_config["enabled"],
        "provider": llm_config["provider"],
        "provider_label": provider_spec["label"],
        "model": llm_config["model"],
        "api_key_configured": bool((LLM_API_KEYS.get(llm_config["provider"]) or "").strip()),
        "semantic_enabled": llm_config["semantic_enabled"],
        "similarity_threshold": llm_config["similarity_threshold"],
        "ttl_seconds": llm_config["ttl_seconds"],
        "cached_entries": await store.count_cache_entries(),
        "max_entries": llm_config["max_entries"],
        "last_sweep_at": last_llm_sweep_at,
        "summary": data["summary"],
        "hourly": data["hourly"],
        "model_breakdown": data["model_breakdown"],
        "recent_events": events[:50],
    }


# ---------------------------------------------------------------------------
# Agent memory (see app/agent_memory.py; storage/search in couchbase_client.py)
# ---------------------------------------------------------------------------
class AddMemoryRequest(BaseModel):
    user_id: str
    content: str
    session_id: str | None = None
    memory_type: str = agent_memory.DEFAULT_MEMORY_TYPE
    metadata: dict = Field(default_factory=dict)
    ttl_seconds: int = 0


class SearchMemoryRequest(BaseModel):
    user_id: str
    query: str
    session_id: str | None = None
    memory_type: str | None = None
    top_k: int = 5


class ClearMemoryRequest(BaseModel):
    user_id: str
    session_id: str | None = None


@app.post("/v1/memory")
async def add_memory(req: AddMemoryRequest, authorization: str | None = Header(default=None)):
    """Store one memory entry for `user_id`, embedded for later semantic
    recall via POST /v1/memory/search. Authenticated exactly like
    discover/invoke/complete - any valid API key may write memory, scoped
    by the `user_id` it names rather than by RBAC role."""
    role, subject = await authenticate(authorization)
    if not req.content or not req.content.strip():
        raise HTTPException(status_code=400, detail="content is required")
    if not store.connected or embeddings is None:
        raise HTTPException(status_code=503, detail="Operations manager not fully initialized yet")

    start = time.time()
    memory_id = agent_memory.new_memory_id(req.user_id)
    embedding_text = agent_memory.build_embedding_text(req.content, req.metadata)
    embedding = embeddings.embed(embedding_text)
    doc = agent_memory.build_memory_doc(
        user_id=req.user_id, content=req.content, embedding=embedding,
        session_id=req.session_id, memory_type=req.memory_type, metadata=req.metadata,
        role=role, subject_label=subject,
    )
    await store.upsert_memory(memory_id, doc, ttl_seconds=req.ttl_seconds)
    latency_ms = int((time.time() - start) * 1000)

    await store.log_access(
        action="memory_add", role=role, subject_label=subject, query=req.content[:240],
        tool_id=None, server_id=None, decision="ALLOW",
        reason=f"stored {doc['memory_type']} memory for user '{req.user_id}'", latency_ms=latency_ms,
    )
    return {"memory_id": memory_id, "user_id": req.user_id, "memory_type": doc["memory_type"], "created_at": doc["created_at"]}


@app.get("/v1/memory")
async def list_memory_route(
    user_id: str, session_id: str | None = None, memory_type: str | None = None, limit: int = 100,
    authorization: str | None = Header(default=None),
):
    """Chronological listing for one user (optionally narrowed to a
    session or memory type) - what a fresh agent turn re-hydrates before
    reasoning, or what a debugging session inspects directly."""
    role, subject = await authenticate(authorization)
    if not store.connected:
        raise HTTPException(status_code=503, detail="Operations manager not fully initialized yet")
    entries = await store.list_memory(user_id, session_id=session_id, memory_type=memory_type, limit=min(limit, 500))
    await store.log_access(
        action="memory_list", role=role, subject_label=subject, query=None, tool_id=None, server_id=None,
        decision="ALLOW", reason=f"listed {len(entries)} memory entr(ies) for user '{user_id}'", latency_ms=0,
    )
    return {"user_id": user_id, "entries": entries, "count": len(entries)}


@app.post("/v1/memory/search")
async def search_memory_route(req: SearchMemoryRequest, authorization: str | None = Header(default=None)):
    """Semantic recall: the memory entries for `user_id` whose content is
    closest to `query`, not just the most recent ones - the same vector
    kNN pattern discover() runs over the tool catalog, scoped to one user's
    memory instead of one role's tools."""
    role, subject = await authenticate(authorization)
    if not req.query or not req.query.strip():
        raise HTTPException(status_code=400, detail="query is required")
    if not store.connected or embeddings is None:
        raise HTTPException(status_code=503, detail="Operations manager not fully initialized yet")

    start = time.time()
    vector = embeddings.embed(req.query)
    memory_type = agent_memory.normalize_memory_type(req.memory_type) if req.memory_type else None
    results = await store.search_memory(
        req.user_id, vector, session_id=req.session_id, memory_type=memory_type, top_k=req.top_k,
    )
    latency_ms = int((time.time() - start) * 1000)

    await store.log_access(
        action="memory_search", role=role, subject_label=subject, query=req.query, tool_id=None, server_id=None,
        decision="ALLOW", reason=f"{len(results)} memory match(es) for user '{req.user_id}'", latency_ms=latency_ms,
    )
    return {"user_id": req.user_id, "entries": results, "latency_ms": latency_ms}


@app.delete("/v1/memory/{memory_id:path}")
async def delete_memory_route(memory_id: str, authorization: str | None = Header(default=None)):
    role, subject = await authenticate(authorization)
    deleted = await store.delete_memory(memory_id)
    await store.log_access(
        action="memory_delete", role=role, subject_label=subject, query=None, tool_id=None, server_id=None,
        decision="ALLOW" if deleted else "ERROR",
        reason="deleted" if deleted else "memory entry not found", latency_ms=0,
    )
    if not deleted:
        raise HTTPException(status_code=404, detail="Memory entry not found")
    return {"deleted": True, "memory_id": memory_id}


@app.post("/v1/memory/clear")
async def clear_memory_route(req: ClearMemoryRequest, authorization: str | None = Header(default=None)):
    """Bulk-wipe a user's memory, or just one session of it - e.g. an agent
    clearing short-term conversational memory at session end while leaving
    that user's durable profile memories untouched."""
    role, subject = await authenticate(authorization)
    removed = await store.clear_memory(req.user_id, session_id=req.session_id)
    await store.log_access(
        action="memory_clear", role=role, subject_label=subject, query=None, tool_id=None, server_id=None,
        decision="ALLOW", reason=f"cleared {removed} memory entr(ies) for user '{req.user_id}'", latency_ms=0,
    )
    return {"user_id": req.user_id, "cleared": removed}


# ---------------------------------------------------------------------------
# Local dashboard login (see app/user_auth.py). Distinct from authenticate()
# above: that resolves an agent's bearer API key to an RBAC role; everything
# below resolves a person's username/password (local or LDAP) to a signed
# session cookie that require_dashboard_session (the app middleware near the
# top of this file) then requires on every other /v1 and /api route.
# ---------------------------------------------------------------------------

def _client_ip(request: Request) -> str:
    """Best-effort real client IP for login-lockout accounting. nginx sets
    X-Forwarded-For (see ui/nginx.conf.template); request.client.host alone
    would only ever show the ui container's address, since this API is
    always reached through that reverse proxy in the bundled compose
    stack. Only the first hop is trusted here (this app has exactly one
    known reverse proxy in front of it) - not a general trusted-proxy chain
    parser."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


async def _log_login_attempt(username: str, decision: str, reason: str) -> None:
    await store.log_access(
        action="dashboard_login", role=None, subject_label=username, query=None,
        tool_id=None, server_id=None, decision=decision, reason=reason, latency_ms=0,
    )


async def _finish_login(username: str, response: Response, request: Request):
    doc = await store.get_user(username)
    if not doc:
        raise HTTPException(status_code=500, detail="Account vanished mid-login")
    token = user_auth.create_session_token(username, doc.get("role", user_auth.DEFAULT_LOCAL_ROLE))
    response.set_cookie(
        key=user_auth.SESSION_COOKIE_NAME,
        value=token,
        httponly=True,
        samesite="lax",
        secure=request.url.scheme == "https",
        max_age=AUTH_SESSION_TTL_HOURS * 3600,
        path="/",
    )
    doc["last_login_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    await store.upsert_user(username, doc)
    return doc


@app.get("/v1/auth/bootstrap-status")
async def bootstrap_status():
    """Tells the login page which form to render: the one-time "set the
    admin password" form (a fresh install, or one where it was never
    completed) or the normal username/password login form."""
    admin_doc = await store.get_user(DEFAULT_ADMIN_USERNAME)
    needs_setup = bool(admin_doc) and not admin_doc.get("password_hash")
    return {"needs_setup": needs_setup, "username": DEFAULT_ADMIN_USERNAME}


@app.post("/v1/auth/bootstrap")
async def bootstrap(req: BootstrapRequest, request: Request, response: Response):
    """Sets the default admin account's password the first time anyone
    reaches the login page. Refuses once a password already exists - after
    that, POST /v1/auth/login (or a password reset from Settings) is the
    only way in."""
    admin_doc = await store.get_user(DEFAULT_ADMIN_USERNAME)
    if not admin_doc:
        raise HTTPException(status_code=503, detail="Not ready yet - try again shortly.")
    if admin_doc.get("password_hash"):
        raise HTTPException(status_code=409, detail="The admin password has already been set. Use the login form.")
    policy_error = user_auth.password_policy_error(req.password, username=DEFAULT_ADMIN_USERNAME)
    if policy_error:
        raise HTTPException(status_code=400, detail=policy_error)

    admin_doc["password_hash"] = user_auth.hash_password(req.password)
    admin_doc["must_change_password"] = False
    admin_doc["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    await store.upsert_user(DEFAULT_ADMIN_USERNAME, admin_doc)

    doc = await _finish_login(DEFAULT_ADMIN_USERNAME, response, request)
    return {"user": user_auth.public_user(DEFAULT_ADMIN_USERNAME, doc)}


@app.post("/v1/auth/login")
async def login(req: LoginRequest, request: Request, response: Response):
    username = req.username.strip()
    if not username or not req.password:
        raise HTTPException(status_code=400, detail="Username and password are required.")

    ip = _client_ip(request)
    locked, retry_after = user_auth.login_lockout_status(username, ip)
    if locked:
        await _log_login_attempt(username, "DENY", f"locked out ({retry_after}s remaining)")
        raise HTTPException(
            status_code=429,
            detail=f"Too many failed login attempts. Try again in about {max(1, retry_after // 60)} minute(s).",
            headers={"Retry-After": str(retry_after)},
        )

    user_doc = await store.get_user(username)

    if user_doc and user_doc.get("source", "local") == "local":
        if not user_doc.get("password_hash"):
            raise HTTPException(
                status_code=409,
                detail="This account has no password set yet - use the setup form instead.",
            )
        if not user_doc.get("active", True):
            await _log_login_attempt(username, "DENY", "account disabled")
            raise HTTPException(status_code=403, detail="This account has been disabled.")
        if not user_auth.verify_password(req.password, user_doc.get("password_hash")):
            user_auth.record_failed_login(username, ip)
            await _log_login_attempt(username, "DENY", "invalid password")
            raise HTTPException(status_code=401, detail="Invalid username or password.")
        user_auth.record_successful_login(username, ip)
        await _log_login_attempt(username, "ALLOW", "local password login")
        doc = await _finish_login(username, response, request)
        return {"user": user_auth.public_user(username, doc)}

    # No local account by that name (or it's a previously-provisioned LDAP
    # shadow record) - try the directory if one is configured.
    if ldap_config.get("enabled"):
        success, detail, is_admin = await user_auth.ldap_authenticate(ldap_config, username, req.password)
        if not success:
            user_auth.record_failed_login(username, ip)
            await _log_login_attempt(username, "DENY", f"LDAP: {detail}")
            raise HTTPException(status_code=401, detail=detail)
        if user_doc and user_doc.get("active") is False:
            await _log_login_attempt(username, "DENY", "account disabled")
            raise HTTPException(status_code=403, detail="This account has been disabled.")

        role = "admin" if is_admin else user_auth.DEFAULT_LOCAL_ROLE
        shadow = user_auth.new_local_user_doc(role=role, password_hash=None, source="ldap")
        if user_doc:
            shadow["created_at"] = user_doc.get("created_at", shadow["created_at"])
            shadow["active"] = user_doc.get("active", True)
        await store.upsert_user(username, shadow)
        user_auth.record_successful_login(username, ip)
        await _log_login_attempt(username, "ALLOW", "LDAP login")
        doc = await _finish_login(username, response, request)
        return {"user": user_auth.public_user(username, doc)}

    user_auth.record_failed_login(username, ip)
    await _log_login_attempt(username, "DENY", "no such account")
    raise HTTPException(status_code=401, detail="Invalid username or password.")


@app.post("/v1/auth/logout")
async def logout(response: Response):
    response.delete_cookie(user_auth.SESSION_COOKIE_NAME, path="/")
    return {"logged_out": True}


@app.get("/v1/auth/me")
async def auth_me(request: Request):
    session = getattr(request.state, "user", None)
    if not session:
        raise HTTPException(status_code=401, detail="Not authenticated")
    doc = await store.get_user(session["username"])
    if not doc:
        raise HTTPException(status_code=401, detail="Account no longer exists")
    return {"user": user_auth.public_user(session["username"], doc)}


@app.post("/v1/auth/change-password")
async def change_password(req: ChangePasswordRequest, request: Request):
    """Self-service password change - also clears must_change_password, so
    this is what an account created with a forced reset uses to satisfy it."""
    session = getattr(request.state, "user", None)
    if not session:
        raise HTTPException(status_code=401, detail="Not authenticated")
    username = session["username"]
    doc = await store.get_user(username)
    if not doc:
        raise HTTPException(status_code=404, detail="Account not found")
    if doc.get("source") != "local":
        raise HTTPException(status_code=400, detail="This account authenticates via LDAP - there is no local password to change.")
    if not user_auth.verify_password(req.current_password, doc.get("password_hash")):
        raise HTTPException(status_code=401, detail="Current password is incorrect.")
    policy_error = user_auth.password_policy_error(req.new_password, username=username)
    if policy_error:
        raise HTTPException(status_code=400, detail=policy_error)

    doc["password_hash"] = user_auth.hash_password(req.new_password)
    doc["must_change_password"] = False
    doc["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    await store.upsert_user(username, doc)
    return {"user": user_auth.public_user(username, doc)}


@app.get("/v1/auth/roles")
async def auth_roles():
    return {"roles": [{"id": rid, "description": desc} for rid, desc in user_auth.UI_ROLES.items()]}


# -- Settings -> Accounts & Roles (admin only) -------------------------------

@app.get("/v1/auth/users")
async def list_users(request: Request):
    require_admin(request)
    docs = await store.list_users()
    return {"users": [user_auth.public_user(d["username"], d) for d in docs]}


@app.post("/v1/auth/users")
async def create_user(req: CreateUserRequest, request: Request):
    require_admin(request)
    if req.role not in user_auth.UI_ROLES:
        raise HTTPException(status_code=400, detail=f"Unknown role '{req.role}'")
    if await store.get_user(req.username):
        raise HTTPException(status_code=409, detail=f"An account named '{req.username}' already exists.")
    policy_error = user_auth.password_policy_error(req.password, username=req.username)
    if policy_error:
        raise HTTPException(status_code=400, detail=policy_error)

    doc = user_auth.new_local_user_doc(
        role=req.role,
        password_hash=user_auth.hash_password(req.password),
        source="local",
        must_change_password=req.must_change_password,
    )
    await store.upsert_user(req.username, doc)
    return {"user": user_auth.public_user(req.username.lower(), doc)}


@app.put("/v1/auth/users/{username}")
async def update_user(username: str, req: UpdateUserRequest, request: Request):
    admin = require_admin(request)
    doc = await store.get_user(username)
    if not doc:
        raise HTTPException(status_code=404, detail="Account not found")

    is_default_admin = username.lower() == DEFAULT_ADMIN_USERNAME.lower()
    is_self = username.lower() == admin["username"].lower()

    if req.active is False and (is_default_admin or is_self):
        raise HTTPException(
            status_code=400,
            detail="You cannot disable the default admin account or your own account." if is_default_admin else "You cannot disable your own account.",
        )

    if req.role is not None:
        if req.role not in user_auth.UI_ROLES:
            raise HTTPException(status_code=400, detail=f"Unknown role '{req.role}'")
        if is_default_admin and req.role != "admin":
            raise HTTPException(status_code=400, detail="The default admin account must keep the admin role.")
        doc["role"] = req.role

    if req.active is not None:
        doc["active"] = req.active

    if req.password is not None:
        if doc.get("source") != "local":
            raise HTTPException(status_code=400, detail="This account authenticates via LDAP - it has no local password to set.")
        policy_error = user_auth.password_policy_error(req.password, username=username)
        if policy_error:
            raise HTTPException(status_code=400, detail=policy_error)
        doc["password_hash"] = user_auth.hash_password(req.password)

    if req.must_change_password is not None:
        doc["must_change_password"] = req.must_change_password

    doc["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    await store.upsert_user(username, doc)
    return {"user": user_auth.public_user(username.lower(), doc)}


@app.delete("/v1/auth/users/{username}")
async def delete_user(username: str, request: Request):
    admin = require_admin(request)
    if username.lower() == DEFAULT_ADMIN_USERNAME.lower():
        raise HTTPException(status_code=400, detail="The default admin account cannot be deleted.")
    if username.lower() == admin["username"].lower():
        raise HTTPException(status_code=400, detail="You cannot delete your own account.")
    deleted = await store.delete_user(username)
    if not deleted:
        raise HTTPException(status_code=404, detail="Account not found")
    return {"deleted": True, "username": username.lower()}


# -- Settings -> LDAP Authentication (admin only) ----------------------------

@app.get("/v1/auth/ldap-config")
async def get_ldap_config(request: Request):
    require_admin(request)
    return {"config": user_auth.public_ldap_config(ldap_config)}


@app.put("/v1/auth/ldap-config")
async def put_ldap_config(req: LdapConfigRequest, request: Request):
    """Save the LDAP policy. bind_password is only present in the request
    body when the admin actually typed a new one in that field - omitted or
    blank leaves the encrypted secret already on file untouched, so this
    form never has to round-trip (or even know) the current secret."""
    require_admin(request)
    merged = {**ldap_config, **req.config}
    merged.pop("bind_password_encrypted", None)  # never accepted directly from the client
    normalized = user_auth.normalize_ldap_config(merged)
    if normalized["ca_certificate"]:
        try:
            user_auth.parse_ca_certificate(normalized["ca_certificate"])
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=f"Corporate CA certificate: {exc}")
    if req.bind_password:
        normalized["bind_password_encrypted"] = user_auth.encrypt_secret(req.bind_password)
    else:
        normalized["bind_password_encrypted"] = ldap_config.get("bind_password_encrypted", "")
    await save_ldap_config(normalized)
    return {"config": user_auth.public_ldap_config(ldap_config)}


@app.post("/v1/auth/ldap-config/validate-ca")
async def validate_ca_certificate(req: LdapCaCertificateRequest, request: Request):
    """Parse (but don't save) a pasted/uploaded corporate CA certificate so
    the Settings page can show its subject/issuer/expiry immediately -
    before the admin commits to Save."""
    require_admin(request)
    try:
        info = user_auth.parse_ca_certificate(req.ca_certificate)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"valid": True, "info": info}


@app.post("/v1/auth/ldap-config/test")
async def test_ldap_config(req: LdapTestRequest, request: Request):
    """Test the *saved* LDAP config (Save first, then Test) against one
    real set of credentials - service-account bind, user search, and user
    bind, exactly like a real login attempt would exercise."""
    require_admin(request)
    success, detail, is_admin = await user_auth.ldap_authenticate(ldap_config, req.username, req.password)
    return {"success": success, "detail": detail, "would_be_admin": is_admin}


# -- Settings -> HTTPS Certificate (admin only) ------------------------------
# Separate feature from the LDAP corporate CA above - see user_auth.py's
# section comment for the distinction. This installs the certificate nginx
# and uvicorn present to browsers, not one this appliance trusts outbound.

@app.get("/v1/auth/tls-cert")
async def get_tls_cert(request: Request):
    require_admin(request)
    return {
        "info": user_auth.current_server_certificate_info(),
        "can_revert": user_auth.can_revert_server_certificate(),
    }


@app.post("/v1/auth/tls-cert/validate")
async def validate_tls_cert(req: ServerCertificateRequest, request: Request):
    """Parse and cross-check a certificate/key pair without installing them,
    so the Settings page can preview subject/issuer/expiry/SANs and catch a
    mismatched key before the admin commits to Install."""
    require_admin(request)
    try:
        info = user_auth.validate_server_key_pair(req.cert_pem, req.key_pem)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"valid": True, "info": info}


@app.put("/v1/auth/tls-cert")
async def put_tls_cert(req: ServerCertificateRequest, request: Request):
    """Install a real certificate/key pair, replacing the self-signed
    fallback for both the dashboard and this API. Written straight to the
    files uvicorn/nginx serve from (see config.TLS_CERT_FILE/TLS_KEY_FILE) -
    neither picks up the change until operations-manager and ui are
    restarted, since TLS listeners don't hot-reload a swapped cert file."""
    require_admin(request)
    try:
        info = user_auth.install_server_certificate(req.cert_pem, req.key_pem)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"info": info, "can_revert": True, "restart_required": True}


@app.post("/v1/auth/tls-cert/revert")
async def revert_tls_cert(request: Request):
    """Restore the original baked-in self-signed certificate, undoing a
    previous Install. Also requires a restart to take effect."""
    require_admin(request)
    try:
        info = user_auth.revert_server_certificate()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"info": info, "can_revert": False, "restart_required": True}
