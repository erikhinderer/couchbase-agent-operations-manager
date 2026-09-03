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

from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from app import hijack_detection, insights, llm_cache, mcp_client
from app.catalog_ingest import ingest_all, ingest_server, rescan_all_tools, seed_servers
from app.couchbase_client import CouchbaseStore
from app.embeddings import ToolEmbeddings
from app.rbac_policy import ROLES
from config import (
    APPLIANCE_NAME,
    COUCHBASE_CONFIG,
    EMBEDDING_CONFIG,
    HIJACK_CHAIN_WINDOW_SECONDS,
    HIJACK_SCAN_INTERVAL_MINUTES,
    INSIGHTS_LOOKBACK_ENTRIES,
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
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

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


@app.on_event("startup")
async def startup():
    global embeddings, ready, last_hijack_scan_at
    logger.info("Loading local embedding model...")
    embeddings = ToolEmbeddings(EMBEDDING_CONFIG["model_name"])

    logger.info("Connecting to Couchbase...")
    await store.connect()

    if store.connected:
        for api_key, role in SEED_API_KEYS.items():
            await store.upsert_identity(api_key, role, label=f"...{api_key[-4:]}")

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
