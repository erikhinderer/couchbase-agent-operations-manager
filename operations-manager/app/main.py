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
import logging
import os
import time
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from app import hijack_detection, insights, mcp_client
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
