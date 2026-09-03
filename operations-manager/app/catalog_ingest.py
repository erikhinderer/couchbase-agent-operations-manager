"""
Catalog ingestion: for a given *trusted, registered* server, connect over
MCP, list its tools, embed each tool's description, attach an RBAC policy,
run the metadata-poisoning scan, and upsert the result into Couchbase's
`tools` collection.

This is the one place an MCP server's tool definitions cross the trust
boundary into the centralized catalog. A server that was never registered
(trust_status != "trusted") never runs through this path, so its tools
simply do not exist as far as the operations manager - and therefore RBAC +
vector search discovery - is concerned. That's true whether the server was
left out entirely (like the bundled shadow-diagnostics sample) or was
registered but marked untrusted pending review.

Every tool that does make it through also runs through
`hijack_detection.apply_metadata_scan()` before it's stored: a tool whose
description carries an injection payload is quarantined automatically
(trust_status forced to "quarantined") regardless of how the server itself
is trusted or how TOOL_POLICY would otherwise classify it - see
app/hijack_detection.py for why metadata poisoning is handled this
strictly, versus response poisoning (caught live, at invoke time, and
flagged rather than blocked).

On startup, `seed_servers()` upserts the bundled sample servers
(rbac_policy.SEED_SERVERS) into Couchbase *only if they don't already
exist*, so editing or removing them later via the Servers page sticks
across restarts. `ingest_all()` then (re-)ingests every currently
trusted, registered server - seeded or user-added - which is also what
runs when a server is registered or manually re-ingested at runtime.
`rescan_all_tools()` is the lighter-weight pass the background hijack
monitor runs on a timer: it re-scans already-ingested tool descriptions
against the current pattern bank without any MCP round-trip, catching
tools ingested before a pattern-bank update, or before hijack detection
existed at all - without hammering downstream MCP servers to do it.
"""
import logging

from app import hijack_detection, mcp_client
from app.rbac_policy import SEED_SERVERS, policy_for

logger = logging.getLogger("operations-manager.catalog_ingest")


async def seed_servers(store, sample_mcp_servers_base_url: str):
    for server_id, meta in SEED_SERVERS.items():
        existing = await store.get_server(server_id)
        if existing:
            continue
        mcp_url = f"{sample_mcp_servers_base_url.rstrip('/')}{meta['mcp_path']}"
        await store.upsert_server(server_id, {
            "server_id": server_id,
            "label": meta["label"],
            "owner": meta["owner"],
            "mcp_url": mcp_url,
            "trust_status": "trusted",
            "default_allowed_roles": [],
            "seeded": True,
        })
        logger.info("Seeded sample server '%s' (%s)", server_id, mcp_url)


async def ingest_server(store, embeddings, server_doc: dict) -> int:
    """Ingest one server's tool catalog. Returns the number of tools
    ingested. Raises on connection/listing failure so callers (the manual
    "re-ingest" endpoint especially) can surface the error."""
    server_id = server_doc["server_id"]
    mcp_url = server_doc["mcp_url"]

    tools = await mcp_client.list_tools(mcp_url)
    default_roles = server_doc.get("default_allowed_roles") or []
    quarantined_count = 0

    for tool in tools:
        policy = policy_for(server_id, tool["name"], default_allowed_roles=default_roles)
        embedding_text = build_embedding_text(server_id, server_doc, tool)
        embedding = embeddings.embed(embedding_text)

        tool_id = f"{server_id}::{tool['name']}"
        existing = await store.get_tool(tool_id)

        tool_doc = {
            "tool_id": tool_id,
            "server_id": server_id,
            "name": tool["name"],
            "description": tool["description"],
            "input_schema": tool["input_schema"],
            "allowed_roles": policy["allowed_roles"],
            "risk_level": policy["risk_level"],
            "trust_status": "trusted",
            "embedding": embedding,
        }
        tool_doc = hijack_detection.apply_metadata_scan(tool_doc, existing)
        if tool_doc["trust_status"] == "quarantined":
            quarantined_count += 1
            logger.warning(
                "Quarantined tool '%s' at ingest - metadata poisoning signal(s): %s",
                tool_id, [s["pattern_id"] for s in tool_doc.get("hijack_signals", [])],
            )

        await store.upsert_tool(tool_id, tool_doc)

    logger.info(
        "Ingested catalog for '%s': %d tool(s), %d quarantined for suspected metadata poisoning",
        server_id, len(tools), quarantined_count,
    )
    return len(tools)


async def ingest_all(store, embeddings):
    """(Re-)ingest every currently trusted, registered server."""
    for server_doc in await store.list_servers():
        if server_doc.get("trust_status") != "trusted":
            continue
        try:
            await ingest_server(store, embeddings, server_doc)
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "Failed to ingest catalog for registered server '%s' (%s): %s",
                server_doc.get("server_id"), server_doc.get("mcp_url"), exc,
            )


async def rescan_all_tools(store) -> int:
    """Re-run the metadata-poisoning scan against every already-ingested
    tool's stored description, with no MCP round-trip. Only writes back
    documents whose trust_status or hijack_status actually changed, so a
    quiet monitor tick costs one N1QL read plus one KV get per tool and no
    writes at all when nothing changed.

    Note: this re-fetches each tool via `get_tool()` (a full KV read)
    rather than reusing `list_tools()`'s rows, because that listing
    intentionally omits the `embedding` vector to keep API responses
    small - upserting a doc built from it would silently strip the
    embedding and break vector search discovery for that tool.
    """
    summaries = await store.list_tools()
    changed = 0
    for summary in summaries:
        tool = await store.get_tool(summary["tool_id"])
        if not tool:
            continue
        updated = dict(tool)
        updated = hijack_detection.apply_metadata_scan(updated, tool)
        if updated.get("trust_status") != tool.get("trust_status") or updated.get("hijack_status") != tool.get("hijack_status"):
            await store.upsert_tool(tool["tool_id"], updated)
            changed += 1
            if updated["trust_status"] == "quarantined" and tool.get("trust_status") != "quarantined":
                logger.warning(
                    "Background scan quarantined tool '%s' - metadata poisoning signal(s): %s",
                    tool["tool_id"], [s["pattern_id"] for s in updated.get("hijack_signals", [])],
                )
    return changed


def build_embedding_text(server_id: str, server_meta: dict, tool: dict) -> str:
    parts = [tool["name"], tool["description"], server_meta.get("label", server_id), f"server:{server_id}"]
    schema = tool.get("input_schema") or {}
    props = schema.get("properties") or {}
    for pname, pinfo in props.items():
        if isinstance(pinfo, dict) and pinfo.get("description"):
            parts.append(f"{pname}: {pinfo['description']}")
    return " ".join(parts)
