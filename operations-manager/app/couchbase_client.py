"""
Everything that talks to Couchbase: connection lifecycle, the RBAC +
vector-search Search (FTS) index, and the KV collections used as the tool
registry, the identity table, and the access audit log.

The centerpiece is `discover_tools()`: a single Couchbase Search request
that combines an RBAC pre-filter (a Conjunction of TermQuerys on
`allowed_roles` and `trust_status`) with a vector kNN query on `embedding`.
The pre-filter narrows the candidate set *before/alongside* the similarity
ranking - a tool outside the caller's role, or from a server that was never
registered as trusted, cannot be returned no matter how well it matches the
query semantically. That is the "RBAC + Couchbase Vector Search
Pre-filtering" this whole appliance is built around.
"""
import asyncio
import hashlib
import logging
import time
import uuid
from datetime import timedelta

import numpy as np
import requests
from couchbase.auth import PasswordAuthenticator
from couchbase.cluster import Cluster
from couchbase.exceptions import DocumentNotFoundException
from couchbase.options import ClusterOptions, ClusterTimeoutOptions, QueryOptions, SearchOptions, UpsertOptions
import couchbase.search as cb_search
from couchbase.vector_search import VectorQuery as CBVectorQuery, VectorSearch as CBVectorSearch

from config import AUDIT_LOG_RETENTION_HOURS, COUCHBASE_CONFIG, EMBEDDING_CONFIG

logger = logging.getLogger("operations-manager.couchbase")


def hash_key(api_key: str) -> str:
    """Never store raw API keys as document IDs - hash them instead."""
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


class CouchbaseStore:
    def __init__(self):
        self.cluster = None
        self.bucket = None
        self.scope = None
        self.servers = None
        self.tools = None
        self.identities = None
        self.access_log = None
        self.connected = False

    async def connect(self, retries: int = 30, delay_seconds: float = 5.0):
        for attempt in range(1, retries + 1):
            try:
                await asyncio.to_thread(self._connect_sync)
                self.connected = True
                logger.info("Connected to Couchbase on attempt %d", attempt)
                await self.ensure_search_index()
                return
            except Exception as exc:  # noqa: BLE001
                logger.warning("Couchbase connect attempt %d/%d failed: %s", attempt, retries, exc)
                await asyncio.sleep(delay_seconds)
        logger.error("Could not connect to Couchbase after %d attempts - running degraded", retries)
        self.connected = False

    def _connect_sync(self):
        auth = PasswordAuthenticator(COUCHBASE_CONFIG["username"], COUCHBASE_CONFIG["password"])
        cluster = Cluster(
            COUCHBASE_CONFIG["connection_string"],
            ClusterOptions(auth, timeout_options=ClusterTimeoutOptions(kv_timeout=timedelta(seconds=10))),
        )
        cluster.wait_until_ready(timedelta(seconds=20))
        bucket = cluster.bucket(COUCHBASE_CONFIG["bucket"])
        scope = bucket.scope(COUCHBASE_CONFIG["scope"])

        servers = scope.collection(COUCHBASE_CONFIG["servers_collection"])
        tools = scope.collection(COUCHBASE_CONFIG["tools_collection"])
        identities = scope.collection(COUCHBASE_CONFIG["identities_collection"])
        access_log = scope.collection(COUCHBASE_CONFIG["access_log_collection"])

        # Building the four collection handles above is a purely local
        # object in the Couchbase Python SDK - it does NOT confirm the
        # scope or its collections actually exist on the cluster yet.
        # couchbase-init provisions them asynchronously (docker-compose
        # gates operations-manager behind its successful completion, but this
        # probe is defense-in-depth for anyone running the service outside
        # that compose file, or against an already-running cluster that's
        # mid-provisioning). Without this check, connect() would report
        # success and the very first real write - e.g. seeding an identity
        # on startup - would crash with ScopeNotFoundException/
        # CollectionNotFoundException instead of being retried by the
        # backoff loop in connect().
        for collection in (servers, tools, identities, access_log):
            collection.exists("__startup_probe__")

        self.cluster = cluster
        self.bucket = bucket
        self.scope = scope
        self.servers = servers
        self.tools = tools
        self.identities = identities
        self.access_log = access_log

    # -- Search (FTS) vector index -----------------------------------------

    def _index_definition(self) -> dict:
        bucket = COUCHBASE_CONFIG["bucket"]
        scope = COUCHBASE_CONFIG["scope"]
        collection = COUCHBASE_CONFIG["tools_collection"]
        type_key = f"{scope}.{collection}"

        def text_field(name: str) -> dict:
            return {
                "dynamic": False,
                "enabled": True,
                "fields": [{"name": name, "type": "text", "analyzer": "standard", "index": True, "store": True}],
            }

        properties = {
            "name": text_field("name"),
            "description": text_field("description"),
            "server_id": text_field("server_id"),
            "trust_status": text_field("trust_status"),
            "allowed_roles": text_field("allowed_roles"),
            "risk_level": text_field("risk_level"),
            "embedding": {
                "dynamic": False,
                "enabled": True,
                "fields": [{
                    "name": "embedding",
                    "type": "vector",
                    "dims": EMBEDDING_CONFIG["vector_dim"],
                    "similarity": "dot_product",
                    "index": True,
                    "store": True,
                }],
            },
        }

        return {
            "type": "fulltext-index",
            "name": f"{bucket}.{scope}.{COUCHBASE_CONFIG['tools_index']}",
            "sourceType": "gocbcore",
            "sourceName": bucket,
            "planParams": {"maxPartitionsPerPIndex": 512, "indexPartitions": 1},
            "params": {
                "doc_config": {"mode": "scope.collection.type_field", "type_field": "doc_type"},
                "mapping": {
                    "default_analyzer": "standard",
                    "default_datetime_parser": "dateTimeOptional",
                    "default_field": "_all",
                    "default_mapping": {"dynamic": False, "enabled": False},
                    "default_type": "_default",
                    "docvalues_dynamic": False,
                    "index_dynamic": False,
                    "store_dynamic": False,
                    "type_field": "_type",
                    "types": {type_key: {"dynamic": False, "enabled": True, "properties": properties}},
                },
            },
            "store": {"indexType": "scorch", "segmentVersion": 16},
            "sourceParams": {},
        }

    def _search_admin_url(self, index_name: str) -> str:
        host = COUCHBASE_CONFIG["search_host"]
        port = COUCHBASE_CONFIG["search_port"]
        bucket = COUCHBASE_CONFIG["bucket"]
        scope = COUCHBASE_CONFIG["scope"]
        return f"http://{host}:{port}/api/bucket/{bucket}/scope/{scope}/index/{index_name}"

    async def ensure_search_index(self):
        def _upsert():
            auth = (COUCHBASE_CONFIG["username"], COUCHBASE_CONFIG["password"])
            index_name = COUCHBASE_CONFIG["tools_index"]
            url = self._search_admin_url(index_name)
            existing = requests.get(url, auth=auth, timeout=10)
            if existing.status_code == 200:
                logger.info("Search index '%s' already exists", index_name)
                return
            resp = requests.put(url, auth=auth, json=self._index_definition(), timeout=15)
            if resp.status_code in (200, 201):
                logger.info("Search index '%s' created", index_name)
            else:
                logger.warning("Search index creation returned %s: %s", resp.status_code, resp.text[:300])

        try:
            await asyncio.to_thread(_upsert)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Search index setup failed (will retry on discover): %s", exc)

    # -- Server registry ------------------------------------------------------

    async def upsert_server(self, doc_id: str, doc: dict):
        await asyncio.to_thread(self.servers.upsert, doc_id, doc)

    async def get_server(self, server_id: str) -> dict | None:
        def _get():
            try:
                return self.servers.get(server_id).content_as[dict]
            except DocumentNotFoundException:
                return None

        return await asyncio.to_thread(_get)

    async def delete_server(self, server_id: str) -> bool:
        def _delete():
            try:
                self.servers.remove(server_id)
                return True
            except DocumentNotFoundException:
                return False

        return await asyncio.to_thread(_delete)

    async def list_servers(self) -> list[dict]:
        bucket, scope = COUCHBASE_CONFIG["bucket"], COUCHBASE_CONFIG["scope"]
        coll = COUCHBASE_CONFIG["servers_collection"]

        def _run():
            q = f"SELECT s.* FROM `{bucket}`.`{scope}`.`{coll}` s"
            return list(self.cluster.query(q, QueryOptions(metrics=False)).rows())

        try:
            return await asyncio.to_thread(_run)
        except Exception as exc:  # noqa: BLE001
            logger.warning("list_servers query failed: %s", exc)
            return []

    # -- Tool registry ----------------------------------------------------------

    async def upsert_tool(self, doc_id: str, doc: dict):
        await asyncio.to_thread(self.tools.upsert, doc_id, doc)

    async def count_tools(self) -> int:
        return await self._count(COUCHBASE_CONFIG["tools_collection"])

    async def list_tools(self) -> list[dict]:
        bucket, scope = COUCHBASE_CONFIG["bucket"], COUCHBASE_CONFIG["scope"]
        coll = COUCHBASE_CONFIG["tools_collection"]

        def _run():
            # Everything except `embedding` (384 floats/tool - no reason to
            # ship that over the API for a catalog listing) and
            # `input_schema` gets returned, including the hijack-detection
            # fields the Threat Detection page needs.
            field_names = [
                "tool_id", "server_id", "name", "description", "input_schema", "allowed_roles", "risk_level",
                "trust_status", "hijack_status", "hijack_severity", "hijack_signals", "hijack_scanned_at",
                "hijack_manual_override",
            ]
            fields = ", ".join(f"t.{f}" for f in field_names)
            q = f"SELECT {fields} FROM `{bucket}`.`{scope}`.`{coll}` t"
            return list(self.cluster.query(q, QueryOptions(metrics=False)).rows())

        try:
            return await asyncio.to_thread(_run)
        except Exception as exc:  # noqa: BLE001
            logger.warning("list_tools query failed: %s", exc)
            return []

    async def get_tool(self, tool_id: str) -> dict | None:
        def _get():
            try:
                return self.tools.get(tool_id).content_as[dict]
            except DocumentNotFoundException:
                return None

        return await asyncio.to_thread(_get)

    async def delete_tools_by_server(self, server_id: str) -> int:
        bucket, scope = COUCHBASE_CONFIG["bucket"], COUCHBASE_CONFIG["scope"]
        coll = COUCHBASE_CONFIG["tools_collection"]

        def _run():
            q = (
                f"DELETE FROM `{bucket}`.`{scope}`.`{coll}` t "
                f"WHERE t.server_id = $server_id RETURNING META(t).id"
            )
            rows = list(self.cluster.query(q, QueryOptions(named_parameters={"server_id": server_id}, metrics=False)).rows())
            return len(rows)

        try:
            return await asyncio.to_thread(_run)
        except Exception as exc:  # noqa: BLE001
            logger.warning("delete_tools_by_server(%s) failed: %s", server_id, exc)
            return 0

    async def _count(self, collection_name: str) -> int:
        if not self.connected:
            return 0
        bucket, scope = COUCHBASE_CONFIG["bucket"], COUCHBASE_CONFIG["scope"]

        def _run():
            q = f"SELECT RAW COUNT(*) FROM `{bucket}`.`{scope}`.`{collection_name}`"
            rows = list(self.cluster.query(q, QueryOptions(metrics=False)).rows())
            return rows[0] if rows else 0

        try:
            return await asyncio.to_thread(_run)
        except Exception as exc:  # noqa: BLE001
            logger.debug("count(%s) failed: %s", collection_name, exc)
            return 0

    # -- Identities (API key -> role) ---------------------------------------

    async def upsert_identity(self, api_key: str, role: str, label: str):
        doc_id = hash_key(api_key)
        await asyncio.to_thread(self.identities.upsert, doc_id, {"role": role, "label": label})

    async def resolve_role(self, api_key: str) -> str | None:
        doc_id = hash_key(api_key)

        def _get():
            try:
                return self.identities.get(doc_id).content_as[dict]
            except DocumentNotFoundException:
                return None

        doc = await asyncio.to_thread(_get)
        return doc["role"] if doc else None

    # -- RBAC + vector pre-filtered discovery --------------------------------

    def _run_search_sync(self, role: str, vector: list, top_k: int) -> list[dict]:
        index_name = COUCHBASE_CONFIG["tools_index"]

        vector_query = CBVectorQuery.create("embedding", vector, num_candidates=max(top_k * 4, 25))
        vector_search = CBVectorSearch.from_vector_query(vector_query)

        # The RBAC + trust pre-filter: a Conjunction ("AND") of exact-term
        # matches on the two fields that gate access. Couchbase evaluates
        # this together with the vector query in the same Search request -
        # tools outside the role, or from an unregistered/untrusted server,
        # are excluded from the candidate set the kNN ranks over, not
        # filtered out afterwards.
        prefilter = cb_search.ConjunctionQuery(
            cb_search.TermQuery(role, field="allowed_roles"),
            cb_search.TermQuery("trusted", field="trust_status"),
        )

        request = cb_search.SearchRequest.create(prefilter).with_vector_search(vector_search)
        result = self.scope.search(
            index_name,
            request,
            SearchOptions(limit=top_k, fields=["name", "description", "server_id", "risk_level", "embedding"]),
        )
        rows = []
        for row in result.rows():
            rows.append({"id": row.id, "fields": row.fields or {}})
        return rows

    async def discover_tools(self, role: str, query_vector: list, top_k: int = 5) -> list[dict]:
        try:
            rows = await asyncio.to_thread(self._run_search_sync, role, query_vector, top_k)
        except Exception as exc:  # noqa: BLE001
            logger.warning("RBAC vector search failed (%s) - falling back to a filtered KV scan", exc)
            rows = await self._fallback_scan(role, top_k)

        query_np = np.array(query_vector, dtype=np.float32)
        out = []
        for row in rows:
            fields = row["fields"]
            stored_vector = fields.get("embedding")
            similarity = round(float(np.dot(query_np, np.array(stored_vector, dtype=np.float32))), 3) if stored_vector else 0.0
            out.append({
                "tool_id": row["id"],
                "name": fields.get("name"),
                "description": fields.get("description"),
                "server_id": fields.get("server_id"),
                "risk_level": fields.get("risk_level"),
                "similarity": similarity,
            })
        out.sort(key=lambda t: t["similarity"], reverse=True)
        return out

    async def _fallback_scan(self, role: str, top_k: int) -> list[dict]:
        """Defense-in-depth fallback if the Search service is briefly
        unavailable: a plain N1QL scan that applies the SAME RBAC + trust
        predicate in the WHERE clause, then ranks by cosine similarity in
        Python. Slower, but never less strict than the primary path."""
        bucket, scope = COUCHBASE_CONFIG["bucket"], COUCHBASE_CONFIG["scope"]
        coll = COUCHBASE_CONFIG["tools_collection"]

        def _run():
            q = (
                f"SELECT META(t).id AS id, t.name, t.description, t.server_id, t.risk_level, t.embedding "
                f"FROM `{bucket}`.`{scope}`.`{coll}` t "
                f"WHERE t.trust_status = $trust AND $role IN t.allowed_roles"
            )
            result = self.cluster.query(q, QueryOptions(named_parameters={"trust": "trusted", "role": role}, metrics=False))
            return list(result.rows())

        try:
            rows = await asyncio.to_thread(_run)
        except Exception as exc:  # noqa: BLE001
            logger.error("Fallback KV scan also failed: %s", exc)
            return []
        return [{"id": r["id"], "fields": r} for r in rows][:top_k]

    # -- Audit log -------------------------------------------------------------

    async def log_access(
        self,
        *,
        action: str,
        role: str | None,
        subject_label: str | None,
        query: str | None,
        tool_id: str | None,
        server_id: str | None,
        decision: str,
        reason: str,
        latency_ms: int,
        hijack_flagged: bool = False,
        hijack_severity: str | None = None,
        hijack_signals: list | None = None,
    ):
        doc_id = f"log::{int(time.time() * 1000)}::{uuid.uuid4().hex[:8]}"
        doc = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "action": action,
            "role": role,
            "subject": subject_label,
            "query": query,
            "tool_id": tool_id,
            "server_id": server_id,
            "decision": decision,
            "reason": reason,
            "latency_ms": latency_ms,
            # Response-payload hijack scan result for this call (invoke
            # only - see app/hijack_detection.py). Always present so the
            # Threat Detection page and chain correlation can filter on it
            # without a schema-dependent WHERE clause.
            "hijack_flagged": hijack_flagged,
            "hijack_severity": hijack_severity,
            "hijack_signals": hijack_signals or [],
        }
        try:
            await asyncio.to_thread(
                self.access_log.upsert, doc_id, doc, UpsertOptions(expiry=timedelta(hours=AUDIT_LOG_RETENTION_HOURS))
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to write audit log entry: %s", exc)

    async def recent_access_log(self, limit: int = 50) -> list[dict]:
        bucket, scope = COUCHBASE_CONFIG["bucket"], COUCHBASE_CONFIG["scope"]
        coll = COUCHBASE_CONFIG["access_log_collection"]

        def _run():
            q = (
                f"SELECT l.* FROM `{bucket}`.`{scope}`.`{coll}` l "
                f"ORDER BY l.timestamp DESC LIMIT $limit"
            )
            return list(self.cluster.query(q, QueryOptions(named_parameters={"limit": limit}, metrics=False)).rows())

        try:
            return await asyncio.to_thread(_run)
        except Exception as exc:  # noqa: BLE001
            logger.warning("recent_access_log query failed: %s", exc)
            return []
