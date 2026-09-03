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

from config import (
    AUDIT_LOG_RETENTION_HOURS,
    COUCHBASE_CONFIG,
    EMBEDDING_CONFIG,
    LLM_CACHE_LOG_RETENTION_HOURS,
)

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
        self.llm_cache = None
        self.llm_cache_log = None
        self.settings = None
        self.connected = False

    async def connect(self, retries: int = 30, delay_seconds: float = 5.0):
        for attempt in range(1, retries + 1):
            try:
                await asyncio.to_thread(self._connect_sync)
                self.connected = True
                logger.info("Connected to Couchbase on attempt %d", attempt)
                await self.ensure_search_index()
                await self.ensure_llm_cache_index()
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
        llm_cache = scope.collection(COUCHBASE_CONFIG["llm_cache_collection"])
        llm_cache_log = scope.collection(COUCHBASE_CONFIG["llm_cache_log_collection"])
        settings = scope.collection(COUCHBASE_CONFIG["settings_collection"])

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
        for collection in (servers, tools, identities, access_log, llm_cache, llm_cache_log, settings):
            collection.exists("__startup_probe__")

        self.cluster = cluster
        self.bucket = bucket
        self.scope = scope
        self.servers = servers
        self.tools = tools
        self.identities = identities
        self.access_log = access_log
        self.llm_cache = llm_cache
        self.llm_cache_log = llm_cache_log
        self.settings = settings

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

    # -- LLM response cache ----------------------------------------------------
    #
    # The cache is a KV collection with a second Search (FTS) vector index over
    # it. Exact matches are a single KV get on a deterministic document ID -
    # no query, no index, sub-millisecond. Semantic matches reuse exactly the
    # pattern `discover_tools` already uses for the tool catalog: a
    # Conjunction pre-filter (provider + model + scope + namespace) evaluated
    # alongside a vector kNN over the prompt embedding, so an entry belonging
    # to a different model or a different tenant scope can never be returned
    # no matter how similar the prompt is.

    def _llm_cache_index_definition(self) -> dict:
        bucket = COUCHBASE_CONFIG["bucket"]
        scope = COUCHBASE_CONFIG["scope"]
        collection = COUCHBASE_CONFIG["llm_cache_collection"]
        type_key = f"{scope}.{collection}"

        def keyword_field(name: str) -> dict:
            # `keyword`, not `standard`: provider/model/scope values are
            # identifiers ("claude-sonnet-4-5", "role:finance_analyst"), and
            # the standard analyzer would tokenize them apart and turn an
            # exact pre-filter into a fuzzy one.
            return {
                "dynamic": False,
                "enabled": True,
                "fields": [{"name": name, "type": "text", "analyzer": "keyword", "index": True, "store": True}],
            }

        properties = {
            "provider": keyword_field("provider"),
            "model": keyword_field("model"),
            "scope_key": keyword_field("scope_key"),
            "namespace": keyword_field("namespace"),
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
            "name": f"{bucket}.{scope}.{COUCHBASE_CONFIG['llm_cache_index']}",
            "sourceType": "gocbcore",
            "sourceName": bucket,
            "planParams": {"maxPartitionsPerPIndex": 512, "indexPartitions": 1},
            "params": {
                "doc_config": {"mode": "scope.collection.type_field", "type_field": "doc_type"},
                "mapping": {
                    "default_analyzer": "keyword",
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

    async def ensure_llm_cache_index(self):
        def _upsert():
            auth = (COUCHBASE_CONFIG["username"], COUCHBASE_CONFIG["password"])
            index_name = COUCHBASE_CONFIG["llm_cache_index"]
            url = self._search_admin_url(index_name)
            existing = requests.get(url, auth=auth, timeout=10)
            if existing.status_code == 200:
                logger.info("LLM cache search index '%s' already exists", index_name)
                return
            resp = requests.put(url, auth=auth, json=self._llm_cache_index_definition(), timeout=15)
            if resp.status_code in (200, 201):
                logger.info("LLM cache search index '%s' created", index_name)
            else:
                logger.warning("LLM cache index creation returned %s: %s", resp.status_code, resp.text[:300])

        try:
            await asyncio.to_thread(_upsert)
        except Exception as exc:  # noqa: BLE001
            logger.warning("LLM cache index setup failed (semantic lookups will fall back to exact): %s", exc)

    async def get_cache_entry(self, entry_id: str) -> dict | None:
        def _get():
            try:
                return self.llm_cache.get(entry_id).content_as[dict]
            except DocumentNotFoundException:
                return None

        try:
            return await asyncio.to_thread(_get)
        except Exception as exc:  # noqa: BLE001
            logger.warning("get_cache_entry(%s) failed: %s", entry_id, exc)
            return None

    async def upsert_cache_entry(self, entry_id: str, doc: dict, ttl_seconds: int = 0):
        """Written with a Couchbase document expiry equal to the configured
        TTL (plus any stale-while-revalidate grace) so the cluster reclaims
        the space even if the background sweeper never runs. The logical TTL
        check in llm_cache.evaluate_entry still runs on read - expiry is the
        floor, not the policy."""
        def _upsert():
            if ttl_seconds and ttl_seconds > 0:
                self.llm_cache.upsert(entry_id, doc, UpsertOptions(expiry=timedelta(seconds=ttl_seconds)))
            else:
                self.llm_cache.upsert(entry_id, doc)

        try:
            await asyncio.to_thread(_upsert)
        except Exception as exc:  # noqa: BLE001
            logger.warning("upsert_cache_entry(%s) failed: %s", entry_id, exc)

    async def delete_cache_entry(self, entry_id: str) -> bool:
        def _delete():
            try:
                self.llm_cache.remove(entry_id)
                return True
            except DocumentNotFoundException:
                return False

        try:
            return await asyncio.to_thread(_delete)
        except Exception as exc:  # noqa: BLE001
            logger.warning("delete_cache_entry(%s) failed: %s", entry_id, exc)
            return False

    async def list_cache_entries(self, limit: int = 200) -> list[dict]:
        """Everything except `embedding` (384 floats/entry) and the full
        `response` body - the table only needs previews."""
        bucket, scope = COUCHBASE_CONFIG["bucket"], COUCHBASE_CONFIG["scope"]
        coll = COUCHBASE_CONFIG["llm_cache_collection"]

        def _run():
            field_names = [
                "entry_id", "provider", "model", "scope_key", "namespace", "prompt_preview",
                "response_preview", "prompt_tokens", "completion_tokens", "total_tokens",
                "cost_usd", "created_at", "last_hit_at", "hit_count", "exact_hits",
                "semantic_hits", "tokens_saved", "cost_saved_usd", "origin_latency_ms",
                "config_version", "catalog_version", "override", "stub",
            ]
            fields = ", ".join(f"c.{f}" for f in field_names)
            q = (
                f"SELECT {fields} FROM `{bucket}`.`{scope}`.`{coll}` c "
                f"ORDER BY c.created_at DESC LIMIT $limit"
            )
            return list(self.cluster.query(q, QueryOptions(named_parameters={"limit": limit}, metrics=False)).rows())

        try:
            return await asyncio.to_thread(_run)
        except Exception as exc:  # noqa: BLE001
            logger.warning("list_cache_entries query failed: %s", exc)
            return []

    async def count_cache_entries(self) -> int:
        return await self._count(COUCHBASE_CONFIG["llm_cache_collection"])

    async def purge_cache(self, provider: str | None = None, model: str | None = None, namespace: str | None = None) -> int:
        """Manual invalidation. With no arguments this is 'purge everything';
        the optional filters are what the LLM Caching page's per-provider and
        per-model purge buttons send."""
        bucket, scope = COUCHBASE_CONFIG["bucket"], COUCHBASE_CONFIG["scope"]
        coll = COUCHBASE_CONFIG["llm_cache_collection"]
        clauses, params = [], {}
        if provider:
            clauses.append("c.provider = $provider")
            params["provider"] = provider
        if model:
            clauses.append("c.model = $model")
            params["model"] = model
        if namespace:
            clauses.append("c.namespace = $namespace")
            params["namespace"] = namespace
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""

        def _run():
            q = f"DELETE FROM `{bucket}`.`{scope}`.`{coll}` c{where} RETURNING META(c).id"
            rows = list(self.cluster.query(q, QueryOptions(named_parameters=params, metrics=False)).rows())
            return len(rows)

        try:
            return await asyncio.to_thread(_run)
        except Exception as exc:  # noqa: BLE001
            logger.warning("purge_cache failed: %s", exc)
            return 0

    def _run_cache_search_sync(self, provider: str, model: str, scope_key: str, namespace: str, vector: list, top_k: int) -> list[dict]:
        index_name = COUCHBASE_CONFIG["llm_cache_index"]
        vector_query = CBVectorQuery.create("embedding", vector, num_candidates=max(top_k * 2, 20))
        vector_search = CBVectorSearch.from_vector_query(vector_query)

        prefilter = cb_search.ConjunctionQuery(
            cb_search.TermQuery(provider, field="provider"),
            cb_search.TermQuery(model, field="model"),
            cb_search.TermQuery(scope_key, field="scope_key"),
            cb_search.TermQuery(namespace, field="namespace"),
        )
        request = cb_search.SearchRequest.create(prefilter).with_vector_search(vector_search)
        result = self.scope.search(
            index_name,
            request,
            SearchOptions(limit=top_k, fields=["provider", "model", "scope_key", "namespace", "embedding"]),
        )
        return [{"id": row.id, "fields": row.fields or {}} for row in result.rows()]

    async def semantic_cache_lookup(
        self, provider: str, model: str, scope_key: str, namespace: str, query_vector: list, top_k: int = 20
    ) -> list[dict]:
        """Return [{entry_id, similarity}] best-first. Similarity is a plain
        dot product, which equals cosine here because ToolEmbeddings.embed
        L2-normalizes every vector it produces."""
        try:
            rows = await asyncio.to_thread(
                self._run_cache_search_sync, provider, model, scope_key, namespace, query_vector, top_k
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Semantic cache lookup failed (%s) - exact matching only for this call", exc)
            return []

        query_np = np.array(query_vector, dtype=np.float32)
        out = []
        for row in rows:
            stored = row["fields"].get("embedding")
            if not stored:
                continue
            similarity = float(np.dot(query_np, np.array(stored, dtype=np.float32)))
            out.append({"entry_id": row["id"], "similarity": round(similarity, 4)})
        out.sort(key=lambda r: r["similarity"], reverse=True)
        return out

    # -- LLM cache event log ---------------------------------------------------

    async def log_llm_event(self, doc: dict):
        doc_id = f"llmevt::{int(time.time() * 1000)}::{uuid.uuid4().hex[:8]}"
        try:
            await asyncio.to_thread(
                self.llm_cache_log.upsert,
                doc_id,
                doc,
                UpsertOptions(expiry=timedelta(hours=LLM_CACHE_LOG_RETENTION_HOURS)),
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to write LLM cache event: %s", exc)

    async def recent_llm_events(self, limit: int = 500) -> list[dict]:
        bucket, scope = COUCHBASE_CONFIG["bucket"], COUCHBASE_CONFIG["scope"]
        coll = COUCHBASE_CONFIG["llm_cache_log_collection"]

        def _run():
            q = (
                f"SELECT e.* FROM `{bucket}`.`{scope}`.`{coll}` e "
                f"ORDER BY e.timestamp DESC LIMIT $limit"
            )
            return list(self.cluster.query(q, QueryOptions(named_parameters={"limit": limit}, metrics=False)).rows())

        try:
            return await asyncio.to_thread(_run)
        except Exception as exc:  # noqa: BLE001
            logger.warning("recent_llm_events query failed: %s", exc)
            return []

    # -- Settings (user-editable runtime policy) -------------------------------

    async def get_setting(self, doc_id: str) -> dict | None:
        def _get():
            try:
                return self.settings.get(doc_id).content_as[dict]
            except DocumentNotFoundException:
                return None

        try:
            return await asyncio.to_thread(_get)
        except Exception as exc:  # noqa: BLE001
            logger.warning("get_setting(%s) failed: %s", doc_id, exc)
            return None

    async def upsert_setting(self, doc_id: str, doc: dict):
        try:
            await asyncio.to_thread(self.settings.upsert, doc_id, doc)
        except Exception as exc:  # noqa: BLE001
            logger.warning("upsert_setting(%s) failed: %s", doc_id, exc)
