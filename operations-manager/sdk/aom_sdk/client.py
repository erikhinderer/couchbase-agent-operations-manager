"""
Client SDK for the Couchbase Agent Operations Manager.

An agent that talks to the operations manager directly has to attach a
bearer API key to every call, know the exact JSON shape for discover /
invoke / complete, and turn HTTP status codes back into something it can
branch on. `AOMClient` does all three, so integrating code looks like:

    from aom_sdk import AOMClient

    client = AOMClient("http://localhost:8090", api_key="demo-support-agent-9f21")
    discovered = client.discover("look up a customer's open tickets")
    result = client.invoke(discovered["tools"][0]["tool_id"], arguments={})

See the bundled examples/ directory and the appliance's Tools -> Developer
SDK page for the full quickstart, including cached LLM completions.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

import requests

from .exceptions import (
    AOMAuthenticationError,
    AOMAuthorizationError,
    AOMConnectionError,
    AOMError,
    AOMNotFoundError,
    AOMServerError,
)
from .mcp_tools import to_mcp_tool

DEFAULT_TIMEOUT_SECONDS = 30


class AOMClient:
    """A thin, typed wrapper around the operations manager's REST gateway.

    Parameters
    ----------
    base_url:
        Where the operations manager is reachable, e.g. ``http://localhost:8090``
        for the bundled Docker Compose stack, or your appliance's real
        origin in production.
    api_key:
        The bearer API key issued for your agent's RBAC role (see the
        Roles & RBAC page, or the operations-manager container's ``.env``).
        Only required for calls that authenticate - discover, invoke and
        complete - not for ``health()`` or ``roles()``.
    timeout:
        Per-request timeout in seconds, passed straight to ``requests``.
    session:
        Reuse an existing ``requests.Session`` (e.g. for connection pooling
        across many agent instances) instead of letting the client create
        its own.
    """

    def __init__(
        self,
        base_url: str,
        api_key: Optional[str] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        session: Optional[requests.Session] = None,
    ) -> None:
        if not base_url:
            raise ValueError("base_url is required, e.g. AOMClient('http://localhost:8090')")
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self._session = session or requests.Session()

    def __repr__(self) -> str:
        return f"AOMClient(base_url={self.base_url!r}, authenticated={bool(self.api_key)})"

    # -- internals ----------------------------------------------------------
    def _headers(self, auth: bool) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if auth:
            if not self.api_key:
                raise AOMAuthenticationError(
                    "This call requires an API key - pass api_key=... to AOMClient(...)"
                )
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def _request(
        self,
        method: str,
        path: str,
        *,
        auth: bool = False,
        json_body: Optional[dict] = None,
        params: Optional[dict] = None,
    ) -> Any:
        url = f"{self.base_url}{path}"
        try:
            response = self._session.request(
                method,
                url,
                headers=self._headers(auth),
                json=json_body,
                params=params,
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise AOMConnectionError(
                f"Could not reach the operations manager at {self.base_url}: {exc}"
            ) from exc

        if response.status_code >= 400:
            detail: Optional[str]
            try:
                detail = response.json().get("detail")
            except ValueError:
                detail = response.text or None
            message = detail or f"{response.status_code} {response.reason}"

            if response.status_code == 401:
                raise AOMAuthenticationError(message, response.status_code, detail)
            if response.status_code == 403:
                raise AOMAuthorizationError(message, response.status_code, detail)
            if response.status_code == 404:
                raise AOMNotFoundError(message, response.status_code, detail)
            if response.status_code >= 500:
                raise AOMServerError(message, response.status_code, detail)
            raise AOMError(message, response.status_code, detail)

        if response.status_code == 204 or not response.content:
            return None
        return response.json()

    # -- health / metadata ----------------------------------------------------
    def health(self) -> dict:
        """GET /api/health - no API key required. Useful as a startup
        readiness check before an agent starts sending real traffic."""
        return self._request("GET", "/api/health")

    def roles(self) -> List[dict]:
        """GET /v1/roles - the RBAC roles configured on this appliance."""
        return self._request("GET", "/v1/roles")["roles"]

    # -- tool discovery / invocation -------------------------------------------
    def discover(self, query: str, top_k: int = 5) -> dict:
        """POST /v1/tools/discover - RBAC + vector-search pre-filtered tool
        search for your role. Never returns a tool your API key's role
        can't also invoke."""
        return self._request(
            "POST", "/v1/tools/discover", auth=True,
            json_body={"query": query, "top_k": top_k},
        )

    def invoke(self, tool_id: str, arguments: Optional[dict] = None) -> dict:
        """POST /v1/tools/invoke - re-checks authorization independently of
        discover, then proxies to the tool's real MCP server. The response
        includes ``hijack_warning`` (non-null when the live payload was
        flagged by the MCP Tool Hijacking detector) - always check it
        rather than trusting ``result`` blindly."""
        return self._request(
            "POST", "/v1/tools/invoke", auth=True,
            json_body={"tool_id": tool_id, "arguments": arguments or {}},
        )

    def discover_and_invoke(
        self, query: str, arguments: Optional[dict] = None, top_k: int = 1
    ) -> dict:
        """Convenience wrapper: discover the single best-matching tool for
        ``query`` and invoke it immediately. Raises ``AOMNotFoundError`` if
        nothing matched - handy for a quick script, less so for an agent
        that should reason about *which* discovered tool to pick."""
        discovered = self.discover(query, top_k=max(1, top_k))
        tools = discovered.get("tools") or []
        if not tools:
            raise AOMNotFoundError(f"No tool matched query: {query!r}")
        return self.invoke(tools[0]["tool_id"], arguments=arguments)

    # -- cached LLM completions ----------------------------------------------
    def complete(
        self,
        prompt: str,
        *,
        provider: Optional[str] = None,
        model: Optional[str] = None,
        namespace: Optional[str] = None,
        bypass_cache: bool = False,
        params: Optional[dict] = None,
    ) -> dict:
        """POST /v1/llm/complete - a cached completion. A repeat or
        near-duplicate prompt (see the similarity threshold in the LLM
        Caching policy) is answered from Couchbase without spending a
        single token. ``response["cache"]["status"]`` is one of
        ``hit_exact`` / ``hit_semantic`` / ``miss`` / ``bypass``;
        ``response["usage"]`` and ``response["cost_usd"]`` reflect actual
        provider spend - i.e. zero on any hit. Set ``bypass_cache=True`` for
        a prompt that must always reach the live model."""
        return self._request(
            "POST", "/v1/llm/complete", auth=True,
            json_body={
                "prompt": prompt,
                "provider": provider,
                "model": model,
                "namespace": namespace,
                "bypass_cache": bypass_cache,
                "params": params or {},
            },
        )

    # -- agent memory ---------------------------------------------------------
    # Durable, cross-session recall stored in the same Couchbase cluster as
    # everything else in this appliance - not a separate service to run or
    # depend on. All four calls authenticate like discover/invoke/complete;
    # they are scoped by the `user_id` you pass, not by RBAC role.

    def add_memory(
        self,
        user_id: str,
        content: str,
        *,
        session_id: Optional[str] = None,
        memory_type: str = "conversational",
        metadata: Optional[dict] = None,
        ttl_seconds: int = 0,
    ) -> dict:
        """POST /v1/memory - store one memory entry for `user_id`, embedded
        for later semantic recall via `search_memory()`. `memory_type` is
        one of "conversational" (the default - what was said in a
        session), "profile" (durable facts about the user), or "semantic"
        (retrieved knowledge worth remembering). `ttl_seconds` is optional -
        memory is durable by default, unlike the LLM response cache."""
        return self._request(
            "POST", "/v1/memory", auth=True,
            json_body={
                "user_id": user_id,
                "content": content,
                "session_id": session_id,
                "memory_type": memory_type,
                "metadata": metadata or {},
                "ttl_seconds": ttl_seconds,
            },
        )

    def list_memory(
        self,
        user_id: str,
        *,
        session_id: Optional[str] = None,
        memory_type: Optional[str] = None,
        limit: int = 100,
    ) -> List[dict]:
        """GET /v1/memory - chronological listing for one user, optionally
        narrowed to a session or memory type. Use this to re-hydrate recent
        context at the start of a turn; use `search_memory()` when you want
        the most *relevant* entries instead of the most recent ones."""
        params: Dict[str, Any] = {"user_id": user_id, "limit": limit}
        if session_id:
            params["session_id"] = session_id
        if memory_type:
            params["memory_type"] = memory_type
        return self._request("GET", "/v1/memory", auth=True, params=params)["entries"]

    def search_memory(
        self,
        user_id: str,
        query: str,
        *,
        session_id: Optional[str] = None,
        memory_type: Optional[str] = None,
        top_k: int = 5,
    ) -> List[dict]:
        """POST /v1/memory/search - semantic recall: the memory entries for
        `user_id` whose content is closest to `query`, ranked by
        similarity - the same vector-search pattern `discover()` runs over
        the tool catalog, scoped to one user's memory instead of one
        role's tools."""
        return self._request(
            "POST", "/v1/memory/search", auth=True,
            json_body={
                "user_id": user_id,
                "query": query,
                "session_id": session_id,
                "memory_type": memory_type,
                "top_k": top_k,
            },
        )["entries"]

    def delete_memory(self, memory_id: str) -> bool:
        """DELETE /v1/memory/{memory_id} - remove one entry, e.g. after a
        user asks to be forgotten or a fact turns out to be wrong."""
        return bool(self._request("DELETE", f"/v1/memory/{memory_id}", auth=True)["deleted"])

    def clear_memory(self, user_id: str, *, session_id: Optional[str] = None) -> int:
        """POST /v1/memory/clear - bulk-wipe a user's memory, or just one
        session of it (e.g. clearing short-term conversational memory at
        session end while leaving that user's durable profile memories
        alone). Returns the number of entries removed."""
        return self._request(
            "POST", "/v1/memory/clear", auth=True,
            json_body={"user_id": user_id, "session_id": session_id},
        )["cleared"]

    # -- MCP tool integration ---------------------------------------------------
    # AOM already speaks MCP to every downstream tool server it proxies to
    # (see the appliance's app/mcp_client.py); these helpers make that
    # protocol visible on the client side too, so a discovered tool can be
    # handed directly to any MCP-compatible agent runtime instead of only
    # ever being called through invoke().

    def catalog(self) -> List[dict]:
        """GET /v1/catalog - the full vetted tool catalog (no API key
        required): every tool's id, name, description, input_schema,
        allowed_roles and trust status. `discover()` alone doesn't carry
        `input_schema`; this is how `discover_mcp_tools()` fills it in."""
        return self._request("GET", "/v1/catalog")["tools"]

    def discover_mcp_tools(self, query: str, top_k: int = 5) -> List[dict]:
        """Like `discover()`, but returns each matched tool already
        converted to a standard MCP tool definition
        (``{"name", "description", "inputSchema"}``) - ready to hand to any
        MCP-compatible agent runtime or tool-calling API without writing
        the conversion yourself. `name` is the AOM tool_id; pass it
        straight to `invoke()` (or its alias `invoke_mcp_tool()`)."""
        discovered = self.discover(query, top_k=top_k)
        matched_ids = [t["tool_id"] for t in discovered.get("tools", [])]
        if not matched_ids:
            return []
        catalog_by_id = {t["tool_id"]: t for t in self.catalog()}
        return [to_mcp_tool(catalog_by_id[tid]) for tid in matched_ids if tid in catalog_by_id]

    def invoke_mcp_tool(self, name: str, arguments: Optional[dict] = None) -> dict:
        """Alias for `invoke()` using MCP tool-call terminology - `name`
        here is the AOM tool_id, which doubles as the MCP tool name
        returned by `discover_mcp_tools()`."""
        return self.invoke(name, arguments=arguments)
