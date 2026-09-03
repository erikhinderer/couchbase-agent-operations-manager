# Couchbase Agent Operations Manager - Developer SDK

Official Python client for the Couchbase Agent Operations Manager: a thin,
typed wrapper around the appliance's REST gateway so your agent code never
hand-rolls bearer-token headers or JSON payloads for `discover` / `invoke` /
`complete`.

Get the appliance's own overview and architecture from the repo README;
this package only covers the client.

## Install

Unzip this package, then from inside the `couchbase-aom-sdk-*` folder:

```bash
pip install .
```

Editable install, for iterating against the SDK source itself:

```bash
pip install -e .
```

Requires Python 3.8+ and `requests`.

## Quickstart

```python
from aom_sdk import AOMClient

client = AOMClient(
    base_url="http://localhost:8090",   # your operations-manager origin
    api_key="demo-support-agent-9f21",  # your RBAC role's API key
)

# 1. Discover tools for a task - RBAC + vector-search pre-filtered, never a
#    full unfiltered tool dump.
discovered = client.discover("look up a customer's open support tickets")
for tool in discovered["tools"]:
    print(tool["tool_id"], tool["name"])

# 2. Invoke the one you picked - re-checked against Couchbase independently,
#    then proxied to its real MCP server.
result = client.invoke(discovered["tools"][0]["tool_id"], arguments={})
print(result["result"])

# 3. Route model calls through the same gateway to get response caching -
#    a repeat or near-duplicate prompt costs zero tokens.
answer = client.complete("Summarize this ticket thread in two sentences.")
print(answer["response"], answer["cache"]["status"])

# 4. Remember things about this user across sessions.
client.add_memory("user-42", "Prefers responses in metric units.", memory_type="profile")
for m in client.search_memory("user-42", "does this user use metric or imperial?"):
    print(m["content"], m["similarity"])
```

## Agent memory

Durable, cross-session recall stored in the same Couchbase cluster as
everything else in this appliance - not a separate service to stand up.
`add_memory()` embeds and stores an entry scoped to a `user_id` (and
optionally a `session_id`); `search_memory()` recalls the entries closest
in meaning to a new query, the same vector-search idea `discover()` runs
over the tool catalog. `list_memory()`, `delete_memory()` and
`clear_memory()` round out the CRUD surface. See `examples/agent_memory.py`.

Three conventional `memory_type` values - `conversational` (the default;
what was said in a session), `profile` (durable facts about the user),
and `semantic` (retrieved knowledge worth remembering) - are labels for
your own filtering, not enforced behavior.

## MCP tool integration

AOM already speaks MCP to every downstream tool server it proxies to; this
SDK makes that protocol visible on the client side too:

- `client.discover_mcp_tools(query)` - like `discover()`, but returns each
  matched tool already converted to a standard MCP tool definition
  (`{"name", "description", "inputSchema"}`), ready to hand to any
  MCP-compatible agent runtime or tool-calling API.
- `client.invoke_mcp_tool(name, arguments)` - alias for `invoke()` using
  MCP tool-call terminology.
- `aom_sdk.mcp_server` - an optional bridge (`pip install
  "couchbase-aom-sdk[mcp]"`) that runs this appliance as a real local MCP
  server over stdio, so any MCP host (Claude Desktop, Claude Code, etc.)
  can attach to it directly and reach every tool your API key's role is
  authorized for - still governed by AOM's RBAC and audit trail. Run it
  with:

  ```bash
  AOM_BASE_URL=http://localhost:8090 AOM_API_KEY=demo-support-agent-9f21 \
      python -m aom_sdk.mcp_server
  ```

  See `examples/mcp_tools.py`.

## Why route completions through `complete()` too

Agents tend to ask a small set of questions over and over, reworded every
time, across sessions and users. Every one of those calls is a fresh,
billed round trip to the model provider unless something recognizes the
repeat. `client.complete()` sends the prompt to `/v1/llm/complete` instead
of the provider directly, where it's matched against Couchbase first - by
an exact hash for a byte-for-byte repeat, or by vector similarity for a
paraphrase - and only reaches the provider on a genuine miss. See "Why
route model calls through the SDK too" on the appliance's **Tools ->
Developer SDK** page for the cost/latency math behind this.

## Error handling

Every non-2xx response raises a typed exception from `aom_sdk`:

| Exception | Raised on |
|---|---|
| `AOMConnectionError` | Could not reach the operations manager at all |
| `AOMAuthenticationError` | 401 - missing or invalid API key |
| `AOMAuthorizationError` | 403 - role not authorized for that tool |
| `AOMNotFoundError` | 404 - unknown tool/server/entry |
| `AOMServerError` | 5xx - operations manager or downstream MCP server failed |
| `AOMError` | Base class; any other 4xx |

```python
from aom_sdk import AOMClient, AOMAuthorizationError

client = AOMClient("http://localhost:8090", api_key="demo-support-agent-9f21")
try:
    client.invoke("billing-service::refund_customer", arguments={"order_id": "123"})
except AOMAuthorizationError as exc:
    print(f"Not authorized: {exc}")
```

## Examples

- `examples/quickstart.py` - discover, invoke, and one cached completion.
- `examples/llm_caching.py` - sends the same prompt, a paraphrase, and a
  forced bypass, and prints the cache status/cost/latency for each so you
  can see a miss turn into a hit.
- `examples/agent_memory.py` - stores durable and session-scoped memories,
  then recalls the relevant one semantically instead of just the most
  recent one.
- `examples/mcp_tools.py` - discovers tools in MCP schema shape and
  invokes one by its MCP name.

## Full API reference

This SDK wraps a deliberate subset of the appliance's REST API. The
gateway's own OpenAPI docs (`/docs` on the operations-manager origin) and
the appliance's repo README are the source of truth for every endpoint,
including the admin surface (server registration, roles, audit log, cache
administration) that most agent code never needs.

## License

MIT - see the appliance repo's `LICENSE`.
