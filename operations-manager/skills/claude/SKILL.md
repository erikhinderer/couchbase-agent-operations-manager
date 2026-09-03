---
name: couchbase-aom-sdk
description: Use when integrating an agent codebase with the Couchbase Agent Operations Manager - installing the aom_sdk Python client, and wiring up RBAC-gated tool discovery/invocation, cached LLM completions, agent memory, or the MCP server bridge in place of hand-rolled REST calls.
---

# Couchbase Agent Operations Manager SDK integration

Use this skill whenever a codebase should talk to a Couchbase Agent
Operations Manager (AOM) appliance - the RBAC + vector-search gateway that
sits between an agent and its MCP tool servers - and doesn't yet use
`aom_sdk`, the appliance's official Python client. It applies whether the
codebase is brand new or already has hand-written `requests` calls against
the appliance's REST API that should be replaced.

## When to use this

- The user asks to "connect this agent to AOM / the Operations Manager",
  "add tool discovery", "wire up the Couchbase agent gateway", or similar.
- You find raw HTTP calls to endpoints under `/v1/tools/`, `/v1/llm/`, or
  `/v1/memory/` on an AOM appliance and the codebase has no `aom_sdk`
  dependency yet - replace them with the SDK rather than leaving both
  patterns in the same codebase.
- A new agent project needs to call out to external tools, cache LLM
  completions, or remember things about a user, and an AOM appliance is
  the intended backend for that.

## Step 1 - get the SDK

`couchbase-aom-sdk` is not published to a public package index; it ships
from the appliance itself. Get it one of two ways:

- The appliance's dashboard: **Tools -> Developer SDK -> Download SDK**.
- Directly: `curl -k -o aom-sdk.zip https://<appliance-host>:8090/v1/sdk/download` (`-k` skips verifying the appliance's certificate - it's self-signed by default; drop it once a real one is installed)
  (default port `8090`; adjust the host for the target deployment).

Then, from the project that will depend on it:

```bash
unzip aom-sdk.zip -d /tmp/aom-sdk
pip install /tmp/aom-sdk/couchbase-aom-sdk-*
```

For a project using a lockfile-based workflow (Poetry, uv, pip-tools),
vendor the unzipped SDK folder into the repo (e.g. `vendor/aom-sdk/`) and
add it as a local/path dependency instead of leaving it in `/tmp`, so the
build is reproducible for other developers and CI.

If the target codebase's agent runtime needs to speak MCP directly rather
than call the SDK's Python API (see Step 4), install the optional extra:
`pip install "/tmp/aom-sdk/couchbase-aom-sdk-*[mcp]"`.

## Step 2 - configure a client

Every call needs the appliance's base URL and (for anything but
`health()`/`roles()`/`catalog()`) a bearer API key tied to an RBAC role.
Read both from environment variables - never hardcode a key:

```python
import os
from aom_sdk import AOMClient

client = AOMClient(
    base_url=os.environ["AOM_BASE_URL"],   # e.g. "https://localhost:8090"
    api_key=os.environ.get("AOM_API_KEY"),  # the agent's RBAC role's key
    # The appliance serves HTTPS with a self-signed certificate by default -
    # this reads AOM_VERIFY_SSL (default "false") the same way the bundled
    # SDK examples do; set it to "true" once a real certificate is installed.
    verify=os.environ.get("AOM_VERIFY_SSL", "false").lower() == "true",
)
```

If the codebase has a settings/config module (Pydantic settings, Django
settings, a `.env` loader), add `AOM_BASE_URL` and `AOM_API_KEY` there
following that project's existing convention rather than introducing a new
one.

## Step 3 - replace tool calling with discover/invoke

Look for existing code that lists or calls tools directly (a hardcoded
tool registry, a raw MCP client, or direct HTTP calls to a tool server)
and replace it with the gateway pattern: discover, then invoke. Never let
an agent invoke a tool_id it didn't get from `discover()` in the same
codebase - the appliance re-checks authorization independently, but the
client-side code should still follow the intended flow.

```python
discovered = client.discover("look up a customer's open support tickets")
tool = discovered["tools"][0]
result = client.invoke(tool["tool_id"], arguments={})
```

Check `result["hijack_warning"]` before trusting `result["result"]` in
anything user-facing - a non-null value means the appliance's hijack
detector flagged the live tool response.

## Step 4 - or bridge as a real MCP server

If the target framework already speaks MCP (it configures MCP servers by
URL/command rather than calling a Python client directly - LangGraph's
MCP adapters, Claude Desktop, Claude Code, etc.), don't write a custom
adapter. Point it at the bundled bridge instead:

```bash
pip install "couchbase-aom-sdk[mcp]"
AOM_BASE_URL=https://localhost:8090 AOM_API_KEY=<role-api-key> \
    AOM_VERIFY_SSL=false python -m aom_sdk.mcp_server
```

This runs AOM as a local MCP server over stdio: `list_tools` returns the
caller's authorized catalog, `call_tool` invokes through AOM's RBAC and
audit trail. Wire it into the framework's MCP server configuration (a
command + args entry, typically) the same way as any other MCP server.

If only the tool *definitions* are needed in MCP shape (e.g. to hand to an
OpenAI-style function-calling API without running a server), use
`client.discover_mcp_tools(query)` instead - it returns
`{"name", "description", "inputSchema"}` dicts directly.

## Step 5 - cache LLM completions

If the codebase calls an LLM provider (Anthropic/OpenAI/Google) directly
for completions that could repeat - support-style Q&A, summarization,
templated prompts - route them through the same gateway instead, so
repeated or near-duplicate prompts cost zero tokens:

```python
answer = client.complete("Summarize this ticket thread in two sentences.")
print(answer["response"], answer["cache"]["status"])  # hit_exact/hit_semantic/miss/bypass
```

Use `bypass_cache=True` for prompts that must always reach the live
model (anything time-sensitive - "what's today's date").

## Step 6 - add agent memory where the codebase tracks user/session state

If the codebase already has ad hoc state for "what does this user
prefer" or "what happened earlier in this session" - a dict, a database
table, a home-grown cache - consider replacing it with AOM's memory API so
recall is durable and semantic rather than exact-key-only:

```python
client.add_memory(user_id, "Prefers responses in metric units.", memory_type="profile")
client.add_memory(user_id, "Asked about a damaged order.", session_id=session_id)

relevant = client.search_memory(user_id, "what did they say about their order?")
```

Don't migrate state that's already correctly modeled elsewhere (e.g. a
proper user-profile table with its own migrations) just to use this -
reach for it for state that was informal or missing before.

## Error handling

Wrap calls in the SDK's typed exceptions rather than checking HTTP status
codes: `AOMConnectionError`, `AOMAuthenticationError`,
`AOMAuthorizationError`, `AOMNotFoundError`, `AOMServerError`, and the
`AOMError` base class for anything else. Match the target codebase's
existing error-handling style (exceptions vs. result objects) when
wrapping these.

## After integrating

- Confirm `AOM_BASE_URL` and `AOM_API_KEY` are documented in whatever the
  project uses for setup instructions (README, `.env.example`, etc.).
- If the project has tests, add or update one that exercises the new
  `AOMClient` usage against a mock/fake rather than a live appliance.
- Do not commit a real API key. If one was hardcoded during
  exploration, replace it with an environment variable read before
  finishing.
