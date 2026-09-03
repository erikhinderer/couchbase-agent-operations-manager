# Couchbase Agent Operations Manager SDK integration

You are helping integrate an agent codebase with a Couchbase Agent
Operations Manager (AOM) appliance - the RBAC + vector-search gateway that
sits between an agent and its MCP tool servers - using `aom_sdk`, the
appliance's official Python client. Apply this whether the codebase is
brand new or already has hand-written HTTP calls against the appliance's
REST API that should be replaced.

## When to apply this

- You're asked to connect an agent to AOM / the Operations Manager, add
  tool discovery, or wire up the Couchbase agent gateway.
- You find raw HTTP calls to endpoints under `/v1/tools/`, `/v1/llm/`, or
  `/v1/memory/` on an AOM appliance and the codebase has no `aom_sdk`
  dependency yet - replace them with the SDK rather than leaving both
  patterns in the same codebase.
- A new agent project needs to call external tools, cache LLM
  completions, or remember things about a user, with an AOM appliance as
  the backend.

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

For a lockfile-based workflow (Poetry, uv, pip-tools), vendor the unzipped
SDK folder into the repo (e.g. `vendor/aom-sdk/`) as a local/path
dependency instead of leaving it in `/tmp`, so the build is reproducible
in CI.

Need the SDK to speak MCP directly (Step 4)? Install the optional extra:
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

Add `AOM_BASE_URL`/`AOM_API_KEY` to whatever config system the codebase
already uses rather than introducing a new one.

## Step 3 - replace tool calling with discover/invoke

Replace any hardcoded tool registry, raw MCP client, or direct tool-server
HTTP calls with the gateway pattern: discover, then invoke.

```python
discovered = client.discover("look up a customer's open support tickets")
tool = discovered["tools"][0]
result = client.invoke(tool["tool_id"], arguments={})
```

Check `result["hijack_warning"]` before trusting `result["result"]` in
anything user-facing - a non-null value means the appliance's hijack
detector flagged the live tool response.

## Step 4 - or bridge as a real MCP server

If the target framework already speaks MCP by URL/command rather than
calling a Python client directly, don't write a custom adapter - point it
at the bundled bridge:

```bash
pip install "couchbase-aom-sdk[mcp]"
AOM_BASE_URL=https://localhost:8090 AOM_API_KEY=<role-api-key> \
    AOM_VERIFY_SSL=false python -m aom_sdk.mcp_server
```

This runs AOM as a local MCP server over stdio: `list_tools` returns the
caller's authorized catalog, `call_tool` invokes through AOM's RBAC and
audit trail. If only the tool *definitions* are needed in MCP shape,
without running a server, use `client.discover_mcp_tools(query)` instead -
it returns `{"name", "description", "inputSchema"}` dicts directly.

## Step 5 - cache LLM completions

Route repeatable completions (support-style Q&A, summarization, templated
prompts) through the gateway instead of the provider directly, so a
repeat or near-duplicate prompt costs zero tokens:

```python
answer = client.complete("Summarize this ticket thread in two sentences.")
print(answer["response"], answer["cache"]["status"])  # hit_exact/hit_semantic/miss/bypass
```

Use `bypass_cache=True` for prompts that must always reach the live model.

## Step 6 - add agent memory where the codebase tracks user/session state

Replace ad hoc "what does this user prefer" / "what happened earlier"
state (a dict, a database table, a home-grown cache) with AOM's memory API
for durable, semantic recall:

```python
client.add_memory(user_id, "Prefers responses in metric units.", memory_type="profile")
client.add_memory(user_id, "Asked about a damaged order.", session_id=session_id)

relevant = client.search_memory(user_id, "what did they say about their order?")
```

Don't migrate state that's already correctly modeled elsewhere.

## Error handling

Use the SDK's typed exceptions rather than checking HTTP status codes:
`AOMConnectionError`, `AOMAuthenticationError`, `AOMAuthorizationError`,
`AOMNotFoundError`, `AOMServerError`, and `AOMError` as the base class.
Match the codebase's existing error-handling style when wrapping these.

## After integrating

- Document `AOM_BASE_URL`/`AOM_API_KEY` wherever the project documents
  setup (README, `.env.example`, etc.).
- Add or update a test that exercises the new `AOMClient` usage against a
  mock/fake, not a live appliance.
- Never commit a real API key - replace any hardcoded key used during
  exploration with an environment variable read before finishing.
