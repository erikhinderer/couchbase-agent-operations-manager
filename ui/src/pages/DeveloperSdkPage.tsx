import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, ApiError } from "../api/client";
import type { SdkInfo, SkillInfo } from "../api/types";

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

const INSTALL_CODE = `unzip couchbase-aom-sdk-*.zip
cd couchbase-aom-sdk-*
pip install .`;

const QUICKSTART_CODE = `from aom_sdk import AOMClient

client = AOMClient(
    base_url="http://localhost:8090",   # your operations-manager origin
    api_key="demo-support-agent-9f21",  # your RBAC role's API key
)

# 1. Discover tools for a task - RBAC + vector-search pre-filtered.
discovered = client.discover("look up a customer's open support tickets")
tool_id = discovered["tools"][0]["tool_id"]

# 2. Invoke the one you picked - re-checked against Couchbase, then
#    proxied to its real MCP server.
result = client.invoke(tool_id, arguments={})
print(result["result"])`;

const CACHING_CODE = `# Route model calls through the same gateway to get response caching -
# a repeat or near-duplicate prompt costs zero tokens.
answer = client.complete("What is our refund policy for orders over 30 days old?")
print(answer["response"])
print(answer["cache"]["status"])   # "miss" the first time
print(answer["usage"]["total_tokens"], answer["cost_usd"])

# Ask it again, worded differently - semantic matching catches the paraphrase.
answer2 = client.complete("Can a customer get a refund on a month-old order?")
print(answer2["cache"]["status"])  # "hit_semantic" - zero tokens spent`;

const MEMORY_CODE = `# Durable facts about the user - outlive any one session.
client.add_memory("user-42", "Prefers responses in metric units.", memory_type="profile")

# What was said in this session.
client.add_memory("user-42", "Asked about a damaged order (#48213).", session_id="s-1")

# Recall by MEANING, not just recency - ranked by similarity.
for m in client.search_memory("user-42", "what did they say about their order?"):
    print(m["similarity"], m["content"])

# Wipe short-term session memory at session end; profile memory stays.
client.clear_memory("user-42", session_id="s-1")`;

const MCP_CODE = `# Get tools already shaped as standard MCP tool definitions -
# {"name", "description", "inputSchema"} - ready for any MCP-compatible
# agent runtime or tool-calling API.
mcp_tools = client.discover_mcp_tools("look up a customer's open support tickets")
result = client.invoke_mcp_tool(mcp_tools[0]["name"], arguments={})

# Or run this appliance as a real local MCP server any MCP host can attach
# to (pip install "couchbase-aom-sdk[mcp]"):
#   AOM_BASE_URL=http://localhost:8090 AOM_API_KEY=... python -m aom_sdk.mcp_server`;

const SKILL_PLATFORMS: Array<{ platform: string; label: string; blurb: string }> = [
  { platform: "chatgpt", label: "ChatGPT Skill", blurb: "Custom GPT instructions, an Assistants/Responses system message, or an AGENTS.md file." },
  { platform: "gemini", label: "Gemini Skill", blurb: "A GEMINI.md context file for Gemini CLI/Code Assist, or a Gem's instructions." },
];

function SkillDownloadRow({
  platform,
  label,
  blurb,
  primary,
}: {
  platform: string;
  label: string;
  blurb: string;
  primary?: boolean;
}) {
  const [info, setInfo] = useState<SkillInfo | null>(null);

  useEffect(() => {
    (async () => {
      try {
        setInfo(await api.skillInfo(platform));
      } catch {
        // Skill metadata is a nice-to-have on this row - the download link
        // below works regardless of whether this fetch succeeds.
      }
    })();
  }, [platform]);

  return (
    <div className="flex-between" style={{ padding: "10px 0", borderTop: primary ? undefined : "1px solid var(--border)" }}>
      <div>
        <div style={{ fontWeight: 600 }}>{label}</div>
        <div className="cell-muted" style={{ fontSize: 12.5 }}>
          {blurb}
          {info ? ` · ${formatBytes(info.size_bytes)}` : ""}
        </div>
      </div>
      <a className={primary ? "btn btn-primary" : "btn btn-secondary"} href={`/v1/skills/${platform}/download`}>
        <span>⤓</span> Download{info ? ` (v${info.version})` : ""}
      </a>
    </div>
  );
}

export function DeveloperSdkPage() {
  const [info, setInfo] = useState<SdkInfo | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      try {
        setInfo(await api.sdkInfo());
      } catch (err) {
        const e = err as ApiError;
        setError(e.message || "Could not load SDK metadata");
      }
    })();
  }, []);

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Developer SDK</h1>
          <p className="page-subtitle">
            A typed Python client for the discover / invoke / complete / memory gateway, so your agent code never
            hand-rolls bearer headers or JSON payloads against the raw REST API.
          </p>
        </div>
        <a className="btn btn-primary" href="/v1/sdk/download">
          <span>⤓</span> Download SDK{info ? ` (v${info.version})` : ""}
        </a>
      </div>

      {error && <div className="error-note">{error}</div>}

      <div className="helper-banner">
        {info ? (
          <>
            Latest build: <code>{info.filename}</code> · {formatBytes(info.size_bytes)}. Rebuilt from the source
            shipped in this appliance's image on every download, so it always matches the API you're talking to.
          </>
        ) : (
          "Loading SDK metadata..."
        )}
      </div>

      <div className="card section-gap">
        <div className="card-title">1. Install</div>
        <p className="cell-muted" style={{ marginBottom: 10 }}>
          Download the zip above, unzip it, and install it into your agent's Python environment. Requires Python
          3.8+ and <code>requests</code>.
        </p>
        <pre className="json-block">{INSTALL_CODE}</pre>
      </div>

      <div className="card section-gap">
        <div className="card-title">2. Discover and invoke a tool</div>
        <p className="cell-muted" style={{ marginBottom: 10 }}>
          Every call authenticates with the same bearer API key your role already uses (see{" "}
          <Link to="/roles">Roles &amp; RBAC</Link>). <code>discover</code> only ever returns tools your role can also{" "}
          <code>invoke</code> - both are re-checked against Couchbase independently, so a client can never skip
          discovery and invoke something it was never shown.
        </p>
        <pre className="json-block">{QUICKSTART_CODE}</pre>
      </div>

      <div className="card section-gap">
        <div className="card-title">3. Why route model calls through the SDK too</div>
        <p className="cell-muted" style={{ marginBottom: 10 }}>
          Agents ask the same handful of questions constantly - "what's our refund policy," "summarize this ticket,"
          the same system prompt re-sent with one new turn appended - just worded differently every time, across
          sessions and sometimes across users. Calling the provider fresh for each one burns tokens and waits out a
          full network round trip for an answer that was already computed once. <code>client.complete()</code>{" "}
          sends the prompt through <code>/v1/llm/complete</code> instead of the provider directly, so a repeat
          question is answered straight out of Couchbase - by an exact hash match, or by vector similarity for a
          paraphrase - rather than spending tokens on it again.
        </p>

        <div className="two-col" style={{ marginBottom: 14 }}>
          <div className="panel">
            <div style={{ fontWeight: 600, marginBottom: 6 }}>Exact match</div>
            <div className="cell-muted" style={{ fontSize: 12.5 }}>
              SHA-256 of the normalized prompt (whitespace collapsed, case-folded) plus provider, model, namespace
              and scope. One KV get - the same prompt, byte-for-byte, costs nothing the second time.
            </div>
          </div>
          <div className="panel">
            <div style={{ fontWeight: 600, marginBottom: 6 }}>Semantic match</div>
            <div className="cell-muted" style={{ fontSize: 12.5 }}>
              Vector similarity over the prompt embedding, scoped to the same provider/model/namespace. Catches
              paraphrases exact hashing would miss - the default similarity threshold is 0.94.
            </div>
          </div>
        </div>

        <div className="card-title" style={{ fontSize: 13 }}>
          The cost and latency math at scale
        </div>
        <p className="cell-muted" style={{ marginBottom: 10 }}>
          Illustrative example, using this appliance's own default pricing table (
          <code>operations-manager/app/llm_cache.py</code>) for <code>claude-sonnet-4-5</code> - $3 per million input
          tokens, $15 per million output tokens. Your actual savings depend on your traffic volume and
          repeat-question rate; check the live numbers on <Link to="/llm-caching">LLM Caching → Cache Dashboard</Link>.
        </p>

        <div className="table-wrap" style={{ marginBottom: 12 }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>Assumption</th>
                <th>Value</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td className="cell-muted">Completions per day</td>
                <td className="cell-mono">50,000</td>
              </tr>
              <tr>
                <td className="cell-muted">Average prompt / completion size</td>
                <td className="cell-mono">600 / 250 tokens</td>
              </tr>
              <tr>
                <td className="cell-muted">Cost per uncached call</td>
                <td className="cell-mono">(600 ÷ 1,000,000 × $3) + (250 ÷ 1,000,000 × $15) = $0.00555</td>
              </tr>
              <tr>
                <td className="cell-muted">Repeat / near-duplicate rate</td>
                <td className="cell-mono">35% (typical for support-style, high-repetition workloads)</td>
              </tr>
              <tr>
                <td className="cell-muted">Calls served from cache</td>
                <td className="cell-mono">17,500 / day, at $0 provider cost each</td>
              </tr>
              <tr>
                <td className="cell-muted" style={{ fontWeight: 600 }}>
                  Cost avoided
                </td>
                <td className="cell-mono" style={{ fontWeight: 600 }}>
                  ≈ $97/day → ≈ $2,900/month → ≈ $35,000/year
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <p className="cell-muted" style={{ marginBottom: 14 }}>
          That's one workload on one model. Savings scale linearly with traffic, and every additional agent sharing
          the cache (global or per-role scope) compounds the hit rate instead of paying to warm up its own. Latency
          drops the same way: a cache hit resolves as a single Couchbase KV get or one Search request - typically
          single-digit to low-double-digit milliseconds - instead of a full network round trip to the model
          provider, which commonly runs several hundred milliseconds to a few seconds depending on model and output
          length. A cached answer isn't just free, it's also the fastest possible response your agent can give.
        </p>

        <pre className="json-block">{CACHING_CODE}</pre>
      </div>

      <div className="card section-gap">
        <div className="card-title">4. Store agent memory</div>
        <p className="cell-muted" style={{ marginBottom: 10 }}>
          Durable, cross-session recall stored in the same Couchbase cluster as everything else in this appliance -
          not a separate service to run or depend on. <code>add_memory()</code> embeds and stores an entry scoped to
          a <code>user_id</code> (and optionally a <code>session_id</code>); <code>search_memory()</code> recalls the
          entries closest in <em>meaning</em> to a new query, not just the most recent ones - the same vector-search
          idea <code>discover()</code> runs over the tool catalog, scoped to one user's memory instead of one role's
          tools.
        </p>
        <div className="two-col" style={{ marginBottom: 14 }}>
          <div className="panel">
            <div style={{ fontWeight: 600, marginBottom: 6 }}>conversational / profile / semantic</div>
            <div className="cell-muted" style={{ fontSize: 12.5 }}>
              Three conventional <code>memory_type</code> values - <code>conversational</code> (default: what was
              said in a session), <code>profile</code> (durable facts about the user), <code>semantic</code>
              (retrieved knowledge worth remembering) - labels for your own filtering, not enforced behavior.
            </div>
          </div>
          <div className="panel">
            <div style={{ fontWeight: 600, marginBottom: 6 }}>Scoped clearing</div>
            <div className="cell-muted" style={{ fontSize: 12.5 }}>
              <code>clear_memory(user_id, session_id=...)</code> wipes just one session's short-term memory, leaving
              that user's durable profile memories untouched - important once an agent starts writing both kinds.
            </div>
          </div>
        </div>
        <pre className="json-block">{MEMORY_CODE}</pre>
      </div>

      <div className="card section-gap">
        <div className="card-title">5. MCP tool integration</div>
        <p className="cell-muted" style={{ marginBottom: 10 }}>
          AOM already speaks MCP to every downstream tool server it proxies to - this SDK makes that protocol visible
          on the client side too. <code>discover_mcp_tools()</code> returns each matched tool already converted to a
          standard MCP tool definition, and <code>aom_sdk.mcp_server</code> (optional <code>[mcp]</code> extra) runs
          this appliance as a real local MCP server over stdio, so any MCP host - Claude Desktop, Claude Code, or
          another MCP-compatible agent runtime - can attach to it directly and reach every tool your API key's role
          is authorized for, still governed by AOM's RBAC and audit trail.
        </p>
        <pre className="json-block">{MCP_CODE}</pre>
      </div>

      <div className="card section-gap">
        <div className="card-title">6. Handling errors</div>
        <p className="cell-muted" style={{ marginBottom: 10 }}>
          Every non-2xx response raises a typed exception instead of a bare HTTP error, so calling code can branch on
          what actually went wrong:
        </p>
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>Exception</th>
                <th>Raised on</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td className="cell-mono">AOMConnectionError</td>
                <td className="cell-muted">Could not reach the operations manager at all</td>
              </tr>
              <tr>
                <td className="cell-mono">AOMAuthenticationError</td>
                <td className="cell-muted">401 - missing or invalid API key</td>
              </tr>
              <tr>
                <td className="cell-mono">AOMAuthorizationError</td>
                <td className="cell-muted">403 - role not authorized for that tool</td>
              </tr>
              <tr>
                <td className="cell-mono">AOMNotFoundError</td>
                <td className="cell-muted">404 - unknown tool, server, or cache/memory entry</td>
              </tr>
              <tr>
                <td className="cell-mono">AOMServerError</td>
                <td className="cell-muted">5xx - operations manager or downstream MCP server failed</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <div className="card section-gap">
        <div className="card-title">AI assistant integration skills</div>
        <p className="cell-muted" style={{ marginBottom: 10 }}>
          The same integration knowledge above - install, configure a client, replace hand-rolled tool calls with
          discover/invoke, cache completions, add agent memory, bridge to MCP - packaged so a coding assistant can
          apply it to a codebase directly instead of you copying snippets by hand.
        </p>
        <SkillDownloadRow platform="claude" label="Claude Skill" blurb="A real Claude Skill (SKILL.md) - drop it in and Claude applies the integration itself." primary />
        {SKILL_PLATFORMS.map((s) => (
          <SkillDownloadRow key={s.platform} platform={s.platform} label={s.label} blurb={s.blurb} />
        ))}
      </div>

      <div className="helper-banner">
        The SDK wraps a deliberate subset of the API. For the full surface - server registration, roles, audit log,
        cache administration - see the appliance's <code>README.md</code> or try the raw endpoints on the{" "}
        <Link to="/agent-tool-audit">Agent Tool Audit</Link> page.
      </div>
    </div>
  );
}
