# Couchbase Agent Operations Manager

A Dockerized appliance that uses **Couchbase as a centralized, secure MCP
tool database**: MCP tool definitions are embedded and stored in Couchbase,
and access to them is controlled with **RBAC combined with Couchbase Vector
Search pre-filtering** - a single Search (FTS) request that narrows the
candidate tool set by role and trust status *before/alongside* ranking by
semantic similarity, not after.

This grew out of a demo of the same idea
(`couchbase-mcp-access-server-demo`); this version turns the operations manager
into something you'd actually stand up and keep running - register real
MCP servers instead of hardcoded ones, an admin dashboard instead of a
side-by-side comparison UI, and an insights engine that flags RBAC/catalog
hygiene issues instead of a fixed script of "try these presets."

## The problem this solves

Most MCP-using agents today treat every configured MCP server, and every
tool it advertises, as trusted by default. There is usually no login, no
per-tool authorization, and no record of who called what. That default
model creates three well-known failure modes:

- **Unauthorized local code execution** - a tool from an unreviewed server
  gets run just because the agent was pointed at it.
- **Hidden prompt injection** - a tool's *description* (not its output) can
  carry instructions the LLM treats as trusted system text, because
  nothing distinguishes "text from a vetted source" from "text from
  anywhere."
- **Over-privileged access** - any caller can invoke any tool on any
  configured server, including destructive admin actions, because nothing
  ties a request to who is actually asking.

The Couchbase Agent Operations Manager sits between your agents and the world
of MCP tool servers and closes all three: agents never talk to a downstream
MCP server directly. They authenticate to this appliance, ask it to *discover*
tools for a task (RBAC + vector-search pre-filter, never a full unfiltered
tool dump), and ask it to *invoke* whichever tool they picked - re-checked
against Couchbase independently before anything is proxied downstream. Every
decision is written to an append-only audit log.

It also runs a dedicated **MCP Tool Hijacking detector** (see
[MCP Tool Hijacking detection](#mcp-tool-hijacking-detection) below) - the
indirect-prompt-injection variant where a malicious tool description or
response tries to steer the agent's next action, up to and including
calling a completely different, higher-privilege tool. RBAC and trust
review stop an *unregistered* tool from ever being reachable; hijacking
detection is what catches a *registered, reviewed* tool whose description
or live output has been poisoned.

## Architecture

```
                     ┌─────────────────────────────────────────────┐
  Your AI agent  ───▶│  Couchbase Agent Operations Manager (API)   │
  (or the bundled    │  - authenticates callers (API key -> role)  │
   Agent Tool Audit) │  - discover: RBAC + vector Search pre-filter│──▶ your real
                     │  - invoke: re-checked, then proxied         │    MCP servers
                     └─────────────────────────────────────────────┘    (registered
                                          │                              & trusted)
                                          ▼
                                    ┌───────────┐
                                    │ Couchbase │  servers / tools /
                                    │           │  identities / access_log
                                    └───────────┘
                                          ▲
                                          │
                                    ┌───────────┐
                                    │  Dashboard │  React + TS + Vite
                                    │    (UI)    │  admin console
                                    └───────────┘
```

Five containers:

- **couchbase** - Couchbase Server, Enterprise Edition. Required (not a
  preference): the vector-typed index field this appliance's core feature
  depends on is rejected outright by Community Edition. Free to run for
  development/testing under Couchbase's standard license.
- **couchbase-init** - one-shot provisioning: bucket/scope/collections
  (`servers`, `tools`, `identities`, `access_log`) and primary indexes.
- **sample-mcp-servers** - six bundled mock MCP tool servers so the
  appliance is testable immediately, no real credentials needed: `jira`,
  `zendesk`, `snowflake` (well-behaved), `docs-search` and `web-search`
  (MCP Tool Hijacking fixtures - see below), and `shadow-diagnostics` (an
  intentionally unregistered server). Remove this container whenever you
  no longer need the samples.
- **operations-manager** - the appliance itself. Authenticates callers, ingests
  only explicitly-registered/trusted servers' tool catalogs into Couchbase
  with embeddings + `allowed_roles` + `trust_status`, answers discovery
  requests with one Couchbase Search request combining vector kNN with an
  RBAC/trust pre-filter, re-checks authorization before proxying any
  invoke, and writes an audit-log entry for every decision. Also runs the
  MCP Tool Hijacking detector: a metadata scan at ingest time, a response
  scan on every invoke, and a background monitor that re-scans the catalog
  on a timer.
- **ui** - the admin dashboard (React + TypeScript + Vite, served by nginx): a
  live findings/insights feed, server registration, the tool catalog, roles,
  the audit log, and an Agent Tool Audit for calling discover/invoke directly.

## RBAC model

Three seed roles, each with its own API key (see `.env.example`):

- `support_agent` - Jira (read) + Zendesk (read/write)
- `finance_analyst` - Snowflake read-only analytics
- `admin` - everything trusted, including the two high-risk Snowflake admin
  tools (`manage_users`, `manage_warehouse`)

Roles themselves are reviewable, code-owned config in
`operations-manager/app/rbac_policy.py` - they're the kind of thing a security
team reviews in a PR, not something added through a UI. **Servers**,
though, are meant to change without a redeploy: register new ones from the
Servers page (or `POST /v1/servers`) and their tools get ingested with a
deny-by-default policy (admin-only, `risk_level: unclassified`) unless you
assign default allowed roles at registration time, or add a reviewed
override to `TOOL_POLICY`. Couchbase's `tools` collection - not the Python
file - is the actual runtime source of truth the operations manager queries on
every request.

## Run it

```bash
cp .env.example .env    # optional - defaults work out of the box
docker compose up --build
```

or, for a clearer view of the multi-container startup sequence:

```bash
./start.sh
```

First boot downloads the Couchbase Enterprise image and a local embedding
model (~100MB, cached afterwards) - give it a few minutes. Then open:

- **Dashboard**: <http://localhost:5173>
- **Operations Manager API**: <http://localhost:8090> (see `/docs` for the
  OpenAPI UI)
- **Couchbase Web Console**: <http://localhost:8091> (`Administrator` /
  `CouchbaseDemo123!` by default)

`docker compose down -v` gives you a fully clean start (drops the
Couchbase and embedding-model-cache volumes).

## Using the dashboard

- **Dashboard** - stat cards (open findings, registered/trusted servers,
  tools ingested, access events), an access-volume chart, an allow/deny/
  error donut, and the highest-severity open findings.
- **MCP Servers** - the registered server list; register a new one (server
  ID, label, owner, MCP URL, trust status, default allowed roles) and its
  catalog is ingested immediately; re-ingest or unregister existing ones.
- **Tool Catalog** - every tool actually stored in Couchbase's registry,
  filterable by server/role - the full transparency view of what
  discovery can ever return.
- **Roles & RBAC** - the three seed roles and how many tools each can
  reach. API keys live in environment variables, never in the UI or API
  responses - only a masked `...last4` label is ever shown.
- **Threat Detection** - the MCP Tool Hijacking surface: quarantined tools
  with their matched signals and a one-click Release action, recently
  flagged live responses, cross-tool hijack chain findings, and the last
  background scan time. See [MCP Tool Hijacking
  detection](#mcp-tool-hijacking-detection) below.
- **Insights** - findings derived from the current catalog, server
  registry, and recent audit log: quarantined tools, cross-tool hijack
  chains, unclassified tools defaulting to admin-only, trusted servers
  with an empty catalog, repeated invalid API key attempts, invoke
  attempts against unregistered/untrusted tools, repeated RBAC denials for
  a role/tool pair, and critical-risk tool usage. Everything except the
  quarantine state itself is recomputed on every load, nothing extra
  stored.
- **Audit Log** - every discover/invoke/authenticate decision, live-
  refreshing, filterable by action and decision.
- **Agent Tool Audit** - paste in a role's API key and call `discover`/`invoke`
  directly (no LLM in the loop) to see exactly what the RBAC + vector
  pre-filter returns. Try `shadow-diagnostics::run_diagnostic` as a tool
  ID in the Invoke panel - it's intentionally never registered, so it's
  denied no matter which role you use.

## MCP Tool Hijacking detection

MCP Tool Hijacking - usually delivered as a Tool Poisoning Attack - is an
indirect prompt injection vulnerability that's structural to MCP, not a
bug in any one server: an LLM ingests tool *descriptions* and tool *call
results* into the same trusted working context it reasons over, with no
built-in way to tell "text from a vetted source" apart from "text from
anywhere." A hidden instruction in one tool's metadata or output can
shadow, override, or redirect execution toward a completely different,
higher-privilege tool - data exfiltration, privilege escalation, and
silent execution (especially under an "always allow" auto-approval
config) are the usual payoffs. RBAC and server-trust review, on their
own, only stop tools that were never registered in the first place; they
don't catch a tool that looked fine at review time and was compromised
afterward, or a clean tool whose live response is what's actually
poisoned. This appliance runs three complementary defenses for that
(`operations-manager/app/hijack_detection.py`):

1. **Metadata poisoning**, caught at ingest time. Every tool's name,
   description, and input-schema property descriptions are scanned
   against a pattern bank (instruction-override language, covert/silent-
   execution cues, data-exfiltration cues, hidden-content markers like
   HTML comments or zero-width characters, and privilege-escalation
   language) the moment it's ingested. A match quarantines the tool
   immediately - `trust_status` is forced to `quarantined`, which the
   RBAC + vector Search pre-filter already excludes, the same way an
   untrusted server's tools are excluded. It's never discoverable or
   invokable by any role until released from the Threat Detection page.
2. **Response payload poisoning**, caught live. A tool's description can
   be completely clean and still return a poisoned payload at call time -
   a compromised web page, a tampered ticket body. That can't be caught
   at ingest because it doesn't exist yet, so every successful `invoke`
   response is scanned instead. A match doesn't withhold the response
   (the same words that flag an attack show up in a lot of harmless data
   too), but it's logged loudly: flagged on that audit-log entry and
   surfaced on Threat Detection and Insights.
3. **Cross-tool hijack chains**, the actual mechanism the first two
   defenses exist to catch in the act: a response-poisoning-flagged
   invoke by some caller, followed within `HIJACK_CHAIN_WINDOW_SECONDS`
   (default 120s) by that same caller invoking a materially higher-risk
   tool, is exactly the shape a successful hijack takes - the poisoned
   response steering the next tool call. This is a timing correlation
   over the audit log, not a confirmed compromise, so it's surfaced as a
   lead to investigate rather than an automatic block.

A background monitor also re-scans every already-ingested tool's stored
description against the current pattern bank on a timer
(`HIJACK_SCAN_INTERVAL_MINUTES`, default 5) with no MCP round-trip - this
is what catches a tool that was ingested before hijack detection existed,
or before a pattern-bank update, without hammering downstream MCP
servers to do it. A manual release or quarantine from the Threat
Detection or Tool Catalog page is remembered (`hijack_manual_override`)
so the next scan pass doesn't silently revert an admin's decision.

**Try it**: `docs-search::search_docs` (a registered, trusted sample
server) is quarantined automatically the moment it's ingested - open the
Threat Detection page to see why, and Release it to confirm it becomes
invokable again. `web-search::fetch_page` ingests and invokes completely
normally - its description is clean - but its mock response is poisoned;
invoke it from the Agent Tool Audit as any role, then invoke
`snowflake::manage_users` shortly after as `admin`, and watch a critical
cross-tool hijack chain finding appear on Insights and Threat Detection.

## Registering your own MCP servers

Point the Servers page (or `POST /v1/servers`) at any Streamable-HTTP MCP
endpoint your infrastructure runs. A server's tools are only ever ingested
if it's marked `trusted` - leave a newly-added server `untrusted` until
you've reviewed it, then flip it to trusted and hit Re-ingest.

```bash
curl -X POST http://localhost:8090/v1/servers \
  -H "Content-Type: application/json" \
  -d '{
        "server_id": "billing-service",
        "label": "Billing Service (Internal)",
        "owner": "Platform Team",
        "mcp_url": "http://billing-service.internal:9000/mcp",
        "trust_status": "trusted",
        "default_allowed_roles": ["admin"]
      }'
```

## Notes

- The bundled sample MCP servers return small, representative mock data -
  no real Jira/Zendesk/Snowflake credentials, and no real network access,
  are needed to try the appliance (or the hijacking-detection fixtures)
  out of the box.
- API keys in `.env.example` are placeholder values only - rotate them
  before exposing this appliance beyond your laptop.
- Audit log entries expire after `AUDIT_LOG_RETENTION_HOURS` (default 30
  days) via a Couchbase document TTL.
- The hijack pattern bank is heuristic, not proof of malicious intent - it
  is deliberately tuned toward catching real attacks over avoiding every
  false positive, since the cost of a false positive is one click on
  Release and the cost of a false negative is a live prompt-injection
  payload sitting in the catalog unnoticed.
