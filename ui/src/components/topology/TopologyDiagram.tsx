import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "../../api/client";
import { CouchbaseBadge } from "../common/CouchbaseLogo";
import type { TopologyLlmProvider, TopologyResponse, TopologyServer } from "../../api/types";

// Layout is computed dynamically (see buildLayout) rather than fixed: the
// diagram always fits a constant target height, and node/text sizing
// scales up when there are few nodes to show and down when there are many
// - so a 2-agent/3-server evaluation setup and a 20-server production one
// both render as one comfortably-filled diagram instead of either a mostly
// empty canvas or an overflowing one. These are the k=1 reference sizes,
// tuned to look right at REF_ROWS rows.
const VIEW_W = 1000;
const LEFT_X = 10;
const GATEWAY_X = 500;
const REF_ROWS = 8;
const TARGET_HEIGHT = 336;
const BASE = {
  nodeW: 104,
  nodeH: 30,
  rowH: 38,
  gatewayR: 25,
  rx: 5,
  dotR: 2.5,
  strokeW: 1.2,
  gatewayStrokeW: 1.8,
  titleFont: 10,
  subFont: 9,
  headerFont: 9.5,
  gatewayFont: 9.5,
};
const TOP_PAD = 20;
const K_MIN = 0.5;
const K_MAX = 1.7;

// Average glyph width as a fraction of font-size, used to estimate how wide
// a label will render so font size can be solved to fit a given box width -
// separate estimates for the bold title text and the regular-weight subtitle.
const CHAR_W_TITLE = 0.62;
const CHAR_W_SUB = 0.55;
const MIN_TITLE_FONT = 6.5;
const MIN_SUB_FONT = 6;

const COLOR_AGENT = "var(--blue)";
const COLOR_SERVER = "var(--teal)";
const COLOR_LLM = "var(--amber)";

function clamp(v: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, v));
}

function relativeTime(iso: string | null | undefined): string {
  if (!iso) return "no activity in this window";
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return "no activity in this window";
  const seconds = Math.max(0, Math.floor((Date.now() - then) / 1000));
  if (seconds < 60) return `active ${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `active ${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `active ${hours}h ago`;
  return `active ${Math.floor(hours / 24)}d ago`;
}

function truncate(s: string, max: number): string {
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}

function edgeWidth(count: number, maxCount: number, k: number): number {
  if (count <= 0) return 0.75 * k;
  const denom = Math.log(maxCount + 1) || 1;
  return (1 + (Math.log(count + 1) / denom) * 3.5) * k;
}

interface Row<T> {
  item: T;
  y: number;
}

function layoutRows<T>(items: T[], top: number, bottom: number): Row<T>[] {
  if (items.length === 0) return [];
  if (items.length === 1) return [{ item: items[0], y: (top + bottom) / 2 }];
  const step = (bottom - top) / (items.length - 1);
  return items.map((item, i) => ({ item, y: top + step * i }));
}

/** Solve for the single scale factor k that makes the diagram's total
 * height land on TARGET_HEIGHT for this many rows, then derive every
 * other pixel value (node size, font size, stroke width, dot radius)
 * from it - one knob, everything resizes together. */
function buildLayout(rowCount: number, targetHeight: number) {
  const denom = Math.max(0, rowCount - 1) * BASE.rowH + BASE.nodeH;
  const k = clamp((targetHeight - TOP_PAD * 2) / denom, K_MIN, K_MAX);

  const nodeW = BASE.nodeW * k;
  const nodeH = BASE.nodeH * k;
  const rowH = BASE.rowH * k;
  const gatewayR = clamp(BASE.gatewayR * k, 16, 42);
  const rx = BASE.rx * k;
  const dotR = clamp(BASE.dotR * k, 1.8, 4);
  const strokeW = clamp(BASE.strokeW * k, 1, 2);
  const gatewayStrokeW = clamp(BASE.gatewayStrokeW * k, 1.3, 2.6);
  const titleFont = clamp(BASE.titleFont * k, 8, 15);
  const subFont = clamp(BASE.subFont * k, 7.5, 13);
  const headerFont = clamp(BASE.headerFont * k, 8, 13);
  const gatewayFont = clamp(BASE.gatewayFont * k, 8, 13);

  const rowsHeight = TOP_PAD * 2 + Math.max(0, rowCount - 1) * rowH + nodeH;

  // The gateway node is the Couchbase mark with a two-line label set below
  // it rather than text inside the circle, so with only one or two rows the
  // row-driven height above can be too short to hold it - pad the diagram
  // out to whatever the gateway block needs as a floor.
  const gwLabelGap = gatewayR * 0.45;
  const gwLineHeight = gatewayFont * 1.25;
  const gwBelow = (gatewayR + gwLabelGap + 2 * gwLineHeight) * 1.05;
  const gatewayMinHeight = TOP_PAD * 2 + 2 * Math.max(gatewayR, gwBelow);

  const height = Math.max(rowsHeight, gatewayMinHeight);
  const rightX = VIEW_W - LEFT_X - nodeW;
  const bandTop = TOP_PAD + nodeH / 2;
  const bandBottom = height - TOP_PAD - nodeH / 2;
  const gatewayY = (bandTop + bandBottom) / 2;

  return {
    k,
    nodeW,
    nodeH,
    gatewayR,
    rx,
    dotR,
    strokeW,
    gatewayStrokeW,
    titleFont,
    subFont,
    headerFont,
    gatewayFont,
    gwLabelGap,
    gwLineHeight,
    height,
    rightX,
    bandTop,
    bandBottom,
    gatewayY,
  };
}

type RightEntry =
  | { kind: "server"; data: TopologyServer }
  | { kind: "llm"; data: TopologyLlmProvider };

export function TopologyDiagram() {
  const [data, setData] = useState<TopologyResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  // The diagram fills whatever box its parent gives it (see TopologyPage,
  // which sizes that box to the remaining viewport height) rather than a
  // fixed aspect ratio. A ResizeObserver tracks the actual rendered pixel
  // size of that box; buildLayout() is handed a target height converted
  // into the SVG's own viewBox units (VIEW_W * boxHeight / boxWidth) so the
  // viewBox's aspect ratio matches the box's real aspect ratio - the SVG
  // below is then set to width:100%/height:100% of that box and the
  // browser's default preserveAspectRatio="meet" scales it uniformly to
  // fill both dimensions with no distortion (a mismatched aspect ratio
  // here would otherwise stretch circles into ellipses or letterbox).
  const boxRef = useRef<HTMLDivElement>(null);
  const [box, setBox] = useState<{ w: number; h: number }>({ w: VIEW_W, h: TARGET_HEIGHT });

  useEffect(() => {
    const el = boxRef.current;
    if (!el) return;
    const observer = new ResizeObserver((entries) => {
      const entry = entries[0];
      if (!entry) return;
      const { width, height } = entry.contentRect;
      if (width > 0 && height > 0) setBox({ w: width, h: height });
    });
    observer.observe(el);
    return () => observer.disconnect();
  }, []);

  const load = useCallback(async () => {
    try {
      const res = await api.topology(24);
      setData(res);
      setError(null);
    } catch (e: any) {
      setError(e.message || "Failed to load topology");
    }
  }, []);

  useEffect(() => {
    load();
    const id = setInterval(load, 30000);
    return () => clearInterval(id);
  }, [load]);

  if (error) return <div className="error-note">{error}</div>;
  if (!data) return <div className="loading-note">Loading topology...</div>;

  const agents = data.agents;
  const rightEntries: RightEntry[] = [
    ...data.servers.map((s): RightEntry => ({ kind: "server", data: s })),
    ...data.llm_providers.map((p): RightEntry => ({ kind: "llm", data: p })),
  ];

  const rowCount = Math.max(agents.length, rightEntries.length, 1);
  const targetViewBoxHeight = box.w > 0 ? (VIEW_W * box.h) / box.w : TARGET_HEIGHT;
  const L = buildLayout(rowCount, targetViewBoxHeight);

  const agentRows = layoutRows(agents, L.bandTop, L.bandBottom);
  const rightRows = layoutRows(rightEntries, L.bandTop, L.bandBottom);

  const maxAgentCalls = Math.max(1, ...agents.map((a) => a.tool_calls + a.llm_calls));
  const maxServerCalls = Math.max(1, ...data.servers.map((s) => s.calls));
  const maxLlmCalls = Math.max(1, ...data.llm_providers.map((p) => p.calls));

  // Node-relative offsets (dot position, text baselines) scale with the
  // node size itself so the layout stays proportional at every k.
  const dotDx = L.nodeH * 0.3;
  const dotDy = L.nodeH * 0.27;
  const titleDx = L.nodeH * 0.5;
  const titleDy = L.nodeH * 0.37;
  const subDx = L.nodeH * 0.27;
  const subDy = L.nodeH * 0.23;

  // Font size is capped by the k-derived nominal size but shrinks further,
  // uniformly across every node, whenever the longest label at that size
  // would spill past its box - so every node keeps the same font and none
  // of them ever overflow their border, regardless of label length.
  const textRightPad = L.nodeH * 0.3;
  const titleAvailWidth = Math.max(1, L.nodeW - titleDx - textRightPad);
  const subAvailWidth = Math.max(1, L.nodeW - subDx - textRightPad);

  const titleTexts = [
    ...agents.map((a) => truncate(a.role, 15)),
    ...data.servers.map((s) => truncate(s.label, 18)),
    ...data.llm_providers.map((p) => truncate(p.label, 15) + (p.is_default ? " \u2605" : "")),
  ];
  const subTexts = [
    ...agents.map((a) => {
      const total = a.tool_calls + a.llm_calls;
      return total > 0 ? `${total} call${total === 1 ? "" : "s"} (24h)` : "idle";
    }),
    ...data.servers.map((s) =>
      s.calls > 0
        ? `${s.calls} call${s.calls === 1 ? "" : "s"} (24h) \u00b7 ${s.tool_count} tools`
        : `${s.tool_count} tools \u00b7 idle`
    ),
    ...data.llm_providers.map((p) =>
      !p.configured
        ? `${p.vendor} \u00b7 no API key`
        : p.calls > 0
        ? `${p.calls} call${p.calls === 1 ? "" : "s"} (24h)`
        : `${p.vendor} \u00b7 configured, idle`
    ),
  ];

  const widestTitleChars = Math.max(1, ...titleTexts.map((t) => t.length));
  const widestSubChars = Math.max(1, ...subTexts.map((t) => t.length));

  const fitTitleFont = clamp(titleAvailWidth / (widestTitleChars * CHAR_W_TITLE), MIN_TITLE_FONT, L.titleFont);
  const fitSubFont = clamp(subAvailWidth / (widestSubChars * CHAR_W_SUB), MIN_SUB_FONT, L.subFont);

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%" }}>
      <div ref={boxRef} style={{ flex: 1, minHeight: 0 }}>
        <svg
          viewBox={`0 0 ${VIEW_W} ${L.height}`}
          width={box.w}
          height={box.h}
          preserveAspectRatio="none"
          style={{ display: "block" }}
        >
        {/* column headers */}
        <text
          x={LEFT_X + L.nodeW / 2}
          y={13}
          textAnchor="middle"
          fontSize={L.headerFont}
          fontWeight={700}
          fill="var(--text-muted)"
        >
          AGENTS
        </text>
        <text x={GATEWAY_X} y={13} textAnchor="middle" fontSize={L.headerFont} fontWeight={700} fill="var(--text-muted)">
          GATEWAY
        </text>
        <text
          x={L.rightX + L.nodeW / 2}
          y={13}
          textAnchor="middle"
          fontSize={L.headerFont}
          fontWeight={700}
          fill="var(--text-muted)"
        >
          MCP SERVERS &amp; LLM PROVIDERS
        </text>

        {/* edges: agent -> gateway */}
        {agentRows.map(({ item, y }) => {
          const total = item.tool_calls + item.llm_calls;
          const w = edgeWidth(total, maxAgentCalls, L.k);
          const active = total > 0;
          return (
            <path
              key={`e-agent-${item.role}`}
              d={`M ${LEFT_X + L.nodeW} ${y} C ${(LEFT_X + L.nodeW + GATEWAY_X) / 2} ${y}, ${(LEFT_X + L.nodeW + GATEWAY_X) / 2} ${L.gatewayY}, ${GATEWAY_X - L.gatewayR} ${L.gatewayY}`}
              fill="none"
              stroke={COLOR_AGENT}
              strokeWidth={w}
              strokeOpacity={active ? 0.55 : 0.15}
              strokeDasharray={active ? undefined : "4 4"}
            />
          );
        })}

        {/* edges: gateway -> server/llm */}
        {rightRows.map(({ item, y }) => {
          const isServer = item.kind === "server";
          const count = isServer ? item.data.calls : (item.data as TopologyLlmProvider).calls;
          const maxCount = isServer ? maxServerCalls : maxLlmCalls;
          const w = edgeWidth(count, maxCount, L.k);
          const active = count > 0;
          const color = isServer ? COLOR_SERVER : COLOR_LLM;
          return (
            <path
              key={`e-right-${isServer ? item.data.server_id : (item.data as TopologyLlmProvider).provider}`}
              d={`M ${GATEWAY_X + L.gatewayR} ${L.gatewayY} C ${(GATEWAY_X + L.rightX) / 2} ${L.gatewayY}, ${(GATEWAY_X + L.rightX) / 2} ${y}, ${L.rightX} ${y}`}
              fill="none"
              stroke={color}
              strokeWidth={w}
              strokeOpacity={active ? 0.55 : 0.15}
              strokeDasharray={active ? undefined : "4 4"}
            />
          );
        })}

        {/* gateway node - the Couchbase mark itself, with a small status
            dot on the badge and the "Operations Manager" label below it */}
        <g transform={`translate(${GATEWAY_X - L.gatewayR}, ${L.gatewayY - L.gatewayR})`}>
          <CouchbaseBadge size={L.gatewayR * 2} />
        </g>
        <circle cx={GATEWAY_X + L.gatewayR * 0.72} cy={L.gatewayY + L.gatewayR * 0.72} r={L.dotR * 1.5} fill="var(--card-bg)" />
        <circle cx={GATEWAY_X + L.gatewayR * 0.72} cy={L.gatewayY + L.gatewayR * 0.72} r={L.dotR} fill="var(--green)" />
        <text
          x={GATEWAY_X}
          y={L.gatewayY + L.gatewayR + L.gwLabelGap + L.gatewayFont * 0.85}
          textAnchor="middle"
          fontSize={L.gatewayFont}
          fontWeight={700}
          fill="var(--text)"
        >
          Operations
        </text>
        <text
          x={GATEWAY_X}
          y={L.gatewayY + L.gatewayR + L.gwLabelGap + L.gatewayFont * 0.85 + L.gwLineHeight}
          textAnchor="middle"
          fontSize={L.gatewayFont}
          fontWeight={700}
          fill="var(--text)"
        >
          Manager
        </text>

        {/* agent nodes */}
        {agentRows.map(({ item, y }) => {
          const total = item.tool_calls + item.llm_calls;
          return (
            <g key={`n-agent-${item.role}`}>
              <rect
                x={LEFT_X}
                y={y - L.nodeH / 2}
                width={L.nodeW}
                height={L.nodeH}
                rx={L.rx}
                fill="var(--card-bg)"
                stroke={COLOR_AGENT}
                strokeWidth={L.strokeW}
              />
              <circle cx={LEFT_X + dotDx} cy={y - L.nodeH / 2 + dotDy} r={L.dotR} fill={total > 0 ? "var(--green)" : "var(--text-faint)"} />
              <text x={LEFT_X + titleDx} y={y - L.nodeH / 2 + titleDy} fontSize={fitTitleFont} fontWeight={700} fill="var(--text)">
                {truncate(item.role, 15)}
              </text>
              <text x={LEFT_X + subDx} y={y + L.nodeH / 2 - subDy} fontSize={fitSubFont} fill="var(--text-muted)">
                {total > 0 ? `${total} call${total === 1 ? "" : "s"} (24h)` : "idle"}
              </text>
              <title>
                {item.description}
                {"\n"}Tool calls: {item.tool_calls} · LLM calls: {item.llm_calls}
                {"\n"}
                {relativeTime(item.last_active_at)}
              </title>
            </g>
          );
        })}

        {/* right column nodes (servers + llm providers) */}
        {rightRows.map(({ item, y }) => {
          if (item.kind === "server") {
            const s = item.data;
            const dotColor =
              s.trust_status !== "trusted" ? "var(--red)" : s.calls > 0 ? "var(--green)" : "var(--text-faint)";
            return (
              <g key={`n-server-${s.server_id}`}>
                <rect
                  x={L.rightX}
                  y={y - L.nodeH / 2}
                  width={L.nodeW}
                  height={L.nodeH}
                  rx={L.rx}
                  fill="var(--card-bg)"
                  stroke={COLOR_SERVER}
                  strokeWidth={L.strokeW}
                />
                <circle cx={L.rightX + dotDx} cy={y - L.nodeH / 2 + dotDy} r={L.dotR} fill={dotColor} />
                <text x={L.rightX + titleDx} y={y - L.nodeH / 2 + titleDy} fontSize={fitTitleFont} fontWeight={700} fill="var(--text)">
                  {truncate(s.label, 18)}
                </text>
                <text x={L.rightX + subDx} y={y + L.nodeH / 2 - subDy} fontSize={fitSubFont} fill="var(--text-muted)">
                  {s.calls > 0 ? `${s.calls} call${s.calls === 1 ? "" : "s"} (24h) · ${s.tool_count} tools` : `${s.tool_count} tools · idle`}
                </text>
                <title>
                  {s.label} ({s.server_id}){"\n"}
                  Owner: {s.owner || "-"}
                  {"\n"}
                  Trust: {s.trust_status}
                  {"\n"}
                  {relativeTime(s.last_active_at)}
                </title>
              </g>
            );
          }
          const p = item.data;
          const dotColor = !p.configured ? "var(--text-faint)" : p.calls > 0 ? "var(--green)" : "var(--amber)";
          return (
            <g key={`n-llm-${p.provider}`}>
              <rect
                x={L.rightX}
                y={y - L.nodeH / 2}
                width={L.nodeW}
                height={L.nodeH}
                rx={L.rx}
                fill="var(--card-bg)"
                stroke={COLOR_LLM}
                strokeWidth={L.strokeW}
                strokeDasharray={p.configured ? undefined : "3 3"}
              />
              <circle cx={L.rightX + dotDx} cy={y - L.nodeH / 2 + dotDy} r={L.dotR} fill={dotColor} />
              <text x={L.rightX + titleDx} y={y - L.nodeH / 2 + titleDy} fontSize={fitTitleFont} fontWeight={700} fill="var(--text)">
                {truncate(p.label, 15)}
                {p.is_default ? " ★" : ""}
              </text>
              <text x={L.rightX + subDx} y={y + L.nodeH / 2 - subDy} fontSize={fitSubFont} fill="var(--text-muted)">
                {!p.configured
                  ? `${p.vendor} · no API key`
                  : p.calls > 0
                  ? `${p.calls} call${p.calls === 1 ? "" : "s"} (24h)`
                  : `${p.vendor} · configured, idle`}
              </text>
              <title>
                {p.label} ({p.vendor}){"\n"}
                {p.configured ? "API key configured" : "No API key configured"}
                {"\n"}
                Caching {p.caching_enabled ? "enabled" : "disabled"}
                {p.is_default ? "\nDefault provider" : ""}
                {"\n"}
                {relativeTime(p.last_active_at)}
              </title>
            </g>
          );
        })}
        </svg>
      </div>

      <div
        className="flex-row"
        style={{ gap: 18, marginTop: 6, flexWrap: "wrap", fontSize: 11.5, color: "var(--text-muted)", flexShrink: 0 }}
      >
        <span>
          <span
            style={{
              display: "inline-block",
              width: 8,
              height: 8,
              borderRadius: "50%",
              background: "var(--blue)",
              marginRight: 5,
            }}
          />
          Agents (RBAC roles)
        </span>
        <span>
          <span
            style={{
              display: "inline-block",
              width: 8,
              height: 8,
              borderRadius: "50%",
              background: "var(--teal)",
              marginRight: 5,
            }}
          />
          MCP tool servers
        </span>
        <span>
          <span
            style={{
              display: "inline-block",
              width: 8,
              height: 8,
              borderRadius: "50%",
              background: "var(--amber)",
              marginRight: 5,
            }}
          />
          LLM providers
        </span>
        <span>Line thickness = call volume in the last {data.window_hours}h · dashed/dim = no activity in that window</span>
      </div>
    </div>
  );
}
