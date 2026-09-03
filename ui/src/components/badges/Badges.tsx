type Severity = "critical" | "high" | "medium" | "low" | "info" | string;
type Decision = "ALLOW" | "DENY" | "ERROR" | string;
type Trust = "trusted" | "untrusted" | string;

const KNOWN_SEVERITIES = new Set(["critical", "high", "medium", "low", "info"]);

export function SeverityBadge({ severity, solid = false }: { severity: Severity; solid?: boolean }) {
  const known = KNOWN_SEVERITIES.has(severity);
  const cls = solid && severity === "critical" ? "badge-solid-critical" : known ? `badge-${severity}` : "badge-neutral";
  return <span className={`badge ${cls}`}>{severity}</span>;
}

export function DecisionBadge({ decision }: { decision: Decision }) {
  const cls = decision === "ALLOW" ? "badge-allow" : decision === "DENY" ? "badge-deny" : "badge-error";
  return <span className={`badge ${cls}`}>{decision}</span>;
}

export function TrustBadge({ trust }: { trust: Trust }) {
  const cls = trust === "trusted" ? "badge-trusted" : "badge-untrusted";
  return <span className={`badge ${cls}`}>{trust}</span>;
}

export function TagBadge({ label }: { label: string }) {
  return <span className="badge badge-neutral">{label}</span>;
}
