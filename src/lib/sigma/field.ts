import type { SigmaFieldMatch } from "./types";

/** Normalize Sigma list-wildcard fields like containerDefinitions{}.image → approximate path */
export function normalizeFieldPath(field: string): string {
  return field.replace(/\{\}/g, "");
}

export function escapeSql(value: string): string {
  return value.replace(/'/g, "''");
}

export function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export function valueToString(v: string | number | boolean): string {
  return String(v);
}

/** Join match alternatives: OR within a field's values (unless allValues) */
export function joinAlts(parts: string[], allValues?: boolean): string {
  if (parts.length === 0) return "true";
  if (parts.length === 1) return parts[0];
  const joiner = allValues ? " AND " : " OR ";
  return `(${parts.join(joiner)})`;
}

export function matchToSqlPredicate(m: SigmaFieldMatch, fieldExpr?: string): string {
  const field = fieldExpr ?? normalizeFieldPath(m.field);
  const parts = m.values.map((v) => {
    const s = valueToString(v);
    switch (m.modifier) {
      case "contains":
        return `${field} LIKE '%${escapeSql(s)}%'`;
      case "startswith":
        return `${field} LIKE '${escapeSql(s)}%'`;
      case "endswith":
        return `${field} LIKE '%${escapeSql(s)}'`;
      case "re":
        return `REGEXP_LIKE(${field}, '${escapeSql(s)}')`;
      case "cidr":
        return `${field} LIKE '${escapeSql(s)}%' /* cidr approx */`;
      default:
        if (typeof v === "boolean" || typeof v === "number") {
          return `${field} = ${v}`;
        }
        return `${field} = '${escapeSql(s)}'`;
    }
  });
  return joinAlts(parts, m.allValues);
}

export function matchToSplunkExpr(m: SigmaFieldMatch): string {
  const field = normalizeFieldPath(m.field);
  const parts = m.values.map((v) => {
    const s = valueToString(v);
    switch (m.modifier) {
      case "contains":
        return `like(${field}, "%${s.replace(/"/g, '\\"')}%")`;
      case "startswith":
        return `like(${field}, "${s.replace(/"/g, '\\"')}%")`;
      case "endswith":
        return `like(${field}, "%${s.replace(/"/g, '\\"')}")`;
      case "re":
        return `match(${field}, "${s.replace(/"/g, '\\"')}")`;
      default:
        if (typeof v === "boolean") return `${field}=${v}`;
        if (typeof v === "number") return `${field}=${v}`;
        // Prefer search-time equality for eventName/eventSource
        if (field === "eventName" || field === "eventSource") {
          return `${field}=${s.includes(" ") ? `"${s}"` : s}`;
        }
        return `${field}="${s.replace(/"/g, '\\"')}"`;
    }
  });
  return joinAlts(parts, m.allValues);
}

export function matchToCloudWatchFilter(m: SigmaFieldMatch): string {
  const field = normalizeFieldPath(m.field);
  const parts = m.values.map((v) => {
    const s = valueToString(v);
    switch (m.modifier) {
      case "contains":
        return `${field} like /${escapeRegex(s)}/`;
      case "startswith":
        return `${field} like /^${escapeRegex(s)}/`;
      case "endswith":
        return `${field} like /${escapeRegex(s)}$/`;
      case "re":
        return `${field} like /${s}/`;
      default:
        if (typeof v === "boolean" || typeof v === "number") {
          return `${field} = ${v}`;
        }
        return `${field} = "${s.replace(/"/g, '\\"')}"`;
    }
  });
  return joinAlts(parts, m.allValues);
}

export function matchToEsqlPredicate(m: SigmaFieldMatch): string {
  const field = normalizeFieldPath(m.field);
  const parts = m.values.map((v) => {
    const s = valueToString(v);
    switch (m.modifier) {
      case "contains":
        return `${field} LIKE "*${s.replace(/\*/g, "\\*")}*"`;
      case "startswith":
        return `${field} LIKE "${s.replace(/\*/g, "\\*")}*"`;
      case "endswith":
        return `${field} LIKE "*${s.replace(/\*/g, "\\*")}"`;
      case "re":
        return `${field} RLIKE "${s.replace(/"/g, '\\"')}"`;
      default:
        if (typeof v === "boolean" || typeof v === "number") {
          return `${field} == ${v}`;
        }
        return `${field} == "${s.replace(/"/g, '\\"')}"`;
    }
  });
  return joinAlts(parts, m.allValues).replace(/ OR /g, " OR ").replace(/ AND /g, " AND ");
}

/** Datadog Log Explorer / Cloud SIEM style facets */
export function matchToDatadogClause(m: SigmaFieldMatch): string {
  const field = normalizeFieldPath(m.field);
  // Map common CloudTrail fields to Datadog facets
  const facetMap: Record<string, string> = {
    eventName: "@evt.name",
    eventSource: "@evt.source",
    "userIdentity.arn": "@userIdentity.arn",
    "userIdentity.type": "@userIdentity.type",
    sourceIPAddress: "@network.client.ip",
  };
  const facet = facetMap[field] ?? `@${field}`;

  const parts = m.values.map((v) => {
    const s = valueToString(v);
    switch (m.modifier) {
      case "contains":
        return `${facet}:*${escapeDatadog(s)}*`;
      case "startswith":
        return `${facet}:${escapeDatadog(s)}*`;
      case "endswith":
        return `${facet}:*${escapeDatadog(s)}`;
      case "re":
        return `${facet}:/${s}/`;
      default:
        if (typeof v === "boolean" || typeof v === "number") {
          return `${facet}:${v}`;
        }
        return s.includes(" ") || s.includes(":") || s.includes('"')
          ? `${facet}:"${s.replace(/"/g, '\\"')}"`
          : `${facet}:${s}`;
    }
  });

  if (parts.length === 1) return parts[0];
  const joiner = m.allValues ? " AND " : " OR ";
  return `(${parts.join(joiner)})`;
}

function escapeDatadog(s: string): string {
  return s.replace(/([:*\\])/g, "\\$1");
}

/** Extract eventName / eventSource values for EventBridge-style patterns */
export function extractSimpleEquals(
  matches: SigmaFieldMatch[],
  field: string
): Array<string | number | boolean> {
  const out: Array<string | number | boolean> = [];
  for (const m of matches) {
    if (normalizeFieldPath(m.field) === field && m.modifier === "equals") {
      out.push(...m.values);
    }
  }
  return out;
}
