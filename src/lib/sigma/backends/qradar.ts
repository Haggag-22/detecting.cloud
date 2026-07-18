import type { ParsedSigmaRule } from "../types";
import { matchToQRadarPredicate } from "../field";
import { renderCondition } from "./shared";

export function convertToQRadar(rule: ParsedSigmaRule): { query: string; warnings: string[] } {
  const warnings = [...rule.parseWarnings];
  const { expression, warnings: condWarn } = renderCondition(rule, matchToQRadarPredicate, {
    wrapNot: (inner) => `NOT (${inner})`,
  });
  warnings.push(...condWarn);

  const query = [
    "SELECT UTF8(payload) AS event_payload, \"eventName\", \"eventSource\", \"userIdentity.arn\", \"sourceIPAddress\"",
    "FROM events",
    `WHERE ${expression === "true" ? "1=1" : expression}`,
    "LAST 24 HOURS",
  ].join("\n");

  warnings.push(
    "QRadar AQL is best-effort — custom properties / DSM mappings may differ from Sigma field names"
  );
  return { query, warnings };
}
